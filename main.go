package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const defaultURL = "https://mensura.cdn-apple.com/api/v1/gm/large"

func main() {
	confPath := flag.String("f", "", "WireGuard config file (wg-quick format)")
	duration := flag.Duration("d", 10*time.Second, "download duration")
	timeout := flag.Duration("timeout", 10*time.Second, "time limit until the response headers arrive")
	verbose := flag.Bool("v", false, "verbose WireGuard logging")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s -f wg.conf [flags] [URL]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *confPath == "" || flag.NArg() > 1 {
		flag.Usage()
		os.Exit(2)
	}
	url := defaultURL
	if flag.NArg() == 1 {
		url = flag.Arg(0)
	}

	if err := run(*confPath, url, *duration, *timeout, *verbose); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(confPath, url string, duration, timeout time.Duration, verbose bool) error {
	f, err := os.Open(confPath)
	if err != nil {
		return err
	}
	cfg, err := ParseConfig(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", confPath, err)
	}

	tnet, err := startTunnel(cfg, verbose)
	if err != nil {
		return err
	}

	// The tunnel and connection are deliberately not closed: the process exits right
	// after reporting, and teardown through netstack can block.
	client := &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext}}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	start := time.Now()
	headerTimer := time.AfterFunc(timeout, func() {
		cancel(fmt.Errorf("no response within %v (WireGuard handshake failed?)", timeout))
	})
	resp, err := client.Do(req)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return err
	}
	headerTimer.Stop()
	ttfb := time.Since(start)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}

	var received byteCounter
	done := make(chan error, 1)
	bodyStart := time.Now()
	go func() {
		_, err := io.Copy(&received, resp.Body)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			return err
		}
	case <-time.After(duration):
	}
	elapsed := time.Since(bodyStart)
	n := received.Load()

	fmt.Printf("time to first byte: %v\n", ttfb.Round(time.Millisecond))
	fmt.Printf("downloaded %.2f MB in %v\n", float64(n)/1e6, elapsed.Round(time.Millisecond))
	fmt.Printf("speed: %.2f Mbps\n", float64(n)*8/1e6/elapsed.Seconds())
	return nil
}

type byteCounter struct{ atomic.Int64 }

func (c *byteCounter) Write(p []byte) (int, error) {
	c.Add(int64(len(p)))
	return len(p), nil
}

func startTunnel(cfg *Config, verbose bool) (*netstack.Net, error) {
	uapi, err := cfg.UAPI()
	if err != nil {
		return nil, err
	}

	tunDev, tnet, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, cfg.MTU)
	if err != nil {
		return nil, err
	}

	logLevel := device.LogLevelError
	if verbose {
		logLevel = device.LogLevelVerbose
	}
	bind := conn.NewDefaultBind()
	if cfg.Reserved != nil {
		bind = &reservedBind{Bind: bind, reserved: *cfg.Reserved}
	}
	dev := device.NewDevice(tunDev, bind, device.NewLogger(logLevel, "wireguard: "))
	if err := dev.IpcSet(uapi); err != nil {
		return nil, err
	}
	return tnet, dev.Up()
}
