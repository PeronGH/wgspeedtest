package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func main() {
	confPath := flag.String("f", "", "WireGuard config file (wg-quick format)")
	timeout := flag.Duration("timeout", 30*time.Second, "time limit until the response headers arrive")
	verbose := flag.Bool("v", false, "verbose WireGuard logging")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s -f wg.conf [flags] URL\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *confPath == "" || flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(*confPath, flag.Arg(0), *timeout, *verbose); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(confPath, url string, timeout time.Duration, verbose bool) error {
	f, err := os.Open(confPath)
	if err != nil {
		return err
	}
	cfg, err := ParseConfig(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", confPath, err)
	}

	tnet, closeTunnel, err := startTunnel(cfg, verbose)
	if err != nil {
		return err
	}
	defer closeTunnel()

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
	defer resp.Body.Close()
	ttfb := time.Since(start)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}

	bodyStart := time.Now()
	n, err := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(bodyStart)
	if err != nil {
		return err
	}

	fmt.Printf("time to first byte: %v\n", ttfb.Round(time.Millisecond))
	fmt.Printf("downloaded %.2f MB in %v\n", float64(n)/1e6, elapsed.Round(time.Millisecond))
	fmt.Printf("speed: %.2f Mbps\n", float64(n)*8/1e6/elapsed.Seconds())
	return nil
}

func startTunnel(cfg *Config, verbose bool) (*netstack.Net, func(), error) {
	uapi, err := cfg.UAPI()
	if err != nil {
		return nil, nil, err
	}

	tunDev, tnet, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, cfg.MTU)
	if err != nil {
		return nil, nil, err
	}

	logLevel := device.LogLevelError
	if verbose {
		logLevel = device.LogLevelVerbose
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(logLevel, "wireguard: "))
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, err
	}
	return tnet, dev.Close, nil
}
