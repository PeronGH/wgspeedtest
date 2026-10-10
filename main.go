package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const defaultURL = "https://mensura.cdn-apple.com/api/v1/gm/large"

type options struct {
	url      string
	duration time.Duration
	timeout  time.Duration
	verbose  bool
}

func main() {
	confPath := flag.String("f", "", "WireGuard config file (wg-quick format)")
	endpointsPath := flag.String("e", "", "file with one endpoint (host:port) per line to test in turn")
	duration := flag.Duration("d", 10*time.Second, "download duration per test")
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
	opts := options{url: defaultURL, duration: *duration, timeout: *timeout, verbose: *verbose}
	if flag.NArg() == 1 {
		opts.url = flag.Arg(0)
	}

	ok, err := run(*confPath, *endpointsPath, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if !ok {
		os.Exit(1)
	}
}

// run tests every endpoint and reports whether all of them succeeded.
func run(confPath, endpointsPath string, opts options) (bool, error) {
	cfg, err := loadConfig(confPath)
	if err != nil {
		return false, err
	}

	endpoints := []string{cfg.Peers[0].Endpoint}
	if endpointsPath != "" {
		if endpoints, err = loadEndpoints(endpointsPath); err != nil {
			return false, err
		}
	}

	st := newStatus(os.Stderr)
	width := 0
	for _, ep := range endpoints {
		width = max(width, len(ep))
	}
	allOK := true
	for _, ep := range endpoints {
		label := fmt.Sprintf("%-*s", width, ep)
		res, err := speedTest(withEndpoint(cfg, ep), opts, func(s string) { st.set(label + "  " + s) })
		st.clear()
		if err != nil {
			allOK = false
			fmt.Printf("%s  error: %v\n", label, err)
			continue
		}
		fmt.Printf("%s  ttfb %6v  %8.2f MB in %4.1fs  %7.2f Mbps\n", label,
			res.ttfb.Round(time.Millisecond), float64(res.bytes)/1e6, res.elapsed.Seconds(), mbps(res.bytes, res.elapsed))
	}
	return allOK, nil
}

func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, err := ParseConfig(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func loadEndpoints(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var endpoints []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		if line = strings.TrimSpace(line); line != "" {
			endpoints = append(endpoints, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("%s: no endpoints", path)
	}
	return endpoints, nil
}

func withEndpoint(cfg *Config, endpoint string) *Config {
	c := *cfg
	c.Peers = slices.Clone(cfg.Peers)
	for i := range c.Peers {
		c.Peers[i].Endpoint = endpoint
	}
	return &c
}

type result struct {
	ttfb    time.Duration
	bytes   int64
	elapsed time.Duration
}

func speedTest(cfg *Config, opts options, progress func(string)) (result, error) {
	tnet, dev, err := startTunnel(cfg, opts.verbose)
	if err != nil {
		return result{}, err
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	// Teardown runs in the background so a stuck netstack connection cannot stall the next test.
	defer func() {
		go func() {
			cancel(nil)
			dev.Close()
		}()
	}()

	client := &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.url, nil)
	if err != nil {
		return result{}, err
	}

	start := time.Now()
	progress("connecting...")
	headerTimer := time.AfterFunc(opts.timeout, func() {
		cancel(fmt.Errorf("no response within %v (WireGuard handshake failed?)", opts.timeout))
	})
	resp, err := client.Do(req)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return result{}, cause
		}
		return result{}, err
	}
	headerTimer.Stop()
	ttfb := time.Since(start)
	if resp.StatusCode != http.StatusOK {
		return result{}, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	progress("downloading...")
	var received byteCounter
	done := make(chan error, 1)
	bodyStart := time.Now()
	go func() {
		_, err := io.Copy(&received, resp.Body)
		done <- err
	}()
	deadline := time.After(opts.duration)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var lastBytes int64
	lastTick := bodyStart
	for {
		select {
		case err := <-done:
			if err != nil {
				return result{}, err
			}
			return result{ttfb, received.Load(), time.Since(bodyStart)}, nil
		case <-deadline:
			return result{ttfb, received.Load(), time.Since(bodyStart)}, nil
		case now := <-ticker.C:
			n := received.Load()
			progress(fmt.Sprintf("%4.1fs / %v  %8.2f MB  now %7.2f Mbps  avg %7.2f Mbps",
				now.Sub(bodyStart).Seconds(), opts.duration, float64(n)/1e6,
				mbps(n-lastBytes, now.Sub(lastTick)), mbps(n, now.Sub(bodyStart))))
			lastBytes, lastTick = n, now
		}
	}
}

func mbps(bytes int64, d time.Duration) float64 {
	return float64(bytes) * 8 / 1e6 / d.Seconds()
}

type byteCounter struct{ atomic.Int64 }

func (c *byteCounter) Write(p []byte) (int, error) {
	c.Add(int64(len(p)))
	return len(p), nil
}

func startTunnel(cfg *Config, verbose bool) (*netstack.Net, *device.Device, error) {
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
	bind := conn.NewDefaultBind()
	if cfg.Reserved != nil {
		bind = &reservedBind{Bind: bind, reserved: *cfg.Reserved}
	}
	dev := device.NewDevice(tunDev, bind, device.NewLogger(logLevel, "wireguard: "))
	if err := dev.IpcSet(uapi); err != nil {
		go dev.Close()
		return nil, nil, err
	}
	if err := dev.Up(); err != nil {
		go dev.Close()
		return nil, nil, err
	}
	return tnet, dev, nil
}
