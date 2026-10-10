# wgspeedtest

Measure download speed through a WireGuard tunnel defined by a wg-quick config. It runs entirely in userspace (wireguard-go + gVisor netstack), so no root, TUN device, or system network changes are needed.

## Usage

```sh
go install github.com/PeronGH/wgspeedtest@latest
wgspeedtest -f wg.conf 'https://speed.cloudflare.com/__down?bytes=100000000'
```

Flags must come before the URL:

- `-f` WireGuard config file (required)
- `-timeout` time limit until response headers arrive (default `30s`)
- `-v` verbose WireGuard logging

The config needs a `DNS` entry if the URL uses a hostname, since name resolution happens inside the tunnel.
