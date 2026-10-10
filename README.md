# wgspeedtest

Measure download speed through a WireGuard tunnel defined by a wg-quick config. It runs entirely in userspace (wireguard-go + gVisor netstack), so no root, TUN device, or system network changes are needed.

## Usage

```sh
go install github.com/PeronGH/wgspeedtest@latest
wgspeedtest -f wg.conf
wgspeedtest -f wg.conf -d 5s 'https://speed.cloudflare.com/__down?bytes=100000000'
```

It downloads for `-d` (default 10s) and prints the speed. The URL defaults to `https://mensura.cdn-apple.com/api/v1/gm/large`.

Flags must come before the URL:

- `-f` WireGuard config file (required)
- `-d` download duration (default `10s`)
- `-timeout` time limit until response headers arrive (default `10s`)
- `-v` verbose WireGuard logging

The config needs a `DNS` entry if the URL uses a hostname, since name resolution happens inside the tunnel.

For Cloudflare WARP, add `Reserved = 32, 165, 72` or `ClientId = IKVI` (base64) to `[Peer]` to send the client id in the reserved header bytes.
