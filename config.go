package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Config struct {
	PrivateKey string
	Addresses  []netip.Addr
	DNS        []netip.Addr
	MTU        int
	Peers      []Peer
	// Reserved is set from a WARP Reserved/ClientId key in [Peer]; nil means standard WireGuard.
	Reserved *[3]byte
}

type Peer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []netip.Prefix
	PersistentKeepalive int
}

// ParseConfig reads the subset of the wg-quick(8) format needed for a userspace tunnel.
// Keys that only matter to wg-quick (PostUp, Table, ...) are ignored.
func ParseConfig(r io.Reader) (*Config, error) {
	cfg := &Config{MTU: 1420}
	var section string
	var peer *Peer

	scanner := bufio.NewScanner(r)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				cfg.Peers = append(cfg.Peers, Peer{})
				peer = &cfg.Peers[len(cfg.Peers)-1]
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", lineNo)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		var err error
		switch section {
		case "interface":
			err = cfg.set(key, value)
		case "peer":
			err = peer.set(key, value)
			if err == nil && (key == "reserved" || key == "clientid") {
				cfg.Reserved, err = parseReserved(key, value)
			}
		default:
			err = fmt.Errorf("key outside of [Interface] or [Peer]")
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %s: %w", lineNo, key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("missing PrivateKey in [Interface]")
	}
	if len(cfg.Addresses) == 0 {
		return nil, fmt.Errorf("missing Address in [Interface]")
	}
	if len(cfg.Peers) == 0 {
		return nil, fmt.Errorf("no [Peer] section")
	}
	return cfg, nil
}

func (c *Config) set(key, value string) (err error) {
	switch key {
	case "privatekey":
		c.PrivateKey, err = keyToHex(value)
	case "address":
		for _, s := range splitList(value) {
			addr, _, _ := strings.Cut(s, "/")
			var a netip.Addr
			if a, err = netip.ParseAddr(addr); err != nil {
				return err
			}
			c.Addresses = append(c.Addresses, a)
		}
	case "dns":
		// Non-IP entries are search domains in wg-quick; they are irrelevant here.
		for _, s := range splitList(value) {
			if a, err := netip.ParseAddr(s); err == nil {
				c.DNS = append(c.DNS, a)
			}
		}
	case "mtu":
		c.MTU, err = strconv.Atoi(value)
	}
	return err
}

func (p *Peer) set(key, value string) (err error) {
	switch key {
	case "publickey":
		p.PublicKey, err = keyToHex(value)
	case "presharedkey":
		p.PresharedKey, err = keyToHex(value)
	case "endpoint":
		p.Endpoint = value
	case "allowedips":
		for _, s := range splitList(value) {
			var prefix netip.Prefix
			if prefix, err = netip.ParsePrefix(s); err != nil {
				return err
			}
			p.AllowedIPs = append(p.AllowedIPs, prefix)
		}
	case "persistentkeepalive":
		if value != "off" {
			p.PersistentKeepalive, err = strconv.Atoi(value)
		}
	}
	return err
}

// UAPI renders the device configuration for (*device.Device).IpcSet.
// Endpoints are resolved here because UAPI only accepts IP:port.
func (c *Config) UAPI() (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", c.PrivateKey)
	for _, p := range c.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "preshared_key=%s\n", p.PresharedKey)
		}
		if p.Endpoint != "" {
			addr, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return "", err
			}
			ap := addr.AddrPort()
			fmt.Fprintf(&b, "endpoint=%s\n", netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, prefix := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", prefix)
		}
	}
	return b.String(), nil
}

func keyToHex(s string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(k), nil
}

func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// parseReserved accepts "Reserved = 32, 165, 72" (brackets optional) or the base64
// "ClientId = IKVI" that WARP issues.
func parseReserved(key, value string) (*[3]byte, error) {
	var r [3]byte
	if key == "clientid" {
		b, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, err
		}
		if len(b) != 3 {
			return nil, fmt.Errorf("client id must decode to 3 bytes, got %d", len(b))
		}
		copy(r[:], b)
		return &r, nil
	}
	items := splitList(strings.Trim(value, "[]"))
	if len(items) != 3 {
		return nil, fmt.Errorf("expected 3 bytes, got %d", len(items))
	}
	for i, s := range items {
		v, err := strconv.ParseUint(s, 10, 8)
		if err != nil {
			return nil, err
		}
		r[i] = byte(v)
	}
	return &r, nil
}
