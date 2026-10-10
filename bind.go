package main

import "golang.zx2c4.com/wireguard/conn"

// reservedBind writes Cloudflare WARP's client id into the three reserved header
// bytes of outgoing messages and clears them on incoming ones, because wireguard-go
// reads the first four bytes as the message type.
type reservedBind struct {
	conn.Bind
	reserved [3]byte
}

func (b *reservedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	for i, fn := range fns {
		fns[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(packets, sizes, eps)
			for j := range n {
				if sizes[j] >= 4 {
					clear(packets[j][1:4])
				}
			}
			return n, err
		}
	}
	return fns, actualPort, nil
}

func (b *reservedBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, buf := range bufs {
		if len(buf) >= 4 {
			copy(buf[1:4], b.reserved[:])
		}
	}
	return b.Bind.Send(bufs, ep)
}
