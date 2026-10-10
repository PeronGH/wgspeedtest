package main

import (
	"fmt"
	"os"
)

// status is a single self-overwriting terminal line. It is a no-op when the
// output is not a terminal, so redirected output stays clean.
type status struct {
	out   *os.File
	live  bool
	dirty bool
}

func newStatus(out *os.File) *status {
	fi, err := out.Stat()
	return &status{out: out, live: err == nil && fi.Mode()&os.ModeCharDevice != 0}
}

func (s *status) set(line string) {
	if !s.live {
		return
	}
	fmt.Fprintf(s.out, "\r%s\x1b[K", line)
	s.dirty = true
}

func (s *status) clear() {
	if s.dirty {
		fmt.Fprint(s.out, "\r\x1b[K")
		s.dirty = false
	}
}
