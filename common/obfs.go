package common

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"time"
)

// ─────────────────────────────────────────────
// Connection obfuscation handshake
// ─────────────────────────────────────────────
//
// Immediately after a cell-bearing TCP connection is established (and before
// any cell I/O), both peers exchange a random-length junk preamble:
//
//   [1]   N — preamble length, 16..255
//   [N]   N cryptographically-random bytes (discarded by the receiver)
//
// This means the first bytes of every SbNet connection differ in length and
// content, so a censor cannot fingerprint the start of the stream by a fixed
// handshake signature. Combined with the variable-length cell framing in
// cell.go, the connection has no constant size or byte pattern to match on.
//
// The exchange is mutual and symmetric: each side writes its own preamble and
// reads+discards the peer's. It is safe to call on both the dialer and the
// accepter; ordering does not matter because writes are buffered by the kernel
// and each side reads independently.

const (
	obfsMinPreamble = 16
	obfsMaxPreamble = 255
	// obfsHandshakeTimeout bounds how long the preamble exchange may take so a
	// silent peer cannot hang a connection during setup.
	obfsHandshakeTimeout = 15 * time.Second
)

// ObfsHandshake performs the mutual junk-preamble exchange on conn. It must be
// called exactly once per connection, before any ReadCell/WriteCell.
func ObfsHandshake(conn net.Conn) error {
	// Bound the handshake; restore (clear) the deadline on success so later
	// per-operation deadlines set by callers behave normally.
	_ = conn.SetDeadline(time.Now().Add(obfsHandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	if err := writeObfsPreamble(conn); err != nil {
		return fmt.Errorf("obfs write: %w", err)
	}
	if err := readObfsPreamble(conn); err != nil {
		return fmt.Errorf("obfs read: %w", err)
	}
	return nil
}

func writeObfsPreamble(w io.Writer) error {
	var nb [1]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return err
	}
	n := int(nb[0])
	if n < obfsMinPreamble {
		n += obfsMinPreamble
	}
	if n > obfsMaxPreamble {
		n = obfsMaxPreamble
	}
	buf := make([]byte, 1+n)
	buf[0] = byte(n)
	if _, err := rand.Read(buf[1:]); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}

func readObfsPreamble(r io.Reader) error {
	var nb [1]byte
	if _, err := io.ReadFull(r, nb[:]); err != nil {
		return err
	}
	n := int(nb[0])
	if n == 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, r, int64(n))
	return err
}
