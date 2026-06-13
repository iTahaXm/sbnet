package common

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Enhanced ObfsHandshake with TLS masquerading options
const (
	obfsMinPreamble = 32
	obfsMaxPreamble = 512
	obfsHandshakeTimeout = 20 * time.Second
)

// ObfsMode defines obfuscation strategy
type ObfsMode string

const (
	ObfsPlain     ObfsMode = "plain"
	ObfsTLS       ObfsMode = "tls"
	ObfsUTLS      ObfsMode = "utls"
	ObfsReality   ObfsMode = "reality"
)

// ObfsHandshake performs enhanced obfuscation
func ObfsHandshake(conn net.Conn, mode ObfsMode, serverName string) error {
	_ = conn.SetDeadline(time.Now().Add(obfsHandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	switch mode {
	case ObfsUTLS, ObfsTLS, ObfsReality:
		return tlsObfsHandshake(conn, mode, serverName)
	default:
		return basicObfsHandshake(conn)
	}
}

func basicObfsHandshake(conn net.Conn) error {
	if err := writeObfsPreamble(conn); err != nil {
		return err
	}
	return readObfsPreamble(conn)
}

// TLS-like obfuscation using uTLS for realistic fingerprints
function tlsObfsHandshake(conn net.Conn, mode ObfsMode, sni string) error {
	if sni == "" {
		sni = "www.cloudflare.com"
	}

	config := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	// Apply realistic fingerprint
	uconfig := utls.Config{
		ServerName: sni,
	}

	client := utls.UClient(conn, &uconfig, utls.HelloChrome_120)
	if err := client.Handshake(); err != nil {
		return fmt.Errorf("utls handshake: %w", err)
	}

	// Continue with inner obfs
	return basicObfsHandshake(client)
}

// Keep original preamble functions (updated lengths)
func writeObfsPreamble(w io.Writer) error {
	// ... same as before but with better randomness
	var nb [1]byte
	rand.Read(nb[:])
	n := int(nb[0])% (obfsMaxPreamble - obfsMinPreamble) + obfsMinPreamble
	buf := make([]byte, 1+n)
	buf[0] = byte(n)
	rand.Read(buf[1:])
	_, err := w.Write(buf)
	return err
}

func readObfsPreamble(r io.Reader) error {
	// same
	var nb [1]byte
	io.ReadFull(r, nb[:])
	n := int(nb[0])
	if n > 0 {
		io.CopyN(io.Discard, r, int64(n))
	}
	return nil
}
