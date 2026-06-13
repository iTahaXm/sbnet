package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"

	"sbnet/common"
)

// ─────────────────────────────────────────────
// Bridge URI parser
// ─────────────────────────────────────────────
//
// Format: sbnet://bridge=host:port&token=xxx&obfs=tls&mode=secure

func parseBridgeURI(uri string) (common.BridgeConfig, error) {
	var cfg common.BridgeConfig
	if !strings.HasPrefix(uri, "sbnet://") {
		return cfg, fmt.Errorf("not a sbnet:// URI")
	}
	vals, err := url.ParseQuery(uri[len("sbnet://"):])
	if err != nil {
		return cfg, fmt.Errorf("malformed bridge URI: %w", err)
	}
	cfg.Endpoint = vals.Get("bridge")
	cfg.Token = vals.Get("token")
	cfg.Obfs = vals.Get("obfs")
	cfg.Mode = vals.Get("mode")
	if cfg.Endpoint == "" {
		return cfg, fmt.Errorf("bridge URI missing 'bridge' parameter")
	}
	if cfg.Obfs == "" {
		cfg.Obfs = "tls"
	}
	if cfg.Mode == "" {
		cfg.Mode = "secure"
	}
	return cfg, nil
}

// ─────────────────────────────────────────────
// Bridge server
// ─────────────────────────────────────────────

type bridgeServer struct {
	cfg    common.BridgeServerConfig
	log    *common.Logger
	dialer proxy.Dialer // upstream egress dialer (direct or SOCKS5)

	// foreignRelays is refreshed in background.
	foreignMu    sync.RWMutex
	foreignRelays []common.RelayDescriptor
}


func newBridgeServer(cfg common.BridgeServerConfig) (*bridgeServer, error) {
	lvl := common.ParseLogLevel(cfg.LogLevel)
	b := &bridgeServer{
		cfg: cfg,
		log: common.NewLogger("bridge", lvl, nil),
	}

	if cfg.UpstreamProxy != "" {
		u, err := url.Parse(cfg.UpstreamProxy)
		if err != nil {
			return nil, fmt.Errorf("bad upstream_proxy URL: %w", err)
		}
		switch u.Scheme {
		case "socks5":
			var auth *proxy.Auth
			if u.User != nil {
				pw, _ := u.User.Password()
				auth = &proxy.Auth{User: u.User.Username(), Password: pw}
			}
			d, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("SOCKS5 dialer: %w", err)
			}
			b.dialer = d
		default:
			return nil, fmt.Errorf("unsupported upstream_proxy scheme %q (use socks5://)", u.Scheme)
		}
	} else {
		b.dialer = proxy.Direct
	}

	return b, nil
}

// ─────────────────────────────────────────────
// Foreign network connection
// ─────────────────────────────────────────────

// foreignDial opens a TCP connection to the foreign entry relay, routed
// through the upstream proxy (if any) and optionally wrapped in TLS (obfs=tls).
func (b *bridgeServer) foreignDial(addr string) (net.Conn, error) {
	conn, err := b.dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	if b.cfg.Obfs == "tls" {
		host := strings.Split(addr, ":")[0]
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true, // self-signed cert on foreign relay; trust via token
			ServerName:         host,
		})
		if err := tlsConn.HandshakeContext(context.Background()); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake to %s: %w", addr, err)
		}
		return tlsConn, nil
	}
	return conn, nil
}

// ─────────────────────────────────────────────
// Foreign consensus
// ─────────────────────────────────────────────

func (b *bridgeServer) fetchForeignConsensus() ([]common.RelayDescriptor, error) {
	if b.cfg.ForeignDirURL == "" {
		return nil, fmt.Errorf("foreign_dir_url not configured")
	}
	consensus, err := common.FetchVerifiedConsensus(b.cfg.ForeignDirURL, b.cfg.ForeignDirTLSCA)
	if err != nil {
		return nil, err
	}
	b.log.Info("Foreign consensus: %d relays", len(consensus.Relays))
	return consensus.Relays, nil
}

// refreshForeignConsensus periodically refreshes the foreign relay list.
func (b *bridgeServer) refreshForeignConsensus(ctx context.Context) {
	for {
		relays, err := b.fetchForeignConsensus()
		if err != nil {
			b.log.Warn("Foreign consensus refresh failed: %v", err)
		} else {
			b.foreignMu.Lock()
			b.foreignRelays = relays
			b.foreignMu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Minute):
		}
	}
}

// pickForeignEntry returns a random entry relay from the foreign consensus.
func (b *bridgeServer) pickForeignEntry() *common.RelayDescriptor {
	b.foreignMu.RLock()
	defer b.foreignMu.RUnlock()
	var pool []common.RelayDescriptor
	for _, r := range b.foreignRelays {
		if r.Role == "entry" {
			pool = append(pool, r)
		}
	}
	if len(pool) == 0 {
		return nil
	}
	jb := make([]byte, 1)
	common.RandomBytes(jb)
	r := pool[int(jb[0])%len(pool)]
	return &r
}

// ─────────────────────────────────────────────
// Client session
// ─────────────────────────────────────────────
//
// Protocol:
//   1. Client connects and sends a BridgeHandshake cell:
//        CircID = 0xFFFFFFFF (sentinel)
//        Command = CmdCreate
//        Body: tokenLen(2) | token(tokenLen) | clientEphemeralPub(32)
//   2. Bridge validates the token.
//   3. Bridge dials the foreign entry relay and forwards a CmdCreate with
//      the client's ephemeral pubkey — the client and foreign entry negotiate
//      their own session key; the bridge never sees it.
//   4. Bridge returns the foreign entry's CmdCreated to the client.
//   5. Bridge then acts as a transparent bidirectional pipe.

const bridgeSentinelCircID = uint32(0xFFFFFFFF)

func (b *bridgeServer) handleClientConn(conn net.Conn) {
	defer conn.Close()

	if err := common.ObfsHandshake(conn); err != nil {
		b.log.Debug("obfs handshake from %s failed: %v", conn.RemoteAddr(), err)
		return
	}

	// Step 1: read handshake cell.
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	cell, err := common.ReadCell(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		b.log.Warn("Handshake read error from %s: %v", conn.RemoteAddr(), err)
		return
	}
	if cell.CircID != bridgeSentinelCircID || cell.Command != common.CmdCreate {
		b.log.Warn("Invalid handshake from %s (circID=%08x cmd=%d)",
			conn.RemoteAddr(), cell.CircID, cell.Command)
		return
	}

	// Step 2: validate token.
	if int(cell.Length) < 2 {
		return
	}
	tokenLen := int(binary.BigEndian.Uint16(cell.Body[0:2]))
	if 2+tokenLen+32 > int(cell.Length) {
		b.log.Warn("Truncated handshake from %s", conn.RemoteAddr())
		return
	}
	token := string(cell.Body[2 : 2+tokenLen])
	if subtle.ConstantTimeCompare([]byte(token), []byte(b.cfg.Token)) != 1 {
		b.log.Warn("Invalid token from %s", conn.RemoteAddr())
		return
	}

	// Extract the client's ephemeral pubkey (32 bytes after the token).
	var clientEphPub [32]byte
	copy(clientEphPub[:], cell.Body[2+tokenLen:2+tokenLen+32])

	// Step 3: dial foreign entry.
	entry := b.pickForeignEntry()
	if entry == nil {
		b.log.Warn("No foreign entry relay available for %s", conn.RemoteAddr())
		return
	}
	foreignAddr := fmt.Sprintf("%s:%d", entry.IP, entry.Port)
	foreignConn, err := b.foreignDial(foreignAddr)
	if err != nil {
		b.log.Warn("Cannot reach foreign entry %s: %v", foreignAddr, err)
		return
	}
	defer foreignConn.Close()
	if err := common.ObfsHandshake(foreignConn); err != nil {
		b.log.Warn("obfs handshake with foreign entry %s failed: %v", foreignAddr, err)
		return
	}

	// Forward Create with the client's ephemeral pubkey.
	newCircID := common.RandomUint32()
	fwdCreate := common.Cell{CircID: newCircID, Command: common.CmdCreate, Length: 32}
	copy(fwdCreate.Body[:], clientEphPub[:])
	foreignConn.Write(common.MarshalCell(fwdCreate))

	// Step 4: wait for Created from foreign entry, forward to client.
	foreignConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	created, err := common.ReadCell(foreignConn)
	foreignConn.SetReadDeadline(time.Time{})
	if err != nil || created.Command != common.CmdCreated {
		b.log.Warn("No Created from foreign entry %s: %v", foreignAddr, err)
		return
	}
	// Rewrite CircID to the sentinel so the client's circuit state matches.
	created.CircID = bridgeSentinelCircID
	conn.Write(common.MarshalCell(created))

	b.log.Info("Bridge tunnel: %s → %s (circID=%08x)", conn.RemoteAddr(), foreignAddr, newCircID)

	// Step 5: transparent bidirectional pipe.
	// Rewrite CircIDs: client uses sentinel, foreign relay uses newCircID.
	done := make(chan struct{}, 2)

	// client → foreign: replace sentinel CircID with newCircID
	go func() {
		for {
			c, err := common.ReadCell(conn)
			if err != nil {
				break
			}
			c.CircID = newCircID
			if err := common.WriteCell(foreignConn, c); err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	// foreign → client: replace newCircID with sentinel
	go func() {
		for {
			c, err := common.ReadCell(foreignConn)
			if err != nil {
				break
			}
			c.CircID = bridgeSentinelCircID
			if err := common.WriteCell(conn, c); err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	<-done
	b.log.Debug("Bridge session closed: %s", conn.RemoteAddr())
}

// ─────────────────────────────────────────────
// Listener
// ─────────────────────────────────────────────

func (b *bridgeServer) buildListener() (net.Listener, error) {
	if b.cfg.Obfs == "tls" && b.cfg.TLSCert != "" && b.cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(b.cfg.TLSCert, b.cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load TLS cert/key: %w", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
		ln, err := tls.Listen("tcp", b.cfg.ListenAddr, tlsCfg)
		if err != nil {
			return nil, err
		}
		b.log.Info("Bridge TLS listener on %s", b.cfg.ListenAddr)
		return ln, nil
	}
	ln, err := net.Listen("tcp", b.cfg.ListenAddr)
	if err != nil {
		return nil, err
	}
	if b.cfg.Obfs == "tls" {
		b.log.Warn("obfs=tls configured but no tls_cert/tls_key — falling back to plain TCP")
	}
	b.log.Info("Bridge TCP listener on %s", b.cfg.ListenAddr)
	return ln, nil
}

func (b *bridgeServer) serve(ctx context.Context, ln net.Listener) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				b.log.Warn("Accept error: %v", err)
				continue
			}
		}
		go b.handleClientConn(conn)
	}
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

func loadConfig() common.BridgeServerConfig {
	var cfg common.BridgeServerConfig
	path := "bridge.yaml"
	if p := os.Getenv("SBNET_CONFIG"); p != "" {
		path = p
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("Parse bridge.yaml: %v", err)
		}
	}
	cfg.ApplyDefaults()
	return cfg
}

func main() {
	cfg := loadConfig()
	srv, err := newBridgeServer(cfg)
	if err != nil {
		log.Fatal(err)
	}

	// Initial consensus fetch — fatal if unavailable at startup.
	relays, err := srv.fetchForeignConsensus()
	if err != nil {
		log.Fatalf("Cannot fetch foreign consensus from %s: %v", cfg.ForeignDirURL, err)
	}
	srv.foreignMu.Lock()
	srv.foreignRelays = relays
	srv.foreignMu.Unlock()

	ln, err := srv.buildListener()
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go srv.refreshForeignConsensus(ctx) // background refresh every 5 min

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		srv.log.Info("Bridge shutting down...")
		cancel()
	}()

	srv.log.Info("Bridge ready  foreign=%s  obfs=%s  mode=%s",
		cfg.ForeignDirURL, cfg.Obfs, cfg.Mode)
	srv.serve(ctx, ln)
	srv.log.Info("Bridge stopped.")
}
