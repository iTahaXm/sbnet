package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"sbnet/common"
)

// ─────────────────────────────────────────────
// Circuit
// ─────────────────────────────────────────────

// Circuit represents one hop terminating at this relay.
type Circuit struct {
	ID      uint32
	InConn  net.Conn
	OutConn net.Conn   // nil at exit hop
	Key     []byte     // AES-256-GCM session key for this hop
	writeMu sync.Mutex // serialises all writes to InConn
}

// writeIn sends a cell toward the client, serialised by writeMu.
func (c *Circuit) writeIn(cell common.Cell) {
	c.writeMu.Lock()
	c.InConn.Write(common.MarshalCell(cell))
	c.writeMu.Unlock()
}

// ─────────────────────────────────────────────
// Relay server
// ─────────────────────────────────────────────

type relayServer struct {
	cfg       common.RelayConfig
	log       *common.Logger
	pubKeyHex string

	circuits   map[uint32]*Circuit
	circuitsMu sync.RWMutex

	replay  *common.ReplayFilter
	timeout *common.TimeoutTracker

	reasm   map[uint32]*common.Reassembler
	reasmMu sync.Mutex
}

func newRelayServer(cfg common.RelayConfig) (*relayServer, error) {
	_, pub, err := common.LoadOrCreateX25519(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load/create X25519 key: %w", err)
	}
	lvl := common.ParseLogLevel(cfg.LogLevel)
	s := &relayServer{
		cfg:       cfg,
		log:       common.NewLogger("relay/"+cfg.ID, lvl, nil),
		pubKeyHex: hex.EncodeToString(pub[:]),
		circuits:  make(map[uint32]*Circuit),
		replay:    common.NewReplayFilter(),
		reasm:     make(map[uint32]*common.Reassembler),
	}
	idle := time.Duration(cfg.CircuitIdleSecs) * time.Second
	s.timeout = common.NewTimeoutTracker(idle, s.destroyCircuit)
	return s, nil
}

// ─────────────────────────────────────────────
// Circuit lifecycle
// ─────────────────────────────────────────────

func (s *relayServer) destroyCircuit(circID uint32) {
	s.circuitsMu.Lock()
	circ, ok := s.circuits[circID]
	if ok {
		if circ.OutConn != nil {
			fwd := common.Cell{CircID: circID, Command: common.CmdDestroy}
			circ.OutConn.Write(common.MarshalCell(fwd))
			circ.OutConn.Close()
		}
		delete(s.circuits, circID)
	}
	s.circuitsMu.Unlock()
	s.timeout.Remove(circID)
	s.log.Debug("Circuit %d destroyed", circID)
}

// ─────────────────────────────────────────────
// Cell handler
// ─────────────────────────────────────────────

func (s *relayServer) handleCell(c common.Cell, conn net.Conn) {
	s.timeout.Touch(c.CircID)

	// ── Fragment reassembly ──
	if c.Command == common.CmdFragment || c.Command == common.CmdFragFinal {
		s.reasmMu.Lock()
		ra, ok := s.reasm[c.CircID]
		if !ok {
			ra = &common.Reassembler{}
			s.reasm[c.CircID] = ra
		}
		payload, complete := ra.Add(c)
		if complete {
			delete(s.reasm, c.CircID)
		}
		s.reasmMu.Unlock()
		if !complete {
			return
		}
		if len(payload) > common.CellBodyMax {
			payload = payload[:common.CellBodyMax]
		}
		c = common.Cell{CircID: c.CircID, Command: common.CmdRelay}
		c.Length = uint16(len(payload))
		copy(c.Body[:], payload)
	}

	switch c.Command {

	// ─── Create ───
	case common.CmdCreate:
		var clientPub [32]byte
		copy(clientPub[:], c.Body[:32])
		priv, pub := common.GenKeyPair()
		key := common.DeriveKey(priv, clientPub)

		circ := &Circuit{ID: c.CircID, InConn: conn, Key: key}
		s.circuitsMu.Lock()
		s.circuits[c.CircID] = circ
		s.circuitsMu.Unlock()

		reply := common.Cell{CircID: c.CircID, Command: common.CmdCreated, Length: 32}
		copy(reply.Body[:], pub[:])
		conn.Write(common.MarshalCell(reply))
		s.log.Info("Circuit %d created (role=%s)", c.CircID, s.cfg.Role)

	// ─── Extend ───
	// Encrypted payload: addrLen(1) | addr | clientEphemeralPub(32)
	// We forward Create with the CLIENT'S pubkey so we never learn that session key.
	case common.CmdExtend:
		s.circuitsMu.RLock()
		circ, ok := s.circuits[c.CircID]
		s.circuitsMu.RUnlock()
		if !ok {
			return
		}

		// If this circuit already has a downstream hop, the Extend is destined
		// for a relay further along the circuit, not for us. Peel our onion
		// layer and forward it downstream as an Extend; the next relay that has
		// no OutConn yet will process it locally.
		if circ.OutConn != nil {
			inner, err := common.Decrypt(circ.Key, c.Body[:c.Length])
			if err != nil {
				s.log.Warn("Extend(forward): decrypt error circuit %d: %v", c.CircID, err)
				return
			}
			if len(inner) > common.CellBodyMax {
				s.log.Warn("Extend(forward): payload too large circuit %d", c.CircID)
				return
			}
			fwd := common.Cell{CircID: c.CircID, Command: common.CmdExtend, Length: uint16(len(inner))}
			copy(fwd.Body[:], inner)
			circ.OutConn.Write(common.MarshalCell(fwd))
			return
		}

		payload, err := common.Decrypt(circ.Key, c.Body[:c.Length])
		if err != nil {
			s.log.Warn("Extend: decrypt error circuit %d: %v", c.CircID, err)
			return
		}
		if len(payload) < 34 {
			s.log.Warn("Extend: payload too short circuit %d", c.CircID)
			return
		}
		addrLen := int(payload[0])
		if 1+addrLen+32 > len(payload) {
			s.log.Warn("Extend: truncated payload circuit %d", c.CircID)
			return
		}
		nextAddr := string(payload[1 : 1+addrLen])
		var clientEphPub [32]byte
		copy(clientEphPub[:], payload[1+addrLen:1+addrLen+32])

		nextConn, err := net.DialTimeout("tcp", nextAddr, 10*time.Second)
		if err != nil {
			s.log.Warn("Extend: cannot reach %s: %v", nextAddr, err)
			return
		}
		if err := common.ObfsHandshake(nextConn); err != nil {
			s.log.Warn("Extend: obfs handshake with %s failed: %v", nextAddr, err)
			nextConn.Close()
			return
		}

		createCell := common.Cell{CircID: c.CircID, Command: common.CmdCreate, Length: 32}
		copy(createCell.Body[:], clientEphPub[:])
		nextConn.Write(common.MarshalCell(createCell))

		nextConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		created, err := common.ReadCell(nextConn)
		nextConn.SetReadDeadline(time.Time{})
		if err != nil || created.Command != common.CmdCreated {
			s.log.Warn("Extend: no CmdCreated from %s (err=%v)", nextAddr, err)
			nextConn.Close()
			return
		}

		circ.OutConn = nextConn
		go s.forwardCells(circ)

		reply := common.Cell{CircID: c.CircID, Command: common.CmdExtended, Length: 32}
		copy(reply.Body[:], created.Body[:32])
		conn.Write(common.MarshalCell(reply))

	// ─── Relay ───
	case common.CmdRelay:
		s.circuitsMu.RLock()
		circ, ok := s.circuits[c.CircID]
		s.circuitsMu.RUnlock()
		if !ok {
			return
		}

		payload, err := common.Decrypt(circ.Key, c.Body[:c.Length])
		if err != nil {
			s.log.Warn("Relay: decrypt error circuit %d: %v", c.CircID, err)
			return
		}

		if s.cfg.Role == "exit" {
			go s.handleExitRelay(circ, payload)
			return
		}

		if circ.OutConn == nil {
			return
		}
		const gcmOverhead = 28
		if len(payload)+gcmOverhead > common.CellBodyMax {
			seqID := common.RandomUint32()
			for _, fc := range common.Fragment(c.CircID, seqID, payload) {
				circ.OutConn.Write(common.MarshalCell(fc))
			}
		} else {
			fwd := common.Cell{CircID: c.CircID, Command: common.CmdRelay, Length: uint16(len(payload))}
			copy(fwd.Body[:], payload)
			circ.OutConn.Write(common.MarshalCell(fwd))
		}

	// ─── Ping ───
	case common.CmdPing:
		pong := common.Cell{CircID: c.CircID, Command: common.CmdPong, Length: c.Length}
		copy(pong.Body[:], c.Body[:c.Length])
		conn.Write(common.MarshalCell(pong))

	// ─── Destroy ───
	case common.CmdDestroy:
		s.destroyCircuit(c.CircID)
	}
}

// forwardCells pipes cells from OutConn back toward the client (InConn).
// CmdRelay cells are re-encrypted with this relay's key so the client
// can peel the expected onion layer.
// CmdRelayDone (0xFE) passes through unmodified — it is the end-of-response
// sentinel that the exit relay sends after finishing a request.
func (s *relayServer) forwardCells(circ *Circuit) {
	for {
		c, err := common.ReadCell(circ.OutConn)
		if err != nil {
			return
		}
		// Both data cells (CmdRelay) and the end-of-response sentinel
		// (CmdRelayDone) must be re-encrypted with this relay's key so the
		// client can peel exactly one onion layer per hop. (The sentinel was
		// encrypted once by the exit; without re-encryption here the client's
		// layer-0 peel would fail authentication.)
		if c.Command == common.CmdRelay || c.Command == common.CmdRelayDone {
			enc, err := common.Encrypt(circ.Key, c.Body[:c.Length])
			if err != nil {
				s.log.Warn("forwardCells: encrypt error circuit %d: %v", circ.ID, err)
				return
			}
			if len(enc) > common.CellBodyMax {
				s.log.Warn("forwardCells: encrypted payload exceeds CellBodyMax circuit %d", circ.ID)
				return
			}
			c.Length = uint16(len(enc))
			copy(c.Body[:], enc)
		}
		circ.writeIn(c)
	}
}

// ─────────────────────────────────────────────
// Exit relay
// ─────────────────────────────────────────────
//
// Wire payload from client:
//   hostLen(2) | host(hostLen) | port(2) | HTTP request bytes
//
// After proxying the full response, sends a CmdRelayDone sentinel cell so
// the client knows the response is complete without waiting for a timeout.

func (s *relayServer) handleExitRelay(circ *Circuit, payload []byte) {
	if len(payload) < 4 {
		return
	}
	hostLen := int(binary.BigEndian.Uint16(payload[0:2]))
	if 2+hostLen+2 > len(payload) {
		return
	}
	host := string(payload[2 : 2+hostLen])
	port := binary.BigEndian.Uint16(payload[2+hostLen : 4+hostLen])
	reqData := payload[4+hostLen:]

	// Resolve the host.
	// .sbnet hostnames → internal DoH resolver.
	// Everything else  → system DNS (for local testing and plain internet).
	resolvedIP := s.resolveHost(host)
	if resolvedIP == "" {
		s.sendExitError(circ, "could not resolve host: "+host)
		s.sendDone(circ)
		return
	}

	addr := net.JoinHostPort(resolvedIP, fmt.Sprintf("%d", port))
	originConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		s.sendExitError(circ, fmt.Sprintf("could not connect to %s: %v", addr, err))
		s.sendDone(circ)
		return
	}
	defer originConn.Close()

	if _, err := originConn.Write(reqData); err != nil {
		s.sendDone(circ)
		return
	}

	// Stream response back in chunks, each encrypted with our layer key.
	// forwardCells on the intermediate relays re-add their layers, so we must
	// leave room for ALL THREE onion layers (exit + middle + entry), each of
	// which adds GCM nonce(12)+tag(16)=28 bytes. A chunk of this size becomes
	// exactly CellBodyMax once the client-facing entry has re-encrypted it.
	const gcmOverhead = 28
	const hops = 3
	buf := make([]byte, common.CellBodyMax-hops*gcmOverhead)
	for {
		originConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, readErr := originConn.Read(buf)
		if n > 0 {
			enc, encErr := common.Encrypt(circ.Key, buf[:n])
			if encErr != nil || len(enc) > common.CellBodyMax {
				break
			}
			reply := common.Cell{
				CircID:  circ.ID,
				Command: common.CmdRelay,
				Length:  uint16(len(enc)),
			}
			copy(reply.Body[:], enc)
			circ.writeIn(reply)
		}
		if readErr != nil {
			break
		}
	}

	// Send the end-of-response sentinel so the client stops reading immediately.
	s.sendDone(circ)
}

// sendDone sends a CmdRelayDone cell (encrypted with our key) to signal to
// the client that this request's response stream is finished.
func (s *relayServer) sendDone(circ *Circuit) {
	// The done cell body is a single 0x00 byte, encrypted so intermediate
	// relays treat it like any other relay cell and re-encrypt it.
	enc, err := common.Encrypt(circ.Key, []byte{0x00})
	if err != nil || len(enc) > common.CellBodyMax {
		return
	}
	done := common.Cell{
		CircID:  circ.ID,
		Command: common.CmdRelayDone,
		Length:  uint16(len(enc)),
	}
	copy(done.Body[:], enc)
	circ.writeIn(done)
}

func (s *relayServer) sendExitError(circ *Circuit, msg string) {
	body := fmt.Sprintf("HTTP/1.0 502 Bad Gateway\r\nContent-Length: %d\r\n\r\n%s", len(msg), msg)
	enc, err := common.Encrypt(circ.Key, []byte(body))
	if err != nil || len(enc) > common.CellBodyMax {
		return
	}
	reply := common.Cell{
		CircID:  circ.ID,
		Command: common.CmdRelay,
		Length:  uint16(len(enc)),
	}
	copy(reply.Body[:], enc)
	circ.writeIn(reply)
}

// resolveHost resolves a hostname to an IP address.
// .sbnet hostnames use the internal DoH resolver (exit relay only).
// All other hostnames use the system DNS resolver directly.
func (s *relayServer) resolveHost(host string) string {
	if strings.HasSuffix(host, ".sbnet") {
		return s.resolveInternal(host)
	}
	// System DNS — works for plain internet in local testing.
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		s.log.Warn("DNS lookup failed for %s: %v", host, err)
		return ""
	}
	return addrs[0]
}

// resolveInternal queries the configured internal DoH resolver for .sbnet hosts.
func (s *relayServer) resolveInternal(host string) string {
	if s.cfg.InternalDNS == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://"+s.cfg.InternalDNS+"/dns-query?name="+host, nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var result struct {
		IP string `json:"ip"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.IP
}

// ─────────────────────────────────────────────
// TCP listener
// ─────────────────────────────────────────────

func (s *relayServer) serve(ctx context.Context, ln net.Listener) {
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
				s.log.Warn("Accept error: %v", err)
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *relayServer) handleConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	if err := common.ObfsHandshake(c); err != nil {
		s.log.Debug("obfs handshake failed: %v", err)
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		cell, err := common.ReadCell(c)
		if err != nil {
			return
		}
		s.handleCell(cell, c)
	}
}

// ─────────────────────────────────────────────
// Health endpoint
// ─────────────────────────────────────────────

func (s *relayServer) runHealthServer(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		s.circuitsMu.RLock()
		n := len(s.circuits)
		s.circuitsMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": s.cfg.ID, "role": s.cfg.Role,
			"country": s.cfg.Country, "circuits": n, "version": s.cfg.Version,
		})
	})
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("pong"))
	})
	srv := &http.Server{
		Addr:        fmt.Sprintf(":%d", s.cfg.HealthPort),
		Handler:     mux,
		ReadTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()
	s.log.Info("Health endpoint on :%d", s.cfg.HealthPort)
	srv.ListenAndServe()
}

// ─────────────────────────────────────────────
// Directory keepalive
// ─────────────────────────────────────────────

func (s *relayServer) keepAlive(ctx context.Context) {
	secret := s.cfg.RegSecret
	if secret == "" {
		secret = os.Getenv("SBNET_REG_SECRET")
	}
	if secret == "" {
		s.log.Error("No reg_secret — relay will not register with directory")
		return
	}

	rd := common.RelayDescriptor{
		ID: s.cfg.ID, IP: s.cfg.IP, Port: s.cfg.Port,
		Role: s.cfg.Role, PublicKey: s.pubKeyHex,
		Country: s.cfg.Country, Region: s.cfg.Region,
		OperMode: s.cfg.OperMode, Bandwidth: s.cfg.Bandwidth,
		Version: s.cfg.Version,
	}

	register := func() {
		now := time.Now().Unix()
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(rd.ID + rd.IP + rd.Role + rd.PublicKey))
		body, _ := json.Marshal(common.RegisterRequest{
			Kind: common.KindRelay, Relay: &rd,
			Timestamp: now, HMAC: hex.EncodeToString(mac.Sum(nil)),
		})
		resp, err := http.Post(s.cfg.DirURL+"/register", "application/json", bytes.NewReader(body))
		if err != nil {
			s.log.Warn("Directory unreachable: %v", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			s.log.Warn("Directory rejected registration: HTTP %d", resp.StatusCode)
		} else {
			s.log.Debug("Registered with directory")
		}
	}

	register()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(60 * time.Second):
			register()
		}
	}
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

func loadConfig() common.RelayConfig {
	var cfg common.RelayConfig
	path := "relay.yaml"
	if p := os.Getenv("SBNET_CONFIG"); p != "" {
		path = p
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("Parse relay.yaml: %v", err)
		}
	}
	cfg.ApplyDefaults()
	return cfg
}

func main() {
	cfg := loadConfig()
	srv, err := newRelayServer(cfg)
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		log.Fatal(err)
	}

	srv.log.Info("Relay [%s] role=%s country=%s port=%d healthPort=%d pubkey=%s",
		cfg.ID, cfg.Role, cfg.Country, cfg.Port, cfg.HealthPort, srv.pubKeyHex)

	ctx, cancel := context.WithCancel(context.Background())
	go srv.keepAlive(ctx)
	go srv.runHealthServer(ctx)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		srv.log.Info("Graceful shutdown...")
		cancel()
	}()

	srv.serve(ctx, ln)
	srv.log.Info("Relay stopped.")
}
