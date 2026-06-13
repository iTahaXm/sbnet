package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"sbnet/common"
	"sbnet/webrtcx"
)

// ─────────────────────────────────────────────
// Directory / consensus
// ─────────────────────────────────────────────

// fetchConsensus retrieves and cryptographically verifies the directory
// consensus via the shared helper in common.
func fetchConsensus(dirURL string, caFile string) (*common.SignedConsensus, error) {
	return common.FetchVerifiedConsensus(dirURL, caFile)
}

// ─────────────────────────────────────────────
// Relay selection
// ─────────────────────────────────────────────

func pickRelay(relays []common.RelayDescriptor, role string) *common.RelayDescriptor {
	var pool []common.RelayDescriptor
	for _, r := range relays {
		if r.Role == role {
			pool = append(pool, r)
		}
	}
	if len(pool) == 0 {
		return nil
	}
	b := make([]byte, 1)
	common.RandomBytes(b)
	r := pool[int(b[0])%len(pool)]
	return &r
}

// ─────────────────────────────────────────────
// Broker-assisted relay assignment
// ─────────────────────────────────────────────

func assignViaBroker(brokerAddr, role, country string) (*common.RelayDescriptor, error) {
	body, _ := json.Marshal(common.AssignRequest{Role: role, Country: country})
	resp, err := http.Post("http://"+brokerAddr+"/assign", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("broker returned HTTP %d", resp.StatusCode)
	}
	var ar common.AssignResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return nil, err
	}
	return &ar.Relay, nil
}

// ─────────────────────────────────────────────
// Guard relay pinning
// ─────────────────────────────────────────────

type guardState struct {
	RelayID  string `json:"relay_id"`
	PinnedAt int64  `json:"pinned_at"`
}

func loadOrPickGuard(relays []common.RelayDescriptor, guardFile string) *common.RelayDescriptor {
	var state guardState
	if data, err := os.ReadFile(guardFile); err == nil {
		json.Unmarshal(data, &state)
		for i := range relays {
			if relays[i].ID == state.RelayID && relays[i].Role == "entry" {
				return &relays[i]
			}
		}
	}
	guard := pickRelay(relays, "entry")
	if guard == nil {
		return nil
	}
	state = guardState{RelayID: guard.ID, PinnedAt: time.Now().Unix()}
	data, _ := json.Marshal(state)
	os.WriteFile(guardFile, data, 0600)
	return guard
}

// ─────────────────────────────────────────────
// Circuit
// ─────────────────────────────────────────────

const circuitLifetime = 10 * time.Minute

// Circuit holds the three per-hop AES-256-GCM session keys and the TCP
// connection to the entry relay. All writes to Conn are serialised by writeMu.
type Circuit struct {
	CircID  uint32
	Conn    net.Conn
	Keys    [3][]byte
	built   time.Time
	writeMu sync.Mutex
}

func (c *Circuit) expired() bool { return time.Since(c.built) > circuitLifetime }

func (c *Circuit) writeCell(cell common.Cell) {
	c.writeMu.Lock()
	c.Conn.Write(common.MarshalCell(cell))
	c.writeMu.Unlock()
}

func (c *Circuit) close() {
	destroy := common.Cell{CircID: c.CircID, Command: common.CmdDestroy}
	c.Conn.Write(common.MarshalCell(destroy))
	c.Conn.Close()
}

// buildCircuit connects to entry and extends to middle and exit.
func buildCircuit(entry, middle, exitR *common.RelayDescriptor) (*Circuit, error) {
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", entry.IP, entry.Port), 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial entry %s: %w", entry.ID, err)
	}
	if err := common.ObfsHandshake(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("obfs handshake with entry %s: %w", entry.ID, err)
	}
	return buildCircuitOnConn(conn, common.RandomUint32(), middle, exitR)
}

// buildCircuitOnConn runs the 3-hop telescoping handshake over an already
// established, obfs-handshaked connection to an entry relay. The entry's
// identity is irrelevant to the client (hop 1 is a bare key exchange), so this
// is reused by transports — bridge and kind — that supply the entry connection
// externally. middle and exit must come from a verified consensus.
func buildCircuitOnConn(conn net.Conn, circID uint32, middle, exitR *common.RelayDescriptor) (*Circuit, error) {
	if middle == nil || exitR == nil {
		conn.Close()
		return nil, fmt.Errorf("buildCircuitOnConn: nil middle/exit relay")
	}
	circ := &Circuit{CircID: circID, Conn: conn, built: time.Now()}

	// ── Hop 1: entry ──
	priv0, pub0 := common.GenKeyPair()
	create := common.Cell{CircID: circID, Command: common.CmdCreate, Length: 32}
	copy(create.Body[:], pub0[:])
	conn.Write(common.MarshalCell(create))

	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	created, err := common.ReadCell(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil || created.Command != common.CmdCreated {
		conn.Close()
		return nil, fmt.Errorf("hop1 Created failed (err=%v cmd=%v)", err, created.Command)
	}
	var rPub0 [32]byte
	copy(rPub0[:], created.Body[:32])
	circ.Keys[0] = common.DeriveKey(priv0, rPub0)

	// ── Hop 2: middle ──
	if err := extendCircuit(circ, middle, 1); err != nil {
		conn.Close()
		return nil, fmt.Errorf("extend middle %s: %w", middle.ID, err)
	}

	// ── Hop 3: exit ──
	if err := extendCircuit(circ, exitR, 2); err != nil {
		conn.Close()
		return nil, fmt.Errorf("extend exit %s: %w", exitR.ID, err)
	}

	return circ, nil
}

// extendCircuit sends an Extend cell to hopIdx (1=middle, 2=exit).
func extendCircuit(circ *Circuit, next *common.RelayDescriptor, hopIdx int) error {
	priv, pub := common.GenKeyPair()
	addr := fmt.Sprintf("%s:%d", next.IP, next.Port)

	extPayload := make([]byte, 1+len(addr)+32)
	extPayload[0] = byte(len(addr))
	copy(extPayload[1:], addr)
	copy(extPayload[1+len(addr):], pub[:])

	wrapped := extPayload
	for i := hopIdx - 1; i >= 0; i-- {
		enc, err := common.Encrypt(circ.Keys[i], wrapped)
		if err != nil {
			return err
		}
		wrapped = enc
	}
	if len(wrapped) > common.CellBodyMax {
		return fmt.Errorf("Extend payload too large: %d bytes", len(wrapped))
	}

	cell := common.Cell{CircID: circ.CircID, Command: common.CmdExtend, Length: uint16(len(wrapped))}
	copy(cell.Body[:], wrapped)
	circ.Conn.Write(common.MarshalCell(cell))

	circ.Conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	extended, err := common.ReadCell(circ.Conn)
	circ.Conn.SetReadDeadline(time.Time{})
	if err != nil || extended.Command != common.CmdExtended {
		return fmt.Errorf("Extended failed (err=%v cmd=%v)", err, extended.Command)
	}

	var rPub [32]byte
	copy(rPub[:], extended.Body[:32])
	circ.Keys[hopIdx] = common.DeriveKey(priv, rPub)
	return nil
}

// ─────────────────────────────────────────────
// Send a request through the circuit
// ─────────────────────────────────────────────
//
// Outbound: payload encrypted exit→middle→entry (entry is outermost).
// Response: each cell has 3 layers; client peels entry→middle→exit.
//
// The response loop ends when:
//   • CmdRelayDone cell is received (normal end-of-response), OR
//   • read deadline fires (60s), OR
//   • connection error.
//
// Wire payload: hostLen(2) | host | port(2) | rawHTTPRequest

func sendRequest(ctx context.Context, circ *Circuit, host string, port uint16, reqData []byte) ([]byte, error) {
	payload := make([]byte, 2+len(host)+2+len(reqData))
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(host)))
	copy(payload[2:], host)
	binary.BigEndian.PutUint16(payload[2+len(host):], port)
	copy(payload[4+len(host):], reqData)

	wrapped := payload
	for i := 2; i >= 0; i-- {
		enc, err := common.Encrypt(circ.Keys[i], wrapped)
		if err != nil {
			return nil, fmt.Errorf("encrypt layer %d: %w", i, err)
		}
		wrapped = enc
	}
	if len(wrapped) > common.CellBodyMax {
		return nil, fmt.Errorf("request too large after encryption (%d bytes)", len(wrapped))
	}

	cell := common.Cell{CircID: circ.CircID, Command: common.CmdRelay, Length: uint16(len(wrapped))}
	copy(cell.Body[:], wrapped)
	circ.writeCell(cell)

	// Read response cells. The exit relay sends CmdRelayDone (encrypted) after
	// the last chunk — this is peeled like a normal relay cell, and the
	// unwrapped command byte tells us to stop. Without this sentinel the client
	// would have to wait for a timeout because the TCP connection stays open.
	var response []byte
	circ.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	defer circ.Conn.SetReadDeadline(time.Time{})

	for {
		select {
		case <-ctx.Done():
			return response, ctx.Err()
		default:
		}

		c, err := common.ReadCell(circ.Conn)
		if err != nil {
			// Deadline or connection close — return what we have.
			break
		}

		// Only process relay-layer cells; pass control cells through.
		if c.Command != common.CmdRelay && c.Command != common.CmdRelayDone {
			continue
		}

		// Peel entry → middle → exit.
		data := c.Body[:c.Length]
		var decErr error
		for i := 0; i < 3; i++ {
			data, decErr = common.Decrypt(circ.Keys[i], data)
			if decErr != nil {
				return response, fmt.Errorf("decrypt response layer %d: %w", i, decErr)
			}
		}

		// After peeling, CmdRelayDone body is just 0x00 — discard it and stop.
		if c.Command == common.CmdRelayDone {
			break
		}

		response = append(response, data...)
	}
	return response, nil
}

// ─────────────────────────────────────────────
// Circuit pool
// ─────────────────────────────────────────────

type CircuitPool struct {
	mu       sync.RWMutex
	circuits []*Circuit
	ready    bool  // true once at least one circuit is built
	count    int
	log      *common.Logger
	cfg      common.ClientConfig

	relaysMu sync.RWMutex
	relays   []common.RelayDescriptor
	brokers  []common.BrokerDescriptor

	counter uint64
}

func newCircuitPool(cfg common.ClientConfig, log *common.Logger) *CircuitPool {
	return &CircuitPool{cfg: cfg, log: log, count: cfg.CircuitCount}
}

func (p *CircuitPool) setRelays(relays []common.RelayDescriptor, brokers []common.BrokerDescriptor) {
	p.relaysMu.Lock()
	p.relays = relays
	p.brokers = brokers
	p.relaysMu.Unlock()
}

// buildAll replaces all circuits. Does NOT fatal — logs failures and continues
// with however many circuits succeeded.
func (p *CircuitPool) buildAll() error {
	p.relaysMu.RLock()
	relays := p.relays
	brokers := p.brokers
	p.relaysMu.RUnlock()

	p.mu.Lock()
	old := p.circuits
	p.circuits = nil
	p.mu.Unlock()
	for _, c := range old {
		c.close()
	}

	var built []*Circuit
	for i := 0; i < p.count; i++ {
		c, err := p.buildOne(relays, brokers)
		if err != nil {
			p.log.Warn("Circuit %d/%d failed: %v", i+1, p.count, err)
			continue
		}
		built = append(built, c)
		p.log.Info("Circuit %d/%d ready (circID=%08x)", i+1, p.count, c.CircID)
	}

	p.mu.Lock()
	p.circuits = built
	p.ready = len(built) > 0
	p.mu.Unlock()

	if len(built) == 0 {
		return fmt.Errorf("all %d circuit builds failed", p.count)
	}
	return nil
}

func (p *CircuitPool) buildOne(relays []common.RelayDescriptor, brokers []common.BrokerDescriptor) (*Circuit, error) {
	if p.cfg.KindBrokerURL != "" {
		return p.buildViaKind(relays)
	}
	if p.cfg.BrokerID != "" && len(brokers) > 0 {
		return p.buildViaBroker(brokers)
	}
	return p.buildDirect(relays)
}

// buildViaKind builds a circuit through a Snowflake-style volunteer proxy. The
// volunteer connects us to some entry relay (its choice); we still pick the
// middle and exit from the verified consensus and run the normal telescoping
// handshake over the WebRTC datachannel.
func (p *CircuitPool) buildViaKind(relays []common.RelayDescriptor) (*Circuit, error) {
	middle := pickRelay(relays, "middle")
	exitR := pickRelay(relays, "exit")
	if middle == nil || exitR == nil {
		return nil, fmt.Errorf("not enough relays for kind circuit (middle=%v exit=%v)",
			middle != nil, exitR != nil)
	}
	stun := webrtcx.FetchSTUN(p.cfg.KindBrokerURL)
	conn, err := webrtcx.ClientDial(p.cfg.KindBrokerURL, stun, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("kind dial: %w", err)
	}
	if err := common.ObfsHandshake(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("kind obfs handshake: %w", err)
	}
	p.log.Info("Building kind circuit: volunteer → ? → %s → %s", middle.ID, exitR.ID)
	return buildCircuitOnConn(conn, common.RandomUint32(), middle, exitR)
}

func (p *CircuitPool) buildDirect(relays []common.RelayDescriptor) (*Circuit, error) {
	guard := loadOrPickGuard(relays, p.cfg.GuardFile)
	middle := pickRelay(relays, "middle")
	exitR := pickRelay(relays, "exit")
	if guard == nil || middle == nil || exitR == nil {
		return nil, fmt.Errorf("not enough relays (entry=%v middle=%v exit=%v)",
			guard != nil, middle != nil, exitR != nil)
	}
	p.log.Info("Building circuit: %s → %s → %s", guard.ID, middle.ID, exitR.ID)
	return buildCircuit(guard, middle, exitR)
}

func (p *CircuitPool) buildViaBroker(brokers []common.BrokerDescriptor) (*Circuit, error) {
	var brokerAddr string
	for _, b := range brokers {
		if p.cfg.BrokerID == "" || b.ID == p.cfg.BrokerID {
			brokerAddr = fmt.Sprintf("%s:%d", b.IP, b.Port)
			break
		}
	}
	if brokerAddr == "" {
		return nil, fmt.Errorf("broker %q not found in consensus", p.cfg.BrokerID)
	}
	entry, err := assignViaBroker(brokerAddr, "entry", "")
	if err != nil {
		return nil, fmt.Errorf("broker assign entry: %w", err)
	}
	middle, err := assignViaBroker(brokerAddr, "middle", "")
	if err != nil {
		return nil, fmt.Errorf("broker assign middle: %w", err)
	}
	exitR, err := assignViaBroker(brokerAddr, "exit", "")
	if err != nil {
		return nil, fmt.Errorf("broker assign exit: %w", err)
	}
	p.log.Info("Building broker circuit: %s → %s → %s", entry.ID, middle.ID, exitR.ID)
	return buildCircuit(entry, middle, exitR)
}

// isReady returns true once at least one circuit is available.
func (p *CircuitPool) isReady() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.ready
}

// get returns a circuit (round-robin), lazily replacing expired ones.
func (p *CircuitPool) get() (*Circuit, error) {
	p.mu.RLock()
	if len(p.circuits) == 0 {
		p.mu.RUnlock()
		return nil, fmt.Errorf("no circuits available yet — still building")
	}
	idx := int(atomic.AddUint64(&p.counter, 1)-1) % len(p.circuits)
	circ := p.circuits[idx]
	p.mu.RUnlock()

	if !circ.expired() {
		return circ, nil
	}

	p.relaysMu.RLock()
	relays := p.relays
	brokers := p.brokers
	p.relaysMu.RUnlock()

	newCirc, err := p.buildOne(relays, brokers)
	if err != nil {
		p.log.Warn("Circuit replacement failed: %v — using stale circuit", err)
		return circ, nil
	}
	circ.close()
	p.mu.Lock()
	if idx < len(p.circuits) {
		p.circuits[idx] = newCirc
	}
	p.mu.Unlock()
	return newCirc, nil
}

// send routes a request through the pool, rebuilding once on failure.
func (p *CircuitPool) send(ctx context.Context, host string, port uint16, req []byte) ([]byte, error) {
	circ, err := p.get()
	if err != nil {
		return nil, err
	}
	resp, err := sendRequest(ctx, circ, host, port, req)
	if err == nil {
		return resp, nil
	}

	p.log.Warn("Request failed (%v) — rebuilding circuit and retrying", err)
	p.relaysMu.RLock()
	relays := p.relays
	brokers := p.brokers
	p.relaysMu.RUnlock()

	newCirc, buildErr := p.buildOne(relays, brokers)
	if buildErr != nil {
		return nil, fmt.Errorf("send: %v; circuit rebuild: %v", err, buildErr)
	}
	circ.close()
	p.mu.Lock()
	for i, c := range p.circuits {
		if c == circ {
			p.circuits[i] = newCirc
			break
		}
	}
	p.mu.Unlock()
	return sendRequest(ctx, newCirc, host, port, req)
}

// ─────────────────────────────────────────────
// Bridge mode
// ─────────────────────────────────────────────

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
	if cfg.Token == "" {
		return cfg, fmt.Errorf("bridge URI missing 'token' parameter")
	}
	if cfg.Obfs == "" {
		cfg.Obfs = "tls"
	}
	if cfg.Mode == "" {
		cfg.Mode = "secure"
	}
	return cfg, nil
}

func dialBridge(bridgeCfg common.BridgeConfig) (net.Conn, error) {
	var conn net.Conn
	var err error

	if bridgeCfg.Obfs == "tls" {
		conn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: 15 * time.Second},
			"tcp", bridgeCfg.Endpoint,
			&tls.Config{
				InsecureSkipVerify: true,
				ServerName:         strings.Split(bridgeCfg.Endpoint, ":")[0],
			},
		)
	} else {
		conn, err = net.DialTimeout("tcp", bridgeCfg.Endpoint, 15*time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("dial bridge %s: %w", bridgeCfg.Endpoint, err)
	}
	if err := common.ObfsHandshake(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("obfs handshake with bridge: %w", err)
	}

	_, clientEphPub := common.GenKeyPair()
	token := []byte(bridgeCfg.Token)
	bodyLen := 2 + len(token) + 32
	if bodyLen > common.CellBodyMax {
		conn.Close()
		return nil, fmt.Errorf("bridge token too long")
	}

	var handshake common.Cell
	handshake.CircID = 0xFFFFFFFF
	handshake.Command = common.CmdCreate
	handshake.Length = uint16(bodyLen)
	binary.BigEndian.PutUint16(handshake.Body[0:2], uint16(len(token)))
	copy(handshake.Body[2:], token)
	copy(handshake.Body[2+len(token):], clientEphPub[:])
	conn.Write(common.MarshalCell(handshake))
	return conn, nil
}

func buildCircuitViaBridge(bridgeCfg common.BridgeConfig) (*Circuit, error) {
	conn, err := dialBridge(bridgeCfg)
	if err != nil {
		return nil, err
	}

	circID := uint32(0xFFFFFFFF)
	circ := &Circuit{CircID: circID, Conn: conn, built: time.Now()}

	priv0, pub0 := common.GenKeyPair()
	create := common.Cell{CircID: circID, Command: common.CmdCreate, Length: 32}
	copy(create.Body[:], pub0[:])
	conn.Write(common.MarshalCell(create))

	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	created, err := common.ReadCell(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil || created.Command != common.CmdCreated {
		conn.Close()
		return nil, fmt.Errorf("bridge hop1 Created failed (err=%v cmd=%v)", err, created.Command)
	}
	var rPub0 [32]byte
	copy(rPub0[:], created.Body[:32])
	circ.Keys[0] = common.DeriveKey(priv0, rPub0)
	return circ, nil
}

// ─────────────────────────────────────────────
// HTTP proxy handler
// ─────────────────────────────────────────────

func buildHTTPProxy(pool *CircuitPool, logger *common.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !pool.isReady() {
			http.Error(w, "SbNet: circuit not ready yet, please wait", http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodConnect {
			handleCONNECT(w, r, pool, logger)
			return
		}
		handleHTTP(w, r, pool, logger)
	})
}

func handleHTTP(w http.ResponseWriter, r *http.Request, pool *CircuitPool, logger *common.Logger) {
	host := r.Host
	port := uint16(80)

	reqLine := fmt.Sprintf("%s %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n",
		r.Method, r.URL.RequestURI(), host)
	var hdrBuf bytes.Buffer
	r.Header.Write(&hdrBuf)
	rawReq := []byte(reqLine + hdrBuf.String() + "\r\n")
	if r.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		rawReq = append(rawReq, body...)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	respBytes, err := pool.send(ctx, host, port, rawReq)
	if err != nil {
		http.Error(w, "SbNet circuit error: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.Write(respBytes)
}

func handleCONNECT(w http.ResponseWriter, r *http.Request, pool *CircuitPool, logger *common.Logger) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	parts := strings.SplitN(host, ":", 2)
	hostname := parts[0]
	port := uint16(443)
	fmt.Sscanf(parts[1], "%d", &port)

	clientConn, rw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	rw.WriteString("HTTP/1.0 200 Connection Established\r\n\r\n")
	rw.Flush()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	buf := make([]byte, 32*1024)
	for {
		clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, readErr := rw.Read(buf)
		if n > 0 {
			resp, sendErr := pool.send(ctx, hostname, port, buf[:n])
			if sendErr != nil {
				logger.Warn("CONNECT circuit error: %v", sendErr)
				return
			}
			if _, writeErr := clientConn.Write(resp); writeErr != nil {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

// ─────────────────────────────────────────────
// SOCKS5 proxy (RFC 1928)
// ─────────────────────────────────────────────

func runSOCKS5(addr string, pool *CircuitPool, logger *common.Logger, ctx context.Context) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("SOCKS5 listen on %s: %v", addr, err)
		return
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	logger.Info("SOCKS5 proxy on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go handleSOCKS5Conn(conn, pool, logger, ctx)
	}
}

func handleSOCKS5Conn(conn net.Conn, pool *CircuitPool, logger *common.Logger, ctx context.Context) {
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Greeting
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(rw, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	io.ReadFull(rw, methods)
	rw.Write([]byte{0x05, 0x00}) // no-auth
	rw.Flush()

	// Request
	req := make([]byte, 4)
	if _, err := io.ReadFull(rw, req); err != nil {
		return
	}
	if req[0] != 0x05 {
		return
	}
	if req[1] != 0x01 { // CONNECT only
		rw.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		rw.Flush()
		return
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		io.ReadFull(rw, addr)
		host = net.IP(addr).String()
	case 0x04: // IPv6
		addr := make([]byte, 16)
		io.ReadFull(rw, addr)
		host = "[" + net.IP(addr).String() + "]"
	case 0x03: // domain
		lenB := make([]byte, 1)
		io.ReadFull(rw, lenB)
		domain := make([]byte, int(lenB[0]))
		io.ReadFull(rw, domain)
		host = string(domain)
	default:
		rw.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		rw.Flush()
		return
	}

	portBuf := make([]byte, 2)
	io.ReadFull(rw, portBuf)
	port := binary.BigEndian.Uint16(portBuf)

	// Reply success
	rw.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	rw.Flush()
	conn.SetDeadline(time.Time{})

	// If circuit not ready yet, wait up to 30s
	deadline := time.Now().Add(30 * time.Second)
	for !pool.isReady() {
		if time.Now().After(deadline) {
			logger.Warn("SOCKS5: circuit not ready after 30s, dropping connection")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}

	logger.Debug("SOCKS5 CONNECT %s:%d", host, port)

	dataBuf := make([]byte, 32*1024)
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, readErr := rw.Read(dataBuf)
		if n > 0 {
			resp, sendErr := pool.send(ctx, host, port, dataBuf[:n])
			if sendErr != nil {
				logger.Warn("SOCKS5 circuit error: %v", sendErr)
				return
			}
			if _, writeErr := conn.Write(resp); writeErr != nil {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

// ─────────────────────────────────────────────
// Config loader
// ─────────────────────────────────────────────

func loadConfig() common.ClientConfig {
	var cfg common.ClientConfig
	path := "client.yaml"
	if p := os.Getenv("SBNET_CONFIG"); p != "" {
		path = p
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("Parse client.yaml: %v", err)
		}
	}
	cfg.ApplyDefaults()
	if v := os.Getenv("SBNET_DIR"); v != "" {
		cfg.DirURL = v
	}
	if v := os.Getenv("SBNET_BRIDGE"); v != "" {
		cfg.BridgeURI = v
	}
	if v := os.Getenv("SBNET_KIND"); v != "" {
		cfg.KindBrokerURL = v
	}
	return cfg
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

func main() {
	cfg := loadConfig()
	lvl := common.ParseLogLevel(cfg.LogLevel)
	logger := common.NewLogger("client", lvl, nil)

	pool := newCircuitPool(cfg, logger)
	ctx, cancel := context.WithCancel(context.Background())

	// ── Start proxy listeners FIRST, before circuits are built.
	// SOCKS5 and HTTP handlers will wait for pool.isReady() before processing.
	go runSOCKS5(cfg.SOCKS5Addr, pool, logger, ctx)

	httpSrv := &http.Server{
		Addr:    cfg.HTTPProxyAddr,
		Handler: buildHTTPProxy(pool, logger),
	}
	go func() {
		logger.Info("HTTP/CONNECT proxy on %s", cfg.HTTPProxyAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// ── Build circuits in a background goroutine.
	go func() {
		if cfg.BridgeURI != "" {
			bridgeCfg, err := parseBridgeURI(cfg.BridgeURI)
			if err != nil {
				logger.Error("Invalid bridge URI: %v", err)
				return
			}
			logger.Info("Bridge mode: %s (obfs=%s)", bridgeCfg.Endpoint, bridgeCfg.Obfs)
			var circuits []*Circuit
			for i := 0; i < cfg.CircuitCount; i++ {
				c, err := buildCircuitViaBridge(bridgeCfg)
				if err != nil {
					logger.Warn("Bridge circuit %d/%d failed: %v", i+1, cfg.CircuitCount, err)
					continue
				}
				circuits = append(circuits, c)
				logger.Info("Bridge circuit %d/%d ready", i+1, cfg.CircuitCount)
			}
			if len(circuits) == 0 {
				logger.Error("All bridge circuit builds failed")
				return
			}
			pool.mu.Lock()
			pool.circuits = circuits
			pool.ready = true
			pool.mu.Unlock()
			return
		}

		// Normal / broker / kind mode.
		if cfg.KindBrokerURL != "" {
			logger.Info("Kind mode: volunteer proxies via broker %s", cfg.KindBrokerURL)
		} else if cfg.BrokerID != "" {
			logger.Info("Broker mode: pinned broker %s", cfg.BrokerID)
		}
		logger.Info("Fetching consensus from %s", cfg.DirURL)
		consensus, err := fetchConsensus(cfg.DirURL, cfg.DirTLSCA)
		if err != nil {
			logger.Error("Cannot get consensus: %v", err)
			return
		}
		logger.Info("Consensus: %d relays, %d brokers", len(consensus.Relays), len(consensus.Brokers))
		pool.setRelays(consensus.Relays, consensus.Brokers)

		if err := pool.buildAll(); err != nil {
			logger.Error("Circuit pool build failed: %v", err)
			return
		}
		logger.Info("All circuits ready. Proxy is active.")
	}()

	// ── Periodic circuit rotation ──
	if cfg.BridgeURI == "" {
		rotateDur := time.Duration(cfg.CircuitRotateSecs) * time.Second
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(rotateDur):
					logger.Info("Rotating circuits...")
					c, err := fetchConsensus(cfg.DirURL, cfg.DirTLSCA)
					if err != nil {
						logger.Warn("Consensus refresh failed: %v", err)
						continue
					}
					pool.setRelays(c.Relays, c.Brokers)
					if err := pool.buildAll(); err != nil {
						logger.Warn("Circuit rebuild failed: %v", err)
					}
				}
			}
		}()
	}

	// ── Graceful shutdown ──
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down...")
	cancel()

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	httpSrv.Shutdown(shutCtx)

	pool.mu.RLock()
	for _, c := range pool.circuits {
		c.close()
	}
	pool.mu.RUnlock()
	logger.Info("Client stopped.")
}
