package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"sbnet/common"
)

// ─────────────────────────────────────────────
// Token store
// ─────────────────────────────────────────────

type tokenEntry struct {
	relay     common.RelayDescriptor
	expiresAt time.Time
}

type tokenStore struct {
	mu     sync.Mutex
	tokens map[string]tokenEntry
}

func newTokenStore() *tokenStore {
	ts := &tokenStore{tokens: make(map[string]tokenEntry)}
	go ts.gc()
	return ts
}

func (ts *tokenStore) issue(relay common.RelayDescriptor) (token string, expiresAt int64) {
	raw := make([]byte, 32)
	rand.Read(raw)
	token = hex.EncodeToString(raw)
	exp := time.Now().Add(common.TokenTTL)
	ts.mu.Lock()
	ts.tokens[token] = tokenEntry{relay: relay, expiresAt: exp}
	ts.mu.Unlock()
	return token, exp.Unix()
}

func (ts *tokenStore) validate(token string) (common.RelayDescriptor, bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	e, ok := ts.tokens[token]
	if !ok || time.Now().After(e.expiresAt) {
		delete(ts.tokens, token)
		return common.RelayDescriptor{}, false
	}
	return e.relay, true
}

func (ts *tokenStore) gc() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		ts.mu.Lock()
		for k, v := range ts.tokens {
			if now.After(v.expiresAt) {
				delete(ts.tokens, k)
			}
		}
		ts.mu.Unlock()
	}
}

// ─────────────────────────────────────────────
// Relay pool
// ─────────────────────────────────────────────

type relayPool struct {
	mu     sync.RWMutex
	relays []common.RelayDescriptor
}

func (p *relayPool) update(relays []common.RelayDescriptor) {
	p.mu.Lock()
	p.relays = relays
	p.mu.Unlock()
}

// pick returns the best relay matching req, or nil if none found.
// Scoring: country match (+3), region match (+2), bandwidth (+0.01/kbps capped at 10),
// plus a small random jitter for equal scores.
func (p *relayPool) pick(req common.AssignRequest) *common.RelayDescriptor {
	p.mu.RLock()
	defer p.mu.RUnlock()

	type scored struct {
		relay common.RelayDescriptor
		score float64
	}
	var candidates []scored
	for _, r := range p.relays {
		if r.Role != req.Role {
			continue
		}
		if req.Mode != "" && r.OperMode != req.Mode {
			continue
		}
		var s float64
		if req.Country != "" && r.Country == req.Country {
			s += 3
		}
		if req.Region != "" && r.Region == req.Region {
			s += 2
		}
		s += math.Min(float64(r.Bandwidth)*0.01, 10)
		jb := make([]byte, 1)
		rand.Read(jb)
		s += float64(jb[0]) / 2560.0
		candidates = append(candidates, scored{r, s})
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})
	r := candidates[0].relay
	return &r
}

// ─────────────────────────────────────────────
// Broker server
// ─────────────────────────────────────────────

type brokerServer struct {
	cfg    common.BrokerConfig
	log    *common.Logger
	pubKey []byte // ed25519 public key

	pool   *relayPool
	tokens *tokenStore
	kind   *kindRendezvous
}

func newBrokerServer(cfg common.BrokerConfig) (*brokerServer, error) {
	pub, _, err := common.LoadOrCreateEd25519(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load/create ed25519 key: %w", err)
	}
	lvl := common.ParseLogLevel(cfg.LogLevel)
	return &brokerServer{
		cfg:    cfg,
		log:    common.NewLogger("broker/"+cfg.ID, lvl, nil),
		pubKey: pub,
		pool:   &relayPool{},
		tokens: newTokenStore(),
		kind:   newKindRendezvous(64),
	}, nil
}

// ─────────────────────────────────────────────
// Consensus polling
// ─────────────────────────────────────────────

func (b *brokerServer) pollConsensus(ctx context.Context) {
	fetch := func() {
		consensus, err := common.FetchVerifiedConsensus(b.cfg.DirURL, b.cfg.DirTLSCA)
		if err != nil {
			b.log.Warn("Consensus fetch/verify failed: %v", err)
			return
		}
		b.pool.update(consensus.Relays)
		b.log.Debug("Pool updated: %d relays", len(consensus.Relays))
	}

	fetch()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Minute):
			fetch()
		}
	}
}

// ─────────────────────────────────────────────
// HTTP handlers
// ─────────────────────────────────────────────

// POST /assign — client requests a relay assignment.
func (b *brokerServer) handleAssign(w http.ResponseWriter, r *http.Request) {
	var req common.AssignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if req.Role == "" {
		http.Error(w, "role is required", 400)
		return
	}
	relay := b.pool.pick(req)
	if relay == nil {
		http.Error(w, "no relay available for this request", 503)
		return
	}
	token, expiresAt := b.tokens.issue(*relay)
	b.log.Debug("Assigned relay %s (%s) to %s", relay.ID, relay.Role, r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(common.AssignResponse{
		Relay:     *relay,
		Token:     token,
		ExpiresAt: expiresAt,
	})
}

// POST /validate — relay verifies a client's session token.
func (b *brokerServer) handleValidate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	relay, ok := b.tokens.validate(body.Token)
	if !ok {
		http.Error(w, "invalid or expired token", 401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"valid": true, "relay_id": relay.ID})
}

// GET /health
func (b *brokerServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	b.pool.mu.RLock()
	n := len(b.pool.relays)
	b.pool.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      b.cfg.ID,
		"country": b.cfg.Country,
		"region":  b.cfg.Region,
		"modes":   b.cfg.Modes,
		"relays":  n,
	})
}

// ─────────────────────────────────────────────
// Directory keepalive
// ─────────────────────────────────────────────

func (b *brokerServer) keepAlive(ctx context.Context) {
	secret := b.cfg.RegSecret
	if secret == "" {
		secret = os.Getenv("SBNET_REG_SECRET")
	}
	if secret == "" {
		b.log.Error("No reg_secret — broker will not register with directory")
		return
	}

	pubHex := hex.EncodeToString(b.pubKey)
	bd := common.BrokerDescriptor{
		ID:        b.cfg.ID,
		IP:        b.cfg.IP,
		Port:      b.cfg.Port,
		PublicKey: pubHex,
		Country:   b.cfg.Country,
		Region:    b.cfg.Region,
		Modes:     b.cfg.Modes,
	}

	register := func() {
		now := time.Now().Unix()
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(bd.ID + bd.IP + bd.PublicKey))
		body, _ := json.Marshal(common.RegisterRequest{
			Kind:      common.KindBroker,
			Broker:    &bd,
			Timestamp: now,
			HMAC:      hex.EncodeToString(mac.Sum(nil)),
		})
		resp, err := http.Post(b.cfg.DirURL+"/register", "application/json", bytes.NewReader(body))
		if err != nil {
			b.log.Warn("Directory unreachable: %v", err)
			return
		}
		resp.Body.Close()
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

func loadConfig() common.BrokerConfig {
	var cfg common.BrokerConfig
	path := "broker.yaml"
	if p := os.Getenv("SBNET_CONFIG"); p != "" {
		path = p
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("Parse broker.yaml: %v", err)
		}
	}
	cfg.ApplyDefaults()
	if v := os.Getenv("SBNET_REG_SECRET"); v != "" {
		cfg.RegSecret = v
	}
	return cfg
}

func main() {
	cfg := loadConfig()
	srv, err := newBrokerServer(cfg)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/assign",   srv.handleAssign)
	mux.HandleFunc("/validate", srv.handleValidate)
	mux.HandleFunc("/health",   srv.handleHealth)
	mux.HandleFunc("/kind/connect", srv.handleKindConnect)
	mux.HandleFunc("/kind/poll",    srv.handleKindPoll)
	mux.HandleFunc("/kind/answer",  srv.handleKindAnswer)
	mux.HandleFunc("/kind/info",    srv.handleKindInfo)

	httpSrv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go srv.pollConsensus(ctx)
	go srv.keepAlive(ctx)

	go func() {
		srv.log.Info("Broker [%s] country=%s on :%d", cfg.ID, cfg.Country, cfg.Port)
		var serveErr error
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			serveErr = httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			serveErr = httpSrv.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Fatal(serveErr)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	srv.log.Info("Graceful shutdown...")
	cancel()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	httpSrv.Shutdown(shutCtx)
	srv.log.Info("Broker stopped.")
}
