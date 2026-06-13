package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"

	"sbnet/common"
)

// ─────────────────────────────────────────────
// Server state
// ─────────────────────────────────────────────

type directoryServer struct {
	cfg     common.DirectoryConfig
	log     *common.Logger
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey

	mu      sync.RWMutex
	relays  map[string]common.RelayDescriptor
	brokers map[string]common.BrokerDescriptor

	limitMu  sync.Mutex
	limiters map[string]*rate.Limiter // key: "ip@rps"

	syncClient *http.Client // for gossiping registrations to peer directories
}

func newServer(cfg common.DirectoryConfig) (*directoryServer, error) {
	pub, priv, err := common.LoadOrCreateEd25519(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load/create ed25519 key: %w", err)
	}
	syncClient, err := common.BuildHTTPClient(cfg.SyncTLSCA)
	if err != nil {
		return nil, fmt.Errorf("build sync client: %w", err)
	}
	lvl := common.ParseLogLevel(cfg.LogLevel)
	s := &directoryServer{
		cfg:        cfg,
		log:        common.NewLogger("directory", lvl, nil),
		privKey:    priv,
		pubKey:     pub,
		relays:     make(map[string]common.RelayDescriptor),
		brokers:    make(map[string]common.BrokerDescriptor),
		limiters:   make(map[string]*rate.Limiter),
		syncClient: syncClient,
	}
	s.log.Info("Directory pubkey: %s", hex.EncodeToString(pub))
	if len(cfg.PeerDirs) > 0 {
		s.log.Info("Peer directories: %v", cfg.PeerDirs)
	}
	return s, nil
}

// ─────────────────────────────────────────────
// Per-IP rate limiting
// ─────────────────────────────────────────────

func (s *directoryServer) limiter(ip string, rps float64) *rate.Limiter {
	key := fmt.Sprintf("%s@%.0f", ip, rps)
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	if l, ok := s.limiters[key]; ok {
		return l
	}
	l := rate.NewLimiter(rate.Limit(rps), int(rps*3)+1)
	s.limiters[key] = l
	return l
}

func (s *directoryServer) rateLimit(rps float64, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			ip = fwd
		}
		if !s.limiter(ip, rps).Allow() {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// ─────────────────────────────────────────────
// HMAC verification
// ─────────────────────────────────────────────

// hmacMessage returns the canonical identity string an HMAC is computed over.
func hmacMessage(req common.RegisterRequest) (string, bool) {
	switch req.Kind {
	case common.KindRelay:
		if req.Relay == nil {
			return "", false
		}
		rd := req.Relay
		return rd.ID + rd.IP + rd.Role + rd.PublicKey, true
	case common.KindBroker:
		if req.Broker == nil {
			return "", false
		}
		bd := req.Broker
		return bd.ID + bd.IP + bd.PublicKey, true
	default:
		return "", false
	}
}

// verifyHMAC validates the request's HMAC and that its timestamp is within
// ±window seconds. Direct /register uses a tight window; gossiped /sync uses a
// wider one to tolerate inter-directory propagation delay.
func (s *directoryServer) verifyHMAC(req common.RegisterRequest, window int64) bool {
	delta := time.Now().Unix() - req.Timestamp
	if delta > window || delta < -window {
		return false
	}
	msg, ok := hmacMessage(req)
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, []byte(s.cfg.RegSecret))
	mac.Write([]byte(msg))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(req.HMAC), []byte(expected))
}

// storeRegistration applies a relay/broker descriptor to local state.
//
// When stampNow is true (direct /register) the descriptor's LastSeen is set to
// the current time and the update is unconditional. When false (a gossiped
// /sync) the descriptor is applied only if its LastSeen is strictly newer than
// what we already hold — this deduplicates and breaks gossip loops.
//
// It returns the stored descriptor (LastSeen filled in) for onward gossip,
// whether local state changed, and an HTTP error (msg, code) if invalid.
func (s *directoryServer) storeRegistration(req common.RegisterRequest, stampNow bool) (common.RegisterRequest, bool, string, int) {
	now := time.Now().Unix()
	out := req
	switch req.Kind {
	case common.KindRelay:
		if req.Relay == nil {
			return out, false, "missing relay", 400
		}
		rd := *req.Relay
		switch rd.Role {
		case "entry", "middle", "exit":
		default:
			return out, false, "invalid role", 400
		}
		if stampNow {
			rd.LastSeen = now
		}
		changed := false
		s.mu.Lock()
		if old, ok := s.relays[rd.ID]; !ok || rd.LastSeen > old.LastSeen {
			s.relays[rd.ID] = rd
			changed = true
		}
		s.mu.Unlock()
		out.Relay = &rd
		return out, changed, "", 0
	case common.KindBroker:
		if req.Broker == nil {
			return out, false, "missing broker", 400
		}
		bd := *req.Broker
		if stampNow {
			bd.LastSeen = now
		}
		changed := false
		s.mu.Lock()
		if old, ok := s.brokers[bd.ID]; !ok || bd.LastSeen > old.LastSeen {
			s.brokers[bd.ID] = bd
			changed = true
		}
		s.mu.Unlock()
		out.Broker = &bd
		return out, changed, "", 0
	default:
		return out, false, "unknown kind", 400
	}
}

// gossip forwards a stored descriptor to every peer directory's /sync endpoint,
// re-authenticated with a fresh HMAC timestamp. Fire-and-forget; failures are
// logged at debug level. /sync receipts are never re-gossiped, so this fans out
// exactly one hop per registration.
func (s *directoryServer) gossip(req common.RegisterRequest) {
	if len(s.cfg.PeerDirs) == 0 {
		return
	}
	msg, ok := hmacMessage(req)
	if !ok {
		return
	}
	mac := hmac.New(sha256.New, []byte(s.cfg.RegSecret))
	mac.Write([]byte(msg))
	out := req
	out.Timestamp = time.Now().Unix()
	out.HMAC = hex.EncodeToString(mac.Sum(nil))
	body, err := json.Marshal(out)
	if err != nil {
		return
	}
	for _, peer := range s.cfg.PeerDirs {
		go func(peer string) {
			resp, err := s.syncClient.Post(peer+"/sync", "application/json", bytes.NewReader(body))
			if err != nil {
				s.log.Debug("gossip to %s failed: %v", peer, err)
				return
			}
			resp.Body.Close()
		}(peer)
	}
}

// ─────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────

// GET /consensus
// Returns the signed relay+broker list. The signature is over the exact JSON
// bytes included in the response so clients can verify without re-marshalling.
func (s *directoryServer) handleConsensus(w http.ResponseWriter, r *http.Request) {
	maxAge := int64(s.cfg.ConsensusMaxAge)
	now := time.Now().Unix()

	s.mu.RLock()
	relayList := make([]common.RelayDescriptor, 0, len(s.relays))
	for _, rd := range s.relays {
		if now-rd.LastSeen < maxAge {
			relayList = append(relayList, rd)
		}
	}
	brokerList := make([]common.BrokerDescriptor, 0, len(s.brokers))
	for _, bd := range s.brokers {
		if now-bd.LastSeen < maxAge {
			brokerList = append(brokerList, bd)
		}
	}
	s.mu.RUnlock()

	relaysJSON, err := json.Marshal(relayList)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	brokersJSON, err := json.Marshal(brokerList)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}

	// Sign the concatenation of both canonical payloads.
	sigPayload := append(relaysJSON, brokersJSON...)
	sig := ed25519.Sign(s.privKey, sigPayload)

	consensus := common.SignedConsensus{
		Relays:      relayList,
		Brokers:     brokerList,
		Timestamp:   now,
		Signature:   hex.EncodeToString(sig),
		RelaysJSON:  string(relaysJSON),
		BrokersJSON: string(brokersJSON),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(consensus)
}

// POST /register — a relay or broker registers directly with this directory.
func (s *directoryServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req common.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if !s.verifyHMAC(req, 30) {
		s.log.Warn("Rejected registration from %s — bad HMAC or stale timestamp", r.RemoteAddr)
		http.Error(w, "unauthorized", 401)
		return
	}
	stored, changed, msg, code := s.storeRegistration(req, true)
	if code != 0 {
		http.Error(w, msg, code)
		return
	}
	switch req.Kind {
	case common.KindRelay:
		rd := stored.Relay
		s.log.Info("Relay registered: %s (%s:%d) role=%s country=%s operMode=%s",
			rd.ID, rd.IP, rd.Port, rd.Role, rd.Country, rd.OperMode)
	case common.KindBroker:
		bd := stored.Broker
		s.log.Info("Broker registered: %s (%s:%d) country=%s modes=%v",
			bd.ID, bd.IP, bd.Port, bd.Country, bd.Modes)
	}
	if changed {
		s.gossip(stored) // fan out one hop to peer directories
	}
	w.WriteHeader(http.StatusOK)
}

// POST /sync — a peer directory forwards a validated registration. Applied only
// if newer than what we hold, and never re-gossiped (one-hop fan-out).
func (s *directoryServer) handleSync(w http.ResponseWriter, r *http.Request) {
	var req common.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if !s.verifyHMAC(req, 120) {
		s.log.Warn("Rejected /sync from %s — bad HMAC or stale timestamp", r.RemoteAddr)
		http.Error(w, "unauthorized", 401)
		return
	}
	stored, changed, msg, code := s.storeRegistration(req, false)
	if code != 0 {
		http.Error(w, msg, code)
		return
	}
	if changed {
		switch req.Kind {
		case common.KindRelay:
			s.log.Debug("Synced relay %s from peer %s", stored.Relay.ID, r.RemoteAddr)
		case common.KindBroker:
			s.log.Debug("Synced broker %s from peer %s", stored.Broker.ID, r.RemoteAddr)
		}
	}
	w.WriteHeader(http.StatusOK)
}

// GET /pubkey — returns the directory's ed25519 public key in hex.
// Clients fetch this once and cache it to verify subsequent consensus signatures.
func (s *directoryServer) handlePubkey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(hex.EncodeToString(s.pubKey)))
}

// GET /health
func (s *directoryServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	nr, nb := len(s.relays), len(s.brokers)
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"relays": nr, "brokers": nb})
}

func (s *directoryServer) buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/consensus", s.rateLimit(s.cfg.ConsensusRPS, s.handleConsensus))
	mux.HandleFunc("/register",  s.rateLimit(s.cfg.RegisterRPS,  s.handleRegister))
	mux.HandleFunc("/sync",      s.rateLimit(s.cfg.ConsensusRPS, s.handleSync))
	mux.HandleFunc("/pubkey",    s.handlePubkey)
	mux.HandleFunc("/health",    s.handleHealth)
	return mux
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

func loadConfig() common.DirectoryConfig {
	var cfg common.DirectoryConfig
	path := "directory.yaml"
	if p := os.Getenv("SBNET_CONFIG"); p != "" {
		path = p
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("Parse directory.yaml: %v", err)
		}
	}
	cfg.ApplyDefaults()
	if v := os.Getenv("SBNET_REG_SECRET"); v != "" {
		cfg.RegSecret = v
	}
	if cfg.RegSecret == "" {
		log.Fatal("reg_secret must be set in directory.yaml or SBNET_REG_SECRET env var")
	}
	return cfg
}

func main() {
	cfg := loadConfig()
	srv, err := newServer(cfg)
	if err != nil {
		log.Fatal(err)
	}

	httpSrv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      srv.buildMux(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			srv.log.Info("Directory (TLS) on %s", cfg.ListenAddr)
			if err := httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		} else {
			srv.log.Info("Directory (plain HTTP) on %s — configure tls_cert/tls_key for production", cfg.ListenAddr)
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	srv.log.Info("Graceful shutdown...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	httpSrv.Shutdown(ctx)
	srv.log.Info("Directory stopped.")
}
