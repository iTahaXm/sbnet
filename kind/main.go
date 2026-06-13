// Command kind is an ephemeral, Snowflake-style volunteer proxy for SbNet.
//
// It long-polls a broker rendezvous for clients, accepts each over a WebRTC
// datachannel, and pipes the (onion-encrypted) cell stream to an entry relay it
// selects from a cryptographically-verified directory consensus. The volunteer
// is a transparent byte pipe: it terminates no SbNet crypto and learns nothing
// about the client's destination.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"sbnet/common"
	"sbnet/webrtcx"
)

type kindProxy struct {
	cfg     common.KindConfig
	log     *common.Logger
	stun    []string
	httpc   *http.Client

	relaysMu sync.RWMutex
	entries  []common.RelayDescriptor
}

func (k *kindProxy) refreshConsensus(ctx context.Context) {
	load := func() {
		consensus, err := common.FetchVerifiedConsensus(k.cfg.DirURL, k.cfg.DirTLSCA)
		if err != nil {
			k.log.Warn("Consensus fetch/verify failed: %v", err)
			return
		}
		var entries []common.RelayDescriptor
		for _, r := range consensus.Relays {
			if r.Role == "entry" {
				entries = append(entries, r)
			}
		}
		k.relaysMu.Lock()
		k.entries = entries
		k.relaysMu.Unlock()
		k.log.Debug("Entry relays available: %d", len(entries))
	}
	load()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Minute):
			load()
		}
	}
}

func (k *kindProxy) pickEntry() *common.RelayDescriptor {
	k.relaysMu.RLock()
	defer k.relaysMu.RUnlock()
	if len(k.entries) == 0 {
		return nil
	}
	r := k.entries[int(common.RandomUint32())%len(k.entries)]
	return &r
}

// poll asks the broker for a client to serve. Returns nil (no error) when the
// long-poll times out with no work.
func (k *kindProxy) poll() (*common.KindPollResponse, error) {
	resp, err := k.httpc.Post(k.cfg.BrokerURL+"/kind/poll", "application/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	var pr common.KindPollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

func (k *kindProxy) serve(pr *common.KindPollResponse) {
	answer, resCh, err := webrtcx.VolunteerAnswer(pr.Offer, k.stun, 30*time.Second)
	if err != nil {
		k.log.Warn("WebRTC answer failed: %v", err)
		return
	}
	body, _ := json.Marshal(common.KindAnswerRequest{SessionID: pr.SessionID, Answer: answer})
	resp, err := k.httpc.Post(k.cfg.BrokerURL+"/kind/answer", "application/json",
		bytes.NewReader(body))
	if err != nil {
		k.log.Warn("Submit answer failed: %v", err)
		return
	}
	resp.Body.Close()

	res := <-resCh
	if res.Err != nil {
		k.log.Debug("Datachannel did not open: %v", res.Err)
		return
	}
	defer res.Conn.Close()

	entry := k.pickEntry()
	if entry == nil {
		k.log.Warn("No entry relay available; dropping client")
		return
	}
	addr := net.JoinHostPort(entry.IP, strconv.Itoa(entry.Port))
	relayConn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		k.log.Warn("Cannot reach entry relay %s: %v", addr, err)
		return
	}
	defer relayConn.Close()

	k.log.Info("Kind tunnel: client → entry %s (%s)", entry.ID, addr)
	pipe(res.Conn, relayConn)
	k.log.Debug("Kind tunnel closed (entry %s)", entry.ID)
}

// worker runs a single serial poll→serve loop; running cfg.Capacity of them
// bounds the number of concurrent client sessions.
func (k *kindProxy) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		pr, err := k.poll()
		if err != nil {
			k.log.Debug("Poll error: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			continue
		}
		if pr == nil {
			continue // long-poll idle timeout, poll again
		}
		k.serve(pr)
	}
}

// pipe shuttles bytes in both directions until either side closes.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); a.Close(); done <- struct{}{} }()
	go func() { io.Copy(b, a); b.Close(); done <- struct{}{} }()
	<-done
}

func loadConfig() common.KindConfig {
	var cfg common.KindConfig
	path := "kind.yaml"
	if p := os.Getenv("SBNET_CONFIG"); p != "" {
		path = p
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("Parse kind.yaml: %v", err)
		}
	}
	cfg.ApplyDefaults()
	if v := os.Getenv("SBNET_BROKER"); v != "" {
		cfg.BrokerURL = v
	}
	if v := os.Getenv("SBNET_DIR"); v != "" {
		cfg.DirURL = v
	}
	return cfg
}

func main() {
	cfg := loadConfig()
	lvl := common.ParseLogLevel(cfg.LogLevel)
	logger := common.NewLogger("kind", lvl, nil)

	// Prefer the broker's advertised STUN servers so client and volunteer agree.
	stun := webrtcx.FetchSTUN(cfg.BrokerURL)
	if len(stun) == 0 {
		stun = cfg.STUNServers
	}

	k := &kindProxy{
		cfg:   cfg,
		log:   logger,
		stun:  stun,
		httpc: &http.Client{Timeout: 35 * time.Second}, // > broker long-poll wait
	}

	ctx, cancel := context.WithCancel(context.Background())
	go k.refreshConsensus(ctx)

	logger.Info("Kind proxy: broker=%s dir=%s capacity=%d stun=%v",
		cfg.BrokerURL, cfg.DirURL, cfg.Capacity, stun)
	for i := 0; i < cfg.Capacity; i++ {
		go k.worker(ctx)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down...")
	cancel()
	time.Sleep(500 * time.Millisecond)
}
