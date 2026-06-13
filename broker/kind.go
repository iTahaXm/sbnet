package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"sbnet/common"
)

// ─────────────────────────────────────────────
// Kind-mode rendezvous (Snowflake-style WebRTC signaling)
// ─────────────────────────────────────────────
//
// The broker matches clients to ephemeral volunteer ("kind") proxies. It only
// relays opaque SDP blobs — it never sees the WebRTC media/data, and the
// volunteer never learns the client's destination (the cell stream stays
// onion-encrypted end to end).
//
//   client  ──POST /kind/connect {offer}──►  broker  ◄──POST /kind/poll──  volunteer
//                                              │  returns {session_id, offer}
//   client  ◄── {answer} ──────────────────── broker ◄──POST /kind/answer {session_id, answer}── volunteer
//
// After the exchange, client and volunteer connect peer-to-peer over a WebRTC
// datachannel; the volunteer pipes that to an entry relay.

type kindSession struct {
	id       string
	offer    string
	answerCh chan string
}

type kindRendezvous struct {
	mu      sync.Mutex
	offers  chan *kindSession       // pending client offers awaiting a volunteer
	pending map[string]*kindSession // sessionID -> session awaiting an answer
}

func newKindRendezvous(capacity int) *kindRendezvous {
	if capacity < 16 {
		capacity = 16
	}
	return &kindRendezvous{
		offers:  make(chan *kindSession, capacity),
		pending: make(map[string]*kindSession),
	}
}

func randSessionID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

const (
	kindConnectWait = 20 * time.Second // how long a client waits for a volunteer
	kindPollWait    = 25 * time.Second // how long a volunteer long-polls for work
	kindMaxSDP      = 64 * 1024        // max accepted SDP blob size
)

// extendDeadlines overrides the server's short read/write timeouts for the
// long-poll handlers so they can block without being cut off mid-response.
func extendDeadlines(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(kindPollWait + 10*time.Second))
	_ = rc.SetWriteDeadline(time.Now().Add(kindPollWait + 10*time.Second))
}

// POST /kind/connect — a client posts its offer SDP and blocks until a
// volunteer supplies an answer (or the wait times out).
func (b *brokerServer) handleKindConnect(w http.ResponseWriter, r *http.Request) {
	extendDeadlines(w)
	var off common.KindOffer
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, kindMaxSDP)).Decode(&off); err != nil || off.SDP == "" {
		http.Error(w, "bad offer", http.StatusBadRequest)
		return
	}
	sess := &kindSession{id: randSessionID(), offer: off.SDP, answerCh: make(chan string, 1)}

	b.kind.mu.Lock()
	b.kind.pending[sess.id] = sess
	b.kind.mu.Unlock()
	defer func() {
		b.kind.mu.Lock()
		delete(b.kind.pending, sess.id)
		b.kind.mu.Unlock()
	}()

	select {
	case b.kind.offers <- sess:
	default:
		http.Error(w, "rendezvous busy", http.StatusServiceUnavailable)
		return
	}

	select {
	case ans := <-sess.answerCh:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(common.KindAnswer{SDP: ans})
	case <-time.After(kindConnectWait):
		http.Error(w, "no volunteer available", http.StatusGatewayTimeout)
	case <-r.Context().Done():
	}
}

// POST /kind/poll — a volunteer long-polls for a client to serve.
func (b *brokerServer) handleKindPoll(w http.ResponseWriter, r *http.Request) {
	extendDeadlines(w)
	select {
	case sess := <-b.kind.offers:
		b.kind.mu.Lock()
		_, live := b.kind.pending[sess.id]
		b.kind.mu.Unlock()
		if !live {
			// Client already gave up; tell the volunteer to poll again.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(common.KindPollResponse{SessionID: sess.id, Offer: sess.offer})
	case <-time.After(kindPollWait):
		w.WriteHeader(http.StatusNoContent)
	case <-r.Context().Done():
	}
}

// POST /kind/answer — a volunteer submits its answer SDP for a session.
func (b *brokerServer) handleKindAnswer(w http.ResponseWriter, r *http.Request) {
	var ar common.KindAnswerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, kindMaxSDP)).Decode(&ar); err != nil || ar.Answer == "" {
		http.Error(w, "bad answer", http.StatusBadRequest)
		return
	}
	b.kind.mu.Lock()
	sess, ok := b.kind.pending[ar.SessionID]
	b.kind.mu.Unlock()
	if !ok {
		http.Error(w, "unknown or expired session", http.StatusGone)
		return
	}
	select {
	case sess.answerCh <- ar.Answer:
	default:
	}
	w.WriteHeader(http.StatusOK)
}

// GET /kind/info — advertises the ICE/STUN servers clients and volunteers
// should use for NAT traversal.
func (b *brokerServer) handleKindInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]string{"stun_servers": b.cfg.STUNServers})
}
