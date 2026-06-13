package common

import (
	"fmt"
	"sync"
	"time"
)

// ─────────────────────────────────────────────
// Replay filter
// ─────────────────────────────────────────────
// Tracks (circID, nonce) pairs to reject replayed cells.
// Entries expire after replayWindow to bound memory.

const replayWindow = 10 * time.Minute

// ReplayFilter rejects duplicate (circID, nonce) pairs within a time window.
type ReplayFilter struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewReplayFilter creates a ready-to-use ReplayFilter.
func NewReplayFilter() *ReplayFilter {
	rf := &ReplayFilter{seen: make(map[string]time.Time)}
	go rf.gc()
	return rf
}

// Allow returns true the first time this (circID, nonce) pair is seen.
// Returns false on a replay.
func (rf *ReplayFilter) Allow(circID uint32, nonce []byte) bool {
	key := fmt.Sprintf("%d:%x", circID, nonce)
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if _, exists := rf.seen[key]; exists {
		return false
	}
	rf.seen[key] = time.Now()
	return true
}

func (rf *ReplayFilter) gc() {
	for range time.Tick(5 * time.Minute) {
		cutoff := time.Now().Add(-replayWindow)
		rf.mu.Lock()
		for k, t := range rf.seen {
			if t.Before(cutoff) {
				delete(rf.seen, k)
			}
		}
		rf.mu.Unlock()
	}
}

// ─────────────────────────────────────────────
// Circuit timeout tracker
// ─────────────────────────────────────────────

// TimeoutTracker fires a callback for circuits idle longer than idleTimeout.
type TimeoutTracker struct {
	mu          sync.Mutex
	lastSeen    map[uint32]time.Time
	idleTimeout time.Duration
	onTimeout   func(circID uint32)
}

// NewTimeoutTracker creates and starts a TimeoutTracker.
func NewTimeoutTracker(idle time.Duration, cb func(uint32)) *TimeoutTracker {
	t := &TimeoutTracker{
		lastSeen:    make(map[uint32]time.Time),
		idleTimeout: idle,
		onTimeout:   cb,
	}
	go t.sweep()
	return t
}

// Touch records activity for circID, resetting its idle timer.
func (t *TimeoutTracker) Touch(circID uint32) {
	t.mu.Lock()
	t.lastSeen[circID] = time.Now()
	t.mu.Unlock()
}

// Remove unregisters circID from tracking.
func (t *TimeoutTracker) Remove(circID uint32) {
	t.mu.Lock()
	delete(t.lastSeen, circID)
	t.mu.Unlock()
}

func (t *TimeoutTracker) sweep() {
	for range time.Tick(30 * time.Second) {
		cutoff := time.Now().Add(-t.idleTimeout)
		t.mu.Lock()
		var expired []uint32
		for id, ts := range t.lastSeen {
			if ts.Before(cutoff) {
				expired = append(expired, id)
				delete(t.lastSeen, id)
			}
		}
		t.mu.Unlock()
		for _, id := range expired {
			t.onTimeout(id)
		}
	}
}
