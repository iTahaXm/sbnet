// Package webrtcx provides a Snowflake-style WebRTC datachannel transport for
// SbNet "kind" mode. It is imported only by the client and the volunteer (kind)
// proxy, so the other binaries do not link the pion stack.
//
// A WebRTC datachannel is message-oriented; SbNet's cell framing is a byte
// stream. Conn bridges the two by buffering each received datachannel message
// and serving it out as a stream, so common.ReadCell (which does small
// io.ReadFull reads) works unmodified over it.
package webrtcx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pion/datachannel"
	"github.com/pion/webrtc/v4"

	"sbnet/common"
)

// Conn adapts a detached WebRTC datachannel to net.Conn (stream-buffered reads).
type Conn struct {
	pc *webrtc.PeerConnection
	dc datachannel.ReadWriteCloser

	mu   sync.Mutex
	rbuf []byte // leftover bytes from the last datachannel message
}

func newConn(pc *webrtc.PeerConnection, dc datachannel.ReadWriteCloser) *Conn {
	return &Conn{pc: pc, dc: dc}
}

func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.rbuf) == 0 {
		tmp := make([]byte, 65536)
		n, err := c.dc.Read(tmp)
		if err != nil {
			return 0, err
		}
		c.rbuf = tmp[:n]
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) { return c.dc.Write(p) }

func (c *Conn) Close() error {
	c.dc.Close()
	return c.pc.Close()
}

func (c *Conn) LocalAddr() net.Addr  { return addr{} }
func (c *Conn) RemoteAddr() net.Addr { return addr{} }

// The detached datachannel supports read deadlines (SCTP stream); write
// deadlines are a no-op.
type readDeadliner interface{ SetReadDeadline(time.Time) error }

func (c *Conn) SetReadDeadline(t time.Time) error {
	if d, ok := c.dc.(readDeadliner); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }
func (c *Conn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }

type addr struct{}

func (addr) Network() string { return "webrtc" }
func (addr) String() string  { return "webrtc-datachannel" }

// ─────────────────────────────────────────────
// API / configuration
// ─────────────────────────────────────────────

func newAPI() *webrtc.API {
	se := webrtc.SettingEngine{}
	se.DetachDataChannels()
	return webrtc.NewAPI(webrtc.WithSettingEngine(se))
}

func iceConfig(stun []string) webrtc.Configuration {
	cfg := webrtc.Configuration{}
	if len(stun) > 0 {
		cfg.ICEServers = []webrtc.ICEServer{{URLs: stun}}
	}
	return cfg
}

// FetchSTUN asks the broker which ICE/STUN servers to use.
func FetchSTUN(brokerURL string) []string {
	hc := &http.Client{Timeout: 10 * time.Second}
	resp, err := hc.Get(brokerURL + "/kind/info")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var info struct {
		STUN []string `json:"stun_servers"`
	}
	if json.NewDecoder(resp.Body).Decode(&info) != nil {
		return nil
	}
	return info.STUN
}

// ─────────────────────────────────────────────
// Client side (offerer)
// ─────────────────────────────────────────────

// ClientDial creates a WebRTC offer, exchanges it with the broker rendezvous,
// and returns a connected net.Conn once the datachannel opens. timeout bounds
// both the broker exchange and the datachannel open.
func ClientDial(brokerURL string, stun []string, timeout time.Duration) (net.Conn, error) {
	pc, err := newAPI().NewPeerConnection(iceConfig(stun))
	if err != nil {
		return nil, err
	}

	connCh := make(chan net.Conn, 1)
	dc, err := pc.CreateDataChannel("sbnet", nil)
	if err != nil {
		pc.Close()
		return nil, err
	}
	dc.OnOpen(func() {
		raw, err := dc.Detach()
		if err != nil {
			pc.Close()
			return
		}
		connCh <- newConn(pc, raw)
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		pc.Close()
		return nil, err
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		pc.Close()
		return nil, err
	}
	<-webrtc.GatheringCompletePromise(pc)

	body, _ := json.Marshal(common.KindOffer{SDP: pc.LocalDescription().SDP})
	hc := &http.Client{Timeout: timeout}
	resp, err := hc.Post(brokerURL+"/kind/connect", "application/json", bytes.NewReader(body))
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("kind/connect: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		pc.Close()
		return nil, fmt.Errorf("kind/connect: HTTP %d", resp.StatusCode)
	}
	var ans common.KindAnswer
	if err := json.NewDecoder(resp.Body).Decode(&ans); err != nil {
		pc.Close()
		return nil, err
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer, SDP: ans.SDP,
	}); err != nil {
		pc.Close()
		return nil, err
	}

	select {
	case conn := <-connCh:
		return conn, nil
	case <-time.After(timeout):
		pc.Close()
		return nil, fmt.Errorf("kind datachannel did not open within %s", timeout)
	}
}

// ─────────────────────────────────────────────
// Volunteer side (answerer)
// ─────────────────────────────────────────────

// VolunteerResult carries the connected datachannel or an error.
type VolunteerResult struct {
	Conn net.Conn
	Err  error
}

// VolunteerAnswer consumes a client's offer SDP, produces an answer SDP to be
// returned to the broker, and returns a channel that yields the net.Conn once
// the datachannel opens (or an error / timeout).
func VolunteerAnswer(offerSDP string, stun []string, openTimeout time.Duration) (string, <-chan VolunteerResult, error) {
	pc, err := newAPI().NewPeerConnection(iceConfig(stun))
	if err != nil {
		return "", nil, err
	}

	resCh := make(chan VolunteerResult, 1)
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		dc.OnOpen(func() {
			raw, err := dc.Detach()
			if err != nil {
				resCh <- VolunteerResult{Err: err}
				pc.Close()
				return
			}
			resCh <- VolunteerResult{Conn: newConn(pc, raw)}
		})
	})

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer, SDP: offerSDP,
	}); err != nil {
		pc.Close()
		return "", nil, err
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		pc.Close()
		return "", nil, err
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		pc.Close()
		return "", nil, err
	}
	<-webrtc.GatheringCompletePromise(pc)

	go func() {
		time.Sleep(openTimeout)
		select {
		case resCh <- VolunteerResult{Err: fmt.Errorf("datachannel open timeout")}:
			pc.Close()
		default:
		}
	}()

	return pc.LocalDescription().SDP, resCh, nil
}
