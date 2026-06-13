package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// ─────────────────────────────────────────────
// Cell wire format
// ─────────────────────────────────────────────
//
// On the wire each cell is a length-prefixed, randomly-padded frame:
//
//   [0:2]            FrameLen — uint16 big-endian, = CellHdrSize + Length + pad
//   ── frame body (FrameLen bytes) ──
//   [0:4]            CircID   — uint32 big-endian
//   [4]              Command  — CellCmd byte
//   [5:7]            Length   — uint16 big-endian, used bytes in Body
//   [7:7+Length]     Body     — Length meaningful bytes
//   [7+Length:end]   Pad      — random bytes, ignored by the receiver
//
// The meaningful payload (header + Body[:Length]) is identical to the old
// fixed format, so the onion-crypto layers are unchanged. What varies is the
// amount of trailing random padding, so the on-wire frame size is no longer a
// constant 512 bytes — defeating trivial size-based DPI fingerprinting.

const (
	CellSize    = 512 // legacy reference size; no longer the fixed wire size
	CellHdrSize = 7
	CellBodyMax = CellSize - CellHdrSize // 505 — max meaningful body per cell

	// FrameLenSize is the width of the on-wire length prefix.
	FrameLenSize = 2
	// MaxFrameLen bounds a single frame to guard against hostile length
	// prefixes (header + max body + generous padding headroom).
	MaxFrameLen = 4096
)

// padBuckets are the target on-wire frame sizes. MarshalCell pads each cell up
// to the smallest bucket that fits its meaningful bytes, chosen at random so a
// given logical cell does not always serialise to the same length.
var padBuckets = []int{128, 256, 512, 768, 1024, 1280}

// CellCmd identifies the purpose of a cell.
type CellCmd byte

const (
	CmdCreate    CellCmd = 1  // client→entry: start circuit, carries client X25519 ephemeral pubkey
	CmdCreated   CellCmd = 2  // relay→client: circuit ready, carries relay X25519 ephemeral pubkey
	CmdExtend    CellCmd = 3  // client→relay: extend circuit to next hop
	CmdExtended  CellCmd = 4  // relay→client: extended, carries next-hop ephemeral pubkey
	CmdRelay     CellCmd = 5  // encrypted onion data cell
	CmdDestroy   CellCmd = 6  // tear down circuit
	CmdPing      CellCmd = 7  // health-check ping
	CmdPong      CellCmd = 8  // health-check pong
	CmdFragment  CellCmd = 9  // intermediate fragment of a large payload
	CmdFragFinal CellCmd = 10 // final fragment — triggers reassembly
	CmdHidden    CellCmd = 11 // hidden-service rendezvous cell
	// CmdRelayDone is sent by the exit relay (encrypted, re-encrypted through
	// intermediate hops) after the last response chunk for a request.
	// The client peels all three layers and stops reading when it sees this,
	// instead of waiting for a read timeout.
	CmdRelayDone CellCmd = 12
)

// Cell is the in-memory representation of one protocol cell.
type Cell struct {
	CircID  uint32
	Command CellCmd
	Length  uint16
	Body    [CellBodyMax]byte
}

// frameBodyLen returns the meaningful frame-body length (header + body) for n
// body bytes, and pickPadTarget chooses the padded on-wire frame size.
func pickPadTarget(meaningful int) int {
	// Smallest bucket that fits, then randomly enlarge to a bigger bucket so
	// the same logical cell varies in size across sends.
	first := len(padBuckets)
	for i, b := range padBuckets {
		if b >= meaningful {
			first = i
			break
		}
	}
	if first >= len(padBuckets) {
		// Payload exceeds the largest bucket: no padding, send as-is.
		return meaningful
	}
	choices := len(padBuckets) - first
	j := first + int(randByte())%choices
	return padBuckets[j]
}

// randByte returns one cryptographically-random byte.
func randByte() byte {
	var b [1]byte
	rand.Read(b[:])
	return b[0]
}

// MarshalCell serialises c into a length-prefixed, randomly-padded frame.
func MarshalCell(c Cell) []byte {
	n := int(c.Length)
	if n > CellBodyMax {
		n = CellBodyMax
	}
	meaningful := CellHdrSize + n
	target := pickPadTarget(meaningful)
	if target > MaxFrameLen {
		target = MaxFrameLen
	}

	buf := make([]byte, FrameLenSize+target)
	binary.BigEndian.PutUint16(buf[0:2], uint16(target))
	frame := buf[FrameLenSize:]
	binary.BigEndian.PutUint32(frame[0:4], c.CircID)
	frame[4] = byte(c.Command)
	binary.BigEndian.PutUint16(frame[5:7], uint16(n))
	copy(frame[CellHdrSize:], c.Body[:n])
	if pad := target - meaningful; pad > 0 {
		rand.Read(frame[meaningful:])
	}
	return buf
}

// UnmarshalCell parses a single frame body (header + body + padding) into a
// Cell. data must be at least CellHdrSize bytes; trailing padding is ignored.
func UnmarshalCell(data []byte) (Cell, error) {
	if len(data) < CellHdrSize {
		return Cell{}, fmt.Errorf("cell too short: %d bytes", len(data))
	}
	var c Cell
	c.CircID = binary.BigEndian.Uint32(data[0:4])
	c.Command = CellCmd(data[4])
	c.Length = binary.BigEndian.Uint16(data[5:7])
	if int(c.Length) > CellBodyMax {
		c.Length = CellBodyMax
	}
	avail := len(data) - CellHdrSize
	if int(c.Length) > avail {
		return Cell{}, fmt.Errorf("cell length %d exceeds frame body %d", c.Length, avail)
	}
	copy(c.Body[:], data[CellHdrSize:CellHdrSize+int(c.Length)])
	return c, nil
}

// ReadCell reads exactly one length-prefixed frame from r and parses it.
func ReadCell(r io.Reader) (Cell, error) {
	var lenBuf [FrameLenSize]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return Cell{}, err
	}
	frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if frameLen < CellHdrSize || frameLen > MaxFrameLen {
		return Cell{}, fmt.Errorf("invalid frame length: %d", frameLen)
	}
	buf := make([]byte, frameLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Cell{}, err
	}
	return UnmarshalCell(buf)
}

// WriteCell serialises and writes c to w.
func WriteCell(w io.Writer, c Cell) error {
	_, err := w.Write(MarshalCell(c))
	return err
}

// ─────────────────────────────────────────────
// Fragmentation
// ─────────────────────────────────────────────

const (
	FragHdrSize = 6
	FragDataMax = CellBodyMax - FragHdrSize // 499 bytes per fragment
)

// Fragment splits data into one or more cells.
func Fragment(circID uint32, seqID uint32, data []byte) []Cell {
	var cells []Cell
	idx := uint16(0)
	for len(data) > 0 {
		chunk := data
		cmd := CmdFragFinal
		if len(data) > FragDataMax {
			chunk = data[:FragDataMax]
			cmd = CmdFragment
		}
		var c Cell
		c.CircID = circID
		c.Command = cmd
		binary.BigEndian.PutUint32(c.Body[0:4], seqID)
		binary.BigEndian.PutUint16(c.Body[4:6], idx)
		n := copy(c.Body[FragHdrSize:], chunk)
		c.Length = uint16(FragHdrSize + n)
		cells = append(cells, c)
		data = data[len(chunk):]
		idx++
	}
	return cells
}

// Reassembler accumulates fragment cells and returns the full payload on completion.
type Reassembler struct {
	pieces   map[uint16][]byte
	finalIdx uint16
	gotFinal bool
}

// Add adds a fragment cell. Returns (payload, true) when all pieces are present.
func (r *Reassembler) Add(c Cell) ([]byte, bool) {
	if r.pieces == nil {
		r.pieces = make(map[uint16][]byte)
	}
	if int(c.Length) < FragHdrSize {
		return nil, false
	}
	idx := binary.BigEndian.Uint16(c.Body[4:6])
	dataLen := int(c.Length) - FragHdrSize
	r.pieces[idx] = append([]byte(nil), c.Body[FragHdrSize:FragHdrSize+dataLen]...)
	if c.Command == CmdFragFinal {
		r.finalIdx = idx
		r.gotFinal = true
	}
	if !r.gotFinal {
		return nil, false
	}
	for i := uint16(0); i <= r.finalIdx; i++ {
		if _, ok := r.pieces[i]; !ok {
			return nil, false
		}
	}
	var out []byte
	for i := uint16(0); i <= r.finalIdx; i++ {
		out = append(out, r.pieces[i]...)
	}
	return out, true
}

// ─────────────────────────────────────────────
// Crypto helpers
// ─────────────────────────────────────────────

// GenKeyPair generates a fresh X25519 ephemeral keypair.
func GenKeyPair() (priv, pub [32]byte) {
	if _, err := rand.Read(priv[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return
}

// DeriveKey performs X25519 ECDH and returns SHA-256(shared_secret).
func DeriveKey(priv, theirPub [32]byte) []byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &priv, &theirPub)
	h := sha256.Sum256(shared[:])
	return h[:]
}

// Encrypt encrypts plaintext under a 32-byte AES-256-GCM key.
// Output: nonce(12) || ciphertext+tag.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("Encrypt: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt. Returns an error if authentication fails.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("Decrypt: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns+gcm.Overhead() {
		return nil, fmt.Errorf("Decrypt: ciphertext too short (%d bytes)", len(ciphertext))
	}
	return gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

// RandomUint32 returns a cryptographically random uint32.
func RandomUint32() uint32 {
	b := make([]byte, 4)
	rand.Read(b)
	return binary.BigEndian.Uint32(b)
}

// RandomBytes fills b with cryptographically random bytes.
func RandomBytes(b []byte) { rand.Read(b) }
