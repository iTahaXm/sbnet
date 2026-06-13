package common

import "time"

// NodeKind distinguishes relay vs broker registrations in the directory.
type NodeKind string

const (
	KindRelay  NodeKind = "relay"
	KindBroker NodeKind = "broker"
)

// ─────────────────────────────────────────────
// Directory types
// ─────────────────────────────────────────────

// RelayDescriptor describes a relay node registered in the directory.
type RelayDescriptor struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Role      string `json:"role"`       // "entry" | "middle" | "exit"
	PublicKey string `json:"public_key"` // X25519 hex — used for onion key agreement
	Country   string `json:"country"`    // ISO 3166-1 alpha-2, e.g. "DE"
	Region    string `json:"region"`     // operator-supplied label, e.g. "eu-west"
	OperMode  string `json:"oper_mode"`  // "normal" | "bridge" | "restricted"
	Bandwidth int    `json:"bandwidth"`  // self-reported kbps
	Version   string `json:"version"`    // software version string
	LastSeen  int64  `json:"last_seen"`  // unix timestamp of last /register
}

// BrokerDescriptor describes a broker node registered in the directory.
type BrokerDescriptor struct {
	ID        string   `json:"id"`
	IP        string   `json:"ip"`
	Port      int      `json:"port"`       // broker API port
	PublicKey string   `json:"public_key"` // ed25519 hex, used to verify token signatures
	Country   string   `json:"country"`
	Region    string   `json:"region"`
	Modes     []string `json:"modes"`    // e.g. ["normal","bridge"]
	LastSeen  int64    `json:"last_seen"`
}

// SignedConsensus is the response body for GET /consensus.
//
// The directory signs the concatenation (RelaysJSON + BrokersJSON) with its
// ed25519 key. Both JSON strings are included verbatim so clients can verify
// without re-marshalling — eliminating any risk of JSON encoding divergence.
type SignedConsensus struct {
	Relays      []RelayDescriptor  `json:"relays"`
	Brokers     []BrokerDescriptor `json:"brokers"`
	Timestamp   int64              `json:"timestamp"`
	Signature   string             `json:"signature"`    // ed25519 hex over RelaysJSON+BrokersJSON
	RelaysJSON  string             `json:"relays_json"`  // exact bytes signed
	BrokersJSON string             `json:"brokers_json"` // exact bytes signed
}

// RegisterRequest is the body for POST /register (relay or broker).
type RegisterRequest struct {
	Kind      NodeKind          `json:"kind"`
	Relay     *RelayDescriptor  `json:"relay,omitempty"`
	Broker    *BrokerDescriptor `json:"broker,omitempty"`
	Timestamp int64             `json:"timestamp"` // unix, must be within 30s of server
	HMAC      string            `json:"hmac"`      // HMAC-SHA256 hex over identity fields
}

// ─────────────────────────────────────────────
// Broker types
// ─────────────────────────────────────────────

// AssignRequest is sent by a client to a broker to obtain a relay assignment.
type AssignRequest struct {
	Role    string `json:"role"`              // "entry" | "middle" | "exit" — required
	Country string `json:"country,omitempty"` // preferred country
	Region  string `json:"region,omitempty"`
	Mode    string `json:"mode,omitempty"` // "normal" | "bridge"
}

// AssignResponse is the broker's reply: a relay plus a short-lived session token.
type AssignResponse struct {
	Relay     RelayDescriptor `json:"relay"`
	Token     string          `json:"token"`      // opaque hex token
	ExpiresAt int64           `json:"expires_at"` // unix
}

// TokenTTL is how long a broker-issued token is valid.
const TokenTTL = 5 * time.Minute

// ─────────────────────────────────────────────
// Hidden service types
// ─────────────────────────────────────────────

// HiddenServiceDescriptor is published by a .sbnet hidden service host.
type HiddenServiceDescriptor struct {
	Hostname    string       `json:"hostname"`     // e.g. "abc123.sbnet"
	IntroPoints []IntroPoint `json:"intro_points"` // relay rendezvous points
	PublicKey   string       `json:"public_key"`   // ed25519 service key hex
	Signature   string       `json:"signature"`    // ed25519 over canonical JSON
	PublishedAt int64        `json:"published_at"`
}

// IntroPoint is a relay used as a rendezvous / introduction point.
type IntroPoint struct {
	RelayID   string `json:"relay_id"`
	RelayIP   string `json:"relay_ip"`
	RelayPort int    `json:"relay_port"`
	AuthKey   string `json:"auth_key"` // X25519 hex
}

// ─────────────────────────────────────────────
// Bridge URI
// ─────────────────────────────────────────────

// BridgeConfig is the parsed form of a sbnet:// bridge URI.
//
//	sbnet://bridge=host:port&token=xxx&obfs=tls&mode=secure
type BridgeConfig struct {
	Endpoint string // host:port of the bridge gateway
	Token    string // pre-shared authorisation token
	Obfs     string // transport obfuscation: "tls" | "none"
	Mode     string // "secure" | "normal"
}

// ─────────────────────────────────────────────
// Kind-mode (Snowflake-style) rendezvous messages
// ─────────────────────────────────────────────

// KindOffer is a client's WebRTC offer SDP posted to the broker rendezvous.
type KindOffer struct {
	SDP string `json:"sdp"`
}

// KindAnswer is a volunteer's WebRTC answer SDP returned to the client.
type KindAnswer struct {
	SDP string `json:"sdp"`
}

// KindPollResponse is returned to a volunteer that has been matched to a client.
type KindPollResponse struct {
	SessionID string `json:"session_id"`
	Offer     string `json:"offer"` // the client's offer SDP
}

// KindAnswerRequest is a volunteer submitting its answer for a matched session.
type KindAnswerRequest struct {
	SessionID string `json:"session_id"`
	Answer    string `json:"answer"`
}
