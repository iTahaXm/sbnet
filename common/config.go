package common

// ─────────────────────────────────────────────
// YAML config structs for all components
// ─────────────────────────────────────────────

// DirectoryConfig is loaded from directory.yaml.
type DirectoryConfig struct {
	ListenAddr      string  `yaml:"listen_addr"`           // e.g. ":7000"
	TLSCert         string  `yaml:"tls_cert"`              // PEM cert path; empty = plain HTTP
	TLSKey          string  `yaml:"tls_key"`               // PEM key path
	KeyFile         string  `yaml:"key_file"`              // persistent ed25519 signing key
	RegSecret       string  `yaml:"reg_secret"`            // HMAC secret for relay/broker auth
	LogLevel        string  `yaml:"log_level"`             // error|warn|info|debug
	RegisterRPS     float64 `yaml:"register_rps"`          // rate limit: POST /register per IP/s
	ConsensusRPS    float64 `yaml:"consensus_rps"`         // rate limit: GET /consensus per IP/s
	ConsensusMaxAge int     `yaml:"consensus_max_age_secs"` // seconds before relay removed from consensus

	// Multi-directory sync: peer directories to gossip validated
	// registrations to. Each directory still signs its own consensus with its
	// own key; clients trust whichever directory they query.
	PeerDirs   []string `yaml:"peer_dirs"`    // e.g. ["https://dir2:7000"]
	SyncTLSCA  string   `yaml:"sync_tls_ca"`  // CA cert for peer /sync TLS; empty = system pool
}

func (c *DirectoryConfig) ApplyDefaults() {
	if c.ListenAddr == ""      { c.ListenAddr = ":7000" }
	if c.KeyFile == ""         { c.KeyFile = "directory.key" }
	if c.LogLevel == ""        { c.LogLevel = "info" }
	if c.RegisterRPS == 0     { c.RegisterRPS = 5 }
	if c.ConsensusRPS == 0    { c.ConsensusRPS = 20 }
	if c.ConsensusMaxAge == 0 { c.ConsensusMaxAge = 300 }
}

// RelayConfig is loaded from relay.yaml.
type RelayConfig struct {
	ID              string `yaml:"id"`
	IP              string `yaml:"ip"`
	Port            int    `yaml:"port"`
	HealthPort      int    `yaml:"health_port"`       // HTTP health endpoint; 0 = port+1000
	Role            string `yaml:"role"`              // entry|middle|exit
	Country         string `yaml:"country"`           // ISO 3166-1 alpha-2
	Region          string `yaml:"region"`
	OperMode        string `yaml:"oper_mode"`         // normal|bridge|restricted
	Bandwidth       int    `yaml:"bandwidth"`         // kbps
	Version         string `yaml:"version"`
	DirURL          string `yaml:"dir_url"`           // e.g. "https://dir.example.com:7000"
	DirTLSCA        string `yaml:"dir_tls_ca"`        // CA cert for TLS dir connection; empty = system pool
	RegSecret       string `yaml:"reg_secret"`        // HMAC secret; falls back to SBNET_REG_SECRET env
	KeyFile         string `yaml:"key_file"`          // persistent X25519 identity key
	InternalDNS     string `yaml:"internal_dns"`      // exit only: DoH resolver address
	LogLevel        string `yaml:"log_level"`
	CircuitIdleSecs int    `yaml:"circuit_idle_secs"` // idle circuit timeout
}

func (c *RelayConfig) ApplyDefaults() {
	if c.Port == 0             { c.Port = 9001 }
	if c.HealthPort == 0       { c.HealthPort = c.Port + 1000 }
	if c.Role == ""            { c.Role = "middle" }
	if c.OperMode == ""        { c.OperMode = "normal" }
	if c.DirURL == ""          { c.DirURL = "https://127.0.0.1:7000" }
	if c.KeyFile == ""         { c.KeyFile = "relay.key" }
	if c.LogLevel == ""        { c.LogLevel = "info" }
	if c.CircuitIdleSecs == 0 { c.CircuitIdleSecs = 300 }
	if c.Version == ""         { c.Version = "1.0.0" }
	if c.InternalDNS == ""     { c.InternalDNS = "127.0.0.1:2080" }
}

// BrokerConfig is loaded from broker.yaml.
type BrokerConfig struct {
	ID        string   `yaml:"id"`
	IP        string   `yaml:"ip"`
	Port      int      `yaml:"port"`
	Country   string   `yaml:"country"`
	Region    string   `yaml:"region"`
	Modes     []string `yaml:"modes"`      // e.g. ["normal","bridge"]
	DirURL    string   `yaml:"dir_url"`
	DirTLSCA  string   `yaml:"dir_tls_ca"`
	RegSecret string   `yaml:"reg_secret"`
	KeyFile   string   `yaml:"key_file"`
	TLSCert   string   `yaml:"tls_cert"`   // optional: serve broker API over TLS
	TLSKey    string   `yaml:"tls_key"`
	LogLevel  string   `yaml:"log_level"`

	// Kind-mode rendezvous: ICE/STUN servers advertised to clients and
	// volunteer proxies for WebRTC NAT traversal.
	STUNServers []string `yaml:"stun_servers"`
}

func (c *BrokerConfig) ApplyDefaults() {
	if c.Port == 0          { c.Port = 7100 }
	if c.DirURL == ""       { c.DirURL = "https://127.0.0.1:7000" }
	if c.KeyFile == ""      { c.KeyFile = "broker.key" }
	if c.LogLevel == ""     { c.LogLevel = "info" }
	if len(c.Modes) == 0   { c.Modes = []string{"normal"} }
	if len(c.STUNServers) == 0 { c.STUNServers = []string{"stun:stun.l.google.com:19302"} }
}

// BridgeServerConfig is loaded from bridge.yaml.
type BridgeServerConfig struct {
	ForeignDirURL   string `yaml:"foreign_dir_url"`   // directory of the foreign SbNet network
	ForeignDirTLSCA string `yaml:"foreign_dir_tls_ca"` // CA cert for verifying foreign directory TLS
	UpstreamProxy   string `yaml:"upstream_proxy"`    // optional egress: socks5://host:port
	ListenAddr      string `yaml:"listen_addr"`       // local client-facing endpoint, e.g. ":9000"
	Token           string `yaml:"token"`             // pre-shared token clients must present
	Obfs            string `yaml:"obfs"`              // "tls" | "none"
	Mode            string `yaml:"mode"`              // "secure" | "normal"
	TLSCert         string `yaml:"tls_cert"`          // TLS cert for client-facing listener (obfs=tls)
	TLSKey          string `yaml:"tls_key"`           // TLS key for client-facing listener
	KeyFile         string `yaml:"key_file"`          // bridge identity key (X25519)
	LogLevel        string `yaml:"log_level"`
}

func (c *BridgeServerConfig) ApplyDefaults() {
	if c.ListenAddr == "" { c.ListenAddr = ":9000" }
	if c.Obfs == ""       { c.Obfs = "tls" }
	if c.Mode == ""       { c.Mode = "secure" }
	if c.KeyFile == ""    { c.KeyFile = "bridge.key" }
	if c.LogLevel == ""   { c.LogLevel = "info" }
}

// ClientConfig is loaded from client.yaml.
type ClientConfig struct {
	DirURL            string `yaml:"dir_url"`             // directory authority URL
	BridgeURI         string `yaml:"bridge_uri"`          // sbnet:// URI; overrides dir_url
	BrokerID          string `yaml:"broker_id"`           // pin to a specific broker ID
	KindBrokerURL     string `yaml:"kind_broker_url"`     // broker rendezvous URL; enables kind (Snowflake) mode
	SOCKS5Addr        string `yaml:"socks5_addr"`         // SOCKS5 listen address
	HTTPProxyAddr     string `yaml:"http_proxy_addr"`     // HTTP/CONNECT proxy listen address
	CircuitCount      int    `yaml:"circuit_count"`       // parallel circuits
	CircuitRotateSecs int    `yaml:"circuit_rotate_secs"` // rebuild interval
	GuardFile         string `yaml:"guard_file"`          // persistent guard relay state
	DirTLSCA          string `yaml:"dir_tls_ca"`          // CA cert for verifying directory TLS
	LogLevel          string `yaml:"log_level"`
}

func (c *ClientConfig) ApplyDefaults() {
	if c.DirURL == ""              { c.DirURL = "https://127.0.0.1:7000" }
	if c.SOCKS5Addr == ""          { c.SOCKS5Addr = "127.0.0.1:1080" }
	if c.HTTPProxyAddr == ""       { c.HTTPProxyAddr = "127.0.0.1:8080" }
	if c.CircuitCount == 0         { c.CircuitCount = 3 }
	if c.CircuitRotateSecs == 0    { c.CircuitRotateSecs = 600 }
	if c.GuardFile == ""           { c.GuardFile = ".sbnet_guard" }
	if c.LogLevel == ""            { c.LogLevel = "info" }
}

// KindConfig is loaded from kind.yaml — the volunteer ("kind") proxy.
// A kind proxy is an ephemeral, Snowflake-style WebRTC relay: it long-polls a
// broker rendezvous, accepts a client over a WebRTC datachannel, and pipes the
// (already onion-encrypted) cell stream to an entry relay. It learns nothing
// about the client's destination.
type KindConfig struct {
	BrokerURL   string   `yaml:"broker_url"`   // broker rendezvous URL
	DirURL      string   `yaml:"dir_url"`      // directory to pick an entry relay from
	DirTLSCA    string   `yaml:"dir_tls_ca"`   // CA cert for verifying directory TLS
	STUNServers []string `yaml:"stun_servers"` // ICE/STUN servers for NAT traversal
	Capacity    int      `yaml:"capacity"`     // max concurrent client sessions
	LogLevel    string   `yaml:"log_level"`
}

func (c *KindConfig) ApplyDefaults() {
	if c.BrokerURL == ""       { c.BrokerURL = "http://127.0.0.1:7100" }
	if c.DirURL == ""          { c.DirURL = "https://127.0.0.1:7000" }
	if len(c.STUNServers) == 0 { c.STUNServers = []string{"stun:stun.l.google.com:19302"} }
	if c.Capacity == 0         { c.Capacity = 4 }
	if c.LogLevel == ""        { c.LogLevel = "info" }
}
