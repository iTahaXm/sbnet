# SbNet — Onion Routing Network

SbNet is a self-hosted, Tor-inspired onion routing network written in Go.
It provides layered encryption across a 3-hop relay circuit, a broker
matchmaking layer, bridge gateways for cross-network access, and both
SOCKS5 and HTTP/CONNECT proxy interfaces for clients.

---

## Architecture

```
Client
  │  SOCKS5 :1080 / HTTP :8080
  │
  ├─► [optional] Bridge  ──► foreign SbNet network
  │
  └─► Entry relay  ──► Middle relay  ──► Exit relay  ──► .sbnet origin
           ▲                                    │
           └──── Directory Authority ───────────┘
                 (consensus + registration)

  Broker (optional) — matchmaking between clients and relays
```

### Components

| Binary | Config | Purpose |
|---|---|---|
| `directory` | `directory.yaml` | Trust anchor. Signs relay/broker consensus. Validates registrations via HMAC. |
| `relay` | `relay.yaml` | Onion relay node. Three roles: `entry`, `middle`, `exit`. |
| `broker` | `broker.yaml` | Matchmaking server. Assigns relays to clients by region/country/mode. |
| `bridge` | `bridge.yaml` | Cross-network gateway. Connects a client to a foreign SbNet via `sbnet://` URI. |
| `client` | `client.yaml` | End-user node. Builds 3-hop circuits. Exposes SOCKS5 + HTTP proxy. |

---

## Quick Start

### 1 — Generate a registration secret

All relays, brokers, and the directory must share the same `reg_secret`.

```bash
openssl rand -hex 32
# e.g.: a3f8c2d1...
export SBNET_REG_SECRET="a3f8c2d1..."
```

### 2 — Start the directory

```bash
cd directory
cp ../config/directory.yaml .
# Edit directory.yaml: set reg_secret (or use SBNET_REG_SECRET env)
go run . 
# Listens on :7000
```

Generate TLS for production:
```bash
openssl req -x509 -newkey ed25519 -keyout dir.key -out dir.crt -days 365 -nodes \
  -subj "/CN=dir.example.com"
# Then set tls_cert/tls_key in directory.yaml
```

### 3 — Start relays (one per machine, one role each)

```bash
# Entry relay
cd relay
cp ../config/relay.yaml .
# Edit: id, ip, port, role=entry, dir_url, reg_secret
go run .

# Middle relay (same binary, different config)
# Edit: role=middle

# Exit relay
# Edit: role=exit, internal_dns=127.0.0.1:2080
```

### 4 — Start a broker (optional)

```bash
cd broker
cp ../config/broker.yaml .
# Edit: id, ip, port, dir_url, reg_secret
go run .
```

### 5 — Run the client

```bash
cd client
cp ../config/client.yaml .
# Edit: dir_url
go run .

# SOCKS5 on 127.0.0.1:1080
# HTTP proxy on 127.0.0.1:8080
```

Configure Firefox: Preferences → Network → Manual proxy → SOCKS5 `127.0.0.1:1080`.

### 6 — Bridge mode

On the bridge machine:
```bash
cd bridge
cp ../config/bridge.yaml .
# Edit: foreign_dir_url, token, tls_cert, tls_key
go run .
```

On the client machine, in `client.yaml`:
```yaml
bridge_uri: "sbnet://bridge=<bridge-ip>:9000&token=<token>&obfs=tls&mode=secure"
```

---

## Features

| Feature | Status | Notes |
|---|---|---|
| 3-hop onion routing | ✅ | X25519 ECDH + AES-256-GCM per hop |
| Fixed-size cells | ✅ | 512 bytes, zero-padded |
| Persistent directory key | ✅ | ed25519, saved to `directory.key` |
| Persistent relay key | ✅ | X25519, saved to `relay.key` |
| Relay authentication | ✅ | HMAC-SHA256 with timestamp replay protection |
| TLS directory communication | ✅ | `tls_cert`/`tls_key` in directory.yaml |
| Consensus signature verification | ✅ | ed25519 over canonical JSON |
| Consensus expiration | ✅ | Relays dropped after `consensus_max_age_secs` |
| Rate limiting `/register` | ✅ | Per-IP token bucket |
| Rate limiting `/consensus` | ✅ | Per-IP token bucket |
| Relay country + region metadata | ✅ | In `RelayDescriptor` |
| Relay operating mode | ✅ | `normal` / `bridge` / `restricted` |
| Guard relay pinning | ✅ | Saved to `.sbnet_guard` |
| Multi-circuit support | ✅ | `circuit_count` parallel circuits, round-robin |
| Circuit rotation | ✅ | Every `circuit_rotate_secs` seconds |
| Circuit failure recovery | ✅ | Auto-rebuild + one retry on send failure |
| Circuit timeout | ✅ | Idle circuits destroyed after `circuit_idle_secs` |
| Replay protection | ✅ | (circID, nonce) pair tracking with 10-min window |
| Fragmentation | ✅ | Payloads > CellBodyMax split across fragment cells |
| Relay health check | ✅ | HTTP `/health` + `/ping` on `health_port` |
| Logging levels | ✅ | error / warn / info / debug |
| Config files (YAML) | ✅ | One per component; env var override |
| Graceful shutdown | ✅ | SIGINT/SIGTERM, 10s drain |
| SOCKS5 proxy | ✅ | RFC 1928; IPv4/IPv6/domain; no-auth |
| HTTP proxy | ✅ | Plain HTTP forwarding |
| HTTPS CONNECT | ✅ | Hijack + stream through circuit |
| Broker system | ✅ | Matchmaking, token issuance, directory registration |
| Broker relay scoring | ✅ | Country/region/bandwidth weighted |
| Multi-broker support | ✅ | All brokers register in same directory |
| Bridge gateway | ✅ | `sbnet://` URI, TLS obfuscation, upstream SOCKS5 |
| Bridge foreign consensus refresh | ✅ | Background refresh every 5 min |
| Hidden services (.sbnet) | ⚠️ | Types defined; routing stub present |

---

## Cell Protocol

```
 0       4    5    7                    512
 ┌───────┬────┬────┬────────────────────┐
 │CircID │Cmd │Len │ Body (zero-padded) │
 │ 4 B   │ 1B │ 2B │      505 B        │
 └───────┴────┴────┴────────────────────┘
```

Commands: `Create(1)` `Created(2)` `Extend(3)` `Extended(4)` `Relay(5)`
`Destroy(6)` `Ping(7)` `Pong(8)` `Fragment(9)` `FragFinal(10)` `Hidden(11)`

---

## Key Exchange

```
Client                    Entry                  Middle                 Exit
  │                         │                       │                     │
  │── Create(myPub0) ──────►│                       │                     │
  │◄─ Created(entryPub0) ───│                       │                     │
  │   [Keys[0] = DH(myPriv0, entryPub0)]            │                     │
  │                         │                       │                     │
  │── Extend(E0(addr1,myPub1)) ────────────────────►│                     │
  │         │           Entry peels E0, forwards Create(myPub1) to Middle │
  │◄─ Extended(middlePub1) ─────────────────────────│                     │
  │   [Keys[1] = DH(myPriv1, middlePub1)]           │                     │
  │                         │                       │                     │
  │── Extend(E0(E1(addr2,myPub2))) ─────────────────────────────────────►│
  │         │         Entry peels E0, Middle peels E1, forwards Create   │
  │◄─ Extended(exitPub2) ───────────────────────────────────────────────│
  │   [Keys[2] = DH(myPriv2, exitPub2)]             │                     │
```

Intermediate relays forward the client's pubkey without learning the
resulting session key. Each relay only knows its own layer.

---

## Security Notes

- The directory signing key (`directory.key`) is the single root of trust. Back it up. Rotate it by regenerating and redeploying the `dir_tls_ca` to all clients.
- The `reg_secret` is a shared HMAC secret. Rotate it by updating all relay/broker configs simultaneously.
- Bridge tokens should be rotated regularly (`openssl rand -hex 32`).
- Exit relay `internal_dns` resolver should not be accessible from outside the machine.
- For production, always configure TLS on the directory and broker.
- The SOCKS5 proxy binds to `127.0.0.1` by default — do not expose it on a public interface.

---

## File Structure

```
sbnet/
├── go.mod
├── go.sum
├── README.md
├── common/
│   ├── cell.go      — cell wire format, fragmentation, AES-256-GCM, X25519
│   ├── config.go    — YAML config structs + ApplyDefaults() for all components
│   ├── keys.go      — persistent ed25519 (directory/broker) and X25519 (relay) key I/O
│   ├── logger.go    — levelled logger (error/warn/info/debug)
│   ├── replay.go    — replay filter + circuit idle timeout tracker
│   └── types.go     — shared types: RelayDescriptor, BrokerDescriptor, SignedConsensus, …
├── directory/
│   └── main.go      — directory authority
├── relay/
│   └── main.go      — relay node (entry / middle / exit)
├── broker/
│   └── main.go      — broker matchmaking server
├── bridge/
│   └── main.go      — bridge cross-network gateway
├── client/
│   └── main.go      — client (SOCKS5 + HTTP/CONNECT proxy)
└── config/
    ├── directory.yaml
    ├── relay.yaml
    ├── broker.yaml
    ├── bridge.yaml
    └── client.yaml
```

---

## Building

```bash
# Build all binaries
go build -o bin/directory ./directory
go build -o bin/relay     ./relay
go build -o bin/broker    ./broker
go build -o bin/bridge    ./bridge
go build -o bin/client    ./client

# Or run directly
go run ./directory
go run ./relay
go run ./broker
go run ./bridge
go run ./client
```

Requires Go 1.21+.
