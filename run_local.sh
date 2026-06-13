#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SbNet Local Test Runner
# Starts a full SbNet network on localhost in one command:
#   directory  :7000
#   relay-entry  :9001
#   relay-middle :9002
#   relay-exit   :9003
#   broker       :7100
#   client       SOCKS5 :1080  HTTP :8080
#
# Usage:  bash run_local.sh [start|stop|status|logs]
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${RESET}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()   { echo -e "${RED}[ERR ]${RESET}  $*" >&2; exit 1; }
sep()   { echo -e "${BLUE}────────────────────────────────────────────────────${RESET}"; }
banner(){ echo -e "\n${BOLD}${BLUE}══ $* ══${RESET}\n"; }

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="${SCRIPT_DIR}/.local_test"
LOG_DIR="${RUN_DIR}/logs"
PID_DIR="${RUN_DIR}/pids"
BIN_DIR="${RUN_DIR}/bin"
REG_SECRET="localtestonly-do-not-use-in-production-abc123"

mkdir -p "$LOG_DIR" "$PID_DIR" "$BIN_DIR"

# ── Go detection ──────────────────────────────────────────────────────────────
find_go() {
    for p in "" "/usr/local/go/bin/" "/usr/bin/" "/usr/local/bin/"; do
        if command -v "${p}go" &>/dev/null; then
            echo "${p}go"; return
        fi
    done
    die "Go not found. Install Go 1.21+: https://go.dev/dl/"
}
GO=$(find_go)

# ── Build all binaries ────────────────────────────────────────────────────────
build_all() {
    banner "Building SbNet binaries"
    cd "$SCRIPT_DIR"

    # The go.sum shipped in the archive was hand-written and has wrong checksums.
    # Delete it and let `go mod tidy` fetch and verify the real ones.
    if [[ -f "go.sum" ]]; then
        info "Regenerating go.sum (removing stale/hand-written checksums)..."
        rm -f go.sum
    fi

    info "Running go mod tidy (downloads dependencies)..."
    "$GO" mod tidy || die "go mod tidy failed — check your internet connection"
    ok "Dependencies ready"

    for comp in directory relay broker bridge client; do
        info "Building $comp..."
        "$GO" build -o "${BIN_DIR}/sbnet-${comp}" "./${comp}" \
            && ok "$comp" \
            || die "Build failed for $comp"
    done
}

# ── Write all configs ─────────────────────────────────────────────────────────
write_configs() {
    banner "Writing local test configs"

    # directory
    cat > "${RUN_DIR}/directory.yaml" << EOF
listen_addr: ":7000"
tls_cert: ""
tls_key: ""
key_file: "${RUN_DIR}/directory.key"
reg_secret: "${REG_SECRET}"
log_level: "debug"
register_rps: 100
consensus_rps: 100
consensus_max_age_secs: 300
EOF

    # relay-entry
    cat > "${RUN_DIR}/relay-entry.yaml" << EOF
id: "relay-entry"
ip: "127.0.0.1"
port: 9001
health_port: 10001
role: "entry"
country: "LO"
region: "localhost"
oper_mode: "normal"
bandwidth: 9999
version: "1.0.0"
dir_url: "http://127.0.0.1:7000"
dir_tls_ca: ""
reg_secret: "${REG_SECRET}"
key_file: "${RUN_DIR}/relay-entry.key"
internal_dns: ""
log_level: "debug"
circuit_idle_secs: 300
EOF

    # relay-middle
    cat > "${RUN_DIR}/relay-middle.yaml" << EOF
id: "relay-middle"
ip: "127.0.0.1"
port: 9002
health_port: 10002
role: "middle"
country: "LO"
region: "localhost"
oper_mode: "normal"
bandwidth: 9999
version: "1.0.0"
dir_url: "http://127.0.0.1:7000"
dir_tls_ca: ""
reg_secret: "${REG_SECRET}"
key_file: "${RUN_DIR}/relay-middle.key"
internal_dns: ""
log_level: "debug"
circuit_idle_secs: 300
EOF

    # relay-exit
    cat > "${RUN_DIR}/relay-exit.yaml" << EOF
id: "relay-exit"
ip: "127.0.0.1"
port: 9003
health_port: 10003
role: "exit"
country: "LO"
region: "localhost"
oper_mode: "normal"
bandwidth: 9999
version: "1.0.0"
dir_url: "http://127.0.0.1:7000"
dir_tls_ca: ""
reg_secret: "${REG_SECRET}"
key_file: "${RUN_DIR}/relay-exit.key"
internal_dns: "127.0.0.1:2080"
log_level: "debug"
circuit_idle_secs: 300
EOF

    # broker
    cat > "${RUN_DIR}/broker.yaml" << EOF
id: "broker-local"
ip: "127.0.0.1"
port: 7100
country: "LO"
region: "localhost"
modes:
  - "normal"
dir_url: "http://127.0.0.1:7000"
dir_tls_ca: ""
reg_secret: "${REG_SECRET}"
key_file: "${RUN_DIR}/broker.key"
tls_cert: ""
tls_key: ""
log_level: "debug"
EOF

    # client
    cat > "${RUN_DIR}/client.yaml" << EOF
dir_url: "http://127.0.0.1:7000"
bridge_uri: ""
broker_id: ""
socks5_addr: "127.0.0.1:1080"
http_proxy_addr: "127.0.0.1:8080"
circuit_count: 1
circuit_rotate_secs: 600
guard_file: "${RUN_DIR}/.sbnet_guard"
dir_tls_ca: ""
log_level: "debug"
EOF

    ok "All configs written to ${RUN_DIR}/"
}

# ── Start a single process ────────────────────────────────────────────────────
start_proc() {
    local name="$1"
    local binary="$2"
    local config="$3"
    local pidfile="${PID_DIR}/${name}.pid"
    local logfile="${LOG_DIR}/${name}.log"

    if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        warn "${name} already running (pid $(cat "$pidfile"))"
        return
    fi

    SBNET_CONFIG="$config" "$binary" > "$logfile" 2>&1 &
    echo $! > "$pidfile"
    ok "${name} started (pid $!, log: $logfile)"
}

# ── Stop a single process ─────────────────────────────────────────────────────
stop_proc() {
    local name="$1"
    local pidfile="${PID_DIR}/${name}.pid"
    if [[ -f "$pidfile" ]]; then
        local pid; pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            ok "${name} stopped (pid $pid)"
        else
            warn "${name} was not running"
        fi
        rm -f "$pidfile"
    else
        warn "${name}: no pidfile found"
    fi
}

# ── Wait for port to be open ──────────────────────────────────────────────────
# Uses pure bash /dev/tcp — no nc/netcat required.
port_open() {
    local port="$1"
    # Try bash built-in TCP redirect; redirect stderr to suppress error messages.
    (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null
}

wait_for_port() {
    local port="$1" name="$2" timeout="${3:-10}"
    local elapsed=0
    while ! port_open "$port"; do
        sleep 0.5
        elapsed=$(( elapsed + 1 ))
        if (( elapsed > timeout * 2 )); then
            warn "Timeout waiting for ${name} on port ${port}"
            return 1
        fi
    done
    ok "${name} is listening on :${port}"
}

# ── Start all ─────────────────────────────────────────────────────────────────
cmd_start() {
    banner "Starting SbNet Local Test Network"

    # Build if needed
    if [[ ! -f "${BIN_DIR}/sbnet-directory" ]]; then
        build_all
    else
        info "Binaries already built. Run '$0 build' to rebuild."
    fi

    write_configs

    sep
    info "Starting components (order matters)..."
    sep

    # 1. Directory
    start_proc "directory" "${BIN_DIR}/sbnet-directory" "${RUN_DIR}/directory.yaml"
    wait_for_port 7000 "directory" 10

    # 2. Relays — small delay between each so directory is ready
    sleep 0.5
    start_proc "relay-entry"  "${BIN_DIR}/sbnet-relay" "${RUN_DIR}/relay-entry.yaml"
    wait_for_port 9001 "relay-entry" 8

    start_proc "relay-middle" "${BIN_DIR}/sbnet-relay" "${RUN_DIR}/relay-middle.yaml"
    wait_for_port 9002 "relay-middle" 8

    start_proc "relay-exit"   "${BIN_DIR}/sbnet-relay" "${RUN_DIR}/relay-exit.yaml"
    wait_for_port 9003 "relay-exit" 8

    # 3. Broker (optional but nice)
    start_proc "broker" "${BIN_DIR}/sbnet-broker" "${RUN_DIR}/broker.yaml"
    wait_for_port 7100 "broker" 8

    # 4. Wait a moment for relays to register with directory
    info "Waiting for relays to register with directory..."
    sleep 3

    # Verify consensus has all 3 relays
    local relay_count=0
    if command -v curl &>/dev/null; then
        local consensus_json
        consensus_json=$(curl -fsSL http://127.0.0.1:7000/consensus 2>/dev/null || echo "")
        if command -v python3 &>/dev/null && [[ -n "$consensus_json" ]]; then
            relay_count=$(echo "$consensus_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('relays',[])))" 2>/dev/null || echo 0)
        elif command -v jq &>/dev/null && [[ -n "$consensus_json" ]]; then
            relay_count=$(echo "$consensus_json" | jq '.relays | length' 2>/dev/null || echo 0)
        elif [[ -n "$consensus_json" ]]; then
            relay_count=$(echo "$consensus_json" | grep -o '"role"' | wc -l | tr -d ' ')
        fi
    fi
    if (( relay_count >= 3 )); then
        ok "Directory consensus has ${relay_count} relays"
    else
        warn "Only ${relay_count} relay(s) in consensus — relays may still be registering"
        warn "Wait a few seconds and check: curl http://127.0.0.1:7000/health"
    fi

    # 5. Client
    start_proc "client" "${BIN_DIR}/sbnet-client" "${RUN_DIR}/client.yaml"
    wait_for_port 1080 "client SOCKS5" 20
    wait_for_port 8080 "client HTTP"   10

    sep
    echo ""
    echo -e "${BOLD}${GREEN}Local SbNet network is running!${RESET}"
    sep
    echo ""
    echo -e "  ${BOLD}Directory:${RESET}    http://127.0.0.1:7000/health"
    echo -e "  ${BOLD}Relay entry:${RESET}  http://127.0.0.1:10001/health"
    echo -e "  ${BOLD}Relay middle:${RESET} http://127.0.0.1:10002/health"
    echo -e "  ${BOLD}Relay exit:${RESET}   http://127.0.0.1:10003/health"
    echo -e "  ${BOLD}Broker:${RESET}       http://127.0.0.1:7100/health"
    echo ""
    sep
    echo -e "  ${BOLD}${CYAN}Test it:${RESET}"
    echo ""
    echo -e "  # Check a request goes through the circuit:"
    echo -e "  ${CYAN}curl -x socks5h://127.0.0.1:1080 http://example.com${RESET}"
    echo ""
    echo -e "  # Or use the HTTP proxy:"
    echo -e "  ${CYAN}curl -x http://127.0.0.1:8080 http://example.com${RESET}"
    echo ""
    echo -e "  # Browser — set SOCKS5 proxy to 127.0.0.1:1080"
    echo ""
    sep
    echo -e "  ${BOLD}Logs:${RESET}  ${LOG_DIR}/"
    echo -e "  ${BOLD}Stop:${RESET}  $0 stop"
    echo -e "  ${BOLD}Status:${RESET} $0 status"
    sep
}

# ── Stop all ──────────────────────────────────────────────────────────────────
cmd_stop() {
    banner "Stopping SbNet Local Test Network"
    for name in client broker relay-exit relay-middle relay-entry directory; do
        stop_proc "$name"
    done
    ok "All components stopped."
}

# ── Status ────────────────────────────────────────────────────────────────────
cmd_status() {
    banner "SbNet Local Test Network Status"
    sep
    printf "  %-16s %-8s %-6s %s\n" "Component" "PID" "Port" "Status"
    sep
    declare -A PORTS=(
        [directory]=7000 [relay-entry]=9001 [relay-middle]=9002
        [relay-exit]=9003 [broker]=7100 [client]=1080
    )
    for name in directory relay-entry relay-middle relay-exit broker client; do
        local pidfile="${PID_DIR}/${name}.pid"
        local pid="-" status port="${PORTS[$name]}"
        local colour="$RED"
        if [[ -f "$pidfile" ]]; then
            pid=$(cat "$pidfile")
            if kill -0 "$pid" 2>/dev/null; then
                status="running"
                colour="$GREEN"
            else
                status="dead"
                pid="${pid}(dead)"
            fi
        else
            status="stopped"
        fi
        printf "  %-16s ${colour}%-8s${RESET} %-6s %s\n" \
            "$name" "$status" ":${port}" "$pid"
    done
    sep

    # Quick health checks
    echo ""
    echo -e "${BOLD}Health checks:${RESET}"
    if command -v curl &>/dev/null; then
        for port_name in "7000:directory" "10001:relay-entry" "10002:relay-middle" "10003:relay-exit" "7100:broker"; do
            local port="${port_name%%:*}" name="${port_name##*:}"
            local result
            result=$(curl -fsSL --max-time 2 "http://127.0.0.1:${port}/health" 2>/dev/null || echo "unreachable")
            printf "  %-16s %s\n" "$name" "$result"
        done
    else
        warn "curl not found — skipping health checks"
    fi
    sep
}

# ── Logs ──────────────────────────────────────────────────────────────────────
cmd_logs() {
    local target="${2:-all}"
    if [[ "$target" == "all" ]]; then
        # Tail all logs together with component prefix
        if command -v multitail &>/dev/null; then
            multitail "${LOG_DIR}"/*.log
        else
            info "Tailing all logs (Ctrl+C to stop)..."
            tail -f "${LOG_DIR}"/*.log
        fi
    else
        local logfile="${LOG_DIR}/${target}.log"
        [[ -f "$logfile" ]] || die "No log for: $target"
        tail -f "$logfile"
    fi
}

# ── Build only ────────────────────────────────────────────────────────────────
cmd_build() {
    build_all
}

# ── Clean ─────────────────────────────────────────────────────────────────────
cmd_clean() {
    cmd_stop 2>/dev/null || true
    echo ""
    warn "This will delete all local test data: ${RUN_DIR}"
    echo -ne "Continue? [y/N]: "
    read -r ans
    [[ "${ans,,}" == "y" ]] || { info "Cancelled"; exit 0; }
    rm -rf "$RUN_DIR"
    ok "Cleaned."
}

# ── Test circuit ──────────────────────────────────────────────────────────────
cmd_test() {
    banner "Testing SbNet Circuit"
    sep

    # 1. Directory health
    echo -ne "  Directory health...  "
    if curl -fsSL --max-time 3 http://127.0.0.1:7000/health &>/dev/null; then
        echo -e "${GREEN}OK${RESET}"
    else
        echo -e "${RED}FAIL${RESET}"; die "Directory not reachable"
    fi

    # 2. Relay count
    echo -ne "  Relay consensus...   "
    local relay_count=0
    local cjson
    cjson=$(curl -fsSL --max-time 3 http://127.0.0.1:7000/consensus 2>/dev/null || echo "")
    if command -v python3 &>/dev/null && [[ -n "$cjson" ]]; then
        relay_count=$(echo "$cjson" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('relays',[])))" 2>/dev/null || echo 0)
    elif command -v jq &>/dev/null && [[ -n "$cjson" ]]; then
        relay_count=$(echo "$cjson" | jq '.relays | length' 2>/dev/null || echo 0)
    else
        relay_count=$(echo "$cjson" | grep -o '"role"' | wc -l | tr -d ' ')
    fi
    if (( relay_count >= 3 )); then
        echo -e "${GREEN}${relay_count} relays${RESET}"
    else
        echo -e "${YELLOW}${relay_count} relays (need 3)${RESET}"
    fi

    # 3. SOCKS5 reachable
    echo -ne "  SOCKS5 proxy...      "
    if port_open 1080; then
        echo -e "${GREEN}listening${RESET}"
    else
        echo -e "${RED}not listening${RESET}"
    fi

    # 4. HTTP proxy reachable
    echo -ne "  HTTP proxy...        "
    if port_open 8080; then
        echo -e "${GREEN}listening${RESET}"
    else
        echo -e "${RED}not listening${RESET}"
    fi

    # 5. Actual circuit request
    echo ""
    echo -e "  ${BOLD}Sending test request through circuit...${RESET}"
    if command -v curl &>/dev/null; then
        local response
        response=$(curl -fsSL \
            --max-time 15 \
            --proxy socks5h://127.0.0.1:1080 \
            http://httpbin.org/ip 2>&1 || echo "FAILED")
        if echo "$response" | grep -q "origin"; then
            echo -e "  ${GREEN}Circuit works!${RESET} Response:"
            echo "$response" | sed 's/^/    /'
        else
            echo -e "  ${YELLOW}Result: ${response}${RESET}"
            warn "Circuit may not be connected to the public internet from exit relay yet"
            warn "(exit relay needs internal DNS for .sbnet; for plain internet, exit proxies directly)"
        fi
    else
        warn "curl not found — test manually: curl -x socks5h://127.0.0.1:1080 http://example.com"
    fi
    sep
}

# ── Restart one component ─────────────────────────────────────────────────────
cmd_restart() {
    local name="${2:-}"
    [[ -z "$name" ]] && die "Usage: $0 restart <component>"
    declare -A CONFIGS=(
        [directory]="${RUN_DIR}/directory.yaml"
        [relay-entry]="${RUN_DIR}/relay-entry.yaml"
        [relay-middle]="${RUN_DIR}/relay-middle.yaml"
        [relay-exit]="${RUN_DIR}/relay-exit.yaml"
        [broker]="${RUN_DIR}/broker.yaml"
        [client]="${RUN_DIR}/client.yaml"
    )
    declare -A BINARIES=(
        [directory]="${BIN_DIR}/sbnet-directory"
        [relay-entry]="${BIN_DIR}/sbnet-relay"
        [relay-middle]="${BIN_DIR}/sbnet-relay"
        [relay-exit]="${BIN_DIR}/sbnet-relay"
        [broker]="${BIN_DIR}/sbnet-broker"
        [client]="${BIN_DIR}/sbnet-client"
    )
    [[ -v "CONFIGS[$name]" ]] || die "Unknown component: $name"
    stop_proc "$name"
    sleep 0.5
    start_proc "$name" "${BINARIES[$name]}" "${CONFIGS[$name]}"
    ok "Restarted $name"
}

# ── Help ──────────────────────────────────────────────────────────────────────
cmd_help() {
    echo ""
    echo -e "${BOLD}SbNet Local Test Runner${RESET}"
    echo ""
    echo -e "  ${CYAN}bash run_local.sh start${RESET}              Build and start full local network"
    echo -e "  ${CYAN}bash run_local.sh stop${RESET}               Stop all components"
    echo -e "  ${CYAN}bash run_local.sh status${RESET}             Show running status + health"
    echo -e "  ${CYAN}bash run_local.sh test${RESET}               Run circuit connectivity test"
    echo -e "  ${CYAN}bash run_local.sh build${RESET}              Build all binaries only"
    echo -e "  ${CYAN}bash run_local.sh logs [component]${RESET}   Tail logs (default: all)"
    echo -e "  ${CYAN}bash run_local.sh restart <component>${RESET} Restart one component"
    echo -e "  ${CYAN}bash run_local.sh clean${RESET}              Stop + delete all local test data"
    echo ""
    echo -e "  Components: directory relay-entry relay-middle relay-exit broker client"
    echo ""
    echo -e "  ${BOLD}Quick test:${RESET}"
    echo -e "  ${CYAN}curl -x socks5h://127.0.0.1:1080 http://example.com${RESET}"
    echo -e "  ${CYAN}curl -x http://127.0.0.1:8080   http://example.com${RESET}"
    echo ""
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
CMD="${1:-help}"
case "$CMD" in
    start)   cmd_start   ;;
    stop)    cmd_stop    ;;
    status)  cmd_status  ;;
    test)    cmd_test    ;;
    build)   cmd_build   ;;
    logs)    cmd_logs "$@" ;;
    restart) cmd_restart "$@" ;;
    clean)   cmd_clean   ;;
    help|--help|-h) cmd_help ;;
    *) die "Unknown command: $CMD  (run '$0 help' for usage)" ;;
esac
