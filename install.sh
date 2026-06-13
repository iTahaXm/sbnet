#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SbNet Installer
# Supports: directory | relay | broker | bridge | client
# Tested on: Ubuntu 20.04+ / Debian 11+ / CentOS 8+ / Fedora 36+ / macOS 12+
# Run as root for server components; any user for client.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';  BOLD='\033[1m'; RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }
banner()  { echo -e "\n${BOLD}${BLUE}══ $* ══${RESET}\n"; }
sep()     { echo -e "${BLUE}────────────────────────────────────────────────${RESET}"; }

# Ask question with default value. Sets variable $REPLY_VAL.
ask() {
    local prompt="$1" default="${2:-}" secret="${3:-no}"
    local display_default=""
    [[ -n "$default" ]] && display_default=" [${YELLOW}${default}${RESET}]"
    echo -ne "${BOLD}${prompt}${RESET}${display_default}: "
    if [[ "$secret" == "yes" ]]; then
        read -rs REPLY_VAL; echo
    else
        read -r REPLY_VAL
    fi
    [[ -z "$REPLY_VAL" ]] && REPLY_VAL="$default"
}

# Ask a yes/no question. Returns 0 for yes, 1 for no.
ask_yn() {
    local prompt="$1" default="${2:-y}"
    local hint
    [[ "$default" == "y" ]] && hint="Y/n" || hint="y/N"
    echo -ne "${BOLD}${prompt}${RESET} [${hint}]: "
    read -r REPLY_VAL
    [[ -z "$REPLY_VAL" ]] && REPLY_VAL="$default"
    [[ "${REPLY_VAL,,}" == "y" || "${REPLY_VAL,,}" == "yes" ]]
}

# Ask to choose from numbered list. Sets $REPLY_VAL to chosen item.
choose() {
    local prompt="$1"; shift
    local options=("$@")
    echo -e "${BOLD}${prompt}${RESET}"
    for i in "${!options[@]}"; do
        echo -e "  ${CYAN}$((i+1))${RESET}) ${options[$i]}"
    done
    while true; do
        echo -ne "Enter number: "
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
            REPLY_VAL="${options[$((choice-1))]}"
            return
        fi
        warn "Please enter a number between 1 and ${#options[@]}"
    done
}

# ── System detection ──────────────────────────────────────────────────────────
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
IS_ROOT=false; [[ "$EUID" -eq 0 ]] && IS_ROOT=true

INSTALL_DIR="/opt/sbnet"
CONFIG_DIR="/etc/sbnet"
LOG_DIR="/var/log/sbnet"
DATA_DIR="/var/lib/sbnet"
BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
SBNET_USER="sbnet"

# For non-root (client mode), use home directory
if ! $IS_ROOT; then
    INSTALL_DIR="$HOME/.sbnet"
    CONFIG_DIR="$HOME/.config/sbnet"
    LOG_DIR="$HOME/.local/share/sbnet/logs"
    DATA_DIR="$HOME/.local/share/sbnet"
    BIN_DIR="$HOME/.local/bin"
fi

detect_pkg_manager() {
    if command -v apt-get &>/dev/null;  then echo "apt"
    elif command -v dnf &>/dev/null;    then echo "dnf"
    elif command -v yum &>/dev/null;    then echo "yum"
    elif command -v pacman &>/dev/null; then echo "pacman"
    elif command -v brew &>/dev/null;   then echo "brew"
    else echo "unknown"
    fi
}

PKG_MGR=$(detect_pkg_manager)

# ── Dependency installation ───────────────────────────────────────────────────
install_go() {
    if command -v go &>/dev/null; then
        local ver
        ver=$(go version | awk '{print $3}' | sed 's/go//')
        local major minor
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if (( major > 1 || (major == 1 && minor >= 21) )); then
            ok "Go $ver already installed"
            return
        fi
        warn "Go $ver found but 1.21+ required — upgrading"
    fi

    info "Installing Go 1.21..."
    local go_ver="1.21.6"
    local go_arch
    case "$ARCH" in
        x86_64)  go_arch="amd64" ;;
        aarch64) go_arch="arm64" ;;
        armv7l)  go_arch="armv6l" ;;
        *)        die "Unsupported architecture: $ARCH" ;;
    esac

    local go_os="$OS"
    local tarball="go${go_ver}.${go_os}-${go_arch}.tar.gz"
    local url="https://go.dev/dl/${tarball}"

    local tmp; tmp=$(mktemp -d)
    info "Downloading ${url}"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$tmp/$tarball"
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O "$tmp/$tarball"
    else
        die "Neither curl nor wget found — cannot download Go"
    fi

    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$tmp/$tarball"
    rm -rf "$tmp"

    # Add to PATH for this session
    export PATH="/usr/local/go/bin:$PATH"

    # Add to /etc/profile.d for future sessions
    if $IS_ROOT; then
        echo 'export PATH="/usr/local/go/bin:$PATH"' > /etc/profile.d/go.sh
    else
        grep -qxF 'export PATH="/usr/local/go/bin:$PATH"' "$HOME/.bashrc" \
            || echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$HOME/.bashrc"
        grep -qxF 'export PATH="/usr/local/go/bin:$PATH"' "$HOME/.profile" \
            || echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$HOME/.profile"
    fi
    ok "Go $(go version) installed"
}

install_deps() {
    banner "Installing System Dependencies"
    case "$PKG_MGR" in
        apt)
            apt-get update -qq
            apt-get install -y -qq curl wget git openssl ca-certificates 2>/dev/null
            ;;
        dnf|yum)
            "$PKG_MGR" install -y -q curl wget git openssl ca-certificates 2>/dev/null
            ;;
        pacman)
            pacman -Sy --noconfirm --quiet curl wget git openssl 2>/dev/null
            ;;
        brew)
            brew install curl wget git openssl 2>/dev/null || true
            ;;
        *)
            warn "Unknown package manager — skipping system deps (ensure curl, git, openssl are available)"
            ;;
    esac
    install_go
}

# ── TLS certificate generation ────────────────────────────────────────────────
gen_tls_cert() {
    local dir="$1" cn="$2" keyfile="$3" certfile="$4"
    info "Generating self-signed TLS certificate for ${cn}..."
    openssl req -x509 -newkey ed25519 \
        -keyout "${dir}/${keyfile}" \
        -out    "${dir}/${certfile}" \
        -days 3650 -nodes \
        -subj "/CN=${cn}" 2>/dev/null
    chmod 600 "${dir}/${keyfile}"
    ok "TLS cert: ${dir}/${certfile}"
    ok "TLS key:  ${dir}/${keyfile}"
}

# ── systemd service writer ────────────────────────────────────────────────────
write_systemd_service() {
    local component="$1" config_path="$2" description="$3"
    local service_file="${SYSTEMD_DIR}/sbnet-${component}.service"

    cat > "$service_file" << EOF
[Unit]
Description=SbNet ${description}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=${SBNET_USER}
Group=${SBNET_USER}
WorkingDirectory=${DATA_DIR}/${component}
Environment=SBNET_CONFIG=${config_path}
ExecStart=${BIN_DIR}/sbnet-${component}
Restart=on-failure
RestartSec=5s
StandardOutput=append:${LOG_DIR}/${component}.log
StandardError=append:${LOG_DIR}/${component}.log

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}/${component} ${LOG_DIR}
PrivateTmp=true
PrivateDevices=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    ok "Systemd service: $service_file"
}

# ── macOS launchd plist writer ────────────────────────────────────────────────
write_launchd_plist() {
    local component="$1" config_path="$2"
    local plist_dir="$HOME/Library/LaunchAgents"
    local plist="${plist_dir}/com.sbnet.${component}.plist"
    mkdir -p "$plist_dir"
    cat > "$plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>             <string>com.sbnet.${component}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_DIR}/sbnet-${component}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SBNET_CONFIG</key>  <string>${config_path}</string>
    </dict>
    <key>WorkingDirectory</key>  <string>${DATA_DIR}/${component}</string>
    <key>StandardOutPath</key>   <string>${LOG_DIR}/${component}.log</string>
    <key>StandardErrorPath</key> <string>${LOG_DIR}/${component}.log</string>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
</dict>
</plist>
EOF
    ok "launchd plist: $plist"
}

# ── systemd or launchd enable/start ──────────────────────────────────────────
enable_and_start() {
    local component="$1"
    if [[ "$OS" == "linux" ]] && command -v systemctl &>/dev/null && $IS_ROOT; then
        systemctl daemon-reload
        systemctl enable "sbnet-${component}"
        systemctl restart "sbnet-${component}"
        ok "Service started: sbnet-${component}"
        systemctl --no-pager status "sbnet-${component}" | head -8 || true
    elif [[ "$OS" == "darwin" ]]; then
        local plist="$HOME/Library/LaunchAgents/com.sbnet.${component}.plist"
        launchctl unload "$plist" 2>/dev/null || true
        launchctl load "$plist"
        ok "launchd agent loaded: com.sbnet.${component}"
    else
        warn "Systemd not available — start manually:"
        warn "  SBNET_CONFIG=${CONFIG_DIR}/${component}/${component}.yaml ${BIN_DIR}/sbnet-${component}"
    fi
}

# ── Source code fetch and build ───────────────────────────────────────────────
fetch_source() {
    local src_dir="$1"
    if [[ -d "$src_dir/.git" ]]; then
        info "Updating source at $src_dir..."
        git -C "$src_dir" pull --ff-only
    elif [[ -d "$src_dir/go.mod" ]] || [[ -f "$src_dir/go.mod" ]]; then
        info "Source already present at $src_dir — skipping fetch"
    else
        # Try git first, fall back to expecting local source
        if command -v git &>/dev/null; then
            info "Cloning SbNet source..."
            # Adjust this URL to wherever the repo is hosted
            local repo_url="${SBNET_REPO_URL:-}"
            if [[ -n "$repo_url" ]]; then
                git clone "$repo_url" "$src_dir"
            else
                # Copy from the directory where this script lives
                local script_dir
                script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
                if [[ -f "$script_dir/go.mod" ]]; then
                    info "Using source from $script_dir"
                    cp -r "$script_dir/." "$src_dir/"
                else
                    die "Cannot find SbNet source. Set SBNET_REPO_URL or run install.sh from the source directory."
                fi
            fi
        else
            local script_dir
            script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
            [[ -f "$script_dir/go.mod" ]] || die "Cannot find SbNet source."
            cp -r "$script_dir/." "$src_dir/"
        fi
    fi
}

build_binary() {
    local component="$1" src_dir="$2"
    info "Building sbnet-${component}..."
    (
        cd "$src_dir"
        # Remove any hand-written go.sum and regenerate with correct checksums.
        [[ -f go.sum ]] && rm -f go.sum
        go mod tidy || { echo "go mod tidy failed"; exit 1; }
        go build -ldflags="-s -w -X main.Version=1.0.0" \
            -o "${BIN_DIR}/sbnet-${component}" \
            "./${component}"
    )
    ok "Binary: ${BIN_DIR}/sbnet-${component}"
}

# ── Directory setup ───────────────────────────────────────────────────────────
setup_dirs() {
    local component="$1"
    mkdir -p "${INSTALL_DIR}" \
             "${CONFIG_DIR}/${component}" \
             "${LOG_DIR}" \
             "${DATA_DIR}/${component}" \
             "${BIN_DIR}"
    if $IS_ROOT; then
        # Create system user if needed
        if ! id "$SBNET_USER" &>/dev/null; then
            useradd -r -s /sbin/nologin -d "${DATA_DIR}" -c "SbNet service" "$SBNET_USER" 2>/dev/null \
                || adduser --system --no-create-home --shell /sbin/nologin "$SBNET_USER" 2>/dev/null \
                || true
            ok "System user '${SBNET_USER}' created"
        fi
        chown -R "${SBNET_USER}:${SBNET_USER}" "${DATA_DIR}" "${LOG_DIR}" "${CONFIG_DIR}"
        chmod 750 "${CONFIG_DIR}/${component}"
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# COMPONENT INSTALLERS
# ═════════════════════════════════════════════════════════════════════════════

install_directory() {
    banner "Installing SbNet Directory Authority"
    local comp="directory"

    setup_dirs "$comp"
    local cfg="${CONFIG_DIR}/${comp}/${comp}.yaml"

    sep
    echo -e "${BOLD}Directory Authority Configuration${RESET}"
    echo "The directory is the trust anchor. It signs the consensus"
    echo "and validates relay/broker registrations."
    sep

    ask "Listen address"             ":7000"
    local listen_addr="$REPLY_VAL"

    ask "Log level (error/warn/info/debug)" "info"
    local log_level="$REPLY_VAL"

    ask "Rate limit: /register requests per IP/sec" "5"
    local reg_rps="$REPLY_VAL"

    ask "Rate limit: /consensus requests per IP/sec" "20"
    local con_rps="$REPLY_VAL"

    ask "Relay max silence before removal (seconds)" "300"
    local max_age="$REPLY_VAL"

    # Registration secret
    local reg_secret
    sep
    info "The registration secret is shared with ALL relays and brokers."
    info "Keep it secret. Use the same value on every node."
    if ask_yn "Generate a random registration secret?" "y"; then
        reg_secret=$(openssl rand -hex 32)
        echo -e "  ${GREEN}Generated secret:${RESET} ${BOLD}${reg_secret}${RESET}"
        warn "COPY THIS NOW — write it down before continuing."
        echo -ne "Press ENTER when you have saved it..."
        read -r
    else
        ask "Enter registration secret (min 32 chars)" ""
        reg_secret="$REPLY_VAL"
        [[ ${#reg_secret} -lt 16 ]] && die "Secret too short (min 16 chars)"
    fi

    # TLS
    local tls_cert="" tls_key=""
    sep
    if ask_yn "Enable TLS on the directory? (recommended for production)" "y"; then
        local cn
        ask "Common Name for TLS certificate (e.g. dir.example.com)" "sbnet-directory"
        cn="$REPLY_VAL"
        gen_tls_cert "${DATA_DIR}/${comp}" "$cn" "dir.key" "dir.crt"
        tls_cert="${DATA_DIR}/${comp}/dir.crt"
        tls_key="${DATA_DIR}/${comp}/dir.key"
    else
        warn "TLS disabled — not recommended for production"
    fi

    # Write config
    cat > "$cfg" << EOF
# SbNet Directory Authority — generated by install.sh
listen_addr: "${listen_addr}"
tls_cert: "${tls_cert}"
tls_key: "${tls_key}"
key_file: "${DATA_DIR}/${comp}/directory.key"
reg_secret: "${reg_secret}"
log_level: "${log_level}"
register_rps: ${reg_rps}
consensus_rps: ${con_rps}
consensus_max_age_secs: ${max_age}
EOF
    chmod 600 "$cfg"
    $IS_ROOT && chown "${SBNET_USER}:${SBNET_USER}" "$cfg"
    ok "Config written: $cfg"

    # Build
    local src_dir="${INSTALL_DIR}/src"
    fetch_source "$src_dir"
    build_binary "$comp" "$src_dir"

    # Service
    if $IS_ROOT; then
        write_systemd_service "$comp" "$cfg" "Directory Authority"
    elif [[ "$OS" == "darwin" ]]; then
        write_launchd_plist "$comp" "$cfg"
    fi

    echo ""
    ok "Directory installation complete."
    sep
    echo -e "  ${BOLD}Registration secret:${RESET} ${reg_secret}"
    [[ -n "$tls_cert" ]] && echo -e "  ${BOLD}TLS cert:${RESET} ${tls_cert}"
    echo -e "  ${BOLD}Config:${RESET}  ${cfg}"
    echo -e "  ${BOLD}Binary:${RESET}  ${BIN_DIR}/sbnet-${comp}"
    sep

    if ask_yn "Start the directory authority now?" "y"; then
        enable_and_start "$comp"
    fi
}

install_relay() {
    banner "Installing SbNet Relay"
    local comp="relay"

    setup_dirs "$comp"
    local cfg="${CONFIG_DIR}/${comp}/${comp}.yaml"

    sep
    echo -e "${BOLD}Relay Configuration${RESET}"
    sep

    ask "Relay ID (unique name, e.g. relay-de-001)" "relay-$(hostname -s)"
    local relay_id="$REPLY_VAL"

    # Auto-detect public IP
    local detected_ip=""
    if command -v curl &>/dev/null; then
        detected_ip=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)
    fi
    ask "Public IP address of this relay" "${detected_ip:-}"
    local relay_ip="$REPLY_VAL"
    [[ -z "$relay_ip" ]] && die "Public IP is required"

    ask "TCP port for cell protocol" "9001"
    local relay_port="$REPLY_VAL"

    local health_port=$(( relay_port + 1000 ))
    ask "Health check HTTP port" "$health_port"
    health_port="$REPLY_VAL"

    sep
    choose "Relay role" "entry" "middle" "exit"
    local relay_role="$REPLY_VAL"
    case "$relay_role" in
        entry)  echo -e "  ${CYAN}Entry:${RESET} First hop. Knows client IP, not destination." ;;
        middle) echo -e "  ${CYAN}Middle:${RESET} Middle hop. Knows neither end." ;;
        exit)   echo -e "  ${CYAN}Exit:${RESET} Last hop. Connects to .sbnet origins." ;;
    esac

    sep
    ask "Country code (ISO 3166-1 alpha-2, e.g. DE, US, NL)" "US"
    local country="$REPLY_VAL"
    country="${country^^}"  # uppercase

    ask "Region label (e.g. eu-west, us-east)" ""
    local region="$REPLY_VAL"

    choose "Operating mode" "normal" "bridge" "restricted"
    local oper_mode="$REPLY_VAL"

    ask "Self-reported bandwidth (kbps)" "1000"
    local bandwidth="$REPLY_VAL"

    sep
    ask "Directory URL" "https://127.0.0.1:7000"
    local dir_url="$REPLY_VAL"

    ask "Registration secret (from directory setup)" ""
    [[ -z "$REPLY_VAL" ]] && die "Registration secret is required"
    local reg_secret="$REPLY_VAL"

    ask "Log level (error/warn/info/debug)" "info"
    local log_level="$REPLY_VAL"

    ask "Circuit idle timeout (seconds)" "300"
    local circuit_idle="$REPLY_VAL"

    local internal_dns=""
    if [[ "$relay_role" == "exit" ]]; then
        sep
        info "Exit relay requires an internal DNS resolver for .sbnet hostnames."
        ask "Internal DNS address" "127.0.0.1:2080"
        internal_dns="$REPLY_VAL"
    fi

    # Write config
    cat > "$cfg" << EOF
# SbNet Relay — generated by install.sh
id: "${relay_id}"
ip: "${relay_ip}"
port: ${relay_port}
health_port: ${health_port}
role: "${relay_role}"
country: "${country}"
region: "${region}"
oper_mode: "${oper_mode}"
bandwidth: ${bandwidth}
version: "1.0.0"
dir_url: "${dir_url}"
dir_tls_ca: ""
reg_secret: "${reg_secret}"
key_file: "${DATA_DIR}/${comp}/relay.key"
internal_dns: "${internal_dns}"
log_level: "${log_level}"
circuit_idle_secs: ${circuit_idle}
EOF
    chmod 600 "$cfg"
    $IS_ROOT && chown "${SBNET_USER}:${SBNET_USER}" "$cfg"
    ok "Config written: $cfg"

    local src_dir="${INSTALL_DIR}/src"
    fetch_source "$src_dir"
    build_binary "$comp" "$src_dir"

    # Open firewall ports if possible
    sep
    info "Opening firewall ports..."
    if command -v ufw &>/dev/null && $IS_ROOT; then
        ufw allow "${relay_port}/tcp" comment "SbNet relay" 2>/dev/null && ok "ufw: port $relay_port/tcp allowed"
        ufw allow "${health_port}/tcp" comment "SbNet relay health" 2>/dev/null && ok "ufw: port $health_port/tcp allowed"
    elif command -v firewall-cmd &>/dev/null && $IS_ROOT; then
        firewall-cmd --permanent --add-port="${relay_port}/tcp" 2>/dev/null && ok "firewalld: port $relay_port/tcp allowed"
        firewall-cmd --reload 2>/dev/null || true
    else
        warn "Firewall not managed — ensure port ${relay_port}/tcp is open"
    fi

    if $IS_ROOT; then
        write_systemd_service "$comp" "$cfg" "Relay (${relay_role})"
    elif [[ "$OS" == "darwin" ]]; then
        write_launchd_plist "$comp" "$cfg"
    fi

    echo ""
    ok "Relay installation complete."
    sep
    echo -e "  ${BOLD}ID:${RESET}     ${relay_id}"
    echo -e "  ${BOLD}Role:${RESET}   ${relay_role}"
    echo -e "  ${BOLD}IP:Port:${RESET} ${relay_ip}:${relay_port}"
    echo -e "  ${BOLD}Config:${RESET} ${cfg}"
    echo -e "  ${BOLD}Binary:${RESET} ${BIN_DIR}/sbnet-${comp}"
    sep

    if ask_yn "Start the relay now?" "y"; then
        enable_and_start "$comp"
    fi
}

install_broker() {
    banner "Installing SbNet Broker"
    local comp="broker"

    setup_dirs "$comp"
    local cfg="${CONFIG_DIR}/${comp}/${comp}.yaml"

    sep
    echo -e "${BOLD}Broker Configuration${RESET}"
    echo "Brokers do matchmaking only — they never forward traffic."
    sep

    ask "Broker ID (e.g. broker-eu-001)" "broker-$(hostname -s)"
    local broker_id="$REPLY_VAL"

    local detected_ip=""
    if command -v curl &>/dev/null; then
        detected_ip=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)
    fi
    ask "Public IP address" "${detected_ip:-}"
    local broker_ip="$REPLY_VAL"
    [[ -z "$broker_ip" ]] && die "Public IP is required"

    ask "API port" "7100"
    local broker_port="$REPLY_VAL"

    ask "Country code (ISO 3166-1 alpha-2)" "US"
    local country="${REPLY_VAL^^}"

    ask "Region label" ""
    local region="$REPLY_VAL"

    sep
    echo -e "${BOLD}Supported modes${RESET} (comma-separated, e.g. normal,bridge):"
    ask "Modes" "normal"
    local modes_raw="$REPLY_VAL"
    # Convert to YAML list
    local modes_yaml=""
    IFS=',' read -ra modes_arr <<< "$modes_raw"
    for m in "${modes_arr[@]}"; do
        m=$(echo "$m" | tr -d ' ')
        modes_yaml+=$'\n'"  - \"${m}\""
    done

    sep
    ask "Directory URL" "https://127.0.0.1:7000"
    local dir_url="$REPLY_VAL"

    ask "Registration secret" ""
    [[ -z "$REPLY_VAL" ]] && die "Registration secret is required"
    local reg_secret="$REPLY_VAL"

    local tls_cert="" tls_key=""
    if ask_yn "Enable TLS on the broker API?" "y"; then
        ask "Common Name" "sbnet-broker"
        gen_tls_cert "${DATA_DIR}/${comp}" "$REPLY_VAL" "broker.key" "broker.crt"
        tls_cert="${DATA_DIR}/${comp}/broker.crt"
        tls_key="${DATA_DIR}/${comp}/broker.key"
    fi

    ask "Log level" "info"
    local log_level="$REPLY_VAL"

    cat > "$cfg" << EOF
# SbNet Broker — generated by install.sh
id: "${broker_id}"
ip: "${broker_ip}"
port: ${broker_port}
country: "${country}"
region: "${region}"
modes:${modes_yaml}
dir_url: "${dir_url}"
dir_tls_ca: ""
reg_secret: "${reg_secret}"
key_file: "${DATA_DIR}/${comp}/broker.key"
tls_cert: "${tls_cert}"
tls_key: "${tls_key}"
log_level: "${log_level}"
EOF
    chmod 600 "$cfg"
    $IS_ROOT && chown "${SBNET_USER}:${SBNET_USER}" "$cfg"
    ok "Config written: $cfg"

    local src_dir="${INSTALL_DIR}/src"
    fetch_source "$src_dir"
    build_binary "$comp" "$src_dir"

    if $IS_ROOT; then
        write_systemd_service "$comp" "$cfg" "Broker"
    elif [[ "$OS" == "darwin" ]]; then
        write_launchd_plist "$comp" "$cfg"
    fi

    echo ""
    ok "Broker installation complete."
    sep
    echo -e "  ${BOLD}ID:${RESET}     ${broker_id}"
    echo -e "  ${BOLD}IP:Port:${RESET} ${broker_ip}:${broker_port}"
    echo -e "  ${BOLD}Config:${RESET} ${cfg}"
    sep

    if ask_yn "Start the broker now?" "y"; then
        enable_and_start "$comp"
    fi
}

install_bridge() {
    banner "Installing SbNet Bridge"
    local comp="bridge"

    setup_dirs "$comp"
    local cfg="${CONFIG_DIR}/${comp}/${comp}.yaml"

    sep
    echo -e "${BOLD}Bridge Gateway Configuration${RESET}"
    echo "The bridge connects clients to a foreign SbNet network."
    echo "Clients use a sbnet:// URI — they never know the foreign directory."
    sep

    ask "Foreign directory URL" ""
    [[ -z "$REPLY_VAL" ]] && die "Foreign directory URL is required"
    local foreign_dir="$REPLY_VAL"

    ask "Local listen address" ":9000"
    local listen_addr="$REPLY_VAL"

    # Bridge token
    local token
    if ask_yn "Generate a random bridge token?" "y"; then
        token=$(openssl rand -hex 32)
        echo -e "  ${GREEN}Generated token:${RESET} ${BOLD}${token}${RESET}"
        warn "Share this token with your clients (in the sbnet:// URI)."
        echo -ne "Press ENTER when saved..."
        read -r
    else
        ask "Bridge token" ""
        token="$REPLY_VAL"
        [[ -z "$token" ]] && die "Token is required"
    fi

    choose "Obfuscation" "tls" "none"
    local obfs="$REPLY_VAL"

    choose "Mode" "secure" "normal"
    local mode="$REPLY_VAL"

    local tls_cert="" tls_key=""
    if [[ "$obfs" == "tls" ]]; then
        sep
        ask "Common Name for bridge TLS cert" "sbnet-bridge"
        gen_tls_cert "${DATA_DIR}/${comp}" "$REPLY_VAL" "bridge-tls.key" "bridge-tls.crt"
        tls_cert="${DATA_DIR}/${comp}/bridge-tls.crt"
        tls_key="${DATA_DIR}/${comp}/bridge-tls.key"
    fi

    local upstream=""
    if ask_yn "Use an upstream SOCKS5 proxy for egress?" "n"; then
        ask "SOCKS5 proxy URL (e.g. socks5://127.0.0.1:1080)" ""
        upstream="$REPLY_VAL"
    fi

    ask "Log level" "info"
    local log_level="$REPLY_VAL"

    cat > "$cfg" << EOF
# SbNet Bridge — generated by install.sh
foreign_dir_url: "${foreign_dir}"
upstream_proxy: "${upstream}"
listen_addr: "${listen_addr}"
token: "${token}"
obfs: "${obfs}"
mode: "${mode}"
tls_cert: "${tls_cert}"
tls_key: "${tls_key}"
key_file: "${DATA_DIR}/${comp}/bridge-identity.key"
log_level: "${log_level}"
EOF
    chmod 600 "$cfg"
    $IS_ROOT && chown "${SBNET_USER}:${SBNET_USER}" "$cfg"
    ok "Config written: $cfg"

    local src_dir="${INSTALL_DIR}/src"
    fetch_source "$src_dir"
    build_binary "$comp" "$src_dir"

    # Build the client URI
    local port="${listen_addr##*:}"
    local detected_ip=""
    if command -v curl &>/dev/null; then
        detected_ip=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)
    fi
    ask "What is this bridge server's public IP (for URI display)?" "${detected_ip:-YOUR_IP}"
    local bridge_public_ip="$REPLY_VAL"
    local bridge_uri="sbnet://bridge=${bridge_public_ip}:${port}&token=${token}&obfs=${obfs}&mode=${mode}"

    if $IS_ROOT; then
        write_systemd_service "$comp" "$cfg" "Bridge Gateway"
    elif [[ "$OS" == "darwin" ]]; then
        write_launchd_plist "$comp" "$cfg"
    fi

    echo ""
    ok "Bridge installation complete."
    sep
    echo -e "  ${BOLD}Client URI:${RESET}"
    echo -e "  ${GREEN}${bridge_uri}${RESET}"
    echo ""
    echo -e "  Give this URI to clients. In client.yaml set:"
    echo -e "  ${CYAN}bridge_uri: \"${bridge_uri}\"${RESET}"
    sep
    echo -e "  ${BOLD}Config:${RESET} ${cfg}"
    sep

    if ask_yn "Start the bridge now?" "y"; then
        enable_and_start "$comp"
    fi
}

install_client() {
    banner "Installing SbNet Client"
    local comp="client"

    setup_dirs "$comp"
    local cfg="${CONFIG_DIR}/${comp}/${comp}.yaml"

    sep
    echo -e "${BOLD}Client Configuration${RESET}"
    echo "The client builds a 3-hop onion circuit and exposes:"
    echo "  • SOCKS5 proxy  (configure your browser)"
    echo "  • HTTP/CONNECT proxy"
    sep

    # Connection mode
    choose "Connection mode" \
        "Normal (connect via directory)" \
        "Bridge (connect via sbnet:// URI)" \
        "Broker (use broker for relay assignment)"
    local conn_mode="$REPLY_VAL"

    local dir_url="" bridge_uri="" broker_id=""

    case "$conn_mode" in
        "Normal"*)
            ask "Directory URL" "https://127.0.0.1:7000"
            dir_url="$REPLY_VAL"
            ;;
        "Bridge"*)
            ask "Bridge URI (sbnet://bridge=...)" ""
            bridge_uri="$REPLY_VAL"
            [[ -z "$bridge_uri" ]] && die "Bridge URI is required"
            [[ "$bridge_uri" != sbnet://* ]] && die "URI must start with sbnet://"
            ;;
        "Broker"*)
            ask "Directory URL" "https://127.0.0.1:7000"
            dir_url="$REPLY_VAL"
            ask "Broker ID (leave empty to use first available)" ""
            broker_id="$REPLY_VAL"
            ;;
    esac

    sep
    ask "SOCKS5 proxy listen address" "127.0.0.1:1080"
    local socks5_addr="$REPLY_VAL"

    ask "HTTP proxy listen address" "127.0.0.1:8080"
    local http_addr="$REPLY_VAL"

    ask "Number of parallel circuits" "3"
    local circuit_count="$REPLY_VAL"

    ask "Circuit rotation interval (seconds)" "600"
    local rotate_secs="$REPLY_VAL"

    ask "Log level" "info"
    local log_level="$REPLY_VAL"

    cat > "$cfg" << EOF
# SbNet Client — generated by install.sh
dir_url: "${dir_url}"
bridge_uri: "${bridge_uri}"
broker_id: "${broker_id}"
socks5_addr: "${socks5_addr}"
http_proxy_addr: "${http_addr}"
circuit_count: ${circuit_count}
circuit_rotate_secs: ${rotate_secs}
guard_file: "${DATA_DIR}/${comp}/.sbnet_guard"
dir_tls_ca: ""
log_level: "${log_level}"
EOF
    ok "Config written: $cfg"

    local src_dir="${INSTALL_DIR}/src"
    fetch_source "$src_dir"
    build_binary "$comp" "$src_dir"

    # For client, also offer launchd/systemd (as user service)
    if [[ "$OS" == "linux" ]] && command -v systemctl &>/dev/null; then
        if $IS_ROOT; then
            write_systemd_service "$comp" "$cfg" "Client"
        else
            # User systemd service
            local user_systemd="$HOME/.config/systemd/user"
            mkdir -p "$user_systemd"
            cat > "${user_systemd}/sbnet-client.service" << EOF
[Unit]
Description=SbNet Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=SBNET_CONFIG=${cfg}
ExecStart=${BIN_DIR}/sbnet-${comp}
Restart=on-failure
RestartSec=5s
StandardOutput=append:${LOG_DIR}/${comp}.log
StandardError=append:${LOG_DIR}/${comp}.log

[Install]
WantedBy=default.target
EOF
            ok "User systemd service: ${user_systemd}/sbnet-client.service"
        fi
    elif [[ "$OS" == "darwin" ]]; then
        write_launchd_plist "$comp" "$cfg"
    fi

    echo ""
    ok "Client installation complete."
    sep
    echo -e "  ${BOLD}SOCKS5 proxy:${RESET}  ${socks5_addr}"
    echo -e "  ${BOLD}HTTP proxy:${RESET}    ${http_addr}"
    echo ""
    echo -e "  ${BOLD}Browser setup:${RESET}"
    echo -e "  Firefox → Settings → Network → Manual proxy configuration"
    echo -e "  SOCKS Host: ${socks5_addr%:*}   Port: ${socks5_addr##*:}   SOCKS v5"
    echo -e "  ✓ Proxy DNS when using SOCKS v5"
    sep
    echo -e "  ${BOLD}Config:${RESET} ${cfg}"
    sep

    if ask_yn "Start the client now?" "y"; then
        if $IS_ROOT; then
            enable_and_start "$comp"
        elif [[ "$OS" == "linux" ]] && command -v systemctl &>/dev/null; then
            systemctl --user daemon-reload
            systemctl --user enable sbnet-client
            systemctl --user start sbnet-client
            ok "Client started (user service)"
            systemctl --user --no-pager status sbnet-client | head -8 || true
        elif [[ "$OS" == "darwin" ]]; then
            local plist="$HOME/Library/LaunchAgents/com.sbnet.client.plist"
            launchctl unload "$plist" 2>/dev/null || true
            launchctl load "$plist"
            ok "Client started"
        else
            warn "Start manually: SBNET_CONFIG=${cfg} ${BIN_DIR}/sbnet-client"
        fi
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

main() {
    clear
    echo -e "${BOLD}${BLUE}"
    cat << 'BANNER'
  ███████╗██████╗ ███╗   ██╗███████╗████████╗
  ██╔════╝██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
  ███████╗██████╔╝██╔██╗ ██║█████╗     ██║
  ╚════██║██╔══██╗██║╚██╗██║██╔══╝     ██║
  ███████║██████╔╝██║ ╚████║███████╗   ██║
  ╚══════╝╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝
BANNER
    echo -e "${RESET}"
    echo -e "  ${BOLD}SbNet Onion Routing Network — Installer${RESET}"
    echo -e "  Running on: ${CYAN}${OS}/${ARCH}${RESET}"
    $IS_ROOT && echo -e "  Privilege: ${GREEN}root${RESET}" \
             || echo -e "  Privilege: ${YELLOW}user (client mode only)${RESET}"
    sep

    # Warn if non-root and trying to install server components
    if ! $IS_ROOT; then
        warn "Not running as root. Server components (directory/relay/broker/bridge)"
        warn "should be installed as root. Only client install is fully supported here."
    fi

    install_deps

    sep
    choose "What would you like to install?" \
        "directory  — Trust anchor / consensus server" \
        "relay      — Onion relay node (entry / middle / exit)" \
        "broker     — Matchmaking server" \
        "bridge     — Cross-network gateway" \
        "client     — End-user client (SOCKS5 + HTTP proxy)"
    local choice="$REPLY_VAL"

    case "${choice%% *}" in
        directory) install_directory ;;
        relay)     install_relay     ;;
        broker)    install_broker    ;;
        bridge)    install_bridge    ;;
        client)    install_client    ;;
        *)         die "Unknown component: $choice" ;;
    esac

    echo ""
    echo -e "${BOLD}${GREEN}Installation complete.${RESET}"
    echo ""
    echo -e "Logs:   ${LOG_DIR}/"
    echo -e "Config: ${CONFIG_DIR}/"
    echo -e "Data:   ${DATA_DIR}/"
    echo ""
}

main "$@"
