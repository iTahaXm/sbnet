#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SbNet Updater
# Updates one or all installed SbNet components:
#   • Pulls latest source (or copies from local dir)
#   • Rebuilds binaries with zero downtime (stop → build → start)
#   • Reports versions before/after
#   • Backs up configs and binaries before overwriting
#   • Optionally reconfigures a component
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';  BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()   { error "$*"; exit 1; }
banner(){ echo -e "\n${BOLD}${BLUE}══ $* ══${RESET}\n"; }
sep()   { echo -e "${BLUE}────────────────────────────────────────────────${RESET}"; }

ask() {
    local prompt="$1" default="${2:-}"
    local display_default=""
    [[ -n "$default" ]] && display_default=" [${YELLOW}${default}${RESET}]"
    echo -ne "${BOLD}${prompt}${RESET}${display_default}: "
    read -r REPLY_VAL
    [[ -z "$REPLY_VAL" ]] && REPLY_VAL="$default"
}

ask_yn() {
    local prompt="$1" default="${2:-y}"
    local hint; [[ "$default" == "y" ]] && hint="Y/n" || hint="y/N"
    echo -ne "${BOLD}${prompt}${RESET} [${hint}]: "
    read -r REPLY_VAL
    [[ -z "$REPLY_VAL" ]] && REPLY_VAL="$default"
    [[ "${REPLY_VAL,,}" == "y" || "${REPLY_VAL,,}" == "yes" ]]
}

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
        warn "Enter a number 1–${#options[@]}"
    done
}

# ── Path constants (mirror install.sh) ───────────────────────────────────────
IS_ROOT=false; [[ "$EUID" -eq 0 ]] && IS_ROOT=true
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

INSTALL_DIR="/opt/sbnet"
CONFIG_DIR="/etc/sbnet"
LOG_DIR="/var/log/sbnet"
DATA_DIR="/var/lib/sbnet"
BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
SBNET_USER="sbnet"
BACKUP_DIR="/var/backups/sbnet"

if ! $IS_ROOT; then
    INSTALL_DIR="$HOME/.sbnet"
    CONFIG_DIR="$HOME/.config/sbnet"
    LOG_DIR="$HOME/.local/share/sbnet/logs"
    DATA_DIR="$HOME/.local/share/sbnet"
    BIN_DIR="$HOME/.local/bin"
    BACKUP_DIR="$HOME/.local/share/sbnet/backups"
fi

ALL_COMPONENTS=(directory relay broker bridge client)

# ── Detect installed components ───────────────────────────────────────────────
detect_installed() {
    local found=()
    for comp in "${ALL_COMPONENTS[@]}"; do
        if [[ -f "${BIN_DIR}/sbnet-${comp}" ]]; then
            found+=("$comp")
        fi
    done
    echo "${found[@]:-}"
}

# ── Version reporting ─────────────────────────────────────────────────────────
get_binary_mtime() {
    local bin="${BIN_DIR}/sbnet-$1"
    if [[ -f "$bin" ]]; then
        if [[ "$OS" == "darwin" ]]; then
            stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$bin" 2>/dev/null || echo "unknown"
        else
            stat -c "%y" "$bin" 2>/dev/null | cut -d'.' -f1 || echo "unknown"
        fi
    else
        echo "not installed"
    fi
}

get_service_status() {
    local comp="$1"
    if [[ "$OS" == "linux" ]] && command -v systemctl &>/dev/null; then
        if $IS_ROOT; then
            systemctl is-active "sbnet-${comp}" 2>/dev/null || echo "inactive"
        else
            systemctl --user is-active "sbnet-${comp}" 2>/dev/null || echo "inactive"
        fi
    elif [[ "$OS" == "darwin" ]]; then
        launchctl list "com.sbnet.${comp}" &>/dev/null && echo "active" || echo "inactive"
    else
        echo "unknown"
    fi
}

print_status_table() {
    sep
    printf "  %-12s %-10s %-22s\n" "Component" "Status" "Binary built"
    sep
    for comp in "${ALL_COMPONENTS[@]}"; do
        if [[ -f "${BIN_DIR}/sbnet-${comp}" ]]; then
            local status; status=$(get_service_status "$comp")
            local mtime; mtime=$(get_binary_mtime "$comp")
            local colour
            [[ "$status" == "active" ]] && colour="$GREEN" || colour="$YELLOW"
            printf "  %-12s ${colour}%-10s${RESET} %-22s\n" "$comp" "$status" "$mtime"
        fi
    done
    sep
}

# ── Backup ────────────────────────────────────────────────────────────────────
backup_component() {
    local comp="$1"
    local ts; ts=$(date +%Y%m%d-%H%M%S)
    local bdir="${BACKUP_DIR}/${comp}/${ts}"
    mkdir -p "$bdir"

    # Backup binary
    if [[ -f "${BIN_DIR}/sbnet-${comp}" ]]; then
        cp "${BIN_DIR}/sbnet-${comp}" "${bdir}/sbnet-${comp}"
        ok "Binary backed up → ${bdir}/sbnet-${comp}"
    fi

    # Backup config
    if [[ -f "${CONFIG_DIR}/${comp}/${comp}.yaml" ]]; then
        cp "${CONFIG_DIR}/${comp}/${comp}.yaml" "${bdir}/${comp}.yaml"
        ok "Config backed up → ${bdir}/${comp}.yaml"
    fi

    echo "$bdir"
}

# ── Service control ───────────────────────────────────────────────────────────
service_stop() {
    local comp="$1"
    info "Stopping sbnet-${comp}..."
    if [[ "$OS" == "linux" ]] && command -v systemctl &>/dev/null; then
        if $IS_ROOT; then
            systemctl stop "sbnet-${comp}" 2>/dev/null || true
        else
            systemctl --user stop "sbnet-${comp}" 2>/dev/null || true
        fi
    elif [[ "$OS" == "darwin" ]]; then
        launchctl unload "$HOME/Library/LaunchAgents/com.sbnet.${comp}.plist" 2>/dev/null || true
    fi
    ok "Stopped"
}

service_start() {
    local comp="$1"
    info "Starting sbnet-${comp}..."
    if [[ "$OS" == "linux" ]] && command -v systemctl &>/dev/null; then
        if $IS_ROOT; then
            systemctl start "sbnet-${comp}" 2>/dev/null || { warn "Failed to start — check logs"; return; }
        else
            systemctl --user start "sbnet-${comp}" 2>/dev/null || { warn "Failed to start — check logs"; return; }
        fi
    elif [[ "$OS" == "darwin" ]]; then
        local plist="$HOME/Library/LaunchAgents/com.sbnet.${comp}.plist"
        [[ -f "$plist" ]] && launchctl load "$plist" || warn "Plist not found: $plist"
    else
        warn "Start manually: SBNET_CONFIG=${CONFIG_DIR}/${comp}/${comp}.yaml ${BIN_DIR}/sbnet-${comp}"
        return
    fi
    sleep 1
    local status; status=$(get_service_status "$comp")
    if [[ "$status" == "active" ]]; then
        ok "sbnet-${comp} is running"
    else
        warn "sbnet-${comp} status: $status — check ${LOG_DIR}/${comp}.log"
    fi
}

# ── Go check ─────────────────────────────────────────────────────────────────
check_go() {
    if ! command -v go &>/dev/null; then
        # Try common Go locations
        for p in /usr/local/go/bin /usr/local/bin /usr/bin; do
            if [[ -x "$p/go" ]]; then
                export PATH="$p:$PATH"
                break
            fi
        done
    fi
    command -v go &>/dev/null || die "Go not found. Run install.sh first or install Go 1.21+ manually."
    local ver; ver=$(go version | awk '{print $3}' | sed 's/go//')
    info "Go version: $ver"
}

# ── Source update ─────────────────────────────────────────────────────────────
update_source() {
    local src_dir="${INSTALL_DIR}/src"
    if [[ -d "${src_dir}/.git" ]]; then
        info "Pulling latest source..."
        git -C "$src_dir" fetch --all
        git -C "$src_dir" pull --ff-only || {
            warn "git pull failed (local changes?). Using existing source."
        }
        ok "Source updated"
    elif [[ -f "${src_dir}/go.mod" ]]; then
        info "Source present at ${src_dir} (no git — using as-is)"
        # If the updater script was run from the source directory, sync it
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        if [[ -f "${script_dir}/go.mod" ]] && [[ "${script_dir}" != "${src_dir}" ]]; then
            info "Syncing from ${script_dir}..."
            rsync -a --delete \
                --exclude='.git' \
                --exclude='*.key' \
                --exclude='*.crt' \
                "${script_dir}/" "${src_dir}/" 2>/dev/null \
                || cp -r "${script_dir}/." "${src_dir}/"
            ok "Source synced"
        fi
    else
        die "Source not found at ${src_dir}. Run install.sh first."
    fi
}

# ── Rebuild binary ────────────────────────────────────────────────────────────
rebuild_binary() {
    local comp="$1"
    local src_dir="${INSTALL_DIR}/src"
    info "Building sbnet-${comp}..."
    (
        cd "$src_dir"
        # Regenerate go.sum — never trust a hand-written one.
        [[ -f go.sum ]] && rm -f go.sum
        go mod tidy || { echo "go mod tidy failed"; exit 1; }
        go build -ldflags="-s -w -X main.Version=1.0.0-updated-$(date +%Y%m%d)" \
            -o "${BIN_DIR}/sbnet-${comp}" \
            "./${comp}"
    )
    ok "Rebuilt: ${BIN_DIR}/sbnet-${comp}"
}

# ── Config editor ─────────────────────────────────────────────────────────────
edit_config() {
    local comp="$1"
    local cfg="${CONFIG_DIR}/${comp}/${comp}.yaml"
    [[ -f "$cfg" ]] || { warn "Config not found: $cfg"; return; }

    echo ""
    echo -e "${BOLD}Current config (${cfg}):${RESET}"
    sep
    cat "$cfg"
    sep
    echo ""

    if ask_yn "Open config in editor?" "y"; then
        local editor="${EDITOR:-}"
        if [[ -z "$editor" ]]; then
            for e in nano vim vi; do
                command -v "$e" &>/dev/null && { editor="$e"; break; }
            done
        fi
        if [[ -n "$editor" ]]; then
            "$editor" "$cfg"
            ok "Config saved"
        else
            warn "No editor found. Set \$EDITOR or edit manually: $cfg"
        fi
    fi
}

# ── Update one component ──────────────────────────────────────────────────────
update_component() {
    local comp="$1"

    if [[ ! -f "${BIN_DIR}/sbnet-${comp}" ]]; then
        warn "sbnet-${comp} is not installed — skipping"
        return
    fi

    banner "Updating sbnet-${comp}"

    local before_mtime; before_mtime=$(get_binary_mtime "$comp")
    local before_status; before_status=$(get_service_status "$comp")

    sep
    echo -e "  Component:  ${BOLD}${comp}${RESET}"
    echo -e "  Status:     ${before_status}"
    echo -e "  Built:      ${before_mtime}"
    sep
    echo ""

    # Backup first
    if ask_yn "Create backup before updating?" "y"; then
        local bdir; bdir=$(backup_component "$comp")
        info "Backup saved to: $bdir"
    fi

    # Optionally edit config
    if ask_yn "Edit configuration before update?" "n"; then
        edit_config "$comp"
    fi

    # Stop service
    local was_running=false
    if [[ "$before_status" == "active" ]]; then
        was_running=true
        service_stop "$comp"
    fi

    # Rebuild
    update_source
    check_go
    rebuild_binary "$comp"

    # Restart if was running
    if $was_running; then
        service_start "$comp"
    else
        warn "Service was not running — not starting. Start manually if desired."
    fi

    local after_mtime; after_mtime=$(get_binary_mtime "$comp")
    local after_status; after_status=$(get_service_status "$comp")

    echo ""
    ok "Update complete for ${comp}"
    sep
    echo -e "  Before: ${before_mtime}  →  After: ${after_mtime}"
    echo -e "  Status: ${after_status}"
    sep

    # Show recent logs
    local logfile="${LOG_DIR}/${comp}.log"
    if [[ -f "$logfile" ]]; then
        echo ""
        echo -e "${BOLD}Recent log (last 10 lines):${RESET}"
        tail -10 "$logfile" || true
    fi
}

# ── Rollback ──────────────────────────────────────────────────────────────────
rollback_component() {
    local comp="$1"
    local bdir="${BACKUP_DIR}/${comp}"

    if [[ ! -d "$bdir" ]]; then
        die "No backups found for ${comp} in ${bdir}"
    fi

    echo -e "${BOLD}Available backups for ${comp}:${RESET}"
    local backups=()
    while IFS= read -r -d $'\0' d; do
        backups+=("$(basename "$d")")
    done < <(find "$bdir" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z -r)

    if [[ ${#backups[@]} -eq 0 ]]; then
        die "No backups found"
    fi

    choose "Select backup to restore:" "${backups[@]}"
    local selected="${BACKUP_DIR}/${comp}/${REPLY_VAL}"

    echo ""
    warn "This will replace the current binary and config with the backup."
    ask_yn "Continue?" "n" || { info "Rollback cancelled"; return; }

    service_stop "$comp" || true

    if [[ -f "${selected}/sbnet-${comp}" ]]; then
        cp "${selected}/sbnet-${comp}" "${BIN_DIR}/sbnet-${comp}"
        chmod +x "${BIN_DIR}/sbnet-${comp}"
        ok "Binary restored"
    fi
    if [[ -f "${selected}/${comp}.yaml" ]]; then
        cp "${selected}/${comp}.yaml" "${CONFIG_DIR}/${comp}/${comp}.yaml"
        ok "Config restored"
    fi

    if ask_yn "Start ${comp} now?" "y"; then
        service_start "$comp"
    fi

    ok "Rollback complete"
}

# ── Logs viewer ───────────────────────────────────────────────────────────────
show_logs() {
    local comp="$1"
    local logfile="${LOG_DIR}/${comp}.log"
    if [[ ! -f "$logfile" ]]; then
        warn "Log file not found: $logfile"
        return
    fi

    choose "Log view mode:" \
        "tail -f (follow live)" \
        "last 50 lines" \
        "last 200 lines" \
        "grep for errors" \
        "grep for warnings"
    local mode="$REPLY_VAL"
    case "${mode%% *}" in
        "tail")  tail -f "$logfile" ;;
        "last")
            if [[ "$mode" == *"50"* ]]; then tail -50 "$logfile"
            else tail -200 "$logfile"; fi ;;
        "grep" )
            if [[ "$mode" == *"error"* ]]; then grep -i "error\|fatal\|panic" "$logfile" | tail -50 || echo "(none)"
            else grep -i "warn" "$logfile" | tail -50 || echo "(none)"; fi ;;
    esac
}

# ── Full system status ────────────────────────────────────────────────────────
show_full_status() {
    banner "SbNet System Status"
    print_status_table

    for comp in "${ALL_COMPONENTS[@]}"; do
        if [[ -f "${BIN_DIR}/sbnet-${comp}" ]]; then
            local logfile="${LOG_DIR}/${comp}.log"
            if [[ -f "$logfile" ]]; then
                echo ""
                echo -e "${BOLD}${comp} — last 5 log lines:${RESET}"
                tail -5 "$logfile" 2>/dev/null || true
            fi
        fi
    done
}

# ── Parse CLI flags ───────────────────────────────────────────────────────────
POSITIONAL=()
FLAG_COMPONENT=""
FLAG_ACTION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --component|-c)  FLAG_COMPONENT="$2"; shift 2 ;;
        --action|-a)     FLAG_ACTION="$2";    shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--component <name>] [--action update|rollback|logs|status|config]"
            echo ""
            echo "Components: directory relay broker bridge client all"
            echo "Actions:    update rollback logs status config"
            echo ""
            echo "Examples:"
            echo "  $0                          # interactive menu"
            echo "  $0 -c relay -a update       # update relay non-interactively"
            echo "  $0 -c all -a update         # update all installed components"
            echo "  $0 -c directory -a rollback # roll back directory to previous version"
            echo "  $0 -c client -a logs        # view client logs"
            echo "  $0 -a status                # show status of all components"
            exit 0
            ;;
        *) POSITIONAL+=("$1"); shift ;;
    esac
done

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
    echo -e "  ${BOLD}SbNet Onion Routing Network — Updater${RESET}"
    echo -e "  Running on: ${CYAN}${OS}/$(uname -m)${RESET}"
    $IS_ROOT && echo -e "  Privilege: ${GREEN}root${RESET}" \
             || echo -e "  Privilege: ${YELLOW}user${RESET}"
    sep

    # ── Non-interactive mode ──
    if [[ -n "$FLAG_ACTION" ]]; then
        local targets=()
        if [[ "$FLAG_COMPONENT" == "all" ]]; then
            IFS=' ' read -ra targets <<< "$(detect_installed)"
        elif [[ -n "$FLAG_COMPONENT" ]]; then
            targets=("$FLAG_COMPONENT")
        else
            # action without component: status works on all
            if [[ "$FLAG_ACTION" == "status" ]]; then
                show_full_status; exit 0
            fi
            die "--component is required when --action is set (or use 'all')"
        fi

        for t in "${targets[@]}"; do
            case "$FLAG_ACTION" in
                update)   update_component "$t"  ;;
                rollback) rollback_component "$t" ;;
                logs)     show_logs "$t"         ;;
                status)   show_full_status        ;;
                config)   edit_config "$t"        ;;
                *)        die "Unknown action: $FLAG_ACTION" ;;
            esac
        done
        exit 0
    fi

    # ── Interactive mode ──
    show_full_status

    local installed_str; installed_str=$(detect_installed)
    if [[ -z "$installed_str" ]]; then
        die "No SbNet components found in ${BIN_DIR}. Run install.sh first."
    fi

    echo ""
    choose "What would you like to do?" \
        "Update a component" \
        "Update ALL installed components" \
        "Roll back a component" \
        "Edit a component's config" \
        "View logs" \
        "Show status" \
        "Exit"

    local action="$REPLY_VAL"

    case "${action%% *}" in

        "Update" )
            if [[ "$action" == *"ALL"* ]]; then
                IFS=' ' read -ra components <<< "$installed_str"
                echo ""
                warn "This will update: ${components[*]}"
                ask_yn "Continue?" "y" || exit 0
                update_source
                check_go
                for comp in "${components[@]}"; do
                    update_component "$comp"
                done
            else
                IFS=' ' read -ra components <<< "$installed_str"
                choose "Which component?" "${components[@]}"
                update_component "$REPLY_VAL"
            fi
            ;;

        "Roll" )
            IFS=' ' read -ra components <<< "$installed_str"
            choose "Which component to roll back?" "${components[@]}"
            rollback_component "$REPLY_VAL"
            ;;

        "Edit" )
            IFS=' ' read -ra components <<< "$installed_str"
            choose "Which component's config?" "${components[@]}"
            local comp="$REPLY_VAL"
            edit_config "$comp"
            if ask_yn "Restart ${comp} to apply changes?" "y"; then
                service_stop "$comp" || true
                service_start "$comp"
            fi
            ;;

        "View" )
            IFS=' ' read -ra components <<< "$installed_str"
            choose "Logs for which component?" "${components[@]}"
            show_logs "$REPLY_VAL"
            ;;

        "Show" )
            show_full_status
            ;;

        "Exit" )
            exit 0
            ;;
    esac

    echo ""
    ok "Done."
}

main "$@"
