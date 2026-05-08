#!/usr/bin/env bash
# lpe-check.sh - Detect and mitigate two recent Linux kernel LPE vulnerabilities:
#   - Copy Fail  (CVE-2026-31431) - algif_aead page-cache write
#   - Dirty Frag (no CVE assigned at time of writing) - xfrm-ESP and rxrpc page-cache writes
#
# References:
#   https://ubuntu.com/security/CVE-2026-31431
#   https://xint.io/blog/copy-fail-linux-distributions
#   https://github.com/V4bel/dirtyfrag
#   https://www.openwall.com/lists/oss-security/2026/05/07/8
#
# What this script does NOT do:
#   - It does not patch the kernel. Real fix = vendor kernel update + reboot.
#   - It does not detect successful exploitation. It only detects exposure.
#   - It does not modify any modprobe.d file it did not create.

set -euo pipefail

readonly SCRIPT_VERSION="1.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly MODPROBE_DIR="/etc/modprobe.d"
readonly COPYFAIL_CONF="${MODPROBE_DIR}/disable-copyfail.conf"
readonly DIRTYFRAG_CONF="${MODPROBE_DIR}/disable-dirtyfrag.conf"
readonly OWNER_TAG="# Managed-by: ${SCRIPT_NAME} v${SCRIPT_VERSION}"

# ---------- output helpers ----------
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
    BOLD=$(tput bold); DIM=$(tput dim); RESET=$(tput sgr0)
    RED=$(tput setaf 1); GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3); BLUE=$(tput setaf 4)
else
    BOLD=""; DIM=""; RESET=""; RED=""; GREEN=""; YELLOW=""; BLUE=""
fi

info()   { printf '%s[*]%s %s\n' "$BLUE"   "$RESET" "$*"; }
ok()     { printf '%s[+]%s %s\n' "$GREEN"  "$RESET" "$*"; }
warn()   { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$*"; }
err()    { printf '%s[x]%s %s\n' "$RED"    "$RESET" "$*" >&2; }
header() { printf '\n%s=== %s ===%s\n' "$BOLD" "$*" "$RESET"; }

usage() {
    cat <<EOF
${BOLD}${SCRIPT_NAME}${RESET} - Detect and mitigate Copy Fail (CVE-2026-31431) and
                Dirty Frag Linux kernel local-privilege-escalation vulnerabilities.

${BOLD}Usage:${RESET}
  ${SCRIPT_NAME}              Detect, then prompt before applying each mitigation.
  ${SCRIPT_NAME} --check      Detect only. Make no changes. Exit 0 if not exposed,
                              1 if exposure found, 2 on error.
  ${SCRIPT_NAME} --rollback   Remove mitigations previously applied by this script.
  ${SCRIPT_NAME} --help       Show this message.

${BOLD}Notes:${RESET}
  * Detection works without root. Applying or rolling back mitigations requires root.
  * The real fix is your distribution's patched kernel package + reboot.
    These mitigations are temporary defense-in-depth.
  * Rollback only removes files this script created (identified by tag header).
EOF
}

# ---------- module + kernel inspection ----------

# 0 if module file exists in the running kernel's tree (i.e. could be loaded)
module_present() {
    local mod="$1"
    # modinfo is the most reliable cross-distro check
    modinfo -n -- "$mod" >/dev/null 2>&1
}

# 0 if module is currently loaded (sysfs is mounted on every modern Linux;
# /sys/module/<mod> exists for both LKM-loaded and built-in modules).
module_loaded() {
    [[ -d "/sys/module/$1" ]]
}

# refcount of a loaded module (-1 if not loaded)
module_refcount() {
    local mod="$1"
    if [[ -r "/sys/module/$mod/refcnt" ]]; then
        cat "/sys/module/$mod/refcnt"
    else
        echo "-1"
    fi
}

# 0 if any modprobe.d file blocks the module via 'install ... false/true' or 'blacklist'.
# Uses grep -q directly (no pipe) to avoid SIGPIPE issues under 'set -o pipefail',
# and matches /bin/, /usr/bin/, /sbin/, /usr/sbin/ paths to handle usrmerge layouts.
module_blocked() {
    local mod="$1"
    [[ -d "$MODPROBE_DIR" ]] || return 1
    grep -rEsq "^[[:space:]]*install[[:space:]]+${mod}[[:space:]]+(/usr)?/(s)?bin/(false|true)\b" \
        "$MODPROBE_DIR" 2>/dev/null && return 0
    grep -rEsq "^[[:space:]]*blacklist[[:space:]]+${mod}\b" \
        "$MODPROBE_DIR" 2>/dev/null && return 0
    return 1
}

# Returns one of: ABSENT, BLOCKED_UNLOADED, BLOCKED_LOADED, LOADED, LOADABLE
module_status() {
    local mod="$1"
    local blocked=0 loaded=0 present=0
    module_blocked "$mod" && blocked=1
    module_loaded  "$mod" && loaded=1
    module_present "$mod" && present=1

    if (( blocked && !loaded ));     then echo BLOCKED_UNLOADED
    elif (( blocked && loaded ));    then echo BLOCKED_LOADED
    elif (( loaded ));               then echo LOADED
    elif (( present ));              then echo LOADABLE
    else                                  echo ABSENT
    fi
}

print_module_row() {
    local mod="$1" status="$2"
    local color text
    case "$status" in
        ABSENT)           color="$GREEN";  text="not present in this kernel" ;;
        BLOCKED_UNLOADED) color="$GREEN";  text="mitigated (blocked, not loaded)" ;;
        BLOCKED_LOADED)   color="$YELLOW"; text="blocked, but still loaded - rmmod or reboot" ;;
        LOADED)           color="$RED";    text="VULNERABLE (loaded)" ;;
        LOADABLE)         color="$YELLOW"; text="VULNERABLE (not loaded but loadable)" ;;
        *)                color="";        text="$status" ;;
    esac
    printf "    %-10s %s%s%s\n" "$mod" "$color" "$text" "$RESET"
}

# ---------- live-use checks (so we don't break running services) ----------

ipsec_in_use() {
    command -v ip >/dev/null 2>&1 || return 1
    # 'ip xfrm state' produces output only if there are configured SAs
    local out
    out="$(ip xfrm state 2>/dev/null || true)"
    [[ -n "${out//[[:space:]]/}" ]]
}

rxrpc_in_use() {
    [[ "$(module_refcount rxrpc)" -gt 0 ]] 2>/dev/null
}

afs_mounted() {
    grep -qE '\bafs\b' /proc/mounts 2>/dev/null
}

# ---------- detection summary ----------

declare -A MOD_STATUS
COPYFAIL_EXPOSED=0
DIRTYFRAG_EXPOSED=0

run_detection() {
    header "System information"
    info "Kernel:       $(uname -srm)"
    if [[ -r /etc/os-release ]]; then
        local pretty
        pretty="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-$NAME}")"
        info "Distribution: $pretty"
    fi

    header "Module status"
    for mod in algif_aead esp4 esp6 rxrpc; do
        MOD_STATUS[$mod]="$(module_status "$mod")"
        print_module_row "$mod" "${MOD_STATUS[$mod]}"
    done

    # Determine exposure per vulnerability
    case "${MOD_STATUS[algif_aead]}" in
        LOADED|LOADABLE|BLOCKED_LOADED) COPYFAIL_EXPOSED=1 ;;
    esac
    for m in esp4 esp6 rxrpc; do
        case "${MOD_STATUS[$m]}" in
            LOADED|LOADABLE|BLOCKED_LOADED) DIRTYFRAG_EXPOSED=1 ;;
        esac
    done

    header "Active-use checks"
    if ipsec_in_use; then
        warn "IPsec is ACTIVE on this host (ip xfrm state has entries)."
        warn "Blocking esp4/esp6 will break IPsec VPN traffic."
        IPSEC_ACTIVE=1
    else
        ok "IPsec does not appear to be in use."
        IPSEC_ACTIVE=0
    fi
    if rxrpc_in_use || afs_mounted; then
        warn "rxrpc/AFS appears to be in active use. Blocking rxrpc will break AFS."
        RXRPC_ACTIVE=1
    else
        ok "rxrpc/AFS does not appear to be in use."
        RXRPC_ACTIVE=0
    fi

    header "Exposure summary"
    if (( COPYFAIL_EXPOSED )); then
        printf '  %sCopy Fail  (CVE-2026-31431):%s exposed\n' "$RED" "$RESET"
    else
        printf '  %sCopy Fail  (CVE-2026-31431):%s not exposed\n' "$GREEN" "$RESET"
    fi
    if (( DIRTYFRAG_EXPOSED )); then
        printf '  %sDirty Frag                 :%s exposed\n' "$RED" "$RESET"
    else
        printf '  %sDirty Frag                 :%s not exposed\n' "$GREEN" "$RESET"
    fi
    echo
}

# ---------- prompts ----------

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        err "Applying changes requires root. Re-run with sudo."
        exit 2
    fi
}

confirm() {
    # confirm "Question?"  -> returns 0 on yes, 1 on no
    local prompt="$1" reply
    while true; do
        printf '%s [y/N]: ' "$prompt"
        read -r reply || return 1
        case "${reply,,}" in
            y|yes) return 0 ;;
            ""|n|no) return 1 ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

# ---------- mitigation writers ----------

write_conf() {
    # write_conf <path> <module1> [module2 ...]
    local path="$1"; shift
    {
        echo "$OWNER_TAG"
        echo "# Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# Remove with: ${SCRIPT_NAME} --rollback   (or just delete this file)"
        echo
        for mod in "$@"; do
            echo "install $mod /bin/false"
        done
    } > "$path"
    chmod 0644 "$path"
}

unload_modules_best_effort() {
    # Attempt to unload modules; do not fail the script if a module is in use.
    for mod in "$@"; do
        if module_loaded "$mod"; then
            local rc
            rc="$(module_refcount "$mod")"
            if [[ "$rc" -gt 0 ]]; then
                warn "$mod is in use (refcnt=$rc); cannot unload now. Reboot to fully clear."
                continue
            fi
            if rmmod "$mod" 2>/dev/null; then
                ok "Unloaded $mod."
            else
                warn "Could not unload $mod (may be built-in or busy). Reboot to fully clear."
            fi
        fi
    done
}

apply_copyfail_mitigation() {
    header "Copy Fail mitigation (CVE-2026-31431)"
    cat <<EOF
This will:
  - Create $COPYFAIL_CONF blocking the algif_aead module from loading.
  - Try to unload algif_aead now if loaded.

Impact: blocks the AEAD interface of the kernel's userspace crypto API
(AF_ALG). Does NOT affect LUKS/dm-crypt, kTLS, IPsec, OpenSSL/GnuTLS/NSS,
SSH, or HTTPS. Only impact is for software that explicitly uses kcapi-style
AF_ALG AEAD sockets (uncommon).
EOF
    if ! confirm "Apply Copy Fail mitigation?"; then
        info "Skipped Copy Fail mitigation."
        return 0
    fi
    require_root
    if [[ -f "$COPYFAIL_CONF" ]]; then
        warn "$COPYFAIL_CONF already exists - leaving as-is."
    else
        write_conf "$COPYFAIL_CONF" algif_aead
        ok "Wrote $COPYFAIL_CONF"
    fi
    unload_modules_best_effort algif_aead
}

apply_dirtyfrag_mitigation() {
    header "Dirty Frag mitigation"
    cat <<EOF
This will:
  - Create $DIRTYFRAG_CONF blocking esp4, esp6, and rxrpc.
  - Try to unload these modules now if loaded.

Impact:
  - esp4 / esp6: BREAKS IPsec VPNs (strongSwan, Libreswan, IKEv2/IPsec).
                 Does NOT affect WireGuard, OpenVPN, or Tailscale.
  - rxrpc:       BREAKS AFS (Andrew File System). No effect on common workloads.
EOF
    if (( ${IPSEC_ACTIVE:-0} )); then
        warn "*** IPsec is currently ACTIVE on this host. ***"
        warn "Applying this mitigation will tear down IPsec security associations."
    fi
    if (( ${RXRPC_ACTIVE:-0} )); then
        warn "*** rxrpc/AFS appears to be in active use. ***"
    fi
    if ! confirm "Apply Dirty Frag mitigation?"; then
        info "Skipped Dirty Frag mitigation."
        return 0
    fi
    require_root
    if [[ -f "$DIRTYFRAG_CONF" ]]; then
        warn "$DIRTYFRAG_CONF already exists - leaving as-is."
    else
        write_conf "$DIRTYFRAG_CONF" esp4 esp6 rxrpc
        ok "Wrote $DIRTYFRAG_CONF"
    fi
    unload_modules_best_effort esp4 esp6 rxrpc
}

# ---------- rollback ----------

rollback_one() {
    # Sets ROLLBACK_REMOVED=1 if it actually deleted something
    local path="$1"
    if [[ ! -e "$path" ]]; then
        info "$path not present - nothing to remove."
        return 0
    fi
    if ! grep -qF "$OWNER_TAG" "$path" 2>/dev/null; then
        warn "$path is NOT tagged as managed by this script. Refusing to remove."
        warn "If you want to remove it, do so manually."
        return 1
    fi
    rm -f -- "$path"
    ok "Removed $path"
    ROLLBACK_REMOVED=1
}

run_rollback() {
    require_root
    header "Rollback"
    local ROLLBACK_REMOVED=0
    rollback_one "$COPYFAIL_CONF" || true
    rollback_one "$DIRTYFRAG_CONF" || true
    if (( ROLLBACK_REMOVED )); then
        info "Mitigation files removed. Modules will be loadable again next boot,"
        info "or immediately when something requests them."
        info "If you want to actively load them now: modprobe <name>"
    else
        info "No managed mitigation files were removed."
    fi
}

# ---------- main ----------

main() {
    local mode="interactive"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--check)    mode="check"; shift ;;
            --rollback)    mode="rollback"; shift ;;
            -h|--help)     usage; exit 0 ;;
            --)            shift; break ;;
            *)             err "Unknown argument: $1"; usage; exit 2 ;;
        esac
    done

    if [[ "$mode" == "rollback" ]]; then
        run_rollback
        exit 0
    fi

    run_detection

    if [[ "$mode" == "check" ]]; then
        if (( COPYFAIL_EXPOSED || DIRTYFRAG_EXPOSED )); then
            exit 1
        fi
        exit 0
    fi

    # interactive
    if (( !COPYFAIL_EXPOSED && !DIRTYFRAG_EXPOSED )); then
        ok "No exposure detected. Nothing to do."
        exit 0
    fi

    if (( COPYFAIL_EXPOSED )); then
        apply_copyfail_mitigation
    fi
    if (( DIRTYFRAG_EXPOSED )); then
        apply_dirtyfrag_mitigation
    fi

    header "Done"
    info "Re-run '${SCRIPT_NAME} --check' to verify. Patch the kernel from your"
    info "distro and reboot as soon as fixed packages are available, then run"
    info "'${SCRIPT_NAME} --rollback' to remove these temporary mitigations."
}

main "$@"
