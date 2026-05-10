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
SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly MODPROBE_DIR="/etc/modprobe.d"
readonly COPYFAIL_CONF="${MODPROBE_DIR}/disable-copyfail.conf"
readonly DIRTYFRAG_CONF="${MODPROBE_DIR}/disable-dirtyfrag.conf"
readonly OWNER_TAG="# Managed-by: ${SCRIPT_NAME} v${SCRIPT_VERSION}"
# OWNER_MATCH is the prefix used to recognize files written by ANY version of
# this script during rollback. New versions can change OWNER_TAG freely without
# orphaning files written by older versions.
readonly OWNER_MATCH="# Managed-by: ${SCRIPT_NAME}"

# ---------- output helpers ----------
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
    BOLD=$(tput bold); RESET=$(tput sgr0)
    RED=$(tput setaf 1); GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3); BLUE=$(tput setaf 4)
else
    BOLD=""; RESET=""; RED=""; GREEN=""; YELLOW=""; BLUE=""
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

# 0 if module is built into the kernel (not a loadable module).
# Built-in modules cannot be unloaded and modprobe.d does NOT control them.
module_is_builtin() {
    local mod="$1"
    [[ -d "/sys/module/$mod" ]] || return 1
    local fname
    fname="$(modinfo -F filename -- "$mod" 2>/dev/null || true)"
    # modinfo prints "(builtin)" for built-ins, or empty/error if unknown
    [[ -z "$fname" || "$fname" == "(builtin)" ]]
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

# Print, one per line, the modprobe.d files that block this module.
# Empty output if none. Deduplicated across the install/blacklist patterns.
module_blocked_by() {
    local mod="$1"
    [[ -d "$MODPROBE_DIR" ]] || return 0
    {
        grep -rEsl "^[[:space:]]*install[[:space:]]+${mod}[[:space:]]+(/usr)?/(s)?bin/(false|true)\b" \
            "$MODPROBE_DIR" 2>/dev/null || true
        grep -rEsl "^[[:space:]]*blacklist[[:space:]]+${mod}\b" \
            "$MODPROBE_DIR" 2>/dev/null || true
    } | sort -u
}

# Print informational lines describing pre-existing blocks for the given modules.
# Excludes the script's own designated config files, since those have their own
# "already exists" messaging path. Silent for modules with no existing block.
report_existing_blocks() {
    local mod files f
    for mod in "$@"; do
        module_blocked "$mod" || continue
        files="$(module_blocked_by "$mod")"
        [[ -n "$files" ]] || continue
        # Filter out our own config files
        files="$(printf '%s\n' "$files" | grep -vxF "$COPYFAIL_CONF" | grep -vxF "$DIRTYFRAG_CONF" || true)"
        [[ -n "$files" ]] || continue
        info "$mod is already blocked by:"
        while IFS= read -r f; do
            [[ -n "$f" ]] && info "    $f"
        done <<< "$files"
    done
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

# ---------- patch verification (false-positive reduction) ----------
# These functions look for evidence that the running kernel includes a fix
# for the CVE, independent of whether the vulnerable module is loaded. They
# turn "module present, therefore vulnerable" into "module present AND no
# patch evidence, therefore probably vulnerable."
#
# Both signals are heuristic. A negative result means "no patch evidence
# found", not "definitely unpatched". A positive changelog hit is high
# confidence; a positive build-date hit is medium confidence.

# Print the running kernel's build time as a Unix epoch, or empty on failure.
# uname -v formats vary, e.g.
#   "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
#   "#2 SMP PREEMPT_DYNAMIC Wed Jan 14 17:56:08 UTC 2026"
# Extract from the first day-of-week token onward and feed that to date -d.
kernel_build_epoch() {
    local v date_str
    v="$(uname -v 2>/dev/null)" || return 0
    date_str="$(printf '%s' "$v" | grep -oE '(Sun|Mon|Tue|Wed|Thu|Fri|Sat) .*')" || return 0
    [[ -n "$date_str" ]] || return 0
    date -d "$date_str" +%s 2>/dev/null || true
}

# 0 if the running kernel was built on or after $1 (date string `date -d` accepts).
kernel_built_on_or_after() {
    local target="$1" target_epoch build_epoch
    target_epoch="$(date -d "$target" +%s 2>/dev/null)" || return 1
    build_epoch="$(kernel_build_epoch)"
    [[ -n "$build_epoch" ]] || return 1
    (( build_epoch >= target_epoch ))
}

# 0 if the running kernel package's changelog mentions $1 (case-insensitive,
# fixed string). Tries Debian/Ubuntu doc paths first, then rpm changelogs.
# Network-free; works only with locally-installed changelogs.
kernel_changelog_mentions() {
    local needle="$1" kver loc pkg
    kver="$(uname -r)"
    for loc in \
        "/usr/share/doc/linux-image-$kver/changelog.Debian.gz" \
        "/usr/share/doc/linux-image-$kver/changelog.gz" \
        "/usr/share/doc/linux-image-unsigned-$kver/changelog.Debian.gz" \
        "/usr/share/doc/linux-modules-$kver/changelog.Debian.gz" \
    ; do
        if [[ -r "$loc" ]]; then
            zcat -- "$loc" 2>/dev/null | grep -qiF -- "$needle" && return 0
        fi
    done
    if command -v rpm >/dev/null 2>&1; then
        for pkg in "kernel-$kver" "kernel-core-$kver" "kernel-default-$kver"; do
            rpm -q --changelog -- "$pkg" 2>/dev/null | grep -qiF -- "$needle" && return 0
        done
    fi
    return 1
}

# ---------- detection summary ----------

declare -A MOD_STATUS
COPYFAIL_EXPOSED=0
DIRTYFRAG_EXPOSED=0
COPYFAIL_PATCH_EVIDENCE=""
DIRTYFRAG_PATCH_EVIDENCE=""

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

    header "Patch verification (heuristic)"
    # Disclosed dates: Copy Fail 2026-04-29, Dirty Frag 2026-05-07.
    # Distro patches typically ship within ~2 weeks of disclosure; use disclosure
    # date + 14 days as the threshold for "kernel built late enough to likely
    # include the fix". Changelog hits are higher confidence than build-date.
    if kernel_changelog_mentions "CVE-2026-31431"; then
        ok "Copy Fail patch confirmed: CVE-2026-31431 referenced in kernel changelog."
        COPYFAIL_PATCH_EVIDENCE="changelog"
    elif kernel_built_on_or_after "2026-05-13"; then
        info "Copy Fail: kernel built after patch window opened (likely patched, not confirmed)."
        COPYFAIL_PATCH_EVIDENCE="build-date"
    else
        info "Copy Fail: no patch evidence found in kernel metadata."
    fi
    # Dirty Frag has no CVE assigned at the time of writing. Match in
    # priority order:
    #   HIGH confidence (overrides module-based verdict): disclosure name
    #   or discoverer references — these are unique to this CVE.
    #     - "Dirty Frag" / "dirty-frag" / "dirtyfrag"
    #     - the discoverer's name and GitHub repo path
    #     - the eventual CVE ID once assigned (add a kernel_changelog_mentions
    #       line below when known).
    #   MEDIUM confidence (does NOT override): subsystem markers like
    #   "MSG_SPLICE_PAGES" + esp/rxrpc — strongly correlated with this fix
    #   but could in principle match an unrelated commit touching the same
    #   files. Surfaced for visibility only.
    #   LOW confidence (does NOT override): build date past patch window.
    # Add upstream commit SHAs at HIGH tier once they are published.
    if   kernel_changelog_mentions "dirty frag"     \
      || kernel_changelog_mentions "dirty-frag"     \
      || kernel_changelog_mentions "dirtyfrag"      \
      || kernel_changelog_mentions "v4bel/dirtyfrag" \
      || kernel_changelog_mentions "Hyunwoo Kim"; then
        ok "Dirty Frag patch confirmed: disclosure name referenced in kernel changelog."
        DIRTYFRAG_PATCH_EVIDENCE="changelog"
    elif kernel_changelog_mentions "MSG_SPLICE_PAGES" \
         && (   kernel_changelog_mentions "esp4"   \
             || kernel_changelog_mentions "esp6"   \
             || kernel_changelog_mentions "rxrpc"); then
        info "Dirty Frag: subsystem markers found in changelog (MSG_SPLICE_PAGES + ESP/rxrpc);"
        info "  this is consistent with the patch but is not definitive. Not overriding verdict."
        DIRTYFRAG_PATCH_EVIDENCE="subsystem-marker"
    elif kernel_built_on_or_after "2026-05-21"; then
        info "Dirty Frag: kernel built after patch window opened (likely patched, not confirmed)."
        DIRTYFRAG_PATCH_EVIDENCE="build-date"
    else
        info "Dirty Frag: no patch evidence found in kernel metadata."
    fi

    # High-confidence changelog evidence overrides module-presence verdict.
    # Build-date evidence is shown but does NOT override (still flagged exposed).
    if (( COPYFAIL_EXPOSED )) && [[ "$COPYFAIL_PATCH_EVIDENCE" == "changelog" ]]; then
        COPYFAIL_EXPOSED=0
    fi
    if (( DIRTYFRAG_EXPOSED )) && [[ "$DIRTYFRAG_PATCH_EVIDENCE" == "changelog" ]]; then
        DIRTYFRAG_EXPOSED=0
    fi

    header "Exposure summary"
    print_verdict() {
        local label="$1" exposed="$2" evidence="$3"
        if (( exposed )); then
            local note=""
            case "$evidence" in
                build-date)        note=" (kernel build date suggests likely-patched, but module check fires)" ;;
                subsystem-marker)  note=" (changelog has subsystem markers consistent with the fix; not definitive)" ;;
            esac
            printf '  %s%s%s exposed%s\n' "$RED" "$label" "$RESET" "$note"
        else
            local note="(module-based check)"
            [[ "$evidence" == "changelog" ]] && note="(kernel changelog confirms patch)"
            printf '  %s%s%s not exposed %s\n' "$GREEN" "$label" "$RESET" "$note"
        fi
    }
    print_verdict "Copy Fail  (CVE-2026-31431):" "$COPYFAIL_EXPOSED" "$COPYFAIL_PATCH_EVIDENCE"
    print_verdict "Dirty Frag                 :" "$DIRTYFRAG_EXPOSED" "$DIRTYFRAG_PATCH_EVIDENCE"
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
    # Loudly warn if a module is built-in, since modprobe.d does NOT block
    # built-in modules and the user is NOT actually protected by this script.
    for mod in "$@"; do
        if ! module_loaded "$mod"; then
            continue
        fi
        if module_is_builtin "$mod"; then
            warn "$mod is BUILT INTO THE KERNEL on this system."
            warn "  modprobe.d cannot block built-in modules. This mitigation"
            warn "  does NOT protect you for $mod. Only a kernel patch will."
            continue
        fi
        local rc
        rc="$(module_refcount "$mod")"
        if [[ "$rc" -gt 0 ]]; then
            warn "$mod is in use (refcnt=$rc); cannot unload now. Reboot to fully clear."
            continue
        fi
        if rmmod "$mod" 2>/dev/null; then
            ok "Unloaded $mod."
        else
            warn "Could not unload $mod (busy or unexpected). Reboot to fully clear."
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
    report_existing_blocks algif_aead
    if [[ -f "$COPYFAIL_CONF" ]]; then
        warn "$COPYFAIL_CONF already exists - leaving as-is."
    elif module_blocked algif_aead; then
        info "Not writing a redundant config. Will still attempt to unload now."
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
    report_existing_blocks esp4 esp6 rxrpc
    if [[ -f "$DIRTYFRAG_CONF" ]]; then
        warn "$DIRTYFRAG_CONF already exists - leaving as-is."
    elif module_blocked esp4 && module_blocked esp6 && module_blocked rxrpc; then
        info "All Dirty Frag modules already blocked elsewhere."
        info "Not writing a redundant config. Will still attempt to unload now."
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
    if ! grep -qF "$OWNER_MATCH" "$path" 2>/dev/null; then
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
