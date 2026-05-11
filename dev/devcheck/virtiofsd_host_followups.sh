#!/usr/bin/env bash
# Host-side follow-up diagnostics for the virtiofsd-EMFILE investigation.
#
# Run on the libvirt/KVM host (NOT inside the VM). Read-only; uses sudo
# only for /proc/<pid>/fd of virtiofsd (which typically runs as root/qemu).
#
# Usage:
#     sudo bash dev/devcheck/virtiofsd_host_followups.sh \
#         > host-followups.txt 2>&1
#
# Then read host-followups.txt from the shared virtiofs mount inside the
# guest (same path, since /home/joncrall/code/aivm mirrors).
#
# What this script answers
# ------------------------
#   Section 0  Which virtiofsd processes are running, what version, and
#              what flags. Establishes whose FDs we are about to inspect.
#
#   Section 1  For the busiest persistent-root virtiofsd, what host paths
#              do its open FDs actually point to? Confirms the per-inode
#              FD design and tells us where its cache lives.
#
#   Section 2  Aggregate those FDs by persistent-root token. Identifies
#              which attached tree dominates virtiofsd's cache right now.
#
#   Section 3  List every token directory on disk under persistent-root
#              and compare to the tags in the current aivm config. Tokens
#              on disk but missing from config are likely leftover staged
#              binds (the geowatch-style "detached but still exported"
#              case from the original investigation).
#
#   Section 4  systemd unit + drop-in content for virtqemud / libvirtd,
#              current effective LimitNOFILE, and any NOFILE-related
#              journal events in the last 90 days. Tells us whether the
#              limit was bumped recently and roughly when.
#
#   Section 5  Per-token regular-file count, host-side (does NOT go
#              through virtiofs). Bounds the maximum inode set virtiofsd
#              could plausibly cache for a full traversal of each token.

VM="${AIVM_VM:-aivm-2404}"
PERSISTENT_ROOT="/var/lib/libvirt/aivm/${VM}/persistent-root"
CONFIG_FILE="${AIVM_CONFIG:-${SUDO_USER:+/home/${SUDO_USER}}/.config/aivm/config.toml}"
[ -n "${SUDO_USER:-}" ] || CONFIG_FILE="${AIVM_CONFIG:-$HOME/.config/aivm/config.toml}"

banner() {
    printf '\n============================================================\n'
    printf '%s\n' "$*"
    printf '============================================================\n'
}
sub() { printf '\n--- %s\n' "$*"; }

banner "host followups for VM=${VM}"
echo "host:            $(hostname)"
echo "date:            $(date -Is)"
echo "persistent-root: ${PERSISTENT_ROOT}"
echo "config file:     ${CONFIG_FILE}"

# ---------------------------------------------------------------------------
banner "0. virtiofsd inventory"
sub "virtiofsd --version"
for cand in /usr/libexec/virtiofsd /usr/bin/virtiofsd "$(command -v virtiofsd 2>/dev/null)"; do
    [ -x "$cand" ] || continue
    echo ">> $cand"
    "$cand" --version 2>&1 | sed 's/^/    /'
    break
done

sub "running virtiofsd processes (matched by exe basename)"
pids=()
for entry in /proc/[0-9]*; do
    pid="${entry##*/}"
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
    if [ "$(basename "$exe")" = "virtiofsd" ]; then
        pids+=("$pid")
    fi
done
printf "    %-8s %-8s %-22s %s\n" "PID" "FDS" "NOFILE(soft/hard)" "SOURCE"
busy_pid=""
busy_fds=0
for pid in "${pids[@]}"; do
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
    source=$(echo "$cmdline" | grep -oE 'source=[^ ]+' | head -1)
    source="${source:-source=?}"
    fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
    nofile=$(awk '/Max open files/ {print $4"/"$5}' "/proc/$pid/limits" 2>/dev/null)
    printf "    %-8s %-8s %-22s %s\n" "$pid" "$fds" "${nofile:-?}" "$source"
    case "$source" in
        *persistent-root*)
            if [ "$fds" -gt "$busy_fds" ]; then
                busy_fds=$fds
                busy_pid=$pid
            fi
            ;;
    esac
done

# ---------------------------------------------------------------------------
banner "1. FD target audit for busiest persistent-root virtiofsd (pid=${busy_pid:-none}, fds=${busy_fds})"
if [ -n "$busy_pid" ] && [ -d "/proc/$busy_pid/fd" ]; then
    sub "fd-target prefix breakdown (top 40, host paths)"
    # ls -l on /proc/<pid>/fd shows -> target for each FD; capture targets only.
    ls -l "/proc/$busy_pid/fd" 2>/dev/null \
        | awk -F' -> ' 'NF==2 {print $2}' \
        | sed -E "s|^(${PERSISTENT_ROOT}/[^/]+).*|\1|" \
        | sed -E 's|^(/[^/]+/[^/]+/[^/]+).*|\1...|' \
        | sort | uniq -c | sort -rn | head -40

    sub "fd-target kinds (sockets / pipes / files etc.)"
    ls -l "/proc/$busy_pid/fd" 2>/dev/null \
        | awk -F' -> ' 'NF==2 {print $2}' \
        | awk '
            /^socket:/   { s++; next }
            /^pipe:/     { p++; next }
            /^anon_inode/{ a++; next }
            /^\/memfd:/  { m++; next }
            /^\//        { f++; next }
            { o++ }
            END {
                printf "    sockets    : %d\n", s
                printf "    pipes      : %d\n", p
                printf "    anon_inode : %d\n", a
                printf "    memfd      : %d\n", m
                printf "    regular fs : %d\n", f
                printf "    other      : %d\n", o
            }'
else
    echo "(no persistent-root virtiofsd found; skipping)"
fi

# ---------------------------------------------------------------------------
banner "2. virtiofsd FD distribution by persistent-root token"
if [ -n "$busy_pid" ] && [ -d "$PERSISTENT_ROOT" ]; then
    ls -l "/proc/$busy_pid/fd" 2>/dev/null \
        | awk -F' -> ' 'NF==2 {print $2}' \
        | grep "^${PERSISTENT_ROOT}/" \
        | sed -E "s|^${PERSISTENT_ROOT}/([^/]+).*|\1|" \
        | sort | uniq -c | sort -rn
else
    echo "(skipped)"
fi

# ---------------------------------------------------------------------------
banner "3. token directories on disk vs configured attachments"
DISK_LIST=$(mktemp)
CFG_LIST=$(mktemp)
trap 'rm -f "$DISK_LIST" "$CFG_LIST"' EXIT

sub "token directories present under persistent-root"
if [ -d "$PERSISTENT_ROOT" ]; then
    ls -1 "$PERSISTENT_ROOT" 2>/dev/null | sort > "$DISK_LIST"
    cat "$DISK_LIST" | sed 's/^/    /'
else
    echo "    (missing: $PERSISTENT_ROOT)"
fi

sub "tags referenced in current aivm config"
if [ -f "$CONFIG_FILE" ]; then
    grep -oE '^tag = "[^"]+"' "$CONFIG_FILE" \
        | sed -E 's/tag = "(.*)"/\1/' \
        | sort -u > "$CFG_LIST"
    cat "$CFG_LIST" | sed 's/^/    /'
else
    echo "    (config not found: $CONFIG_FILE; pass AIVM_CONFIG=... to override)"
fi

sub "tokens on disk but NOT in current config (likely leftover staged binds)"
if [ -s "$DISK_LIST" ] && [ -s "$CFG_LIST" ]; then
    comm -23 "$DISK_LIST" "$CFG_LIST" | sed 's/^/    /'
else
    echo "    (cannot compare; one of the lists is empty)"
fi

sub "active bind mounts under persistent-root (findmnt)"
findmnt -R "$PERSISTENT_ROOT" -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null \
    | head -60

# ---------------------------------------------------------------------------
banner "4. systemd LimitNOFILE config + history"
sub "systemctl cat virtqemud (unit + drop-ins)"
systemctl cat virtqemud 2>&1 | sed 's/^/    /'

sub "systemctl cat libvirtd (unit + drop-ins)"
systemctl cat libvirtd 2>&1 | sed 's/^/    /'

sub "current effective limits"
for unit in virtqemud libvirtd; do
    out=$(systemctl show "$unit" -p LimitNOFILE -p LimitNOFILESoft 2>/dev/null \
            | tr '\n' ' ')
    echo "    $unit: $out"
done

sub "journal hits for NOFILE / EMFILE in last 90 days"
journalctl -u virtqemud -u libvirtd --since "90 days ago" 2>/dev/null \
    | grep -iE 'limitnofile|too many open files|emfile|file descriptor' \
    | tail -50
[ "${PIPESTATUS[1]:-1}" -ne 0 ] && echo "    (no matching journal events)"

sub "virtqemud/libvirtd recent restart timestamps (last 10)"
journalctl -u virtqemud -u libvirtd --no-pager 2>/dev/null \
    | grep -iE 'starting|started|stopping' \
    | tail -10 | sed 's/^/    /'

# ---------------------------------------------------------------------------
banner "5. inode-touchable working set per token (host-side find)"
if [ -d "$PERSISTENT_ROOT" ]; then
    sub "regular-file count per token (sorted by count)"
    {
        for d in "$PERSISTENT_ROOT"/*/; do
            [ -d "$d" ] || continue
            name=$(basename "$d")
            cnt=$(find "$d" -type f 2>/dev/null | wc -l)
            printf "%10d  %s\n" "$cnt" "$name"
        done
    } | sort -rn | sed 's/^/    /'

    sub "totals"
    total_f=$(find "$PERSISTENT_ROOT" -type f 2>/dev/null | wc -l)
    total_d=$(find "$PERSISTENT_ROOT" -type d 2>/dev/null | wc -l)
    total_all=$(find "$PERSISTENT_ROOT" 2>/dev/null | wc -l)
    printf "    regular files: %d\n" "$total_f"
    printf "    directories:   %d\n" "$total_d"
    printf "    all entries:   %d  <- upper bound on virtiofsd inode cache for a full traversal\n" "$total_all"
fi

banner "done"
