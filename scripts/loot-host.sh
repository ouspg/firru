#!/bin/bash
# loot-host.sh — Collect listening socket data from host and all network namespaces.
#
# Requires root (nsenter needs CAP_SYS_ADMIN).
#
# WHAT THIS DOES, SO YOU CAN CHECK IT BEFORE RUNNING IT AS ROOT
#
# It reads, and it writes one directory.
#   - Every file it creates is inside the output directory (argument 1, by
#     default /tmp/loot-<hostname>). Its only deletions are `rm -f` of files in
#     that directory that came out empty or failed to write.
#   - It changes nothing on the host: no firewall rule, sysctl, service,
#     package or file outside the output directory.
#   - It makes no network connection and sends nothing anywhere. Getting the
#     directory off the host is up to you.
#   - It runs listing commands only: hostname, ss, ip, ps, nft list ruleset,
#     iptables-save, conntrack -L and lsns, plus sort and sha256sum over its
#     own output. nsenter runs the same ss and ip listings inside the host's
#     other network namespaces, and nothing else.
#   - Besides those commands it reads /proc and /etc/os-release. It does not
#     read configuration files, keys or home directories.
#
# What it collects that you may want to read before the directory leaves the
# host:
#   - psexe has every process's full command line. A secret passed as an
#     argument is in it.
#   - nft.json and iptables are the firewall rules, with counters.
#   - conntrack names the peers of connections open at that moment.
#   - ipaddr and iproute are the host's addresses and routes.
#
# The core of the input is one line of it, `ss -tulnpe`. Without this script,
# `sudo ss -tulnpe > hosts/<hostname>/ss` gives firru its socket table (no
# namespaces, firewall or process detail), and `loot-listeners` reads it.
#
# This is the acquisition end of firru's input contract: it writes the files
# firru.discovery reads back, and it is the only place they come from. Copy it
# to the host, run it as root, bring the directory back as
# hosts/<hostname>/loot-host/, and point `firru synth` or `loot-listeners` at
# the tree. Any transport will do -- ansible fetch, scp, or
#
#     ssh root@host 'bash -s' < loot-host.sh
#
# Transport is deliberately not this script's job yet. The shape it wants is a
# driver that streams the output back in one hop (`... | tar xf -`) and checks
# what came out, because the failures worth catching are the quiet ones: a host
# where nft was absent, a netns sweep that found nothing because nsenter was
# blocked, a truncated fetch that leaves a plausible-looking half tree. A shell
# pipe reports none of those. Until that driver exists, read the manifest and
# the per-host file list by hand.
#
# Output files (per netns, including host):
#   collected-at    — when ss ran, UTC (ISO 8601); a copy without -p keeps it
#   ss              — ss -tulnpe  (includes socket inodes via -e)
#   unix            — ss -xlp: listening unix sockets (php-fpm, gunicorn and
#                     uwsgi behind a web server; netnsN-unix per netns)
#   psexe           — pid, user, comm, args
#   ipaddr          — ip addr show
#   ipaddr.json     — ip -j addr show, when iproute2 supports -j. The text form
#                     is for reading; this one is for parsing, and it is what
#                     carries the interface prefix length. A mask recovered by
#                     regex from the text form is a mask that silently goes
#                     missing the first time the output format shifts.
#   iproute         — ip route show  (reachability context for 0.0.0.0 listeners)
#   nft.json        — nft -j list ruleset  (the running firewall, with counters)
#   iptables        — iptables-save / ip6tables-save, where nft is not in use
#   conntrack       — conntrack -L -o ktimestamp, where conntrack-tools is
#                     installed (host netns only; `loot-conntrack FILE` reads it)
#
# Per extra netns additionally:
#   netnsN-ipaddr.json — ip -j addr show inside the netns
#   netnsN-meta     — pid, ns inode, lsns label (if lsns available)
#   netnsN-cgroup   — /proc/$pid/cgroup  (container/pod attribution)
#
# Top-level:
#   manifest.sha256 — sha256 of sorted ss output per netns (drift detection)
#
# Usage:
#   sudo ./loot-host.sh [outdir]
#   outdir defaults to /tmp/loot-$(hostname -f)

set -uo pipefail

# Minimal installs and containers may lack hostname(1); the kernel knows the
# short name.
HOSTNAME=$(hostname -f 2>/dev/null || cat /proc/sys/kernel/hostname)
OUTDIR="${1:-/tmp/loot-$HOSTNAME}"
mkdir -p "$OUTDIR"

echo "Collecting $HOSTNAME → $OUTDIR"

LSNS=$(command -v lsns 2>/dev/null || true)

_write_manifest() {
    (
        for f in "$OUTDIR/ss" "$OUTDIR"/netns*-ss; do
            [ -f "$f" ] || continue
            printf '%s  %s\n' \
                "$(sort "$f" | sha256sum | cut -d' ' -f1)" \
                "$(basename "$f")"
        done
    ) > "$OUTDIR/manifest.sha256"
}


# ---------------------------------------------------------------------------
# Host network namespace
# ---------------------------------------------------------------------------

date -u +%Y-%m-%dT%H:%M:%SZ > "$OUTDIR/collected-at"
ss -tulnpe       > "$OUTDIR/ss"
ss -xlpH         > "$OUTDIR/unix" 2>/dev/null
# The ephemeral port range, as this host has it (loot-diff uses it).
cat /proc/sys/net/ipv4/ip_local_port_range > "$OUTDIR/ip_local_port_range" 2>/dev/null
# The release (which baseline it compares with).
cp /etc/os-release "$OUTDIR/os-release" 2>/dev/null
ps -eo pid,user,comm,args --no-headers > "$OUTDIR/psexe"
ip addr show     > "$OUTDIR/ipaddr"
ip route show    > "$OUTDIR/iproute"

# The addresses with their prefix lengths, machine-readable. Same run, same
# root, one more file: without it an address reaches NetBox as a bare /32,
# which says nothing about the subnet it sits in and leaves the zone question
# to be answered by hand. Older iproute2 has no -j; the file is simply absent
# and the reader falls back to parsing the text form.
ip -j addr show  > "$OUTDIR/ipaddr.json" 2>/dev/null \
    || rm -f "$OUTDIR/ipaddr.json"

# What the host is enforcing, as opposed to what its policy says it should be.
# Same channel, same root, one more file: nft-to-aerleon reads this back into
# policy YAML, so "committed but never deployed" stops being an inference from
# traffic. Counters come with it, which is how a rule that has never matched
# becomes visible without a capture. Absent nft (or an iptables-only host) this
# is simply not written, and the reader reports it missing rather than empty.
if command -v nft >/dev/null 2>&1; then
    nft -j list ruleset > "$OUTDIR/nft.json" 2>/dev/null || rm -f "$OUTDIR/nft.json"
fi
if command -v iptables-save >/dev/null 2>&1; then
    iptables-save  > "$OUTDIR/iptables"  2>/dev/null || true
    ip6tables-save > "$OUTDIR/ip6tables" 2>/dev/null || true
fi

# The connections the kernel is tracking right now, which is what a listener
# list cannot say: who is actually talking to those sockets. A build without
# -o ktimestamp rejects the whole command, so retry without it; the flows then
# arrive with no start time. Absent conntrack-tools the file is not written.
if command -v conntrack >/dev/null 2>&1; then
    conntrack -L -o ktimestamp > "$OUTDIR/conntrack" 2>/dev/null \
        || conntrack -L > "$OUTDIR/conntrack" 2>/dev/null \
        || rm -f "$OUTDIR/conntrack"
fi

# ---------------------------------------------------------------------------
# Extra network namespaces
# ---------------------------------------------------------------------------

host_ns=$(readlink /proc/1/ns/net 2>/dev/null)
if [ -z "$host_ns" ]; then
    echo "Warning: could not read host netns — skipping netns sweep" >&2
    _write_manifest
    echo "Done: $OUTDIR (host only)"
    exit 0
fi

declare -A seen
idx=0

for f in /proc/[0-9]*/ns/net; do
    [ -e "$f" ] || continue

    ns=$(readlink "$f" 2>/dev/null) || continue
    [ "$ns" = "$host_ns" ] && continue
    [ "${seen[$ns]+x}" ] && continue
    seen[$ns]=1

    pid=$(echo "$f" | cut -d/ -f3)

    # Only keep namespaces with at least one non-loopback listener.
    # Use plain -tulnp for the probe: -e (extended/inode info) can exit
    # non-zero in some namespace contexts, which would silently skip the ns.
    ns_ss=$(nsenter -t "$pid" -n ss -tulnp 2>/dev/null)
    [ -z "$ns_ss" ] && continue
    has_external=$(
        echo "$ns_ss" \
        | grep LISTEN \
        | grep -v ' 127\.' \
        | grep -v ' \[::1\]' \
        | grep -v ' \*:' \
        | head -1
    )
    # Also catch 0.0.0.0 and :: listeners (world-listen inside the netns)
    has_world=$(
        echo "$ns_ss" \
        | grep LISTEN \
        | grep -E ' (0\.0\.0\.0|\[::\]):' \
        | head -1
    )
    [ -z "$has_external" ] && [ -z "$has_world" ] && continue

    idx=$((idx + 1))
    prefix="$OUTDIR/netns${idx}"

    # Re-collect with -e for inode info now that we know the ns is worth keeping.
    # Fall back to the plain output if -e fails.
    ns_ss_ext=$(nsenter -t "$pid" -n ss -tulnpe 2>/dev/null)
    { [ -n "$ns_ss_ext" ] && echo "$ns_ss_ext" || echo "$ns_ss"; } > "${prefix}-ss"

    nsenter -t "$pid" -n ip addr show  2>/dev/null            > "${prefix}-ipaddr"
    nsenter -t "$pid" -n ip route show 2>/dev/null            > "${prefix}-iproute"
    nsenter -t "$pid" -n ip -j addr show 2>/dev/null > "${prefix}-ipaddr.json" \
        || rm -f "${prefix}-ipaddr.json"

    nsenter -t "$pid" -n ss -xlpH 2>/dev/null > "${prefix}-unix"

    # cgroup attribution: container/pod identity from kernel cgroup hierarchy
    [ -r "/proc/$pid/cgroup" ] && cp "/proc/$pid/cgroup" "${prefix}-cgroup" 2>/dev/null || true

    # Human-readable namespace label
    ns_inode=$(echo "$ns" | grep -oE '[0-9]+')
    label=""
    if [ -n "$LSNS" ]; then
        label=$("$LSNS" -t net -o NS,COMMAND --noheadings 2>/dev/null \
                | awk -v inode="$ns_inode" '$1==inode {$1=""; sub(/^ /,""); print; exit}')
    fi
    printf 'pid=%s ns=%s inode=%s label=%s\n' \
        "$pid" "$ns" "$ns_inode" "${label:-unknown}" > "${prefix}-meta"

    echo "  netns${idx}: pid=$pid ns=$ns${label:+ ($label)}"
done

# ---------------------------------------------------------------------------
# Drift detection manifest
# Hash sorted ss output so PID churn between runs doesn't look like drift.
# ---------------------------------------------------------------------------

_write_manifest

echo "Done: $OUTDIR (${idx} extra netns)"
