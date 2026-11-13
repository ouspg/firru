#!/bin/bash
# conn-audit.sh -- which process, and which systemd unit, resolved what and
# connected where. The Linux counterpart of loot-host.ps1 -ConnectionAudit
# (WFP events), kept out of loot-host.sh, which stays a quick socket snapshot.
#
# Needs root and bpftrace (any version from Ubuntu 22.04's 0.14 on; kernels
# 5.15 to 7.0 tested). Observation only: nothing sits in the packet path, and
# the host's sockets and firewall are untouched, so loot-host.sh output taken
# while it runs is unaffected.
#
#     conn-audit.sh start              # bpftrace as the transient unit firru-conn-audit
#     ... wait, or provoke what you want to see:
#         systemctl start apt-daily.service apt-daily-upgrade.service
#         dnf makecache; snap refresh; fwupdmgr refresh
#     conn-audit.sh export OUTDIR      # copy what is recorded so far
#     conn-audit.sh stop OUTDIR        # stop, then export
#
# Bring OUTDIR back next to loot-host/ (hosts/<hostname>/conn-audit/).
# Output:
#   conn-audit.jsonl   -- bpftrace JSON; each printf is one event, see the
#                         program below for the fields
#   conn-audit.meta    -- when it started, bpftrace and kernel versions, and
#                         whether cgroup is a path or an id
#   conn-audit-cgroups.tsv -- cgroup id -> path at export, only when bpftrace
#                         predates cgroup_path(); a unit that has exited by
#                         then (apt-daily.service, say) stays an id

set -uo pipefail

AUDIT_DIR=/var/lib/firru
AUDIT_UNIT=firru-conn-audit

# The audit program. Kept in this file so the script stays one file to copy.
_audit_program() {
    cat <<'BPFTRACE'
// conn-audit.bt -- which process (and systemd unit) resolved what and
// connected where. Observation only: nothing is in the packet path.
// Every event is one printf line, tab-separated:
//   event time(UTC) pid uid comm cgroup fields...
// cgroup is the cgroup v2 path (the systemd unit), or on bpftrace older than
// cgroup_path() the numeric cgroup id, which conn-audit-cgroups.tsv maps.
//   resolve  NAME             -- getaddrinfo/gethostbyname via glibc
//   tcp      FAMILY DADDR DPORT  -- connect() reaching SYN_SENT
//   udp      FAMILY DADDR DPORT  -- first datagram per (pid, dest), connected or sendto
//   dns      DADDR QUESTION   -- a datagram to port 53: the question as sent
//                                 (DNS wire format, escaped), which also
//                                 names resolvers that bypass glibc (Go, musl)
// Constants are numeric (AF_INET 2, AF_INET6 10, IPPROTO_TCP 6, TCP_SYN_SENT 2):
// older bpftrace has no names for them.
// Gaps: DoH/DoT is only its tcp connect; names resolved inside
// systemd-resolved over varlink show as resolve events of the caller, not
// as dns events.

uprobe:libc:getaddrinfo
{
	printf("resolve\t%s\t%d\t%d\t%s\t%s\t%s\n", strftime("%Y-%m-%dT%H:%M:%SZ", nsecs), pid, uid, comm,
	       cgroup_path(cgroup), str(arg0));
}

uprobe:libc:gethostbyname,
uprobe:libc:gethostbyname2
{
	printf("resolve\t%s\t%d\t%d\t%s\t%s\t%s\n", strftime("%Y-%m-%dT%H:%M:%SZ", nsecs), pid, uid, comm,
	       cgroup_path(cgroup), str(arg0));
}

tracepoint:sock:inet_sock_set_state
/args->newstate == 2 && args->protocol == 6/
{
	if (args->family == 2) {
		printf("tcp\t%s\t%d\t%d\t%s\t%s\t4\t%s\t%d\n", strftime("%Y-%m-%dT%H:%M:%SZ", nsecs), pid, uid, comm,
		       cgroup_path(cgroup), ntop(2, args->daddr), args->dport);
	} else {
		printf("tcp\t%s\t%d\t%d\t%s\t%s\t6\t%s\t%d\n", strftime("%Y-%m-%dT%H:%M:%SZ", nsecs), pid, uid, comm,
		       cgroup_path(cgroup), ntop(10, args->daddr_v6), args->dport);
	}
}

// The payload of a datagram, for the dns event, is taken where it enters the
// kernel: syscall arguments are a stable ABI, while the kernel's iov_iter
// changed shape across 5.x-7.x (ubuf, __iov vs iov, the iter_type order).
// Resolvers send with write (Go), sendto (musl, dig), send/sendmmsg (glibc)
// and sendmsg (systemd-resolved): the first buffer is the query.
tracepoint:syscalls:sys_enter_write
{
	@payload[tid] = (uint64)args->buf;
}

tracepoint:syscalls:sys_enter_sendto
{
	@payload[tid] = (uint64)args->buff;
}

tracepoint:syscalls:sys_enter_sendmsg
{
	@payload[tid] = (uint64)((struct iovec *)uptr(((struct user_msghdr *)uptr(args->msg))->msg_iov))->iov_base;
}

tracepoint:syscalls:sys_enter_sendmmsg
{
	@payload[tid] = (uint64)((struct iovec *)uptr(((struct mmsghdr *)uptr(args->mmsg))->msg_hdr.msg_iov))->iov_base;
}

tracepoint:syscalls:sys_exit_write,
tracepoint:syscalls:sys_exit_sendto,
tracepoint:syscalls:sys_exit_sendmsg,
tracepoint:syscalls:sys_exit_sendmmsg
{
	delete(@payload[tid]);
}

// IPv4 UDP. The destination is msg_name for sendto, else the connected peer.
kprobe:udp_sendmsg
{
	$sk = (struct sock *)arg0;
	$msg = (struct msghdr *)arg1;
	$daddr = $sk->__sk_common.skc_daddr;
	$dport = (($sk->__sk_common.skc_dport & 0xff) << 8 | ($sk->__sk_common.skc_dport >> 8) & 0xff);
	if ($msg->msg_name != 0) {
		$sin = (struct sockaddr_in *)$msg->msg_name;
		$daddr = $sin->sin_addr.s_addr;
		$dport = (($sin->sin_port & 0xff) << 8 | ($sin->sin_port >> 8) & 0xff);
	}
	if (@udp4[pid, $daddr, $dport] == 0) {
		@udp4[pid, $daddr, $dport] = 1;
		printf("udp\t%s\t%d\t%d\t%s\t%s\t4\t%s\t%d\n", strftime("%Y-%m-%dT%H:%M:%SZ", nsecs), pid, uid, comm,
		       cgroup_path(cgroup), ntop(2, $daddr), $dport);
	}
	if ($dport == 53 && @payload[tid] != 0) {
		printf("dns\t%s\t%d\t%d\t%s\t%s\t%s\t%r\n", strftime("%Y-%m-%dT%H:%M:%SZ", nsecs), pid, uid, comm,
		       cgroup_path(cgroup), ntop(2, $daddr),
		       buf(uptr(@payload[tid] + 12), 64));
	}
}

kprobe:udpv6_sendmsg
{
	$sk = (struct sock *)arg0;
	$msg = (struct msghdr *)arg1;
	$d = ntop(10, $sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
	$dport = (($sk->__sk_common.skc_dport & 0xff) << 8 | ($sk->__sk_common.skc_dport >> 8) & 0xff);
	if ($msg->msg_name != 0) {
		$sin6 = (struct sockaddr_in6 *)$msg->msg_name;
		$d = ntop(10, $sin6->sin6_addr.in6_u.u6_addr8);
		$dport = (($sin6->sin6_port & 0xff) << 8 | ($sin6->sin6_port >> 8) & 0xff);
	}
	if (@udp6[pid, $d, $dport] == 0) {
		@udp6[pid, $d, $dport] = 1;
		printf("udp\t%s\t%d\t%d\t%s\t%s\t6\t%s\t%d\n", strftime("%Y-%m-%dT%H:%M:%SZ", nsecs), pid, uid, comm,
		       cgroup_path(cgroup), $d, $dport);
	}
	if ($dport == 53 && @payload[tid] != 0) {
		printf("dns\t%s\t%d\t%d\t%s\t%s\t%s\t%r\n", strftime("%Y-%m-%dT%H:%M:%SZ", nsecs), pid, uid, comm,
		       cgroup_path(cgroup), $d, buf(uptr(@payload[tid] + 12), 64));
	}
}

END
{
	clear(@udp4);
	clear(@udp6);
	clear(@payload);
}
BPFTRACE
}

start() {
    BPFT=bpftrace
    command -v bpftrace >/dev/null 2>&1 || { echo "connection audit: bpftrace not installed" >&2; exit 1; }
    # A second start would truncate what the first recorded, also while the
    # first is still starting (activating: is-active says no).
    case $(systemctl show -p ActiveState --value "$AUDIT_UNIT" 2>/dev/null) in
        active|activating|reloading)
            echo "connection audit: $AUDIT_UNIT already running" >&2; exit 1 ;;
    esac
    mkdir -p "$AUDIT_DIR"
    # bpftrace's static release is an AppImage, which mounts itself with FUSE;
    # on some releases that fails even as root with fuse3 installed (Ubuntu
    # 22.04 and 26.04 server). The same release unpacked beside it
    # (bpftrace.d/, as --appimage-extract leaves it) needs no mount and runs
    # from where it lies, so it is used whenever it is there.
    d=$(dirname "$(command -v bpftrace)")/bpftrace.d
    [ -x "$d/AppRun" ] && BPFT=$d/AppRun
    # cgroup_path() is the unit name at the moment of the event; bpftrace
    # without it gets the numeric id, resolved only at export.
    if timeout 15 "$BPFT" -e 'interval:s:1 { printf("%s", cgroup_path(cgroup)); exit(); }' \
            >/dev/null 2>&1; then
        _audit_program > "$AUDIT_DIR/conn-audit.bt"
        cg=path
    else
        _audit_program | sed 's/cgroup_path(cgroup)/cgroup/g; s/\\t%s\\t%s\\t/\\t%s\\t%llu\\t/' \
            > "$AUDIT_DIR/conn-audit.bt"
        cg=id
    fi
    {
        echo "started=$(date -u +%FT%TZ)"
        echo "bpftrace=$("$BPFT" --version 2>&1 | head -1)$([ "$BPFT" = bpftrace ] || echo " unpacked=$BPFT")"
        echo "kernel=$(uname -r)"
        echo "cgroup=$cg"
    } > "$AUDIT_DIR/conn-audit.meta"
    rm -f "$AUDIT_DIR/conn-audit.jsonl"
    # No default dependencies: those order it after basic.target, which on a
    # boot waits for the network a caller started early (before
    # network-pre.target) is holding back for it, and systemd-run waits for
    # the start. Stopped at shutdown all the same.
    systemd-run --unit="$AUDIT_UNIT" --collect --setenv=TZ=UTC \
        -p DefaultDependencies=no -p Conflicts=shutdown.target -p Before=shutdown.target \
        "$BPFT" -f json -o "$AUDIT_DIR/conn-audit.jsonl" "$AUDIT_DIR/conn-audit.bt" >/dev/null \
        || { echo "connection audit: systemd-run failed" >&2; exit 1; }
    # On means attached: bpftrace says so in its own output (attached_probes)
    # once the probes are in, which takes seconds; a caller that starts the
    # network next (baseline-audit.service) must not race it.
    for _ in $(seq 60); do
        systemctl is-active -q "$AUDIT_UNIT" \
            || { echo "connection audit: bpftrace exited; journalctl -u $AUDIT_UNIT" >&2; exit 1; }
        grep -q '"attached_probes"' "$AUDIT_DIR/conn-audit.jsonl" 2>/dev/null && break
        sleep 0.5
    done
    grep -q '"attached_probes"' "$AUDIT_DIR/conn-audit.jsonl" 2>/dev/null \
        || { echo "connection audit: probes not attached after 30 s; journalctl -u $AUDIT_UNIT" >&2; exit 1; }
    echo "Connection audit on ($AUDIT_UNIT, cgroup $cg); conn-audit.sh stop OUTDIR ends it."
}

export_to() {
    local OUTDIR=$1
    [ -f "$AUDIT_DIR/conn-audit.jsonl" ] || { echo "connection audit: nothing recorded" >&2; return 1; }
    mkdir -p "$OUTDIR"
    # Only bpftrace's JSON lines: newer versions print warnings into the same stream.
    grep '^{' "$AUDIT_DIR/conn-audit.jsonl" > "$OUTDIR/conn-audit.jsonl"
    cp "$AUDIT_DIR/conn-audit.meta" "$OUTDIR/conn-audit.meta" 2>/dev/null || true
    if grep -q '^cgroup=id' "$AUDIT_DIR/conn-audit.meta" 2>/dev/null; then
        find /sys/fs/cgroup -type d -printf '%i\t%P\n' > "$OUTDIR/conn-audit-cgroups.tsv" 2>/dev/null
    fi
    echo "connection audit: $(grep -c '"printf"' "$OUTDIR/conn-audit.jsonl") events -> $OUTDIR"
}

case "${1:-}" in
    start)  start ;;
    export) [ -n "${2:-}" ] || { echo "usage: conn-audit.sh export OUTDIR" >&2; exit 2; }
            export_to "$2" ;;
    stop)   [ -n "${2:-}" ] || { echo "usage: conn-audit.sh stop OUTDIR" >&2; exit 2; }
            systemctl stop "$AUDIT_UNIT" 2>/dev/null || true
            export_to "$2" ;;
    *)      echo "usage: conn-audit.sh start | export OUTDIR | stop OUTDIR" >&2; exit 2 ;;
esac
