#!/usr/bin/env python3
"""
aerleon-to-bpf — Generate violation-detection filters from an aerleon policy.

For each ingress accept term with a source restriction, emits a filter that
matches traffic proving the restriction was bypassed — i.e. traffic that
should have been blocked but got through.

  TCP: SYN-ACK from the host on that port to a non-allowed destination
  UDP: any response from the host on that port to a non-allowed destination

Also emits a "catch-all" expression for ports not covered by any accept term —
the fastest way to check whether a centralized firewall is actually enforcing
the policy (if it's down you'll see SYN-ACKs on ports that should be closed).

Usage:
    # BPF for tcpdump on a firewall or end-host (default)
    aerleon-to-bpf --policy policies/pol/myhost_example_org.yml --defs def/

    # Quick firewall-up check: pipe into tcpdump
    tcpdump -i eth0 -n "$(aerleon-to-bpf --policy ... --combined)"

    # Arkime retrospective query
    aerleon-to-bpf --policy ... --format arkime

    # Both formats side by side
    aerleon-to-bpf --policy ... --format both

    # nmap probe list — only tests meaningful from a specific source IP
    aerleon-to-bpf --policy ... --format nmap --from-ip 10.1.2.3
"""

import argparse
import sys
from ipaddress import ip_address, ip_network
from pathlib import Path

from aerleon.lib import naming
from ruyaml import YAML

from firru.policy import DIR_IN, filter_directions

yaml_handler = YAML()

ANY_TOKENS = {"ANY", "ANY_V4", "ANY_V6", "INTERNET", "WORLD", "OFF_NET"}


def ip_in_nets(ip_str, nets):
    """True if ip_str falls within any of the CIDR strings in nets."""
    try:
        addr = ip_address(ip_str)
        for net in nets:
            if addr in ip_network(net, strict=False):
                return True
    except ValueError:
        pass
    return False


# ---------------------------------------------------------------------------
# Definition resolvers
# ---------------------------------------------------------------------------

def resolve_ports(svc_token, proto_filter, defs):
    """
    Resolve a service token (or list) to port integers.
    GetService returns ['22/tcp'], ['7946/tcp', '7946/udp'], etc.
    proto_filter: 'tcp', 'udp', or None (accept all).
    Expands ranges like '7472-7473' to individual ports.
    """
    if not svc_token:
        return []
    tokens = [svc_token] if isinstance(svc_token, str) else list(svc_token)
    ports = []
    for tok in tokens:
        try:
            entries = defs.GetService(tok)  # ['port/proto', ...]
            for entry in entries:
                port_str, svc_proto = entry.split("/")
                if proto_filter and svc_proto.lower() != proto_filter.lower():
                    continue
                if "-" in port_str:
                    lo, hi = port_str.split("-")
                    ports.extend(range(int(lo), int(hi) + 1))
                else:
                    ports.append(int(port_str))
        except Exception:
            try:
                ports.append(int(tok))
            except (ValueError, TypeError):
                pass
    return sorted(set(ports))


def resolve_nets(token_or_list, defs):
    """
    Resolve source-address token(s) to a list of CIDR strings.
    Returns None if the source is unrestricted (ANY / no restriction).
    """
    if not token_or_list:
        return None
    tokens = [token_or_list] if isinstance(token_or_list, str) else list(token_or_list)
    if any(t in ANY_TOKENS for t in tokens):
        return None
    result = []
    for tok in tokens:
        try:
            nets = defs.GetNetAddr(tok)
            result.extend(str(n) for n in nets)
        except Exception:
            pass
    return result


def get_host_ips(host_token, defs):
    try:
        nets = defs.GetNetAddr(host_token)
        return [str(n.network_address) for n in nets
                if n.prefixlen == (128 if n.version == 6 else 32)]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# BPF expression builders
# ---------------------------------------------------------------------------

def _bpf_src_host(host_ips):
    if len(host_ips) == 1:
        return f"src host {host_ips[0]}"
    return "(" + " or ".join(f"src host {ip}" for ip in host_ips) + ")"


def _bpf_dst_host(host_ips):
    if len(host_ips) == 1:
        return f"dst host {host_ips[0]}"
    return "(" + " or ".join(f"dst host {ip}" for ip in host_ips) + ")"


def _bpf_not_nets(nets):
    """BPF: destination NOT in any of the given networks/hosts."""
    parts = [f"dst net {n}" if "/" in n else f"dst host {n}" for n in nets]
    return "not (" + " or ".join(parts) + ")"


def _bpf_not_src_nets(nets):
    """BPF: source NOT in any of the given networks/hosts."""
    parts = [f"src net {n}" if "/" in n else f"src host {n}" for n in nets]
    return "not (" + " or ".join(parts) + ")"


# ---------------------------------------------------------------------------
# Address families.
#
# libpcap's `tcp[13]` indexes the TCP header only for IPv4 packets: the
# expression parses fine with IPv6 hosts alongside it and then never matches
# them, so a dual-stack detector written naively is silently v4-only — the
# exact blind spot the exercise's IPv6 finding lived in. For IPv6 the flags
# byte is at a fixed offset from the fixed header: ip6[40+13] = ip6[53],
# valid when no extension headers sit between the fixed header and TCP.
# libpcap's own `tcp port` primitive makes the same no-extension-header
# assumption for IPv6, so the two halves of each arm are consistent — and
# traffic hiding behind extension headers is invisible to both, which is a
# libpcap limit, not a policy statement.
#
# Every flags-based expression is therefore built per family: v4 hosts with
# tcp[13], v6 hosts with ip6[53], each arm restricted to its own family's
# allowed nets. A term whose sources resolve to one family only gets an
# exclusion in that family's arm; the other family's arm excludes nothing,
# so ANY hit there is a violation — which is the correct reading of a rule
# that admits nobody in that family.
# ---------------------------------------------------------------------------

def _is_v6(s):
    return ":" in s


def _by_family(items):
    """[(family, subset)] for non-empty families, 4 before 6."""
    v4 = [i for i in items if not _is_v6(i)]
    v6 = [i for i in items if _is_v6(i)]
    return [(fam, sub) for fam, sub in ((4, v4), (6, v6)) if sub]


def _tcp_flags(family):
    return "tcp[13]" if family == 4 else "ip6[53]"


def _family_nets(nets, family):
    if not nets:
        return None
    return [n for n in nets if _is_v6(n) == (family == 6)] or None


def _or_arms(arms):
    return arms[0] if len(arms) == 1 else "(" + " or ".join(arms) + ")"


def bpf_tcp_syn(host_ips, port, allowed_nets):
    """SYN inbound to host — centralized firewall failure."""
    arms = []
    for fam, hosts in _by_family(host_ips):
        parts = [_bpf_dst_host(hosts), _bpf_port("tcp", port, "dst"),
                 f"{_tcp_flags(fam)} & 0x12 == 0x02"]
        nets = _family_nets(allowed_nets, fam)
        if nets:
            parts.append(_bpf_not_src_nets(nets))
        arms.append("(" + " and ".join(parts) + ")")
    return _or_arms(arms)


def bpf_tcp_synack(host_ips, port, allowed_nets):
    """SYN-ACK outbound from host — both firewalls failed."""
    arms = []
    for fam, hosts in _by_family(host_ips):
        parts = [_bpf_src_host(hosts), _bpf_port("tcp", port, "src"),
                 f"{_tcp_flags(fam)} & 0x12 == 0x12"]
        nets = _family_nets(allowed_nets, fam)
        if nets:
            parts.append(_bpf_not_nets(nets))
        arms.append("(" + " and ".join(parts) + ")")
    return _or_arms(arms)


def bpf_udp_violation(host_ips, port, allowed_nets):
    """UDP response from host on port, optionally restricted to non-allowed destinations."""
    parts = [_bpf_src_host(host_ips), _bpf_port("udp", port, "src")]
    if allowed_nets:
        parts.append(_bpf_not_nets(allowed_nets))
    return "(" + " and ".join(parts) + ")"


def _port_ranges(ports):
    """Collapse a sorted port list into (lo, hi) pairs for consecutive runs."""
    if not ports:
        return []
    ranges, start, end = [], ports[0], ports[0]
    for p in ports[1:]:
        if p == end + 1:
            end = p
        else:
            ranges.append((start, end))
            start = end = p
    ranges.append((start, end))
    return ranges


def _port_run(port):
    """Normalize a port spec — int or (lo, hi) run — to (lo, hi).

    Detectors are emitted per *run*, not per port: a DC term covering
    49152-65535 is one portrange expression, not 16,384 filters. The catch-all
    always collapsed runs; the per-term path used to iterate individual ports,
    which made a domain controller's policy take minutes to render and produced
    a filter list nobody could load.
    """
    return (port, port) if isinstance(port, int) else (port[0], port[1])


def _port_label(port):
    lo, hi = _port_run(port)
    return str(lo) if lo == hi else f"{lo}-{hi}"


def _bpf_port(proto, port, field):
    lo, hi = _port_run(port)
    if lo == hi:
        return f"{proto} {field} port {lo}"
    return f"{proto} {field} portrange {lo}-{hi}"


def _arkime_port(field, port):
    lo, hi = _port_run(port)
    if lo == hi:
        return f"{field}.port == {lo}"
    return f"({field}.port >= {lo} && {field}.port <= {hi})"


def _bpf_port_exprs(proto, ports, field="src"):
    """BPF port match list, using 'portrange' for consecutive runs.

    field is 'src' or 'dst': for an inbound SYN the service is the
    *destination* port; for the host's SYN-ACK or UDP response it is the
    *source* port.
    """
    parts = []
    for lo, hi in _port_ranges(sorted(ports)):
        if lo == hi:
            parts.append(f"{proto} {field} port {lo}")
        else:
            parts.append(f"{proto} {field} portrange {lo}-{hi}")
    return parts


def _arkime_port_exprs(ports):
    """Arkime port match list, using >= / <= for consecutive runs."""
    parts = []
    for lo, hi in _port_ranges(sorted(ports)):
        if lo == hi:
            parts.append(f"source.port == {lo}")
        else:
            parts.append(f"(source.port >= {lo} && source.port <= {hi})")
    return parts


def bpf_uncovered(host_ips, covered_tcp, covered_udp):
    """
    Centralized FW check: SYN inbound on closed ports.
    Both-FW check: SYN-ACK outbound on closed ports.
    UDP: any response on closed ports (can't distinguish layers).
    """
    exprs = []
    # SYN inbound: the service is the DESTINATION port. SYN-ACK outbound:
    # the host answers FROM its service port, so the SOURCE port. One arm per
    # address family: the flags byte lives at tcp[13] for v4, ip6[53] for v6.
    for fam, hosts in _by_family(host_ips):
        dst = _bpf_dst_host(hosts)
        src = _bpf_src_host(hosts)
        flags = _tcp_flags(fam)
        if covered_tcp:
            not_dst = " or ".join(_bpf_port_exprs("tcp", covered_tcp, "dst"))
            not_src = " or ".join(_bpf_port_exprs("tcp", covered_tcp, "src"))
            exprs.append(f"({dst} and {flags} & 0x12 == 0x02 and not ({not_dst}))")  # SYN in
            exprs.append(f"({src} and {flags} & 0x12 == 0x12 and not ({not_src}))")  # SYN-ACK out
        else:
            exprs.append(f"({dst} and {flags} & 0x12 == 0x02)")
            exprs.append(f"({src} and {flags} & 0x12 == 0x12)")
    # UDP needs no flags byte, so no family split: port primitives match both.
    src_all = _bpf_src_host(host_ips)
    if covered_udp:
        # UDP response comes FROM the host, so the service is the source port.
        not_ports = " or ".join(_bpf_port_exprs("udp", covered_udp, "src"))
        exprs.append(f"({src_all} and udp and not ({not_ports}))")
    else:
        exprs.append(f"({src_all} and udp)")
    return " or\n    ".join(exprs)


# ---------------------------------------------------------------------------
# Arkime expression builders
# ---------------------------------------------------------------------------

def _arkime_src_host(host_ips):
    if len(host_ips) == 1:
        return f"source.ip == {host_ips[0]}"
    return "(" + " || ".join(f"source.ip == {ip}" for ip in host_ips) + ")"


def _arkime_not_nets(nets):
    return " && ".join(f"destination.ip != {n}" for n in nets)


def _arkime_dst_host(host_ips):
    if len(host_ips) == 1:
        return f"destination.ip == {host_ips[0]}"
    return "(" + " || ".join(f"destination.ip == {ip}" for ip in host_ips) + ")"


def _arkime_not_src_nets(nets):
    return " && ".join(f"source.ip != {n}" for n in nets)


def arkime_tcp_syn(host_ips, port, allowed_nets):
    """SYN reached host, no SYN-ACK — centralized firewall failed, host firewall held."""
    parts = [_arkime_dst_host(host_ips), _arkime_port("destination", port),
             "protocols == tcp", "tcpflags.syn == 1", "tcpflags.syn-ack == 0"]
    if allowed_nets:
        parts.append(_arkime_not_src_nets(allowed_nets))
    return "(" + " && ".join(parts) + ")"


def arkime_tcp_synack(host_ips, port, allowed_nets):
    """SYN-ACK seen — both firewalls failed, connection established."""
    parts = [_arkime_dst_host(host_ips), _arkime_port("destination", port),
             "protocols == tcp", "tcpflags.syn-ack == 1"]
    if allowed_nets:
        parts.append(_arkime_not_src_nets(allowed_nets))
    return "(" + " && ".join(parts) + ")"


def arkime_udp_violation(host_ips, port, allowed_nets):
    parts = [_arkime_src_host(host_ips), _arkime_port("source", port), "protocols == udp"]
    if allowed_nets:
        parts.append(_arkime_not_nets(allowed_nets))
    return "(" + " && ".join(parts) + ")"


def arkime_uncovered(host_ips, covered_tcp, covered_udp):
    # TODO(upstream): mirror the BPF catch-all port-direction fix here.
    # These arms are framed as destination.ip == host (session toward the host),
    # so the covered-port exclusion should be on destination.port, but
    # _arkime_port_exprs emits source.port -> covered ports are not excluded on
    # the inbound arm (false positives), same bug the BPF side had.
    # Also reconcile the UDP arm's direction: it uses destination.ip == host,
    # whereas per-term arkime_udp_violation treats the host as source.ip.
    # Not fixed inline because Arkime queries can't be compile-checked the way
    # BPF can; needs a query run against real data + a regression test.
    dst = _arkime_dst_host(host_ips)
    src = _arkime_src_host(host_ips)
    exprs = []
    if covered_tcp:
        not_ports = " && ".join(f"!({e})" for e in _arkime_port_exprs(covered_tcp))
        exprs.append(f"({dst} && protocols == tcp && tcpflags.syn == 1 && tcpflags.syn-ack == 0 && {not_ports})")
        exprs.append(f"({dst} && protocols == tcp && tcpflags.syn-ack == 1 && {not_ports})")
    else:
        exprs.append(f"({dst} && protocols == tcp && tcpflags.syn == 1 && tcpflags.syn-ack == 0)")
        exprs.append(f"({dst} && protocols == tcp && tcpflags.syn-ack == 1)")
    if covered_udp:
        not_ports = " && ".join(f"!({e})" for e in _arkime_port_exprs(covered_udp))
        exprs.append(f"({dst} && protocols == udp && {not_ports})")
    else:
        exprs.append(f"({dst} && protocols == udp)")
    return " ||\n    ".join(exprs)


# ---------------------------------------------------------------------------
# Core: walk policy and generate filters
# ---------------------------------------------------------------------------

def generate_filters(policy, defs, default_host_ips):
    """
    Returns list of dicts:
        name, comment, bpf, arkime

    Per-term host IPs come from destination-address if present, falling back
    to default_host_ips (resolved from metadata.host). This makes zone files
    work correctly: each term names its target hosts via destination-address.

    Last entry is always the "uncovered ports" catch-all.
    """
    covered_tcp    = set()
    covered_udp    = set()
    all_host_ips   = set()   # union across all terms, for the catch-all
    results        = []

    for filt in policy.get("filters", []):
        # A BPF ingress program carries the inbound half only. Membership, not
        # "not egress": a filter whose direction the document never states is
        # neither half, and compiling it as ingress would open ports the policy
        # never put inbound (firru.policy.filter_directions).
        if DIR_IN not in filter_directions(filt):
            continue

        for term in filt.get("terms", []):
            action = term.get("action", "accept").lower()
            if action in ("deny", "drop", "reject"):
                continue

            proto    = term.get("protocol")
            svc      = term.get("destination-port")
            source   = term.get("source-address")
            dst_addr = term.get("destination-address")

            # Per-term host IPs: destination-address if present, else metadata.host
            if dst_addr:
                term_host_ips = get_host_ips(dst_addr, defs)
            else:
                term_host_ips = default_host_ips

            if not term_host_ips:
                continue

            all_host_ips.update(term_host_ips)

            # Blanket terms (loopback, icmp — no port): skip
            if not svc:
                continue

            is_tcp = proto in ("tcp", None)
            is_udp = proto in ("udp", None)

            tcp_ports = resolve_ports(svc, "tcp", defs) if is_tcp else []
            udp_ports = resolve_ports(svc, "udp", defs) if is_udp else []

            allowed_nets = resolve_nets(source, defs)

            # Track covered ports regardless of restriction
            covered_tcp.update(tcp_ports)
            covered_udp.update(udp_ports)

            if allowed_nets is None:
                # No source restriction → no violation filter needed
                continue

            for run in _port_ranges(tcp_ports):
                label = _port_label(run)
                base = {"proto": "tcp", "port": run, "host_ips": term_host_ips,
                        "allowed_nets": allowed_nets, "source_token": source}
                results.append({
                    **base,
                    "name":    term["name"],
                    "layer":   "centralized-fw",
                    "comment": f"tcp/{label} restricted to {source} — SYN inbound (centralized FW failed, host FW may hold)",
                    "bpf":     bpf_tcp_syn(term_host_ips, run, allowed_nets),
                    "arkime":  arkime_tcp_syn(term_host_ips, run, allowed_nets),
                })
                results.append({
                    **base,
                    "name":    term["name"],
                    "layer":   "both-fw",
                    "comment": f"tcp/{label} restricted to {source} — SYN-ACK outbound (both firewalls failed)",
                    "bpf":     bpf_tcp_synack(term_host_ips, run, allowed_nets),
                    "arkime":  arkime_tcp_synack(term_host_ips, run, allowed_nets),
                })
            for run in _port_ranges(udp_ports):
                results.append({
                    "name":         term["name"],
                    "comment":      f"udp/{_port_label(run)} restricted to {source} — response to non-allowed destination",
                    "bpf":          bpf_udp_violation(term_host_ips, run, allowed_nets),
                    "arkime":       arkime_udp_violation(term_host_ips, run, allowed_nets),
                    "proto":        "udp",
                    "port":         run,
                    "host_ips":     term_host_ips,
                    "allowed_nets": allowed_nets,
                    "source_token": source,
                })

    # Catch-all uses union of all host IPs seen across terms
    catchall_ips = sorted(all_host_ips) or default_host_ips
    if not catchall_ips:
        return results  # no IPs at all — skip catch-all rather than emit a broken filter

    # Catch-all: ports not covered by any accept term
    def _fmt_ranges(ports):
        if not ports:
            return "none"
        return ", ".join(str(lo) if lo == hi else f"{lo}-{hi}"
                         for lo, hi in _port_ranges(sorted(ports)))

    covered_summary = f"tcp={_fmt_ranges(covered_tcp)}, udp={_fmt_ranges(covered_udp)}"
    results.append({
        "name":         "uncovered-ports",
        "comment":      f"response on port not in policy — firewall-down detector (covered: {covered_summary})",
        "bpf":          bpf_uncovered(catchall_ips, covered_tcp, covered_udp),
        "arkime":       arkime_uncovered(catchall_ips, covered_tcp, covered_udp),
        "host_ips":     catchall_ips,
        "allowed_nets": None,   # always meaningful regardless of source
        "source_token": None,
        "covered_tcp":  covered_tcp,
        "covered_udp":  covered_udp,
    })

    return results


# ---------------------------------------------------------------------------
# nmap output
# ---------------------------------------------------------------------------

def _split_ips_by_version(host_ips):
    """Split IP list into (v4_list, v6_list)."""
    v4, v6 = [], []
    for ip in host_ips:
        try:
            (v6 if ip_address(ip).version == 6 else v4).append(ip)
        except ValueError:
            v4.append(ip)
    return v4, v6


def _nmap_commands(flag, port_arg, host_ips):
    """Yield nmap command strings, splitting v4 and v6."""
    v4, v6 = _split_ips_by_version(host_ips)
    if v4:
        yield f"nmap {flag} -n {port_arg} {' '.join(v4)}"
    if v6:
        yield f"nmap -6 {flag} -n {port_arg} {' '.join(v6)}"


def emit_nmap(results, from_ip=None):
    """
    Print nmap probe commands for each violation scenario.

    With --from-ip: skip terms where that IP is already in the allowed set
    (the test would succeed legitimately, not a meaningful probe).
    Uncovered-ports is always included — meaningful from any source.
    """
    def _nmap_exclude(ports):
        return ",".join(str(lo) if lo == hi else f"{lo}-{hi}"
                        for lo, hi in _port_ranges(sorted(ports)))

    skipped = 0
    for r in results:
        allowed_nets  = r.get("allowed_nets")
        source_token  = r.get("source_token")
        host_ips      = r.get("host_ips", [])
        name          = r["name"]
        comment       = r["comment"]

        # Uncovered-ports: always include
        if name == "uncovered-ports":
            covered_tcp = r.get("covered_tcp", set())
            covered_udp = r.get("covered_udp", set())
            print(f"# [{name}] {comment}")
            excl_tcp = f"--exclude-ports {_nmap_exclude(covered_tcp)} " if covered_tcp else ""
            excl_udp = f"--exclude-ports {_nmap_exclude(covered_udp)} " if covered_udp else ""
            for cmd in _nmap_commands("-sS", f"-p 1-65535 {excl_tcp}".strip(), host_ips):
                print(cmd)
            for cmd in _nmap_commands("-sU", f"-p 1-65535 {excl_udp}".strip(), host_ips):
                print(cmd)
            print()
            continue

        # SYN vs SYN-ACK distinction is only meaningful for passive monitoring —
        # nmap always sends a SYN, so both-fw and centralized-fw emit the same command.
        # Emit only one entry per (proto, port, host_ips) combination.
        if r.get("layer") == "both-fw":
            continue

        # Source-restricted term: skip if from_ip is already allowed
        if from_ip and allowed_nets is not None:
            if ip_in_nets(from_ip, allowed_nets):
                skipped += 1
                continue

        proto    = r.get("proto", "tcp")
        port     = r.get("port")
        src_note = f"NOT in {source_token}" if source_token else "non-allowed source"

        print(f"# [{name}] {r['comment'].split(' — ')[0]}")
        if from_ip:
            print(f"# {from_ip} is outside {source_token} — test is meaningful")
        else:
            print(f"# Run from a host {src_note}")
        if proto == "tcp":
            print(f"# open = both FWs failed; use BPF/Arkime SYN filter to detect centralized-FW-only failure")

        flag = "-sS" if proto == "tcp" else "-sU"
        # port is a (lo, hi) run; nmap takes ranges natively
        for cmd in _nmap_commands(flag, f"-p {_port_label(port)}", host_ips):
            print(cmd)
        print()

    if from_ip and skipped:
        print(f"# ({skipped} terms skipped — {from_ip} is in the allowed set for those)")


def _fmt_ranges_str(ports):
    """Helper used by emit_nmap for the covered-ports comment."""
    return ", ".join(str(lo) if lo == hi else f"{lo}-{hi}"
                     for lo, hi in _port_ranges(sorted(ports)))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate violation-detection BPF/Arkime filters from an aerleon policy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # BPF output (default)
  aerleon-to-bpf --policy policies/pol/myhost_example_org.yml --defs def/

  # Feed directly into tcpdump
  tcpdump -i eth0 -n "$(aerleon-to-bpf --policy policies/pol/myhost.yml --defs def/ --combined)"

  # Arkime retrospective search
  aerleon-to-bpf --policy ... --format arkime

  # Both formats
  aerleon-to-bpf --policy ... --format both

  # nmap probes — all tests
  aerleon-to-bpf --policy ... --format nmap

  # nmap probes — only meaningful from this IP (skips terms where it's already allowed)
  aerleon-to-bpf --policy ... --format nmap --from-ip 10.1.2.3
        """,
    )
    parser.add_argument("--policy",   "-p", required=True,
                        help="Aerleon host policy YAML")
    parser.add_argument("--defs",     "-d", default=None,
                        help="Aerleon definitions directory (default: the def/ "
                             "nearest the policy, then ./def/, then firru's own)")
    parser.add_argument("--format",   "-F", default="bpf",
                        choices=["bpf", "arkime", "both", "nmap"],
                        help="Output format (default: bpf)")
    parser.add_argument("--combined", "-c", action="store_true",
                        help="Emit only the combined OR expression, suitable for shell embedding")
    parser.add_argument("--host-ip",  "-H", nargs="+", default=None,
                        help="Override host IP(s) instead of resolving from defs")
    parser.add_argument("--from-ip",  "-I", default=None,
                        help="IP of the scanning host; nmap output filtered to meaningful tests only")
    args = parser.parse_args()

    policy_path = Path(args.policy)
    if not policy_path.exists():
        print(f"Policy not found: {policy_path}", file=sys.stderr)
        sys.exit(1)

    with open(policy_path) as f:
        policy = yaml_handler.load(f)

    host_token = policy.get("metadata", {}).get("host")
    from firru.defs_dir import near
    defs       = naming.Naming(near([policy_path], args.defs))

    if args.host_ip:
        host_ips = args.host_ip
    elif host_token:
        host_ips = get_host_ips(host_token, defs)
    else:
        host_ips = []

    if not host_ips and host_token:
        print(f"Note: {host_token} resolved to no /32 hosts in the definitions "
              f"(networks.yml, or --host-ip) — relying on destination-address in terms",
              file=sys.stderr)

    results = generate_filters(policy, defs, host_ips)

    if not results:
        print("# No violation filters generated (no source-restricted terms found)")
        return

    # --combined: just the single ORed BPF expression, nothing else
    if args.combined:
        print(" or\n".join(r["bpf"] for r in results))
        return

    if args.format == "nmap":
        print(f"# Host: {host_token}  Policy: {policy_path}")
        if args.from_ip:
            print(f"# Scanning from: {args.from_ip}")
        print()
        emit_nmap(results, from_ip=args.from_ip)
        return

    do_bpf    = args.format in ("bpf", "both")
    do_arkime = args.format in ("arkime", "both")

    print(f"# Host: {host_token}  IPs: {', '.join(host_ips)}")
    print(f"# Policy: {policy_path}")
    print()

    all_bpf    = []
    all_arkime = []

    for r in results:
        print(f"# [{r['name']}] {r['comment']}")
        if do_bpf:
            print(r["bpf"])
            all_bpf.append(r["bpf"])
        if do_arkime:
            print(r["arkime"])
            all_arkime.append(r["arkime"])
        print()

    if len(results) > 1:
        if do_bpf:
            print("# --- Combined BPF (any violation) ---")
            print(" or\n".join(all_bpf))
            print()
        if do_arkime:
            print("# --- Combined Arkime (any violation) ---")
            print(" ||\n".join(all_arkime))
            print()


if __name__ == "__main__":
    main()
