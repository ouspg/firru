#!/usr/bin/env python3
"""
firru propose — edits to host policies from the traffic.

Reads aerleon host policies and their flows (the project's store, a JSONL
file, or a live Arkime) and proposes, per host:

  ingress  each term's sources narrowed to the peers seen; a source the site
           declares is kept (declared_sources); a listener nothing reached
           is a log-drop candidate, proposed as a logged deny
  egress   the allow-ANY stub replaced by terms from the observed destinations

Each host's proposal is written to the outdir (the project's proposals/) as
soon as it is read. With -o sh (the default) the edits are printed as firru
commands, one per line, each ending in its reason (firru.cli.propose_sh), so
what to apply is a grep. The policies themselves are never written.

When external (SINET/unknown) sources connect alongside internal ones, the
rule stays as ANY, but the comment shows what was actually observed so a
human can make an informed call.

    firru propose policies/pol/ --window night | grep observed | sh
    firru propose policies/pol/web1.yml --arkime http://localhost:8005/api --date 48

`firru check` (firru.cli.check) reads the same flows and reports what a
policy refuses of them.
"""

import argparse
import os
import ipaddress
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from aerleon.lib import naming
from ruyaml import YAML
from ruyaml.comments import CommentedMap, CommentedSeq

from firru.annotator import PolicyAnnotator
from firru.arkime import ArkimeAPI, SESSION_FIELDS, process_flow
from firru.cli.address_summarizer import (_default_asn_db, summarize,
                                          summarize_asn)
from firru.comments import TAG_AUTO, detached, tagged, set_term_comment, kept_comments_by_term
from firru.src_heuristics import declared_sources, load_profile, scored_ports
from firru.flows import Hits
from firru.policy import DIR_IN, DIR_OUT, filter_directions

# ---------------------------------------------------------------------------
# YAML setup
# ---------------------------------------------------------------------------

yaml_handler = YAML()
yaml_handler.indent(mapping=2, sequence=4, offset=2)
yaml_handler.preserve_quotes = True

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# How many individual tokens before we give up and fall back to ANY
# (and emit a group suggestion instead)
INDIVIDUAL_THRESHOLD = 5

# Max IPs to show in a comment
COMMENT_IP_LIMIT = 4


# ---------------------------------------------------------------------------
# What ANY means, when the sources cannot be tokenized
# ---------------------------------------------------------------------------

def external_counts(ip_counter, annotator):
    """{ip: hits} for the addresses no inventory token covers."""
    return {ip: n for ip, n in ip_counter.items()
            if annotator.annotate_ip(ip)["type"] == "EXTERNAL"}


def unresolved_note(ip_counter, annotator, budget=COMMENT_IP_LIMIT,
                    dns_store=None, asn_db=None, noun="src"):
    """One line saying what ANY covers for this term, or None if nothing does.

    `best_tokens` keeps a term at ANY the moment one source is unresolvable and
    then says nothing further, which is the whole of the review affordance
    today: a term the tightener declined to act on is indistinguishable from one
    it never looked at. This turns the silence into a sentence.

    Three answers, and which one it is decides whether a human can act:

      named   the addresses have DNS names, so the right fix is an inventory
              entry rather than a firewall edit
      blocks  they have a shape -- a few prefixes, or a few autonomous systems
      ANY     they have neither, and ANY is the accurate answer

    Nothing here changes a policy. It is a comment.
    """
    ext = external_counts(ip_counter, annotator)
    if not ext:
        return None

    if dns_store:
        named = {ip: dns_store[ip] for ip in ext if ip in dns_store}
        if named and len(named) == len(ext):
            top = sorted(named.items(), key=lambda kv: -ext[kv[0]])[:budget]
            shown = ", ".join(f"{n} ({ext[ip]}h)" for ip, n in top)
            more = f", +{len(named) - len(top)} more" if len(named) > len(top) else ""
            return (f"ANY covers {len(ext)} unresolved {noun}, all named: "
                    f"{shown}{more} -- name these in the inventory, not in the rule")

    if asn_db:
        try:
            summary = summarize_asn(ext, budget, asn_db, noun)
        except Exception:
            summary = summarize(ext, budget, noun)
    else:
        summary = summarize(ext, budget, noun)

    return (f"ANY covers {len(ext)} unresolved {noun}: {summary} -- "
            f"{_verdict(ext, summary, asn_db, noun)}")


def heavy_hitter_note(ip_counter, annotator, noun="src"):
    """Which unresolved peers carried the flows, or None. A comment only.

    The summary groups by prefix or AS and calls a spread "too scattered";
    this names the single addresses that mattered. On LSPR24 the X-Road
    server's federation peers: eight of sixteen addresses carry 87% of the
    flows. Only host-level heavy hitters are named. Prefix-level ones over
    a spread of unrelated clients are arbitrary slices, and prefix structure
    is what the summary line already reports, so with no single address at
    the share there is nothing to say.
    """
    ext = external_counts(ip_counter, annotator)
    if len(ext) < 2:
        return None
    from firru.heavy_hitters import heavy_hitters
    hosts = [(net, n) for net, n in heavy_hitters(ext)
             if net.prefixlen == net.max_prefixlen]
    if not hosts:
        return None
    total = sum(ext.values())
    shown = ", ".join(f"{net.network_address} {100 * n / total:.1f}%" for net, n in hosts)
    rest = total - sum(n for _, n in hosts)
    others = len(ext) - len(hosts)
    tail = f", the other {others} {100 * rest / total:.1f}%" if others else ""
    return (f"heavy hitters among {len(ext)} unresolved {noun} "
            f"({total} flows): {shown}{tail}")


def _verdict(ext, summary, asn_db=None, noun="src"):
    """Which of the answers this is, in the words a reviewer needs.

    Ordered by what a reader should act on first. Private space in an external
    bucket outranks everything else: it is not a firewall question at all, it is
    an inventory the tool was not given.

    "Has structure" is deliberately hard to earn. An earlier rule called any
    collapse structure, so 27 addresses in 22 unrelated universities read as
    "a named group would fit" -- which is the opposite of true. A group is only
    worth naming if most of the addresses are in a few of them, so the test is
    on the largest group's share, not on the group count.
    """
    private = [ip for ip in ext if ipaddress.ip_address(ip).is_private]
    if private:
        return (f"{len(private)} of {len(ext)} are private address space, so they "
                f"belong in the inventory rather than behind ANY")
    if len(ext) == 1:
        one = "destination" if noun == "dst" else "source"
        return f"a single {one}: name it or deny it, ANY is not the answer either way"

    sizes = _group_sizes(ext, asn_db)
    if not sizes:
        return "one group per address, so no summary narrows it and ANY stays"
    biggest = sizes[0]
    if biggest * 2 >= len(ext):
        return (f"{biggest} of {len(ext)} sit in one group, so a named group "
                f"would cover most of this")
    if sizes[0] == 1:
        return "one group per address, so no summary narrows it and ANY stays"
    return (f"{len(ext)} addresses spread over {len(sizes)} groups, largest {biggest}: "
            f"too scattered to name, so ANY stays")


def _group_sizes(ext, asn_db):
    """Addresses per group, largest first, by AS where one can be read."""
    if asn_db:
        try:
            from firru.cli.address_summarizer import asn_groups
            groups, unknown = asn_groups(ext, asn_db)
            sizes = sorted((d["n"] for d in groups.values()), reverse=True)
            if unknown["n"]:
                sizes.append(unknown["n"])
            return sorted(sizes, reverse=True)
        except Exception:
            pass
    from firru.cli.address_summarizer import prefix_group_sizes
    return prefix_group_sizes(ext)


# ---------------------------------------------------------------------------
# Token consolidation
# ---------------------------------------------------------------------------

def best_tokens(annotations, group_members=None):
    """
    Given annotate_ip() results for a set of IPs, return:
        (token_list, excess_note)

    token_list  — aerleon token(s) to put in source-address, or None
    excess_note — human-readable string about over-permitted hosts, or None

    Strategy:
    1. Any EXTERNAL source → keep ANY unchanged
    2. Single token → use it
    3. Greedy set cover using actual group membership (parents lists).
       Groups are only used if ALL observed hosts they cover are genuine members
       (no fabricated over-permission).  For each group chosen, the unobserved
       members of that group also gain access — this is noted in excess_note.
       Remaining uncovered hosts are listed individually.
       Total token count must fit within INDIVIDUAL_THRESHOLD.
    4. > threshold, no cover → keep ANY unchanged
    """
    relevant = [a for a in annotations if a["type"] in ("HOST", "GROUP", "EXTERNAL")]
    if not relevant:
        return None, None

    if any(a["type"] == "EXTERNAL" for a in relevant):
        return None, None  # external present → can't tighten below ANY

    host_tokens = []
    for a in relevant:
        if a["type"] == "HOST":
            tok = a["host"]
        else:
            tok = a["parents"][0] if a.get("parents") else None
        if tok and tok not in host_tokens:
            host_tokens.append(tok)

    if not host_tokens:
        return None, None

    if len(host_tokens) == 1:
        return host_tokens, None

    observed = frozenset(host_tokens)

    if group_members:
        candidate_groups = set()
        for a in relevant:
            if a["type"] == "HOST":
                candidate_groups.update(a.get("parents", []))

        remaining = set(observed)
        chosen    = []
        excess_parts = []

        while remaining:
            best_grp      = None
            best_coverage = 1  # require ≥ 2 to justify a group token
            best_size     = float('inf')

            # Sorted, so a tie between equal groups goes the same way in
            # every process (set order follows the hash seed).
            for grp in sorted(candidate_groups):
                members  = group_members.get(grp, frozenset())
                coverage = len(members & remaining)
                excess   = len(members) - len(members & observed)
                size     = len(members)
                # Veto if group permits more unobserved hosts than it covers observed ones
                if excess > coverage:
                    continue
                # Prefer max coverage; break ties by smallest group (tightest)
                if coverage > best_coverage or (coverage == best_coverage and size < best_size):
                    best_grp      = grp
                    best_coverage = coverage
                    best_size     = size

            if best_grp:
                chosen.append(best_grp)
                members  = group_members[best_grp]
                excess   = sorted(members - observed)
                if excess:
                    excess_parts.append(f"{best_grp} also permits: {', '.join(excess)}")
                remaining -= members & remaining
            else:
                ungrouped = sorted(remaining)
                chosen.extend(ungrouped)
                if chosen and any(g in group_members for g in chosen if g not in ungrouped):
                    excess_parts.append(
                        f"seen in flows but outside existing groups — verify group membership"
                        f" or allow explicitly: {', '.join(ungrouped)}")
                remaining.clear()

        if len(chosen) <= INDIVIDUAL_THRESHOLD:
            return chosen, "\n".join(excess_parts) or None

        # Too many tokens even with grouping → ANY
        return None, None

    # No group_members available — individual list or ANY. Sorted: the
    # order the addresses arrived in follows the service members' iteration
    # order, which varies between runs, and the list is written into git.
    host_tokens = sorted(host_tokens)
    if len(host_tokens) <= INDIVIDUAL_THRESHOLD:
        return host_tokens, None

    return None, None


# ---------------------------------------------------------------------------
# Comment builder
# ---------------------------------------------------------------------------

def summarise_annotations(ip_counter, annotator):
    """
    Given a Counter of {ip: hit_count}, return a summary string like:
        "1234 hits: ZONE (hostname...) | 42 hits: ZONE2 (host1, host2)"
    and also group IPs by resolved token for best_tokens() input.

    Returns:
        comment     — str
        annotations — list of annotate_ip() results (one per unique IP)
        raw_ips     — {ip: hits} for IPs that couldn't map to any token
    """
    token_groups = defaultdict(lambda: {"hits": 0, "ips": []})  # token → {hits, ips}
    raw_ips = {}
    unanswered = getattr(ip_counter, "unanswered", {})

    for ip, count in ip_counter.items():
        ann = annotator.annotate_ip(ip)
        if ann["type"] == "EXTERNAL":
            token_groups["EXTERNAL"]["hits"] += count
            token_groups["EXTERNAL"]["ips"].append(ip)
        elif ann["type"] in ("HOST", "GROUP"):
            tok = ann["host"] if ann["type"] == "HOST" else (ann["parents"][0] if ann.get("parents") else ip)
            if tok.startswith("REQ_TOKEN_"):
                # Unknown host in a known subnet — keep as raw IP
                raw_ips[ip] = count
                token_groups[f"raw:{ip}"]["hits"] += count
                token_groups[f"raw:{ip}"]["ips"].append(ip)
            else:
                token_groups[tok]["hits"] += count
                token_groups[tok]["ips"].append(ip)
        elif ann["type"] == "ANY":
            pass  # loopback / wildcard — skip
        else:
            raw_ips[ip] = count

    # A fixed order, so the same flows always write the same comment: the
    # comment lives in git, and a reordering would read as a change. Groups by
    # hits, then name; sample addresses by their own hits, then address.
    def _ip_key(ip):
        try:
            a = ipaddress.ip_address(ip)
            return (-ip_counter[ip], a.version, int(a))
        except ValueError:
            return (-ip_counter[ip], 9, 0, ip)

    def _refused(hits, ips):
        """Say so when a group's flows went unanswered: all of them, or some."""
        n = sum(unanswered.get(ip, 0) for ip in ips)
        if not n:
            return ""
        return " [never answered]" if n == hits else f" [{n} unanswered]"

    parts = []
    for tok, data in sorted(token_groups.items(), key=lambda x: (-x[1]["hits"], x[0])):
        hits = data["hits"]
        ips = sorted(data["ips"], key=_ip_key)
        tag = _refused(hits, ips)
        if tok == "EXTERNAL":
            sample = ", ".join(ips[:COMMENT_IP_LIMIT])
            extra = f" and {len(ips) - COMMENT_IP_LIMIT} more" if len(ips) > COMMENT_IP_LIMIT else ""
            parts.append(f"{hits} hits: EXTERNAL ({sample}{extra}){tag}")
        elif tok.startswith("raw:"):
            ip = ips[0]
            parts.append(f"{hits} hits: {ip} (unresolved){tag}")
        else:
            sample = ", ".join(ips[:COMMENT_IP_LIMIT])
            extra = f" and {len(ips) - COMMENT_IP_LIMIT} more" if len(ips) > COMMENT_IP_LIMIT else ""
            parts.append(f"{hits} hits: {tok} ({sample}{extra}){tag}")

    annotations = [annotator.annotate_ip(ip) for ip in ip_counter]
    return " | ".join(parts), annotations, raw_ips


# ---------------------------------------------------------------------------
# Host IP resolution
# ---------------------------------------------------------------------------

def get_host_ips(host_token, defs):
    """Return list of IP address strings for the host token (v4 + v6)."""
    try:
        nets = defs.GetNetAddr(host_token)
        return [str(n.network_address) for n in nets]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Flow collection
# ---------------------------------------------------------------------------

_MULTICAST_NETS = [
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("255.255.255.255/32"),
]

def _is_broadcast_or_multicast(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _MULTICAST_NETS) or addr.is_multicast
    except ValueError:
        return False


def _count(bucket, peer, n, unanswered):
    bucket[peer] += n
    if unanswered and isinstance(bucket, Hits):   # a plain Counter keeps hits only
        bucket.unanswered[peer] += unanswered


def _bucket_flow(flow, host_ips_set, defs, ingress, egress, ingress_ports, egress_ports):
    """Sort one normalised flow dict into ingress/egress counters.

    `n` is how many flows the record stands for: 1 from a row iterator, the
    group size from `iter_flow_groups`. Counting groups instead of flows would
    change every hit number in every comment, so the weight is carried through.
    """
    proto    = flow["protocol"]
    dst_port = flow["dst_port"]
    n        = flow.get("n", 1)
    unanswered = flow.get("unanswered", n if flow.get("responded") is False else 0)

    if _is_broadcast_or_multicast(flow["src_ip"]) or _is_broadcast_or_multicast(flow["dst_ip"]):
        return

    # ICMP and other port-less protocols: bucket by protocol only
    if proto in ("icmp", "icmpv6") or not dst_port:
        svc = proto.upper()
    else:
        try:
            svcs = defs.GetPortParents(dst_port, proto)
            svc  = svcs[0] if svcs else f"unknown-{proto}-{dst_port}"
        except Exception:
            svc = f"unknown-{proto}-{dst_port}"

    if flow["dst_ip"] in host_ips_set:
        _count(ingress[(proto, svc)], flow["src_ip"], n, unanswered)
        if dst_port:
            ingress_ports[(proto, svc)][dst_port] += n
    elif flow["src_ip"] in host_ips_set:
        _count(egress[(proto, svc)], flow["dst_ip"], n, unanswered)
        if dst_port:
            egress_ports[(proto, svc)][dst_port] += n


def _widen(span, flow):
    """Stretch span, a [first, last] list, to cover a flow or a flow group."""
    a = flow.get("first", flow.get("timestamp"))
    b = flow.get("last", flow.get("timestamp"))
    if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        return
    span[0] = a if span[0] is None else min(span[0], a)
    span[1] = b if span[1] is None else max(span[1], b)


def _when(t):
    """An epoch timestamp as UTC, seconds; milli- or microseconds tolerated."""
    from datetime import datetime, timezone
    while t > 1e11:
        t /= 1000
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def window_line(source, span):
    """The header line that says which flows the comments below count."""
    if span is None or span[0] is None:
        return f"Flows: {source}, none for this host"
    return f"Flows: {source}, {_when(span[0])} to {_when(span[1])}"


def collect_flows_from_file(flows_file, host_ips, defs, span=None, window=None):
    """
    Read pre-normalised flows from a .jsonl file (process_flow() output).
    Filters to flows involving host_ips.
    """
    from firru.flows import iter_flow_groups
    host_ips_set = set(host_ips)
    ingress       = defaultdict(Hits)
    egress        = defaultdict(Hits)
    ingress_ports = defaultdict(Counter)
    egress_ports  = defaultdict(Counter)

    for flow in iter_flow_groups(flows_file, host_ips=host_ips_set, span=window):
        _bucket_flow(flow, host_ips_set, defs, ingress, egress, ingress_ports, egress_ports)
        if span is not None:
            _widen(span, flow)

    return ingress, egress, ingress_ports, egress_ports


def collect_flows_multi(flows_file, host_ips_by_token, defs, spans=None, window=None):
    """
    Bucket a single flows file for many hosts in ONE pass.

    Calling collect_flows_from_file() per host re-reads and re-parses the whole
    file once per host, which for a shared capture is the dominant cost: 35
    hosts over a 9M-line dump is 35 full scans. Here every host's addresses go
    into one index, each line is parsed once, and the flow is bucketed into
    every host it involves (east-west flows land in two hosts — ingress for the
    destination, egress for the source).

    Returns {host_token: (ingress, egress, ingress_ports, egress_ports)}.
    `window` (start, end) in epoch seconds limits the read to that time;
    `spans` collects, per host, the first and last flow actually read.

    From a parquet store, iter_flow_groups pushes the host-address filter down
    and hands back counted groups, so the cost follows the matched flows; a
    JSONL dump is still parsed line by line.
    """
    from firru.flows import iter_flow_groups

    ip_owner = defaultdict(list)
    for token, ips in host_ips_by_token.items():
        for ip in ips:
            ip_owner[ip].append(token)

    host_ip_sets = {t: set(ips) for t, ips in host_ips_by_token.items()}
    buckets = {
        t: (defaultdict(Hits), defaultdict(Hits),
            defaultdict(Counter), defaultdict(Counter))
        for t in host_ips_by_token
    }

    scanned = matched = groups = 0
    # The fleet IP union pushes down as a parquet predicate; on JSONL it filters
    # in Python, exactly as before.
    for flow in iter_flow_groups(flows_file, host_ips=set(ip_owner), span=window):
        scanned += flow.get("n", 1)
        groups += 1
        owners = ip_owner.get(flow.get("src_ip"))
        dst_owners = ip_owner.get(flow.get("dst_ip"))
        if not owners and not dst_owners:
            continue
        matched += flow.get("n", 1)
        for token in set((owners or []) + (dst_owners or [])):
            ingress, egress, ingress_ports, egress_ports = buckets[token]
            _bucket_flow(flow, host_ip_sets[token], defs,
                         ingress, egress, ingress_ports, egress_ports)
            if spans is not None:
                _widen(spans.setdefault(token, [None, None]), flow)

    print(f"  {scanned} flows in {groups} conversations, "
          f"{matched} involving a known host", file=sys.stderr)
    return buckets


def collect_flows(arkime, host_ips, defs, date="48", start_time=None, stop_time=None,
                  span=None):
    """
    Query Arkime for all flows to/from host_ips.

    Returns:
        ingress: {(proto, svc_token): Counter({src_ip: hit_count})}
        egress:  {(proto, svc_token): Counter({dst_ip: hit_count})}
    """
    host_ips_set  = set(host_ips)
    ingress       = defaultdict(Hits)
    egress        = defaultdict(Hits)
    ingress_ports = defaultdict(Counter)
    egress_ports  = defaultdict(Counter)

    if not host_ips:
        return ingress, egress, ingress_ports, egress_ports

    time_kwargs = dict(date=date, start_time=start_time, stop_time=stop_time)
    ip_filter = " || ".join(
        f"ip == {ip}" for ip in host_ips
    )
    for raw in arkime.search(ip_filter, fields=SESSION_FIELDS, **time_kwargs):
        flow = process_flow(raw)
        if not flow:
            continue
        _bucket_flow(flow, host_ips_set, defs, ingress, egress, ingress_ports, egress_ports)
        if span is not None:
            _widen(span, flow)

    return ingress, egress, ingress_ports, egress_ports


# ---------------------------------------------------------------------------
# Would-be-blocked check
# ---------------------------------------------------------------------------

def ip_matches_source(ip, source_addr, annotator):
    """True if ip would be accepted by source_addr token (or list of tokens).

    ANY_V4 and ANY_V6 admit their own family only: an IPv4 flow on an ANY_V6
    term is refused, and counting it as admitted hid exactly the dual-stack
    listeners recorded as IPv6-only. An address that does not parse passes,
    the optimistic side, so a pass never overstates a block.
    """
    if not source_addr:
        return True  # no restriction

    tokens = [source_addr] if isinstance(source_addr, str) else list(source_addr)
    if "ANY" in tokens:
        return True  # unrestricted
    try:
        family = ipaddress.ip_address(ip).version
    except ValueError:
        family = None
    for tok, fam in (("ANY_V4", 4), ("ANY_V6", 6)):
        if tok in tokens and family in (fam, None):
            return True
    named = [t for t in tokens if t not in ("ANY_V4", "ANY_V6")]
    if not named:
        return False

    ann    = annotator.annotate_ip(ip)
    actual = ann.get("host", "")
    parents = set(ann.get("parents", []))
    covered = {actual} | parents

    return bool(covered & set(named))


def _annotate_token(ip, annotator):
    """Return best token name for an IP, or None if only the IP itself."""
    ann = annotator.annotate_ip(ip)
    tok = ann.get("host") or (ann["parents"][0] if ann.get("parents") else None)
    return tok if tok and tok != ip else None


# IP protocols that carry no port, so nothing about them belongs in a field
# called "port". Protocol 4 is the one that matters in practice: it is IPIP,
# the encapsulation a Calico or Flannel overlay runs between Kubernetes nodes,
# and rendering it as `service: '4'` under "port not in policy (4)" made a real
# uncovered protocol read as a parse artifact. A finding a reviewer skims past
# is not a finding.
IP_PROTO_NAMES = {
    0: "hopopt", 2: "igmp", 4: "ipip", 41: "ipv6-encap", 47: "gre",
    50: "esp", 51: "ah", 58: "icmpv6", 89: "ospf", 103: "pim",
    112: "vrrp", 132: "sctp",
}


def proto_label(svc):
    """A bare protocol number rendered as its name, anything else unchanged."""
    text = str(svc)
    if text.isdigit():
        return IP_PROTO_NAMES.get(int(text), f"ip-proto-{text}")
    return text


def _blocked_sort_key(b):
    """
    Named services first, then by hits. The tail of an ingress capture is
    one-hit connections to random high ports; on LSPR24 that is 220 of 251
    entries, and left interleaved by hit count it buries the ~30 that name a
    service somebody has to make a decision about.
    """
    svc = str(b.get("svc") or "")
    unnamed = svc.startswith("unknown-") or svc.isdigit()
    # Ties broken by value, so equal counts do not come out in arrival order
    # (which varies between runs and would read as a change in git).
    return (unnamed, -b["hits"], str(b.get("proto") or ""), svc,
            str(b.get("src_ip") or ""), str(b.get("reason") or ""))


def _unanswered(ip_counter, ip):
    return getattr(ip_counter, "unanswered", {}).get(ip, 0)


def find_blocked(ingress_flows, tightened_terms, annotator, defs, ingress_ports):
    """
    For each observed ingress (proto, svc) → src_ips,
    check if the proposed terms would accept them.

    Coverage is decided on the **resolved port surface** (policy.terms_surface),
    not by comparing the term's destination-port token to the flow's service
    name: a term holding a group token covers its ports under whatever name the
    flow was bucketed, where string matching reported every such flow blocked.
    ``ingress_ports`` carries the actual ports behind each (proto, svc) bucket.

    Returns list of dicts: {proto, svc, src_ip, src_token, hits, proposed_src, reason}
    """
    from firru.policy import DIR_IN, terms_surface

    blocked = []
    surface, blanket_proto, has_catch_all = terms_surface(
        defs, list(tightened_terms), DIR_IN)
    if has_catch_all:
        return []

    for (proto, svc), ip_counter in ingress_flows.items():
        # Skip protocols covered by a blanket term (icmp, icmpv6, etc.)
        if proto in blanket_proto:
            continue

        ports = sorted((ingress_ports or {}).get((proto, svc), {}))
        covering, uncovered, seen = [], [], set()
        for p in ports:
            term = surface.get((DIR_IN, proto, p))
            if term is None:
                uncovered.append(p)
            elif id(term) not in seen:
                seen.add(id(term))
                covering.append(term)

        if not ports or uncovered:
            # No term covers (some of) the observed ports → those flows drop.
            # A protocol with no ports at all is a different statement from a
            # port that is missing, and has to say so.
            portless = not ports and str(svc).isdigit()
            missing = ",".join(str(p) for p in uncovered) or proto_label(svc)
            for ip, hits in ip_counter.most_common():
                blocked.append({
                    "proto": proto, "svc": proto_label(svc), "src_ip": ip,
                    "src_token": _annotate_token(ip, annotator),
                    "hits": hits, "unanswered": _unanswered(ip_counter, ip),
                    # No term exists, so there is no proposed source to state;
                    # the reason carries it. Leave the key out rather than
                    # writing a sentinel string into a source-address field.
                    "proposed_src": None,
                    "reason": (f"protocol not in policy ({missing})" if portless
                               else f"port not in policy ({missing})"),
                })
            continue

        # The bucket's source counter is not split per port; when several ports
        # share the bucket, an IP passes if any covering term admits it — the
        # optimistic side, so a pass here never overstates a block.
        sources = [t.get("source-address") for t in covering]
        for ip, hits in ip_counter.items():
            if not any(ip_matches_source(ip, src, annotator) for src in sources):
                shown = sources[0] if len(sources) == 1 else sources
                blocked.append({
                    "proto": proto, "svc": proto_label(svc), "src_ip": ip,
                    "src_token": _annotate_token(ip, annotator),
                    "hits": hits, "unanswered": _unanswered(ip_counter, ip),
                    "proposed_src": shown,
                    "reason": f"src not covered by {shown}",
                })

    return sorted(blocked, key=_blocked_sort_key)


# ---------------------------------------------------------------------------
# Ingress tightening
# ---------------------------------------------------------------------------

def load_host_metadata(defs_dir):
    """The host metadata synth reads by default, <defs>/host_metadata.json;
    {} where there is none or it is empty."""
    path = os.path.join(defs_dir, "host_metadata.json")
    try:
        text = Path(path).read_text()
    except OSError:
        return {}
    return json.loads(text) if text.strip() else {}


def tighten_ingress(in_filter_terms, ingress_flows, annotator, defs, verbose=False,
                    ingress_ports=None, dns_store=None, asn_db=None, any_rows=None,
                    host_token=None, declared=None):
    """
    Rebuild ingress terms with tightened source-address values.

    Returns:
        terms          — CommentedSeq of tightened terms
        unused         — list of dicts: accept terms nothing matched in the window,
                         each a log-drop candidate
        n_changed      — how many terms got a new source

    `declared(service)` gives the sources the site's heuristics declare for a
    service on this host. A term never loses one of those it still has: the
    traffic narrows what was inferred, review decides what was declared.
    """
    terms         = CommentedSeq()
    unused        = []

    changed    = CommentedSeq()
    unchanged  = CommentedSeq()
    deny_terms = CommentedSeq()
    n_changed  = 0

    # Comment contract: rewrite only our own [auto] lines; carry every human
    # and [score] line on each source term forward untouched.
    kept_map = kept_comments_by_term(in_filter_terms)

    for term in in_filter_terms:
        action = term.get("action", "accept").lower()
        if action in ("deny", "drop", "reject"):
            deny_terms.append(detached(term))
            continue

        proto = term.get("protocol")
        svc   = term.get("destination-port")
        key   = (proto, svc)

        new_term = detached(term)

        # For service group tokens (e.g. WINDOWS-DC-BASE), aggregate flows
        # across all member service tokens since flows are bucketed per-port.
        def _svc_label(svc_name, eproto, port_part, ip_ctr):
            base = f"{svc_name}/{eproto}/{port_part}"
            if not verbose:
                return base
            top = [annotator.annotate_ip(ip).get("host", ip) or ip
                   for ip, _ in sorted(ip_ctr.items(), key=lambda kv: (-kv[1], kv[0]))[:COMMENT_IP_LIMIT]]
            return f"{base} [{','.join(top)}]"

        def _resolve_flows(proto, svc):
            """Returns (Counter, port_summary_str) or (None, None)."""
            merged = Hits()
            seen_svcs = []

            # Direct hit: flows already bucketed under this token (e.g. RPC dynamic
            # ports land under WINDOWS-DC-BASE because it's first in GetPortParents).
            if (proto, svc) in ingress_flows:
                ip_ctr = ingress_flows[(proto, svc)]
                merged.merge(ip_ctr)
                port_ctr = (ingress_ports or {}).get((proto, svc), {})
                ports_str = ",".join(str(p) for p in sorted(port_ctr, key=lambda x: (-port_ctr[x], x))[:5])
                label = _svc_label(svc, proto or "", ports_str or "direct", ip_ctr)
                seen_svcs.append(label)
                # Don't return yet — continue to find member-level flows for port_summary.

            # Expand as a service group to find member-level flows.
            try:
                members = defs.GetService(svc)
            except Exception:
                # Not a group or not found — return direct hit if any.
                return (merged, None) if merged else (None, None)

            for entry in members:
                port_part, entry_proto = entry.rsplit('/', 1)
                entry_proto = entry_proto.lower()
                # When term has no protocol, accept all members; otherwise filter.
                if proto and entry_proto != proto.lower():
                    continue
                if '-' in port_part:
                    # Port range — scan ingress_flows for tokens whose definition
                    # includes this range entry (avoids iterating 16k ports).
                    for (fproto, fsvc), ip_ctr in ingress_flows.items():
                        if fproto != entry_proto or fsvc == svc:
                            continue
                        try:
                            if entry in defs.GetService(fsvc):
                                merged.merge(ip_ctr)
                                label = _svc_label(fsvc, entry_proto, port_part, ip_ctr)
                                if label not in seen_svcs:
                                    seen_svcs.append(label)
                        except Exception:
                            pass
                else:
                    try:
                        port = int(port_part)
                        parents = defs.GetPortParents(port, entry_proto)
                        member_svc = parents[0] if parents else str(port)
                    except Exception:
                        member_svc = port_part
                    if member_svc == svc:
                        continue  # already counted in direct hit above
                    if (entry_proto, member_svc) in ingress_flows:
                        ip_ctr = ingress_flows[(entry_proto, member_svc)]
                        merged.merge(ip_ctr)
                        label = _svc_label(member_svc, entry_proto, port_part, ip_ctr)
                        if label not in seen_svcs:
                            seen_svcs.append(label)

            if not merged:
                return None, None
            # The direct hit first, then member services in a fixed order (the
            # members' iteration order varies between runs).
            direct = seen_svcs[:1] if (proto, svc) in ingress_flows else []
            seen_svcs = direct + sorted(seen_svcs[len(direct):])
            port_summary = f"via: {', '.join(seen_svcs)}" if seen_svcs else None
            return merged, port_summary

        ip_counter, port_summary = _resolve_flows(proto, svc)
        if not svc or ip_counter is None:
            set_term_comment(
                new_term,
                [tagged(TAG_AUTO, "no flows observed in window — source unchanged"
                        + ("; log-drop candidate" if svc else ""))],
                kept_map.get(term.get("name"), []),
            )
            # One window without a flow is not proof the service is unused:
            # the term goes to log-drop, where what it would refuse is still
            # recorded, before anyone drops it. Its source does not matter;
            # a listener at ANY that nothing reached is the same finding.
            if svc:
                unused.append({
                    "name":   term.get("name", ""),
                    "proto":  proto,
                    "svc":    svc,
                    "source": term.get("source-address", "ANY"),
                })
            unchanged.append(new_term)
            continue

        total_hits = sum(ip_counter.values())
        comment, annotations, raw_ips = summarise_annotations(ip_counter, annotator)
        comment = f"{total_hits} flows total | {comment}"
        if port_summary:
            comment = f"{comment} | {port_summary}"

        token_list, excess_note = best_tokens(annotations, annotator.group_members)

        old_src = term.get("source-address")
        old_tokens = [old_src] if isinstance(old_src, str) else list(old_src or [])
        floor = ([t for t in old_tokens if t in declared(svc)]
                 if declared and svc and token_list and "ANY" not in token_list else [])
        kept = [t for t in floor if t not in token_list]
        if kept:
            token_list = list(token_list) + kept
            comment = (f"{comment}\nkept, declared by the site's heuristics: "
                       f"{', '.join(kept)}")
        was_changed = False
        if token_list:
            new_src = token_list[0] if len(token_list) == 1 else token_list
            new_term["source-address"] = new_src
            if old_src != new_src:
                old_str = (old_src if isinstance(old_src, str)
                           else ", ".join(old_src) if old_src else "ANY")  # none = any source
                new_term.yaml_add_eol_comment(f"was: {old_str}", "source-address")
                was_changed = True
                n_changed += 1
        # else: keep existing source-address (ANY or whatever was set)

        if excess_note:
            comment = f"{comment}\nNote: {excess_note}"
        if not token_list:
            note = unresolved_note(ip_counter, annotator,
                                   dns_store=dns_store, asn_db=asn_db)
            if note:
                comment = f"{comment}\n{note}"
                heavy = heavy_hitter_note(ip_counter, annotator)
                if heavy:
                    comment = f"{comment}\n{heavy}"
                if any_rows is not None:
                    any_rows.append((host_token, term.get("name"),
                                     external_counts(ip_counter, annotator)))
        auto_lines = [tagged(TAG_AUTO, ln) for ln in comment.split("\n") if ln.strip()]
        set_term_comment(new_term, auto_lines, kept_map.get(term.get("name"), []))

        if was_changed:
            changed.append(new_term)
        else:
            unchanged.append(new_term)

    # Changed terms first (need review), then unchanged, then deny rules at end
    for t in changed:
        terms.append(t)
    for t in unchanged:
        terms.append(t)
    for t in deny_terms:
        terms.append(t)

    return terms, unused, n_changed


# ---------------------------------------------------------------------------
# Egress generation
# ---------------------------------------------------------------------------

def build_egress_terms(egress_flows, annotator, defs, dns_store=None, asn_db=None,
                       any_rows=None, host_token=None):
    """
    Build egress terms from observed outbound flows.
    Replaces the allow-ANY placeholder with real destination terms + drop-ANY.
    Returns CommentedSeq.
    """
    terms = CommentedSeq()

    # Loopback + ICMP are always present regardless of observed flows
    for name, extra in [
        ("allow-loopback", {"source-address": "LOOPBACK"}),
        ("allow-icmp",     {"protocol": "icmp"}),
        ("allow-icmpv6",   {"protocol": "icmpv6"}),
    ]:
        t = CommentedMap()
        t["name"]   = name
        t["action"] = "accept"
        t.update(extra)
        terms.append(t)

    if not egress_flows:
        t = CommentedMap()
        t.yaml_set_start_comment(tagged(TAG_AUTO, "no egress flows observed — placeholder kept"))
        t["name"]   = "allow-ANY"
        t["action"] = "accept"
        terms.append(t)
        return terms

    unnamed = []
    for (proto, svc), ip_counter in sorted(egress_flows.items()):
        # A port with no name gets a note, not a term, as in synthesis: a term
        # naming an undefined service does not compile, and inventing a token
        # here would decide a name nobody chose. The allow-ANY fallback below
        # still carries the traffic until someone names it.
        if svc.startswith("unknown-"):
            unnamed.append((svc, sum(ip_counter.values()), len(ip_counter)))
            continue

        comment, annotations, raw_ips = summarise_annotations(ip_counter, annotator)
        token_list, _ = best_tokens(annotations, annotator.group_members)

        term_name = (
            f"allow-{proto}-{svc}"
            if len(svc) < 18
            else f"allow-{proto}-{svc[:18]}"
        )
        t = CommentedMap()
        t.yaml_set_start_comment(tagged(TAG_AUTO, comment))
        t["name"]     = term_name
        t["protocol"] = proto
        if svc.upper() != proto.upper():
            t["destination-port"] = svc

        if token_list:
            dst = token_list[0] if len(token_list) == 1 else token_list
            if dst not in ("ANY", "ANY_V4", "ANY_V6"):
                t["destination-address"] = dst

        # Raw unresolved destinations go in a comment (aerleon takes no inline
        # addresses). A CDN has no common prefix by design, so the ASN grouping
        # is the one that says anything here.
        note = unresolved_note(ip_counter, annotator, dns_store=dns_store,
                               asn_db=asn_db, noun="dst")
        if note:
            t["comment"] = note
            if any_rows is not None:
                any_rows.append((host_token, term_name,
                                 external_counts(ip_counter, annotator)))
        elif raw_ips:
            raw_note = ", ".join(
                f"{ip} ({h}h)" for ip, h in sorted(raw_ips.items(), key=lambda x: -x[1])[:4]
            )
            t["comment"] = f"unresolved: {raw_note}"

        t["action"] = "accept"
        terms.append(t)

    # Keep allow-ANY as fallback — replace with deny-ANY manually when confident
    # the observed egress terms are complete.
    fallback = CommentedMap()
    note = "review terms above, then replace with deny-ANY when ready"
    if unnamed:
        listed = ", ".join(f"{svc.split('-', 1)[1].replace('-', '/', 1)} "
                           f"({hits} hits, {n} dst)" for svc, hits, n in unnamed[:8])
        more = f" and {len(unnamed) - 8} more" if len(unnamed) > 8 else ""
        note += (f"; unnamed ports only this allows: {listed}{more} -- name them "
                 f"(firru edit-services add) to get terms")
    fallback.yaml_set_start_comment(tagged(TAG_AUTO, note))
    fallback["name"]   = "allow-ANY"
    fallback["action"] = "accept"
    terms.append(fallback)

    return terms


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def any_rollup(rows, asn_db=None, dns_store=None):
    """The fleet view of what keeps terms at ANY, ranked by terms unblocked.

    The per-term comment tells a reviewer what one ANY covers. It does not tell
    them where to start, and the same handful of groups sits behind most of the
    terms: naming one can free dozens. This is that list.

    It proposes no edit. Every row is an inventory decision -- give this group a
    token, or accept that it stays ANY -- and the count is what makes it worth
    the reviewer's afternoon.

    rows: [(host, term, {ip: hits})]
    """
    groups = defaultdict(lambda: {"terms": set(), "hosts": set(),
                                  "addrs": set(), "hits": 0})
    for host, term, ext in rows:
        keyed = defaultdict(dict)
        for ip, hits in ext.items():
            keyed[_group_key(ip, asn_db, dns_store)][ip] = hits
        for key, members in keyed.items():
            g = groups[key]
            g["terms"].add((host, term))
            g["hosts"].add(host)
            g["addrs"].update(members)
            g["hits"] += sum(members.values())

    out = sorted(groups.items(), key=lambda kv: (-len(kv[1]["terms"]), -kv[1]["hits"]))
    lines = [f"{'group':44s} {'terms':>6} {'hosts':>6} {'addrs':>6} {'hits':>9}",
             "-" * 76]
    for key, g in out:
        lines.append(f"{key[:44]:44s} {len(g['terms']):>6} {len(g['hosts']):>6} "
                     f"{len(g['addrs']):>6} {g['hits']:>9}")
    return "\n".join(lines)


_ASN_CACHE = {}


def _group_key(ip, asn_db, dns_store):
    """One address's group: its DNS name, its AS, or its neighborhood."""
    if dns_store and ip in dns_store:
        return f"named: {dns_store[ip]}"
    addr = ipaddress.ip_address(ip)
    if addr.is_private:
        return f"private: {ipaddress.ip_network(f'{ip}/{BLOCK_LEN[addr.version]}', strict=False)}"
    if asn_db:
        if ip not in _ASN_CACHE:
            try:
                import geoip2.database
                with geoip2.database.Reader(asn_db) as r:
                    rec = r.asn(ip)
                    _ASN_CACHE[ip] = f"AS{rec.autonomous_system_number} " \
                                     f"{(rec.autonomous_system_organization or '?')[:30]}"
            except Exception:
                _ASN_CACHE[ip] = None
        if _ASN_CACHE[ip]:
            return _ASN_CACHE[ip]
    return str(ipaddress.ip_network(f"{ip}/{BLOCK_LEN[addr.version]}", strict=False))


BLOCK_LEN = {4: 24, 6: 48}


def load_dns_store(path):
    """{ip: name} from a loot-dns store, keeping the most-seen name per address."""
    best = {}
    if not path:
        return None
    with open(path) as fh:
        for line in fh:
            try:
                d = json.loads(line)
            except Exception:
                continue
            ip, name, n = d.get("ip"), d.get("name"), d.get("count", 0)
            if not ip or not name:
                continue
            if ip not in best or n > best[ip][1]:
                best[ip] = (name, n)
    return {ip: name for ip, (name, _) in best.items()} or None


def _extent(flows):
    """', 2024-03-01 17:00Z to 2024-03-07 18:00Z' for a parquet store, by its
    first and last flow; '' for anything else."""
    from firru.flows import is_parquet, flow_relation
    if not is_parquet(flows):
        return ""
    import duckdb
    from firru.project import describe
    lo, hi = duckdb.sql(f"SELECT min(timestamp), max(timestamp) FROM {flow_relation(flows)}").fetchall()[0]
    return f", {describe((lo, hi))}" if lo is not None else ""


class FlowContext:
    """What propose and check share: the definitions, the site's profile, the
    hosts to read and where their flows come from. Built once per run."""


def add_flow_arguments(parser):
    """The policies and the flow source, for propose and check alike."""
    parser.add_argument("policy", nargs="+", metavar="POLICY",
                        help="Host policy YAML(s), directory, or glob pattern")
    parser.add_argument("--defs",     "-d", default="def",
                        help="Aerleon definitions directory (default: def/, else the "
                             "project's def/, else firru's stock definitions)")
    parser.add_argument("--arkime",   "-a", default=None,
                        help="Arkime API base URL, e.g. http://localhost:8005/api")
    parser.add_argument("--flows-file", "-f", default=None,
                        help="Flows: a JSONL file, a directory of per-host .flows.jsonl "
                             "files, or a parquet store (default: the project's store)")
    parser.add_argument("--user",     "-u", default=None,
                        help="Arkime username (default: the netrc entry's, else admin)")
    parser.add_argument("--password", "-P", default=None,
                        help="Arkime password (default: the netrc entry ($NETRC, firru.toml's [arkime] netrc, ~/.netrc), else asked for; "
                             "a command line is visible to others)")
    parser.add_argument("--basic-auth", action="store_true",
                        help="Use HTTP basic auth instead of digest auth")
    parser.add_argument("--date",       default=None,
                        help="Arkime lookback window in hours, e.g. 48 (default: 48; for "
                             "the project's [arkime], all of it, since an imported "
                             "capture keeps its own times)")
    parser.add_argument("--start-time", default=None,
                        help="Arkime: start of time range, e.g. 2024-03-01 or Unix epoch")
    parser.add_argument("--stop-time",  default=None,
                        help="Arkime: end of time range (default: now)")
    from firru.project import add_window_arguments
    add_window_arguments(parser)


def open_flows(args, parser, *, need_arkime_auth=True):
    """Resolve the flow source, the definitions and every host to read.
    Exits through `parser` on a usage error."""
    from firru.project import find, flows_for
    try:
        project = find()
    except ValueError as e:
        parser.error(str(e))
    asked = any((args.window, args.since, args.until, args.date, args.start_time))
    from_project = None
    try:
        if not args.flows_file and not args.arkime:
            # Nothing named: the project's store, else its Arkime.
            if project is not None and project.store is not None:
                args.flows_file = os.path.relpath(project.store)
                from_project = "store"
            elif project is not None and project.arkime:
                args.arkime = project.arkime.url
                from_project = "arkime"
        named = args.flows_file or (args.arkime and "arkime")
        flows, window, window_label = flows_for(args, named)
    except ValueError as e:
        parser.error(str(e))
    if args.date is None:
        # Relative to now is wrong for an imported capture, which keeps its
        # own times, so the project's Arkime is read whole unless a window says.
        args.date = "-1" if from_project == "arkime" else "48"
    if from_project and not asked:
        where = args.flows_file if from_project == "store" else args.arkime
        print(f"No window given: reading all of {where}{_extent(args.flows_file) if from_project == 'store' else ''}"
              f" (--window, --since/--until to narrow it)", file=sys.stderr)
    from firru.defs_dir import resolve
    args.defs = resolve(args.defs)
    if window and args.arkime:
        if window[0] is not None:
            args.start_time = str(int(window[0]))
        if window[1] is not None:
            args.stop_time = str(int(window[1]))
        window = None
    elif flows and not args.arkime:
        args.flows_file = flows

    if not args.arkime and not args.flows_file:
        print("Either --arkime or --flows-file is required.", file=sys.stderr)
        sys.exit(1)
    if args.flows_file and not Path(args.flows_file).exists():
        print(f"{args.flows_file}: no such file. loot-conntrack, zeek-to-flows "
              "or loot-flows writes one (docs/flow-record.md).", file=sys.stderr)
        sys.exit(1)

    auth = None
    if args.arkime and need_arkime_auth:
        from firru.credentials import http_auth
        from firru.project import service_key
        try:
            auth = http_auth(args.arkime, args.user, args.password,
                             args.basic_auth or service_key(project, "arkime", "auth") == "basic",
                             prompt=True,
                             netrc=service_key(project, "arkime", "netrc"))
        except ValueError as e:
            parser.error(str(e))

    # Policy files: glob, directory, explicit file, or a bare host token.
    import glob as _glob
    host_entries = []  # list of (Path|None, token|None)
    for pat in args.policy:
        p = Path(pat)
        if p.is_dir():
            host_entries.extend((q, None) for q in sorted(p.glob('*.yml')))
        else:
            matched = sorted(Path(f) for f in _glob.glob(pat))
            if matched:
                host_entries.extend((q, None) for q in matched)
            elif p.exists():
                host_entries.append((p, None))
            else:
                host_entries.append((None, pat))
    if not host_entries:
        print(f"No policy files or host tokens found for: {args.policy}", file=sys.stderr)
        sys.exit(1)

    ctx = FlowContext()
    ctx.project      = project
    ctx.window       = window
    ctx.window_label = window_label
    ctx.defs         = naming.Naming(args.defs)
    ctx.annotator    = PolicyAnnotator(args.defs)
    # The site's own source policy and host metadata, as synth reads them, so
    # a declared source survives (declared_sources).
    ctx.profile      = load_profile(args.defs)
    ctx.metadata     = load_host_metadata(args.defs)
    ctx.arkime       = ArkimeAPI(args.arkime, auth) if args.arkime else None
    from firru.flows import is_parquet
    parquet = bool(args.flows_file) and is_parquet(args.flows_file)
    # A per-host-file directory (…/<host>.flows.jsonl); a parquet dir is NOT this.
    ctx.flows_dir = (Path(args.flows_file) if args.flows_file and not parquet
                     and Path(args.flows_file).is_dir() else None)

    # Resolve every host up front: one shared flows file can then be scanned
    # once for all of them instead of once per host.
    ctx.hosts = []   # (policy_path, policy, host_token, host_ips)
    for policy_path, bare_token in host_entries:
        policy = None
        if policy_path is not None:
            if not policy_path.exists():
                print(f"Policy file not found: {policy_path} — skipping", file=sys.stderr)
                continue
            with open(policy_path) as f:
                policy = yaml_handler.load(f)
            host_token = policy.get("metadata", {}).get("host")
            # The file is named by the host's inventory token, which is unique;
            # metadata.host is the collector's label, which need not be (two
            # zones can each have a `www`). Prefer the token the definitions
            # know.
            if get_host_ips(policy_path.stem, ctx.defs):
                host_token = policy_path.stem
            if not host_token:
                print(f"{policy_path}: missing metadata.host — skipping", file=sys.stderr)
                continue
        else:
            host_token = bare_token
        ctx.hosts.append((policy_path, policy, host_token, get_host_ips(host_token, ctx.defs)))
    return ctx


def prescan(ctx, args):
    """One pass over a shared flows file for every host; None otherwise."""
    ctx.prescanned, ctx.spans = None, {}
    if args.flows_file and not ctx.flows_dir:
        print(f"Reading flows from {args.flows_file} (single pass, "
              f"{len(ctx.hosts)} hosts) …", file=sys.stderr)
        ctx.prescanned = collect_flows_multi(
            args.flows_file,
            {tok: ips for _, _, tok, ips in ctx.hosts if ips},
            ctx.defs, spans=ctx.spans, window=ctx.window)


def host_flows(ctx, args, host_token, host_ips):
    """(span, source, ingress, egress, ingress_ports, egress_ports) for one
    host, or None when its per-host flows file is missing."""
    if ctx.flows_dir:
        flows_file = ctx.flows_dir / f"{host_token}.flows.jsonl"
        if not flows_file.exists():
            print(f"  No flows file for {host_token} ({flows_file}) — skipping", file=sys.stderr)
            return None
        print(f"Reading flows from {flows_file} …", file=sys.stderr)
        span = [None, None]
        return (span, str(flows_file),
                *collect_flows_from_file(str(flows_file), host_ips, ctx.defs, span=span))
    if ctx.prescanned is not None:
        source = args.flows_file
        if ctx.window_label:
            source = f"{source} [{ctx.window_label}]"
        empty = (defaultdict(Hits), defaultdict(Hits),
                 defaultdict(Counter), defaultdict(Counter))
        return (ctx.spans.get(host_token), source, *ctx.prescanned.get(host_token, empty))
    window = (f"{args.start_time}-{args.stop_time or 'now'}" if args.start_time
              else "all of it" if args.date == "-1" else f"{args.date}h")
    print(f"Querying Arkime ({window}) …", file=sys.stderr)
    span = [None, None]
    return (span, f"Arkime ({window})",
            *collect_flows(ctx.arkime, host_ips, ctx.defs, args.date, args.start_time,
                           args.stop_time, span=span))


def main():
    parser = argparse.ArgumentParser(
        prog="firru propose",
        description="Propose edits to host policies from the traffic: narrow each "
                    "term's sources to the peers seen, deny the listeners nothing "
                    "reached (logged), and propose egress terms. Each host's proposal "
                    "is written to --outdir as soon as it is read; with -o sh (the "
                    "default) the edits are also printed as firru commands, one per "
                    "line, each tagged with its reason. The policies are not changed.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Each line ends in its reason, so a posture is a grep:
  narrowed observed     the traffic shows fewer peers; safe to apply
  denied unexercised    nothing reached the listener in the window
  widened REVIEW        grants peers the policy did not (commented out)
  egress proposed       a term the egress traffic suggests (commented out)
  pinned                declared by the site or scored; left as it is

  firru propose policies/pol/ --window night | grep observed | sh
  firru propose policies/pol/ --window night | grep -e observed -e unexercised | sh
  firru propose policies/pol/ --window night -o yaml      # the proposals only
        """,
    )
    add_flow_arguments(parser)
    parser.add_argument("-o", "--output", choices=["sh", "yaml"], default="sh",
                        help="sh (default): the edits as tagged firru commands on stdout, "
                             "and the proposals written; yaml: the proposals only")
    parser.add_argument("--outdir", default=None,
                        help="Where the proposals go (default: the project's proposals/, "
                             "else proposals/)")
    parser.add_argument("--dump-flows", action="store_true",
                        help="Arkime: write each host's flows to <outdir>/<host>.flows.jsonl "
                             "and exit")
    parser.add_argument("--any-report", default=None, metavar="PATH",
                        help="write a fleet rollup of what keeps terms at ANY, "
                             "ranked by how many terms naming each group would free")
    # Naming unresolved addresses needs a loot-dns store, which only the name
    # layer produces; where that is not installed the option is not offered.
    import importlib.util
    if importlib.util.find_spec("firru.cli.loot_dns") is not None:
        parser.add_argument("--dns-store", default=None,
                            help="loot-dns store JSONL; names unresolved addresses in "
                                 "the ANY comment, which is where egress pays off")
    parser.set_defaults(dns_store=None)
    parser.add_argument("--asn-db", default=None,
                        help="MaxMind ASN mmdb for grouping unresolved addresses "
                             "(default $GEOIP_ASN_DB or a local GeoLite2-ASN.mmdb)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="In via: annotations, show top source hosts per sub-service")
    args = parser.parse_args()

    ctx = open_flows(args, parser)
    if args.dump_flows and not args.arkime:
        print("--dump-flows requires --arkime.", file=sys.stderr)
        sys.exit(1)
    if args.outdir is None:
        args.outdir = (os.path.relpath(ctx.project.root / "proposals")
                       if ctx.project is not None else "proposals")
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Both only ever affect a comment, so a missing database is not an error.
    dns_store = load_dns_store(args.dns_store)
    asn_db = args.asn_db or _default_asn_db()
    any_rows = [] if args.any_report else None
    sh = args.output == "sh"
    if not args.dump_flows:
        prescan(ctx, args)
    else:
        ctx.prescanned = None
    defs, annotator, profile = ctx.defs, ctx.annotator, ctx.profile
    if sh:
        print(f"# firru propose -o sh: {' '.join(args.policy)}")
        print(f"#   proposals: {args.outdir}/ (each line's file)")

    for policy_path, policy, host_token, host_ips in ctx.hosts:
      if not host_ips:
        print(f"Warning: no IPs found for {host_token} in defs — egress will be empty",
              file=sys.stderr)

      print(f"Host: {host_token}  IPs: {host_ips or '(none in defs)'}", file=sys.stderr)

      if args.dump_flows:
          out_flows = outdir / f"{host_token}.flows.jsonl"
          ip_filter = " || ".join(f"ip == {ip}" for ip in host_ips)
          time_kwargs = dict(date=args.date, start_time=args.start_time, stop_time=args.stop_time)
          written = 0
          with open(out_flows, 'w') as fh:
              for raw in ctx.arkime.search(ip_filter, fields=SESSION_FIELDS, **time_kwargs):
                  flow = process_flow(raw)
                  if flow:
                      fh.write(json.dumps(flow) + '\n')
                      written += 1
          print(f"Written: {out_flows}  ({written} flows)", file=sys.stderr)
          continue

      got = host_flows(ctx, args, host_token, host_ips)
      if got is None:
          continue
      span, source, ingress_flows, egress_flows, ingress_ports, egress_ports = got

      total_in  = sum(sum(c.values()) for c in ingress_flows.values())
      total_out = sum(sum(c.values()) for c in egress_flows.values())
      print(f"  ingress: {total_in} flows across {len(ingress_flows)} service buckets",
            file=sys.stderr)
      print(f"  egress:  {total_out} flows across {len(egress_flows)} service buckets",
            file=sys.stderr)

      if policy is None:
          print(f"  {host_token}: no policy file — use --dump-flows to collect flows", file=sys.stderr)
          continue

      # ------------------------------------------------------------------
      # Rebuild policy
      # ------------------------------------------------------------------
      all_unused        = []
      all_n_changed     = 0
      new_filters = CommentedSeq()
      host_meta = ctx.metadata.get(host_token) or {}
      declared = (lambda svc, h=host_token, m=host_meta:
                  declared_sources(h, svc, m, profile))

      for filt in policy.get("filters", []):
          header  = filt.get("header", {})
          # The direction as the policy states it, for every target: "output"
          # is nftables' word and Windows says "out", so a substring test made
          # every Windows egress filter an ingress one (its allow-ANY then read
          # as an ingress catch-all and hid every would-be-blocked flow).
          dirs    = filter_directions(filt)
          is_out  = DIR_OUT in dirs and DIR_IN not in dirs

          new_filt = CommentedMap()
          if new_filters:
              new_filt.yaml_set_start_comment("\n")
          new_filt["header"] = header

          if is_out:
              new_filt["terms"] = build_egress_terms(
                  egress_flows, annotator, defs,
                  dns_store=dns_store, asn_db=asn_db,
                  any_rows=any_rows, host_token=host_token)
          else:
              tightened, unused, n_changed = tighten_ingress(
                  filt.get("terms", []), ingress_flows, annotator, defs,
                  verbose=args.verbose,
                  ingress_ports=ingress_ports, dns_store=dns_store, asn_db=asn_db,
                  any_rows=any_rows, host_token=host_token, declared=declared,
              )
              all_unused.extend(unused)
              all_n_changed += n_changed
              new_filt["terms"] = tightened

          new_filters.append(new_filt)

      original = None
      if sh:
          with open(policy_path) as f:
              original = yaml_handler.load(f)
      policy["filters"] = new_filters

      # ------------------------------------------------------------------
      # Write the proposal: visible as soon as it exists
      # ------------------------------------------------------------------
      out_policy = outdir / f"{policy_path.stem}.yml"
      policy.yaml_set_start_comment(
          f"firru propose output — review and copy changes to {policy_path}\n"
          f"{window_line(source, span)}\n"
          f"Source suggestions changed: {all_n_changed} | "
          f"Log-drop candidates: {len(all_unused)}"
      )
      with open(out_policy, "w") as f:
          yaml_handler.dump(policy, f)
      print(f"Written: {out_policy}  "
            f"({all_n_changed} changed, {len(all_unused)} log-drop "
            f"candidate{'' if len(all_unused) == 1 else 's'})", file=sys.stderr)
      if sh:
          from firru.cli.propose_sh import emit_host
          emit_host(str(policy_path), str(out_policy), args.defs, original, policy,
                    defs, all_unused, declared, window_line(source, span),
                    scored_ports(host_token, host_meta, profile))
      sys.stdout.flush()

    if any_rows is not None:
        report = any_rollup(any_rows, asn_db=asn_db, dns_store=dns_store)
        Path(args.any_report).write_text(
            f"# What keeps terms at ANY, across {len({r[0] for r in any_rows})} host "
            f"policies and {len(any_rows)} terms.\n"
            f"# Every row is an inventory decision, not a proposed edit: give the\n"
            f"# group a token, or accept that the term stays ANY. `terms` is what\n"
            f"# naming it would free.\n\n{report}\n")
        print(f"Written: {args.any_report}  "
              f"({len(any_rows)} terms kept ANY on unresolved addresses)",
              file=sys.stderr)


if __name__ == "__main__":
    main()
