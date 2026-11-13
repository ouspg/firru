#!/usr/bin/env python3
"""
firru tighten — Tighten host firewall policy sources/egress using flow data.

Reads an aerleon host policy YAML, queries Arkime for actual traffic, and
produces a tightened policy. Outputs:

  policies/tighten/<hostname>.yml        — tightened policy (review + adopt)
  policies/tighten/<hostname>.blocked.yml — flows observed but blocked by proposal
  policies/tighten/<hostname>.groups.yml  — suggested new group defs (when needed)

Ingress: replaces ANY source-address with observed source tokens where possible.
Egress:  replaces allow-ANY stub with terms derived from observed destinations.

When external (SINET/unknown) sources connect alongside internal ones, the
rule stays as ANY — but the comment shows what was actually observed so a
human can make an informed call.

Usage:
    firru tighten \\
        --policy  policies/pol/myhost_example_org.yml \\
        --defs    def/ \\
        --arkime  http://localhost:8005/api \\
        --user    admin --password secret \\
        --date    48

    # Dry-run: print summary only, no files written
    firru tighten --policy ... --defs ... --arkime ... --dry-run
"""

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from aerleon.lib import naming
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from ruyaml import YAML
from ruyaml.comments import CommentedMap, CommentedSeq

from firru.annotator import PolicyAnnotator
from firru.arkime import ArkimeAPI, build_host_filter, process_flow
from firru.cli.address_summarizer import (_default_asn_db, summarize,
                                          summarize_asn)
from firru.comments import TAG_AUTO, detached, tagged, set_term_comment, kept_comments_by_term
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

ARKIME_FIELDS = [
    "source.ip", "destination.ip",
    "source.port", "destination.port",
    "protocol", "tcpflags.syn", "tcpflags.syn-ack", "tags",
]

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
      ANY     they have neither, and ANY is the honest answer

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
        return "one group per address, so no summary narrows it and ANY is honest"
    biggest = sizes[0]
    if biggest * 2 >= len(ext):
        return (f"{biggest} of {len(ext)} sit in one group, so a named group "
                f"would cover most of this")
    if sizes[0] == 1:
        return "one group per address, so no summary narrows it and ANY is honest"
    return (f"{len(ext)} addresses spread over {len(sizes)} groups, largest {biggest}: "
            f"too scattered to name, ANY is honest")


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


def _group_count(summary):
    """The group count out of a summarizer lead line, or None."""
    m = re.search(r"in (\d+) (?:block|AS)", summary)
    return int(m.group(1)) if m else None


# ---------------------------------------------------------------------------
# Token consolidation
# ---------------------------------------------------------------------------

def best_tokens(annotations, group_members=None):
    """
    Given annotate_ip() results for a set of IPs, return:
        (token_list, suggest_group_members, excess_note)

    token_list            — aerleon token(s) to put in source-address, or None
    suggest_group_members — observed host tokens to emit as a tighter group
                            suggestion in .groups.yml (set whenever a broader
                            group is used OR when threshold is exceeded)
    excess_note           — human-readable string about over-permitted hosts, or None

    Strategy:
    1. Any EXTERNAL source → keep ANY unchanged
    2. Single token → use it
    3. Greedy set cover using actual group membership (parents lists).
       Groups are only used if ALL observed hosts they cover are genuine members
       (no fabricated over-permission).  For each group chosen, the unobserved
       members of that group also gain access — this is noted in excess_note and
       the exact observed set is always emitted to .groups.yml so the operator
       can create a tighter group when ready.
       Remaining uncovered hosts are listed individually.
       Total token count must fit within INDIVIDUAL_THRESHOLD.
    4. > threshold, no cover → suggest new group only
    """
    relevant = [a for a in annotations if a["type"] in ("HOST", "GROUP", "EXTERNAL")]
    if not relevant:
        return None, None, None

    if any(a["type"] == "EXTERNAL" for a in relevant):
        return None, None, None  # external present → can't tighten below ANY

    host_tokens = []
    for a in relevant:
        if a["type"] == "HOST":
            tok = a["host"]
        else:
            tok = a["parents"][0] if a.get("parents") else None
        if tok and tok not in host_tokens:
            host_tokens.append(tok)

    if not host_tokens:
        return None, None, None

    if len(host_tokens) == 1:
        return host_tokens, None, None

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

            for grp in candidate_groups:
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
            excess_note     = "\n".join(excess_parts) or None
            suggest_members = sorted(observed) if excess_parts else None
            return chosen, suggest_members, excess_note

        # Too many tokens even with grouping → suggest new group
        return None, sorted(observed), None

    # No group_members available — individual list or suggest
    if len(host_tokens) <= INDIVIDUAL_THRESHOLD:
        return host_tokens, None, None

    return None, host_tokens, None


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

    parts = []
    for tok, data in sorted(token_groups.items(), key=lambda x: (-x[1]["hits"], x[0])):
        hits = data["hits"]
        ips = sorted(data["ips"], key=_ip_key)
        if tok == "EXTERNAL":
            sample = ", ".join(ips[:COMMENT_IP_LIMIT])
            extra = f" and {len(ips) - COMMENT_IP_LIMIT} more" if len(ips) > COMMENT_IP_LIMIT else ""
            parts.append(f"{hits} hits: EXTERNAL ({sample}{extra})")
        elif tok.startswith("raw:"):
            ip = ips[0]
            parts.append(f"{hits} hits: {ip} (unresolved)")
        else:
            sample = ", ".join(ips[:COMMENT_IP_LIMIT])
            extra = f" and {len(ips) - COMMENT_IP_LIMIT} more" if len(ips) > COMMENT_IP_LIMIT else ""
            parts.append(f"{hits} hits: {tok} ({sample}{extra})")

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


def _bucket_flow(flow, host_ips_set, defs, ingress, egress, ingress_ports, egress_ports):
    """Sort one normalised flow dict into ingress/egress counters.

    `n` is how many flows the record stands for: 1 from a row iterator, the
    group size from `iter_flow_groups`. Counting groups instead of flows would
    change every hit number in every comment, so the weight is carried through.
    """
    proto    = flow["protocol"]
    dst_port = flow["dst_port"]
    n        = flow.get("n", 1)

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
        ingress[(proto, svc)][flow["src_ip"]] += n
        if dst_port:
            ingress_ports[(proto, svc)][dst_port] += n
    elif flow["src_ip"] in host_ips_set:
        egress[(proto, svc)][flow["dst_ip"]] += n
        if dst_port:
            egress_ports[(proto, svc)][dst_port] += n


def collect_flows_from_file(flows_file, host_ips, defs):
    """
    Read pre-normalised flows from a .jsonl file (process_flow() output).
    Filters to flows involving host_ips.
    """
    from firru.flows import iter_flow_groups
    host_ips_set = set(host_ips)
    ingress       = defaultdict(Counter)
    egress        = defaultdict(Counter)
    ingress_ports = defaultdict(Counter)
    egress_ports  = defaultdict(Counter)

    for flow in iter_flow_groups(flows_file, host_ips=host_ips_set):
        _bucket_flow(flow, host_ips_set, defs, ingress, egress, ingress_ports, egress_ports)

    return ingress, egress, ingress_ports, egress_ports


def collect_flows_multi(flows_file, host_ips_by_token, defs):
    """
    Bucket a single flows file for many hosts in ONE pass.

    Calling collect_flows_from_file() per host re-reads and re-parses the whole
    file once per host, which for a shared capture is the dominant cost: 35
    hosts over a 9M-line dump is 35 full scans. Here every host's addresses go
    into one index, each line is parsed once, and the flow is bucketed into
    every host it involves (east-west flows land in two hosts — ingress for the
    destination, egress for the source).

    Returns {host_token: (ingress, egress, ingress_ports, egress_ports)}.

    TODO(parquet): this still line-scans a JSONL dump, parsing every record even
    for a fleet that touches a fraction of it. As the flow record grows, back
    this with a columnar store (the demo's verdict vector is already parquet):
    push the host-address filter down as a predicate on src_ip/dst_ip and read
    only (src_ip, dst_ip, protocol, dst_port) instead of decoding whole JSON
    objects, so cost scales with matched flows, not with the file. Keep the
    JSONL path for the small/no-dependency case. The bucketing below is already
    single-pass and store-agnostic; only the read loop changes.
    """
    from firru.flows import iter_flow_groups

    ip_owner = defaultdict(list)
    for token, ips in host_ips_by_token.items():
        for ip in ips:
            ip_owner[ip].append(token)

    host_ip_sets = {t: set(ips) for t, ips in host_ips_by_token.items()}
    buckets = {
        t: (defaultdict(Counter), defaultdict(Counter),
            defaultdict(Counter), defaultdict(Counter))
        for t in host_ips_by_token
    }

    scanned = matched = groups = 0
    # The fleet IP union pushes down as a parquet predicate; on JSONL it filters
    # in Python, exactly as before.
    for flow in iter_flow_groups(flows_file, host_ips=set(ip_owner)):
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

    print(f"  {scanned} flows in {groups} conversations, "
          f"{matched} involving a known host", file=sys.stderr)
    return buckets


def collect_flows(arkime, host_ips, defs, date="48", start_time=None, stop_time=None):
    """
    Query Arkime for all flows to/from host_ips.

    Returns:
        ingress: {(proto, svc_token): Counter({src_ip: hit_count})}
        egress:  {(proto, svc_token): Counter({dst_ip: hit_count})}
    """
    host_ips_set  = set(host_ips)
    ingress       = defaultdict(Counter)
    egress        = defaultdict(Counter)
    ingress_ports = defaultdict(Counter)
    egress_ports  = defaultdict(Counter)

    if not host_ips:
        return ingress, egress, ingress_ports, egress_ports

    time_kwargs = dict(date=date, start_time=start_time, stop_time=stop_time)
    ip_filter = " || ".join(
        f"ip == {ip}" for ip in host_ips
    )
    for raw in arkime.search(ip_filter, fields=ARKIME_FIELDS, **time_kwargs):
        flow = process_flow(raw)
        if not flow:
            continue
        _bucket_flow(flow, host_ips_set, defs, ingress, egress, ingress_ports, egress_ports)

    return ingress, egress, ingress_ports, egress_ports


# ---------------------------------------------------------------------------
# Would-be-blocked check
# ---------------------------------------------------------------------------

def ip_matches_source(ip, source_addr, annotator):
    """True if ip would be accepted by source_addr token (or list of tokens)."""
    if not source_addr:
        return True  # no restriction

    tokens = [source_addr] if isinstance(source_addr, str) else list(source_addr)
    if any(t in ("ANY", "ANY_V4", "ANY_V6") for t in tokens):
        return True  # unrestricted

    ann    = annotator.annotate_ip(ip)
    actual = ann.get("host", "")
    parents = set(ann.get("parents", []))
    covered = {actual} | parents

    return bool(covered & set(tokens))


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
                    "hits": hits,
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
                    "hits": hits,
                    "proposed_src": shown,
                    "reason": f"src not covered by {shown}",
                })

    return sorted(blocked, key=_blocked_sort_key)


# ---------------------------------------------------------------------------
# Ingress tightening
# ---------------------------------------------------------------------------

def _is_any_source(src):
    """Return True if source-address is an ANY wildcard (or list containing one)."""
    if not src:
        return True
    tokens = [src] if isinstance(src, str) else list(src)
    return any(t in ("ANY", "ANY_V4", "ANY_V6") for t in tokens)


def tighten_ingress(in_filter_terms, ingress_flows, annotator, defs, verbose=False,
                    ingress_ports=None, dns_store=None, asn_db=None, any_rows=None,
                    host_token=None):
    """
    Rebuild ingress terms with tightened source-address values.

    Returns:
        terms          — CommentedSeq of tightened terms
        group_suggest  — {port_label: [individual_tokens]} for .groups.yml
        dead_rules     — list of dicts: terms with tightened source but zero traffic
                         (NoPair(policy_term, traffic_in_window) = dead rule candidate)
    """
    terms         = CommentedSeq()
    group_suggest = {}
    dead_rules    = []

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
            merged = Counter()
            seen_svcs = []

            # Direct hit: flows already bucketed under this token (e.g. RPC dynamic
            # ports land under WINDOWS-DC-BASE because it's first in GetPortParents).
            if (proto, svc) in ingress_flows:
                ip_ctr = ingress_flows[(proto, svc)]
                merged.update(ip_ctr)
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
                                merged.update(ip_ctr)
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
                        merged.update(ip_ctr)
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
                [tagged(TAG_AUTO, "no flows observed in window — source unchanged")],
                kept_map.get(term.get("name"), []),
            )
            # Dead-rule detection: no flows observed for a term with a specific source.
            if svc:
                src = term.get("source-address")
                if not _is_any_source(src):
                    dead_rules.append({
                        "name":   term.get("name", ""),
                        "proto":  proto,
                        "svc":    svc,
                        "source": src,
                    })
            unchanged.append(new_term)
            continue

        total_hits = sum(ip_counter.values())
        comment, annotations, raw_ips = summarise_annotations(ip_counter, annotator)
        comment = f"{total_hits} flows total | {comment}"
        if port_summary:
            comment = f"{comment} | {port_summary}"

        token_list, suggest_members, excess_note = best_tokens(annotations, annotator.group_members)

        if suggest_members:
            label = f"{proto}-{svc}"
            group_suggest[label] = sorted(set(suggest_members))

        old_src = term.get("source-address")
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

    return terms, group_suggest, dead_rules, n_changed


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
        token_list, _, _ = best_tokens(annotations, annotator.group_members)

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
# Blocked YAML builder
# ---------------------------------------------------------------------------

def build_blocked_yaml(blocked):
    """Return a CommentedMap YAML doc listing would-be-blocked flows as stubs."""
    doc = CommentedMap()
    doc.yaml_set_start_comment(
        "Would-be-blocked flows — review and add to policy if legitimate,\n"
        "or confirm they should be dropped."
    )
    doc["blocked"] = CommentedSeq()

    for b in blocked:
        entry = CommentedMap()
        entry.yaml_set_start_comment(
            f"{b['hits']} hits | reason: {b['reason']}"
        )
        entry["protocol"]    = b["proto"]
        entry["service"]     = b["svc"]
        entry["src_ip"]      = b["src_ip"]
        if b.get("src_token") and b["src_token"] != b["src_ip"]:
            entry["src_token"] = b["src_token"]
        # Omitted when no term exists — the reason comment already says so.
        if b.get("proposed_src") is not None:
            entry["proposed_src"] = (
                b["proposed_src"] if isinstance(b["proposed_src"], str)
                else str(b["proposed_src"])
            )
        doc["blocked"].append(entry)

    return doc


# ---------------------------------------------------------------------------
# Group suggestion YAML builder
# ---------------------------------------------------------------------------

def build_groups_yaml(group_suggest):
    """Return a stub networks YAML with suggested new group definitions."""
    doc = CommentedMap()
    doc.yaml_set_start_comment(
        "Suggested new network group definitions.\n"
        "Review, name appropriately, and add to def/ before rerunning tighten."
    )
    doc["networks"] = CommentedMap()

    for label, members in sorted(group_suggest.items()):
        token = f"SUGGEST_{label.upper().replace('-', '_')}"
        entry = CommentedMap()
        entry.yaml_set_start_comment(f"observed sources for {label}: {', '.join(members)}")
        entry["values"] = [{"address": m} for m in members]
        doc["networks"][token] = entry

    return doc


# ---------------------------------------------------------------------------
# Dead-rule YAML builder
# ---------------------------------------------------------------------------

def build_dead_yaml(dead_rules):
    """
    Return a CommentedMap YAML doc listing dead-rule candidates.

    A dead rule is an ingress accept term whose source-address has already been
    tightened (not ANY) but which matched zero observed traffic in the lookback
    window.  NoPair(policy_term, traffic_in_window).

    Remediation options per entry:
      - Remove the term if the service is decommissioned.
      - Widen the lookback window if traffic is infrequent.
      - Verify the source host is still active / reachable.
    """
    doc = CommentedMap()
    doc.yaml_set_start_comment(
        "Dead-rule candidates — NoPair(policy_term, traffic_in_window).\n"
        "Each term below has a tightened source-address but zero observed traffic\n"
        "in the lookback window.  Options: remove, widen window, or re-check host."
    )
    doc["dead_rules"] = CommentedSeq()

    for d in dead_rules:
        entry = CommentedMap()
        if d["name"]:
            entry["name"] = d["name"]
        entry["protocol"] = d["proto"]
        entry["service"]  = d["svc"]
        entry["source"]   = (
            d["source"] if isinstance(d["source"], str) else list(d["source"])
        )
        doc["dead_rules"].append(entry)

    return doc


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


def main():
    parser = argparse.ArgumentParser(
        description="Narrow each term's sources to the peers seen in traffic, from a\n"
                    "flows file (--flows-file) or a live Arkime (--arkime). Proposals are\n"
                    "written to --outdir, never into the policy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  firru tighten --policy policies/pol/myhost_example_org.yml \\
          --defs def/ --arkime http://arkime:8005 \\
          --user admin --password secret

  # Last 24 hours only
  firru tighten --policy ... --date 24

  # HTTP basic auth instead of digest
  firru tighten --policy ... --basic-auth
        """,
    )
    parser.add_argument("--policy",   "-p", required=True, nargs='+',
                        help="Host policy YAML(s), directory, or glob pattern")
    parser.add_argument("--defs",     "-d", default="def",
                        help="Aerleon definitions directory (default: def/)")
    parser.add_argument("--arkime",   "-a", default=None,
                        help="Arkime API base URL, e.g. http://localhost:8005/api")
    parser.add_argument("--flows-file", "-f", default=None,
                        help="Pre-dumped flows .jsonl file or directory of per-host .flows.jsonl files")
    parser.add_argument("--dump-flows", action="store_true",
                        help="Dump per-host flows to <outdir>/<host_token>.flows.jsonl and exit")
    parser.add_argument("--user",     "-u", default="admin",
                        help="Arkime username (default: admin)")
    parser.add_argument("--password", "-P", default=None,
                        help="Arkime password (prompted if not given)")
    parser.add_argument("--basic-auth", action="store_true",
                        help="Use HTTP basic auth instead of digest auth")
    parser.add_argument("--date",       default="48",
                        help="Arkime lookback window in hours, e.g. 48 (default: 48)")
    parser.add_argument("--start-time", default=None,
                        help="Start of time range, e.g. 2024-03-01 or Unix epoch")
    parser.add_argument("--stop-time",  default=None,
                        help="End of time range (default: now)")
    parser.add_argument("--outdir",   "-o", default="policies/tighten",
                        help="Output directory (default: policies/tighten/)")
    parser.add_argument("--overwrite", action="store_true",
                        help="Overwrite existing tighten output")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Query Arkime and print summary; do not write files")
    parser.add_argument("--check", action="store_true",
                        help="Check current policy against flows — report would-be-blocked "
                             "traffic aggregated by token, do not tighten or write files")
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

    # Both only ever affect a comment, so a missing database is not an error.
    dns_store = load_dns_store(args.dns_store)
    asn_db = args.asn_db or _default_asn_db()
    any_rows = [] if args.any_report else None

    if not args.arkime and not args.flows_file:
        print("Either --arkime or --flows-file is required.", file=sys.stderr)
        sys.exit(1)
    if args.flows_file and not Path(args.flows_file).exists():
        print(f"{args.flows_file}: no such file. loot-conntrack, zeek-to-flows "
              "or loot-flows writes one (docs/flow-record.md).", file=sys.stderr)
        sys.exit(1)

    if args.dump_flows and not args.arkime:
        print("--dump-flows requires --arkime.", file=sys.stderr)
        sys.exit(1)

    # ------------------------------------------------------------------
    # Credentials (only needed for live Arkime)
    # ------------------------------------------------------------------
    password = args.password
    if args.arkime and password is None and not args.dry_run:
        import getpass
        password = getpass.getpass(f"Arkime password for {args.user}: ")

    auth = (HTTPBasicAuth if args.basic_auth else HTTPDigestAuth)(args.user, password or "") if args.arkime else None

    # ------------------------------------------------------------------
    # Resolve policy file list (glob/dir/explicit/bare-token)
    # Each entry is (policy_path_or_None, host_token_or_None).
    # host_token_or_None is only pre-filled for bare tokens; otherwise
    # it is extracted from the YAML at processing time.
    # ------------------------------------------------------------------
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
                # Treat as a bare host token
                host_entries.append((None, pat))
    if not host_entries:
        print(f"No policy files or host tokens found for: {args.policy}", file=sys.stderr)
        sys.exit(1)

    # ------------------------------------------------------------------
    # Shared setup (defs, annotator, arkime — once for all policies)
    # ------------------------------------------------------------------
    defs      = naming.Naming(args.defs)
    annotator = PolicyAnnotator(args.defs)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    arkime_client = ArkimeAPI(args.arkime, auth) if args.arkime else None
    from firru.flows import is_parquet
    _flows_is_parquet = bool(args.flows_file) and is_parquet(args.flows_file)
    # A per-host-file directory (…/<host>.flows.jsonl); a parquet dir is NOT this.
    flows_dir = (Path(args.flows_file) if args.flows_file and not _flows_is_parquet
                 and Path(args.flows_file).is_dir() else None)

    # Resolve every host up front: one shared flows file can then be scanned
    # once for all of them instead of once per host.
    resolved = []   # (policy_path, policy, host_token, host_ips)
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
            if get_host_ips(policy_path.stem, defs):
                host_token = policy_path.stem
            if not host_token:
                print(f"{policy_path}: missing metadata.host — skipping", file=sys.stderr)
                continue
        else:
            host_token = bare_token
        resolved.append((policy_path, policy, host_token, get_host_ips(host_token, defs)))

    prescanned = None
    if args.flows_file and not flows_dir and not args.dump_flows:
        print(f"Reading flows from {args.flows_file} (single pass, "
              f"{len(resolved)} hosts) …", file=sys.stderr)
        prescanned = collect_flows_multi(
            args.flows_file,
            {tok: ips for _, _, tok, ips in resolved if ips},
            defs)

    for policy_path, policy, host_token, host_ips in resolved:
      if not host_ips:
        print(f"Warning: no IPs found for {host_token} in defs — egress/blocked will be empty",
              file=sys.stderr)

      print(f"Host: {host_token}  IPs: {host_ips or '(none in defs)'}", file=sys.stderr)

      # ------------------------------------------------------------------
      # Collect flows
      # ------------------------------------------------------------------
      if flows_dir:
          flows_file = flows_dir / f"{host_token}.flows.jsonl"
          if not flows_file.exists():
              print(f"  No flows file for {host_token} ({flows_file}) — skipping", file=sys.stderr)
              continue
          print(f"Reading flows from {flows_file} …", file=sys.stderr)
          ingress_flows, egress_flows, ingress_ports, egress_ports = collect_flows_from_file(str(flows_file), host_ips, defs)
      elif prescanned is not None:
          empty = (defaultdict(Counter), defaultdict(Counter),
                   defaultdict(Counter), defaultdict(Counter))
          ingress_flows, egress_flows, ingress_ports, egress_ports = \
              prescanned.get(host_token, empty)
      elif args.flows_file:
          print(f"Reading flows from {args.flows_file} …", file=sys.stderr)
          ingress_flows, egress_flows, ingress_ports, egress_ports = collect_flows_from_file(args.flows_file, host_ips, defs)
      else:
          window = f"{args.start_time}-{args.stop_time or 'now'}" if args.start_time else f"{args.date}h"
          print(f"Querying Arkime ({window}) …", file=sys.stderr)
          ingress_flows, egress_flows, ingress_ports, egress_ports = collect_flows(arkime_client, host_ips, defs,
                                                      args.date, args.start_time, args.stop_time)

      # ------------------------------------------------------------------
      # --dump-flows: write raw flows and move on
      # ------------------------------------------------------------------
      if args.dump_flows:
          out_flows = outdir / f"{host_token}.flows.jsonl"
          ip_filter = " || ".join(f"ip == {ip}" for ip in host_ips)
          time_kwargs = dict(date=args.date, start_time=args.start_time, stop_time=args.stop_time)
          written = 0
          with open(out_flows, 'w') as fh:
              for raw in arkime_client.search(ip_filter, fields=ARKIME_FIELDS, **time_kwargs):
                  flow = process_flow(raw)
                  if flow:
                      fh.write(json.dumps(flow) + '\n')
                      written += 1
          print(f"Written: {out_flows}  ({written} flows)")
          continue

      total_in  = sum(sum(c.values()) for c in ingress_flows.values())
      total_out = sum(sum(c.values()) for c in egress_flows.values())
      print(f"  ingress: {total_in} flows across {len(ingress_flows)} service buckets",
            file=sys.stderr)
      print(f"  egress:  {total_out} flows across {len(egress_flows)} service buckets",
            file=sys.stderr)

      # ------------------------------------------------------------------
      # Bare token with no policy — only dump-flows makes sense (handled above)
      # ------------------------------------------------------------------
      if policy is None:
          print(f"  {host_token}: no policy file — use --dump-flows to collect flows", file=sys.stderr)
          continue

      # ------------------------------------------------------------------
      # --check: verify current policy doesn't over-block observed flows
      # ------------------------------------------------------------------
      if args.check:
          current_terms = []
          for filt in policy.get("filters", []):
              # Membership, not "not egress": an unstated direction is neither
              # half, and must not be checked as if it were ingress.
              if DIR_IN in filter_directions(filt):
                  current_terms.extend(
                      t for t in filt.get("terms", [])
                      if t.get("action", "accept").lower() not in ("deny", "drop", "reject")
                  )
          blocked = find_blocked(ingress_flows, current_terms, annotator,
                                  defs, ingress_ports)

          if not blocked:
              print(f"  {host_token}: no over-blocking detected")
          else:
              # Aggregate by (proto, svc, token) not by IP
              agg = defaultdict(lambda: {"hits": 0, "ips": set()})
              for b in blocked:
                  ann = annotator.annotate_ip(b["src_ip"])
                  tok = (ann.get("host") or
                         (ann["parents"][0] if ann.get("parents") else b["src_ip"]))
                  key = (b["proto"], b["svc"], tok)
                  agg[key]["hits"] += b["hits"]
                  agg[key]["ips"].add(b["src_ip"])

              print(f"\n  {host_token}: WOULD-BE-BLOCKED traffic (aggregated by token):")
              for (proto, svc, tok), data in sorted(agg.items(),
                      key=lambda x: -x[1]["hits"]):
                  ips = ", ".join(sorted(data["ips"]))
                  src = f"{tok} ({ips})" if ips != tok else tok
                  print(f"    {data['hits']:5d} hits  {proto}/{svc:20s}  src: {src}")
          continue

      # ------------------------------------------------------------------
      # Rebuild policy
      # ------------------------------------------------------------------
      all_group_suggest = {}
      all_dead_rules    = []
      all_n_changed     = 0
      new_filters = CommentedSeq()
      all_ingress_terms = CommentedSeq()

      for filt in policy.get("filters", []):
          header  = filt.get("header", {})
          targets = header.get("targets", {})
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
              in_terms = filt.get("terms", [])
              tightened, group_suggest, dead_rules, n_changed = tighten_ingress(
                  in_terms, ingress_flows, annotator, defs, verbose=args.verbose,
                  ingress_ports=ingress_ports, dns_store=dns_store, asn_db=asn_db,
                  any_rows=any_rows, host_token=host_token,
              )
              all_group_suggest.update(group_suggest)
              all_dead_rules.extend(dead_rules)
              all_n_changed += n_changed
              new_filt["terms"] = tightened
              for t in tightened:
                  if t.get("action", "accept").lower() not in ("deny", "drop", "reject"):
                      all_ingress_terms.append(t)

          new_filters.append(new_filt)

      policy["filters"] = new_filters

      # ------------------------------------------------------------------
      # Blocked check
      # ------------------------------------------------------------------
      blocked = find_blocked(ingress_flows, list(all_ingress_terms), annotator,
                             defs, ingress_ports)

      # ------------------------------------------------------------------
      # Dry run summary
      # ------------------------------------------------------------------
      if args.dry_run:
          print(f"\n=== {policy_path.name} ===")
          print("--- Tightened source summary ---")
          for t in all_ingress_terms:
              src = t.get("source-address", "ANY")
              print(f"  {t.get('protocol')}/{t.get('destination-port'):20s}  src: {src}")
          print(f"\n--- Egress terms ---")
          for filt in policy.get("filters", []):
              targets = filt.get("header", {}).get("targets", {})
              if filter_directions(filt) == {DIR_OUT}:
                  for t in filt.get("terms", []):
                      if t.get("action", "deny").lower() not in ("deny", "drop"):
                          print(f"  {t.get('protocol')}/{t.get('destination-port') or '':20s}"
                                f"  dst: {t.get('destination-address', 'ANY')}")
          if blocked:
              print(f"\n--- Would-be-blocked ({len(blocked)} flows) ---")
              for b in blocked[:20]:
                  src = b["src_ip"]
                  if b.get("src_token"):
                      src = f"{b['src_token']} ({b['src_ip']})"
                  print(f"  {b['hits']:5d} hits  {b['proto']}/{b['svc']:20s}  "
                        f"src {src:50s}  {b['reason']}")
              if len(blocked) > 20:
                  print(f"  … and {len(blocked)-20} more")
          if all_dead_rules:
              print(f"\n--- Dead-rule candidates ({len(all_dead_rules)}) ---")
              for d in all_dead_rules:
                  name = f"  [{d['name']}]" if d["name"] else ""
                  print(f"  {d['proto']}/{d['svc']:20s}  src: {d['source']}{name}")
          if all_group_suggest:
              print(f"\n--- Group suggestions ---")
              for label, members in all_group_suggest.items():
                  print(f"  {label}: {members}")
          continue

      # ------------------------------------------------------------------
      # Write outputs
      # ------------------------------------------------------------------
      stem        = policy_path.stem
      out_policy  = outdir / f"{stem}.yml"
      out_blocked = outdir / f"{stem}.blocked.yml"
      out_groups  = outdir / f"{stem}.groups.yml"
      out_dead    = outdir / f"{stem}.dead.yml"

      if out_policy.exists() and not args.overwrite:
          print(f"  {stem}: output exists — skipping (use --overwrite)", file=sys.stderr)
          continue

      policy.yaml_set_start_comment(
          f"firru tighten output — review and copy changes to policies/pol/{policy_path.name}\n"
          f"Source suggestions changed: {all_n_changed} | "
          f"Dead rules: {len(all_dead_rules)} | "
          f"Group suggestions: {len(all_group_suggest)}"
      )
      with open(out_policy, "w") as f:
          yaml_handler.dump(policy, f)
      print(f"Written: {out_policy}  "
            f"({all_n_changed} changed, {len(all_dead_rules)} dead, "
            f"{len(all_group_suggest)} group suggestions)")

      if blocked:
          with open(out_blocked, "w") as f:
              yaml_handler.dump(build_blocked_yaml(blocked), f)
          print(f"Written: {out_blocked}  ({len(blocked)} would-be-blocked flows)")
      else:
          if out_blocked.exists():
              out_blocked.unlink()

      if all_group_suggest:
          with open(out_groups, "w") as f:
              yaml_handler.dump(build_groups_yaml(all_group_suggest), f)
          print(f"Written: {out_groups}  ({len(all_group_suggest)} suggested groups)")
      else:
          if out_groups.exists():
              out_groups.unlink()

      if all_dead_rules:
          with open(out_dead, "w") as f:
              yaml_handler.dump(build_dead_yaml(all_dead_rules), f)
          print(f"Written: {out_dead}  ({len(all_dead_rules)} dead-rule candidates)")
      else:
          if out_dead.exists():
              out_dead.unlink()

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
