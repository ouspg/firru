#!/usr/bin/env python3
"""
firru synth — Convert normalized listener JSON to aerleon host policy YAML.

Reads the JSON output of loot-listeners and generates aerleon YAML policy files,
one per host. Unknown ports (not in services defs) are collected and emitted as a
stub services YAML to stdout for human review and addition to def/services.yml.

Usage:
    firru synth \
        --input  annotated/ \
        --output policy/pol/ \
        --defs   def/ \
        --meta   def/host_metadata.json

    # Preview unknown services only (dry run)
    firru synth --input annotated/ --defs def/ --unknown-only

Output layout (matching aclgen/aerleon expectations):
    policy/
      pol/
        <hostname>.yml      ← per-host policy (never overwrites existing)

Notes:
  - Existing policy files are never overwritten — human edits are preserved.
    Use --overwrite to regenerate from scratch.
  - Unknown ports are collected across all hosts and emitted as a stub
    services YAML on stdout. Add reviewed entries to def/services.yml.
  - host_metadata.json maps hostnames to zone and other metadata:
      { "MY_HOST": { "zone": "NET_DMZ", "os": "linux" }, ... }
"""

import argparse
import ipaddress
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

from aerleon.lib import naming
from ruyaml import YAML
from ruyaml.comments import CommentedMap, CommentedSeq

from firru.ephemeral import (RANGE_TOKEN_FLOOR, ephemeral_for, is_ephemeral,
                             parse_range, range_for_os)
from firru.owners import load_expected, load_owners, owner_evidence
from firru.service_naming import choose_token, owner_surprise, token_width
from firru.src_heuristics import get_dynamic_rules, get_suggested_rule, load_profile
from firru.tokens import is_loopback, normalize_token
from firru.aerleon_caps import check_policy
from firru.comments import TAG_AUTO, tagged

# ---------------------------------------------------------------------------
# YAML setup — preserve formatting for human readability
# ---------------------------------------------------------------------------

yaml_handler = YAML()
yaml_handler.indent(mapping=2, sequence=4, offset=2)
yaml_handler.preserve_quotes = True



# ---------------------------------------------------------------------------
# Term builder
# ---------------------------------------------------------------------------

def listen_to_term(host_token, proto, port, service_tokens, listen_entries, host_meta,
                   naming_note=None, owner_note=None, profile=None):
    """
    Build a CommentedMap aerleon term for one (proto, port) entry.

    listen_entries: list of listen_port records (new flat schema) or
                    legacy list of [cidr_str, [proc_tuple]] (old schema).
    service_tokens: list of service name tokens from defs.GetPortParents().
    Returns the terms (one per rule the source policy gives, usually one), or
    None if the entry should be skipped.
    """
    if not listen_entries:
        return None

    v4_entries, v6_entries = [], []

    for entry in listen_entries:
        # Support both new flat schema (dict) and legacy tuple schema
        if isinstance(entry, dict):
            cidr     = entry.get('bind_address', '')
            proc     = entry.get('process') or {}
            proc_str = ' '.join(filter(None, [
                proc.get('name', ''),
                proc.get('exe', ''),
                ' '.join(proc.get('services', [])),
            ]))
        else:
            # Legacy: (cidr_str, (name, exe, service))
            cidr     = entry[0]
            proc_str = ' '.join(filter(None, entry[1]))

        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue

        # A loopback-bound service is not reachable off-host, so it is not a
        # policy subject and a term for it would be surface that does not
        # exist. The filter lives here rather than in collection: the loot is
        # the observed record, and a service deliberately bound to 127.0.0.1 is
        # evidence the host was configured correctly (the resolved form of the
        # operator taxonomy's configuration-issue case), worth keeping whether
        # or not anything downstream consumes it. A port bound both to loopback
        # and to a real address still gets its term from the latter, because
        # only the loopback *entry* is dropped, not the port.
        if is_loopback(net):
            continue
        version = net.version

        label = f"{cidr} ({proc_str})" if proc_str else cidr
        (v4_entries if version == 4 else v6_entries).append(label)

    if not v4_entries and not v6_entries:
        return None

    service = service_tokens[0] if service_tokens else None
    rules = get_suggested_rule(host_token, service or str(port), bool(v4_entries),
                               bool(v6_entries), host_meta, profile,
                               {"protocol": proto, "port": port,
                                "listeners": listen_entries})
    if not rules:
        return None
    if not isinstance(rules, list):
        rules = [rules]

    # Build # comment summarising what was observed (never goes into nftables)
    comment_parts = []
    if v4_entries:
        comment_parts.append(f"IPv4 {', '.join(v4_entries)}")
    if v6_entries:
        comment_parts.append(f"IPv6 {', '.join(v6_entries)}")
    if service_tokens and len(service_tokens) > 1:
        comment_parts.append(f"aliases: {','.join(service_tokens)}")
    if naming_note:
        comment_parts.append(naming_note)
    comment = " | ".join(comment_parts)

    terms = []
    for i, rule in enumerate(rules):
        action = rule["action"]
        prefix = "allow" if action == "accept" else action
        term_name = f"{prefix}-{proto}-{service}" if service else f"{prefix}-{proto}-{port}"
        if i:
            term_name += f"-{rule.get('suffix') or i}"

        term = CommentedMap()
        text = tagged(TAG_AUTO, comment)
        if owner_note:
            # Its own line, so a reviewer scanning the policy sees it.
            text += "\n" + tagged(TAG_AUTO, owner_note)
        term.yaml_set_start_comment(text)
        term["name"]             = term_name
        term["protocol"]         = proto
        term["destination-port"] = service or str(port)
        term["action"]           = action
        if action == "accept":
            src = rule.get("source")
            if src:
                term["source-address"] = src
        if rule.get("logging"):
            term["logging"] = "true"
        for key, value in (rule.get("options") or {}).items():
            term[key] = value
        terms.append(term)

    return terms


def dynamic_terms(host_token, groups):
    """Terms for dynamic-range listeners a profile gave rules, one per rule:
    no destination-port, the owner matched by the rule's options instead."""
    terms, names = [], set()
    for protocol, owner, listeners, rules in groups:
        # A service when the process hosts one, else the process: lsass
        # hosts six, and naming the term after the first would mislead.
        label = (owner["services"][0] if len(owner["services"]) == 1
                 else owner["name"] or "unowned").lower()
        ports = ", ".join(str(p) for p in sorted({l["port"] for l in listeners}))
        who = " ".join(filter(None, [owner["name"], owner["program"], *owner["services"]]))
        for i, rule in enumerate(rules):
            prefix = "allow" if rule["action"] == "accept" else rule["action"]
            name = f"{prefix}-{protocol}-dynamic-{label}"
            if i:
                name += f"-{rule.get('suffix') or i}"
            while name in names:
                name += "-x"
            names.add(name)
            term = CommentedMap()
            term.yaml_set_start_comment(tagged(TAG_AUTO, f"dynamic range: {protocol}/{ports} ({who})"))
            term["name"] = name
            term["protocol"] = protocol
            term["action"] = rule["action"]
            if rule["action"] == "accept" and rule.get("source"):
                term["source-address"] = rule["source"]
            if rule.get("logging"):
                term["logging"] = "true"
            for key, value in (rule.get("options") or {}).items():
                term[key] = value
            terms.append(term)
    return terms


def load_role(path):
    """(name, terms) from a curated role: an Aerleon terms file, the shape of
    an include (`terms:` at the top), so the same file serves a hand-written
    policy as `- include:`."""
    with open(path) as f:
        doc = yaml_handler.load(f) or {}
    terms = doc.get('terms') if isinstance(doc, dict) else None
    if not terms:
        raise ValueError(f"{path}: no terms (a role is a file with `terms:` at the top)")
    return Path(path).name, terms


def _program_key(path):
    """Comparable program path: %SystemRoot% expanded, arguments dropped, and
    a listener with no path (kernel-mode: SMB, http.sys) as System."""
    p = (path or "").strip().lower().replace("%systemroot%", "c:\\windows")
    if ".exe" in p:
        p = p[:p.index(".exe") + 4]
    return p or "system"


def _owns(term, entry):
    """The listener's process is the one the term's windows-program and
    windows-service name, where it names any. A protected process (services,
    wininit) has a name in the loot but no path: matched on the file name."""
    proc = entry.get("process") or {}
    svc = term.get("windows-service")
    if svc and svc.lower() not in {x.lower() for x in proc.get("services") or ()}:
        return False
    prog = term.get("windows-program")
    if not prog:
        return True
    if _program_key(prog) == "system":
        return (proc.get("name") or "System").lower() == "system" and not proc.get("exe")
    if proc.get("exe") or not proc.get("name"):
        return _program_key(prog) == _program_key(proc.get("exe"))
    return _program_key(prog).rsplit("\\", 1)[-1] == proc["name"].lower() + ".exe"


def role_covers(defs, terms, proto, port, entries):
    """A role accept term admits every listener on the port: by port, and by
    owner where the term is scoped to one. The role is curated, so it decides
    the port's source; a synthesized term beside it would only widen it (a
    Windows allow is not overridden by a narrower one)."""
    from firru.policy import term_covers
    cands = [t for t in terms if t.get("action") == "accept"
             and term_covers(defs, t, proto, port)]
    return bool(cands) and all(any(_owns(t, e) for t in cands) for e in entries)


def role_terms(name, terms, synthesized=()):
    """Copies of a role's terms, each marked with the role it came from. A
    name a synthesized term also has is an error: one would shadow the other
    in every tool that keys on names."""
    import copy
    taken = {t.get('name') for t in synthesized}
    out = []
    for t in terms:
        if t.get('name') in taken:
            raise ValueError(f"role {name}: term {t.get('name')} is also synthesized")
        t = copy.deepcopy(t)
        t.yaml_set_start_comment(tagged(TAG_AUTO, f"role: {name}"))
        out.append(t)
    return out


def pick_role(host, roles):
    """The role for `host` from [(glob, role)], first match, or None."""
    import fnmatch
    return next((r for g, r in roles if fnmatch.fnmatchcase(host, g)), None)


# ---------------------------------------------------------------------------
# Policy skeleton builder
# ---------------------------------------------------------------------------

def loopback_term():
    """Allow all loopback traffic — must be in both input and output filters."""
    t = CommentedMap()
    t["name"]           = "allow-loopback"
    t["source-address"] = "LOOPBACK"
    t["action"]         = "accept"
    return t


def icmp_terms():
    """
    Allow ICMP and ICMPv6 in both directions.

    Required for PMTU discovery (ICMPv4 type 3 code 4 / ICMPv6 type 2),
    ping, traceroute, and basic ICMPv6 operation (NDP, router discovery).
    Aerleon's nftables target generates protocol-level matches; type/code
    filtering can be added in the nftables wrapper if needed.
    """
    t4 = CommentedMap()
    t4["name"]     = "allow-icmp"
    t4["protocol"] = "icmp"
    t4["action"]   = "accept"

    t6 = CommentedMap()
    t6["name"]     = "allow-icmpv6"
    t6["protocol"] = "icmpv6"
    t6["action"]   = "accept"

    return [t4, t6]


def output_term():
    """Placeholder output term — tighten later with egress data."""
    t = CommentedMap()
    t["name"]   = "allow-ANY"
    t["action"] = "accept"
    return t


def drop_term(os_type=None):
    """Terminal drop — should be last in input filter.

    The filter's default policy already drops what reaches the end; the term
    is there because it can count it, and because its action is where the
    enforcement mode lives (log-accept -> log-drop -> drop).

    On Windows it stays in the policy but is not rendered. Windows Firewall
    has no rule order: a block rule beats every allow rule, so a rendered
    `protocol=any action=block` blocks all inbound traffic, the allowed
    services included. The header's `block` sets the profile default instead,
    and `winfw-to-aerleon` reads that default back as this same term.
    """
    t = CommentedMap()
    t["name"]   = "drop-ANY"
    t["action"] = "deny"
    if os_type == 'windows':
        t["platform-exclude"] = ["windows_advfirewall"]
    else:
        t["counter"] = "drop-ANY"
    return t


def build_policy(host_token, terms, os_type, host_meta, notes=(), generator=None):
    """
    Assemble a full aerleon policy CommentedMap for one host. `notes` are
    [auto] comments placed before the input filter's final drop term: what
    was observed but deliberately given no term, and why. `generator`
    replaces the header's generator, its options kept (a profile's TARGETS).
    """
    zone = host_meta.get('zone')

    policy = CommentedMap()
    policy['metadata'] = CommentedMap()
    policy['metadata']['host'] = host_token
    if zone:
        policy['metadata']['zone'] = zone

    # Input filter
    in_header = CommentedMap()
    if os_type == 'linux':
        in_header['targets'] = {'nftables': 'mixed input DROP'}
    elif os_type == 'windows':
        # `mixed` renders both families, icmpv6 included, from one filter;
        # `block` is the default deny, set as the profile's inbound policy,
        # since a deny-all term would be a block rule and block beats allow.
        # Both need the aerleon fork (tests/test_aerleon_upstream.py).
        in_header['targets'] = {'windows_advfirewall': 'in mixed block'}
    else:
        in_header['targets'] = {'nftables': 'mixed input DROP'}

    # Windows gets no loopback term. The Windows Filtering Platform permits
    # loopback traffic implicitly -- a packet to 127.0.0.1 never reaches the
    # firewall -- so the term is inert there, and an inert term in a reviewable
    # artifact is noise. On Linux it is load-bearing: the input filter's policy
    # is DROP, so without an explicit accept, loopback traffic is dropped.
    # Built twice rather than shared between the two filters. ruyaml emits an
    # anchor and an alias (`&id001` / `*id001`) for any object it sees more
    # than once, so reusing these dicts turns a readable policy into one where
    # the egress filter's terms are references the reader has to resolve by
    # hand -- and any tool that edits one filter silently edits the other.
    def structural_terms():
        return ([] if os_type == 'windows' else [loopback_term()]) + icmp_terms()

    structural = structural_terms()

    in_terms = CommentedSeq(list(structural))
    in_terms.extend(terms)
    # No blanket DENY_SERVICES terms here. The filter defaults to DROP, so a
    # service with no listener is already denied — an explicit deny for it is
    # dead weight on every host. Where a host *does* listen on a deny-listed
    # service (SSDP), listen_to_term has already emitted the deny in place,
    # which is the only case an explicit deny means anything (it overrides the
    # allow that listener would otherwise get).
    in_terms.append(drop_term(os_type))
    if notes:
        in_terms.yaml_set_comment_before_after_key(
            len(in_terms) - 1, before='\n'.join(tagged(TAG_AUTO, n) for n in notes), indent=6)

    # Output filter
    out_header = CommentedMap()
    if os_type == 'linux':
        out_header['targets'] = {'nftables': 'mixed output'}
    elif os_type == 'windows':
        # no default: outbound keeps the host's own
        out_header['targets'] = {'windows_advfirewall': 'out mixed'}
    else:
        out_header['targets'] = {'nftables': 'mixed output'}

    if generator:
        for header in (in_header, out_header):
            header['targets'] = {generator: opts for opts in header['targets'].values()}

    filters = CommentedSeq([
        {'header': in_header,  'terms': in_terms},
        {'header': out_header,
         'terms': CommentedSeq(structural_terms() + [output_term()])},
    ])
    filters.yaml_set_comment_before_after_key(1, before='\negress')
    policy['filters'] = filters

    return policy


# ---------------------------------------------------------------------------
# Unknown service registry
# ---------------------------------------------------------------------------

def record_unknown(unknown, host_token, proto, port, listen_entries):
    """Add an unknown (proto, port) to the unknown services registry."""
    key = (proto, int(port))
    if key not in unknown:
        unknown[key] = {'procs': Counter(), 'hosts': set()}

    for entry in listen_entries:
        if isinstance(entry, dict):
            # `process` may be present-but-null for flow-derived loot.
            proc_name = (entry.get('process') or {}).get('name', '')
        else:
            proc_name = entry[1][0] if entry[1] else ''
        if proc_name:
            unknown[key]['procs'][proc_name] += 1

    unknown[key]['hosts'].add(host_token)


def emit_unknown_services(unknown):
    """Print stub services YAML for unknown ports to stdout."""
    if not unknown:
        print("# No unknown services found.", file=sys.stderr)
        return

    print("# --- Unknown services: review and add to def/services.yml ---")
    root = CommentedMap()
    root['services'] = CommentedMap()

    for (proto, port), info in sorted(unknown.items(), key=lambda x: (x[0][0], x[0][1])):
        token = f"{proto.upper()}_{port}"
        root['services'][token] = [{'port': port, 'protocol': proto}]
        comment = (
            f"Procs: {dict(info['procs'])} | "
            f"Hosts: {sorted(info['hosts'])}"
        )
        root['services'].yaml_add_eol_comment(comment, key=token)

    yaml_handler.dump(root, sys.stdout)


def build_service_surface(json_files, defs, all_metadata=None, keep_ephemeral=False,
                          ephemeral_override=None):
    """Walk loot-listeners JSON and resolve every observed (proto, port) against
    the definitions. Returns (known, unknown):
      known:   { token: {'ports': set((proto,port)), 'procs': Counter, 'hosts': set} }
      unknown: { (proto, port): {'procs': Counter, 'hosts': set} }
    Report-mode counterpart to synthesis: same loot JSON, no policy written,
    and the same listeners (synth_entries: host metadata, the ephemeral range,
    platform exclusions), so it never lists a socket synthesis would drop.
    """
    known = {}
    unknown = {}
    for json_path in json_files:
        try:
            with open(json_path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"Warning: could not read {json_path}: {e}", file=sys.stderr)
            continue
        hostname, _os, _meta, grouped, _eph, _excluded = synth_entries(
            data, defs, all_metadata, Path(json_path).stem, keep_ephemeral, ephemeral_override)
        host = normalize_token(hostname)
        for entry in (e for entries in grouped.values() for e in entries):
            proto = entry.get('protocol')
            port  = entry.get('port')
            if proto is None or port is None:
                continue
            port = int(port)
            try:
                tokens = defs.GetPortParents(port, proto)
                token  = tokens[0] if tokens else None
            except Exception:
                token = None
            if token is not None:
                rec = known.setdefault(token, {'ports': set(), 'procs': Counter(), 'hosts': set()})
                rec['ports'].add((proto, port))
            else:
                rec = unknown.setdefault((proto, port), {'procs': Counter(), 'hosts': set()})
            proc_name = (entry.get('process') or {}).get('name', '')
            if proc_name:
                rec['procs'][proc_name] += 1
            rec['hosts'].add(host)
    return known, unknown


def _port_runs(ports):
    """Collapse an iterable of ints into sorted (lo, hi) consecutive runs."""
    runs = []
    for p in sorted(ports):
        if runs and p == runs[-1][1] + 1:
            runs[-1] = (runs[-1][0], p)
        else:
            runs.append((p, p))
    return runs


def _port_value(lo, hi):
    """Aerleon port field: int for a single port, 'lo-hi' string for a range."""
    return lo if lo == hi else f"{lo}-{hi}"


def _hosts_note(hosts, max_hosts=0):
    """'Hosts: [...]', truncated to max_hosts names plus a count when asked."""
    shown = sorted(hosts)
    if max_hosts and len(shown) > max_hosts:
        return f"Hosts({len(shown)}): {shown[:max_hosts]} +{len(shown) - max_hosts} more"
    return f"Hosts: {shown}"


def emit_surface(known, unknown, unknown_only, title=None, stream=None, max_hosts=0):
    """Emit services YAML to stdout, collapsing consecutive ports into ranges
    (e.g. the MS dynamic-RPC band). unknown_only=True restricts to ports with no
    existing token; otherwise the full surface, known tokens reused, new flagged
    [NEW].

    `title` overrides the header comment, so a caller rendering a *subset* of the
    surface (loot-diff's added ports, say) can say which subset it is in the same
    shape as the full inventory."""
    stream = stream or sys.stdout
    root = CommentedMap()
    root['services'] = CommentedMap()
    emitted = False

    # Unknown ports first: collapse consecutive same-proto runs into ranges.
    by_proto = defaultdict(dict)
    for (proto, port), info in unknown.items():
        by_proto[proto][port] = info
    for proto in sorted(by_proto):
        ports = by_proto[proto]
        for lo, hi in _port_runs(ports.keys()):
            procs, hosts = Counter(), set()
            for p in range(lo, hi + 1):
                info = ports.get(p)
                if info:
                    procs.update(info['procs'])
                    hosts |= info['hosts']
            token = f"{proto.upper()}_{lo}" if lo == hi else f"{proto.upper()}_{lo}_{hi}"
            root['services'][token] = [{'port': _port_value(lo, hi), 'protocol': proto}]
            span = "" if lo == hi else f" ({hi - lo + 1} ports)"
            root['services'].yaml_add_eol_comment(
                f"[NEW]{span} Procs: {dict(procs)} | {_hosts_note(hosts, max_hosts)}",
                key=token)
            emitted = True

    # Known services: one entry per token, ports collapsed into ranges.
    if not unknown_only:
        for token in sorted(known):
            info = known[token]
            ports_by_proto = defaultdict(list)
            for proto, port in info['ports']:
                ports_by_proto[proto].append(port)
            entries = []
            for proto in sorted(ports_by_proto):
                for lo, hi in _port_runs(ports_by_proto[proto]):
                    entries.append({'port': _port_value(lo, hi), 'protocol': proto})
            root['services'][token] = entries
            root['services'].yaml_add_eol_comment(
                f"Procs: {dict(info['procs'])} | {_hosts_note(info['hosts'], max_hosts)}",
                key=token)
            emitted = True

    if not emitted:
        print("# No unknown services found." if unknown_only else "# No services found.",
              file=sys.stderr)
        return

    print(title if title else
          "# --- Unknown services: review and add to def/services.yml ---"
          if unknown_only else
          "# --- Observed service surface (known + [NEW] unknown) ---",
          file=stream)
    yaml_handler.dump(root, stream)


# ---------------------------------------------------------------------------
# Per-host processing
# ---------------------------------------------------------------------------

def _named_specifically(defs, protocol, port, eph_range):
    """Whether a token names this port rather than merely spanning it.

    A port the registry names is a service wherever it sits, and a few are
    registered inside an ephemeral range: MySQL's X Protocol on 33060 falls
    inside the Linux range and WinRM on 47001 inside the Windows one. Dropping
    those is a regression, not a cleanup.

    But "has a token" is too weak a test, because `WINDOWS-RPC-DYNAMIC` spans
    49152-65535 and would rescue every dynamic port there is. The token has to
    be narrower than the range it is rescuing a port from, and narrower than
    any OS's dynamic range (RANGE_TOKEN_FLOOR): a token that wide describes a
    range, not a port. The second test is what keeps the Windows range from
    rescuing a Linux client socket, since it is narrower than the Linux one.
    """
    span = min(eph_range[1] - eph_range[0] + 1, RANGE_TOKEN_FLOOR)
    try:
        tokens = defs.GetPortParents(port, protocol)
    except Exception:
        return False
    for tok in tokens:
        if str(tok).upper().startswith(("TCP_", "UDP_")):
            continue
        width = token_width(defs, tok)
        if width is not None and width < span:
            return True
    return False


def synth_entries(data, defs, all_metadata=None, fallback_name=None,
                  keep_ephemeral=False, ephemeral_override=None):
    """
    The listeners synthesis turns into terms, and what it leaves out:
    (hostname, os_type, host_meta, {(proto, port): [entry]}, dynamic, excluded),
    `dynamic` being the entries left out for sitting in the dynamic range and
    `excluded` the ports a platform check gives no term. Shared with the report (`--unknown`, `--all`), so a report
    lists exactly the sockets a policy would have to name.
    """
    from collections import defaultdict
    file_meta   = data.get('metadata', {})
    hostname    = file_meta.get('hostname') or fallback_name or 'unknown-host'
    os_type     = file_meta.get('os', 'linux')
    host_meta   = (all_metadata or {}).get(normalize_token(hostname), {})

    # Merge os from metadata file if not in JSON
    if 'os' not in file_meta and 'os' in host_meta:
        os_type = host_meta['os']

    # An ephemeral bind is a client socket the snapshot happened to catch, not
    # a service, and the range is the host's own: Linux hands out 32768-60999,
    # Windows 49152-65535. A profile's dynamic_rules may still give them terms,
    # by owner rather than by number.
    # The host's own range per protocol when its loot recorded one, else its
    # OS's default (firru.ephemeral.ephemeral_for).
    def eph_range(protocol):
        if keep_ephemeral:
            return None
        return ephemeral_for(data, ephemeral_override, protocol, os_type)
    grouped = defaultdict(list)
    dynamic = []
    excluded = set()
    for entry in data.get('listen_ports', []):
        rng = eph_range(entry['protocol'])
        if rng and is_ephemeral(entry['port'], rng) \
                and not _named_specifically(defs, entry['protocol'],
                                            entry['port'], rng):
            dynamic.append(entry)
            continue
        grouped[(entry['protocol'], entry['port'])].append(entry)
    return hostname, os_type, host_meta, grouped, dynamic, excluded


def synth_host(data, defs, all_metadata=None, fallback_name=None,
               keep_ephemeral=False, ephemeral_override=None, owners=None,
               expected=None, profile=None, role=None):
    """
    Normalized listener JSON (as data) → (host_token, policy_doc, unknown).

    The pure-in-memory synthesis, split from file handling so that a diff can
    generate the current code's view of a loot snapshot and compare it against
    an edited policy without writing anything (observed × intended, reached by
    generating — docs/design.md). `unknown` maps ports with no service token to
    their evidence; they appear in **no term**, so any caller that diffs the
    result must report them rather than let an unnamed listener vanish.
    `profile` is the source policy (firru.src_heuristics.load_profile).
    `role` is (name, terms), a curated role's terms placed before the
    synthesized ones (load_role).
    """
    hostname, os_type, host_meta, grouped, dynamic, excluded = synth_entries(
        data, defs, all_metadata, fallback_name, keep_ephemeral, ephemeral_override)
    host_token  = normalize_token(hostname)
    terms         = CommentedSeq()
    unknown       = {}
    # Track (proto, primary_service_token) pairs already emitted so that
    # port ranges covered by one service token (e.g. WINDOWS_RPC_HIGH spanning
    # 49152-65535) don't produce one duplicate term per individual port.
    seen_service_terms: set = set()

    covered = []
    for (proto, port), entries in sorted(grouped.items()):
        if role and role_covers(defs, role[1], proto, port, entries):
            covered.append(f"{port}/{proto}")
            continue
        try:
            service_tokens = defs.GetPortParents(port, proto)
            # Order the alternatives so the narrowest is first: the caller and
            # the dedup key both take [0], and definition order is arbitrary.
            note = None
            if service_tokens:
                # Two names can claim one port (COCKPIT/PROMETHEUS on 9090);
                # the listener's owner decides, see choose_token.
                chosen, note = choose_token(defs, service_tokens, owners,
                                            owner_evidence(entries))
                service_tokens = [chosen] + [t for t in service_tokens if t != chosen]
            dedup_key = (proto, service_tokens[0]) if service_tokens else (proto, port)
            if dedup_key in seen_service_terms:
                continue
            surprise = (owner_surprise(service_tokens[0], entries, expected)
                        if service_tokens else None)
            port_terms = listen_to_term(host_token, proto, port, service_tokens, entries,
                                        host_meta, naming_note=note, owner_note=surprise,
                                        profile=profile)
            if port_terms:
                seen_service_terms.add(dedup_key)
                terms.extend(port_terms)
        except naming.UndefinedPortError:
            record_unknown(unknown, host_token, proto, port, entries)

    terms.extend(dynamic_terms(host_token, get_dynamic_rules(
        host_token, dynamic, host_meta, profile)))
    notes = []
    if role:
        terms[:0] = role_terms(*role, synthesized=terms)
        if covered:
            notes.append(f"role {role[0]} covers {', '.join(covered)}: no synthesized term")
    residual = data.get('residual')
    if residual:
        notes.append(f"from the residual over baseline {residual['baseline']}: "
                     f"{residual['listeners']} of {residual['of']} listeners; "
                     + (f"the rest are role {role[0]}'s" if role else
                        "the baseline's are in no term"))
    targets = (profile.targets if profile else {}).get((os_type or "").lower())
    return (host_token, build_policy(host_token, terms, os_type, host_meta, notes=notes,
                                     generator=targets),
            unknown)


def process_host(json_path, outdir, defs, all_metadata, overwrite, keep_ephemeral=False, ephemeral_override=None,
                 owners=None, expected=None, profile=None, roles=()):
    """
    Process one annotated JSON file → aerleon YAML on disk.
    Returns (host_token, n_terms, skipped_reason, unknown); skipped_reason is
    None on success.
    """
    with open(json_path) as f:
        data = json.load(f)

    hostname = (data.get('metadata') or {}).get('hostname') or Path(json_path).stem

    # Named by the inventory token, not by the collector's label. A short
    # label is not unique -- this archive carries a `DC1` and a `dc1` that are
    # domain controllers in two different zones -- and a filename that cannot
    # tell them apart is one rename away from overwriting the wrong policy.
    # The canonical token is the FQDN, which carries the zone by construction.
    host_token = normalize_token(hostname)
    meta = (all_metadata or {}).get(host_token, {})
    outname = meta.get('alias_of') or host_token

    outpath = Path(outdir) / f"{outname}.yml"
    if outpath.exists() and not overwrite:
        return host_token, 0, f"skipped (exists — use --overwrite to regenerate)", {}

    hostname = (data.get('metadata') or {}).get('hostname') or Path(json_path).stem
    host_token, policy, unknown = synth_host(
        data, defs, all_metadata, fallback_name=Path(json_path).stem,
        keep_ephemeral=keep_ephemeral, ephemeral_override=ephemeral_override,
        owners=owners, expected=expected, profile=profile,
        role=pick_role(hostname, roles))
    for msg in check_policy(policy):
        print(f"Warning: {host_token}: {msg}", file=sys.stderr)
    n_terms = sum(1 for t in policy["filters"][0]["terms"]
                  if t.get("destination-port") and t.get("action") == "accept")

    with open(outpath, 'w') as f:
        yaml_handler.dump(policy, f)

    return host_token, n_terms, None, unknown


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Convert loot-listeners JSON to aerleon host policy YAML.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Generate policies for all hosts:
    %(prog)s --input annotated/ --output policy/pol/ --defs def/

  With host metadata (zone assignments etc.):
    %(prog)s --input annotated/ --output policy/pol/ --defs def/ --meta def/host_metadata.json

  Preview unknown services only:
    %(prog)s --input annotated/ --defs def/ --unknown-only

  Regenerate all (overwrite existing):
    %(prog)s --input annotated/ --output policy/pol/ --defs def/ --overwrite
        """
    )
    parser.add_argument('--input',        '-i', default=['loot'], nargs='+',
                        help='JSON files, directories, or glob patterns (default: loot/)')
    parser.add_argument('--output',       '-o', default='policies/staged',
                        help='Output directory for aerleon YAMLs (default: policies/staged/)')
    parser.add_argument('--defs',         '-d', default='def',
                        help='Aerleon definitions directory (default: def/)')
    parser.add_argument('--meta',         '-m', default='def/host_metadata.json',
                        help='Host metadata JSON mapping tokens to zone/os (default: def/host_metadata.json)')
    parser.add_argument('--keep-ephemeral', action='store_true',
                        help="emit terms for ports in the host's ephemeral range; "
                             "they are client sockets a snapshot caught, not services")
    parser.add_argument('--ephemeral', metavar='LO-HI', default=None,
                        help='override the per-OS ephemeral range for every host')
    parser.add_argument('--role', action='append', default=[], metavar='[GLOB=]FILE',
                        help="a curated role's terms (an Aerleon file with `terms:` at "
                             "the top) before the synthesized ones, for hosts whose "
                             "hostname matches GLOB (default *); repeatable, first "
                             "match wins. Pair with loot-diff --residual")
    parser.add_argument('--overwrite',    action='store_true',
                        help='Overwrite existing policy files (default: skip)')
    parser.add_argument('--report', action='store_true',
                        help='Report mode: write no policy files, print a services '
                             'report to stdout (defaults to unknown services)')
    parser.add_argument('--all', dest='report_all', action='store_true',
                        help='Report mode: emit the full observed service surface '
                             '(known tokens reused, new ports flagged [NEW]). Implies --report')
    parser.add_argument('--unknown', dest='report_unknown', action='store_true',
                        help='Report mode: emit only unknown services (the default). Implies --report')
    parser.add_argument('--unknown-only', action='store_true',
                        help='Deprecated alias for --report --unknown')
    args = parser.parse_args()

    from firru.defs_dir import resolve
    args.defs     = resolve(args.defs)
    defs          = naming.Naming(args.defs)
    owners        = load_owners(args.defs)
    expected      = load_expected(args.defs)
    profile       = load_profile(args.defs)
    if profile.origin:
        print(f"Source policy: {profile.origin}", file=sys.stderr)
    try:
        roles = []
        for spec in args.role:
            glob, _, path = spec.rpartition('=')
            roles.append((glob or '*', load_role(path)))
    except (OSError, ValueError) as e:
        parser.error(str(e))

    try:
        with open(args.meta) as f:
            all_metadata = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        all_metadata = {}
        if args.meta != 'def/host_metadata.json':
            print(f"Warning: could not load metadata from {args.meta}", file=sys.stderr)

    import glob as _glob
    json_files = []
    for pat in args.input:
        p = Path(pat)
        if p.is_dir():
            json_files.extend(p.glob('*.json'))
        else:
            json_files.extend(Path(f) for f in _glob.glob(pat))
    json_files = sorted(set(json_files))
    if not json_files:
        print(f"No JSON files found for: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Report mode writes no policy: walk the same JSON and print a services
    # report. --all = full surface; otherwise (or --unknown / legacy
    # --unknown-only) = unknown services only.
    report_mode = (args.report or args.report_all or args.report_unknown
                   or args.unknown_only)
    if report_mode:
        known, unknown = build_service_surface(
            json_files, defs, all_metadata, keep_ephemeral=args.keep_ephemeral,
            ephemeral_override=(parse_range(args.ephemeral) if args.ephemeral else None))
        emit_surface(known, unknown, unknown_only=not args.report_all)
        return

    # Normal mode: generate per-host policy files; unknown stub to stdout.
    Path(args.output).mkdir(parents=True, exist_ok=True)
    all_unknown = {}
    for json_path in json_files:
        host_token, n_terms, skipped, host_unknown = process_host(
            json_path, args.output, defs, all_metadata, args.overwrite,
                     keep_ephemeral=args.keep_ephemeral,
                     ephemeral_override=(parse_range(args.ephemeral) if args.ephemeral else None),
                     owners=owners, expected=expected, profile=profile, roles=roles)

        # Merge unknown services across hosts
        for key, info in host_unknown.items():
            rec = all_unknown.setdefault(key, {'procs': Counter(), 'hosts': set()})
            rec['procs'].update(info['procs'])
            rec['hosts'].update(info['hosts'])

        print(f"  {host_token}: {skipped or f'{n_terms} terms'}", file=sys.stderr)

    emit_unknown_services(all_unknown)


if __name__ == '__main__':
    main()
