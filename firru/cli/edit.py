#!/usr/bin/env python3
"""
firru — deterministic edits to a human-edited policy.

firru is the surgical counterpart to opening the file in $EDITOR: it
automates only edits that are mechanical, preserving human intent and honoring
the comment contract (docs/comment-contract.md). Judgment calls are reported,
not decided.

Each verb is one class of change, and edits only what it names, so a line
holds on a policy edited by hand since it was written:

    firru diff  OLD NEW --defs def                # preview (read-only)
    firru diff  OLD NEW -o sh                     # each change as a command
    firru remove-source POL TERM PEER...          # narrow
    firru set-source POL TERM PEER... | ANY       # narrow from ANY, or set outright
    firru add-source POL TERM PEER...             # widen
    firru set-action POL TERM deny --log          # deny, keep the term
    firru add-term POL TERM... --from NEW         # copy a term from a policy or loot
    firru add-term POL TERM --from NEW --replace OLD   # a rename, same ports
    firru rm POL TERM
    (-destination / -dest for egress)

Ingress and egress are the same relation with the peer-set on the other side, so
both live in one policy and both diff the same way. Direction is part of surface
identity: tcp/443 inbound and tcp/443 outbound are two rows, each compared
against its own peer field, and each edited by its own verb.

`diff -o sh` ends each line in its class, so a subset is a grep. A line that
grants somebody what they did not have (a widening, a change the traffic
contradicts, a terminal swap) is itself a comment, so `| sh` on the whole
output never widens:

    firru diff pol.yml proposal.yml -o sh | grep HTTP | sh
    firru diff pol.yml proposal.yml -o sh | grep narrowed | sh

Either side may be JSON instead of YAML, and the shape picks the comparison:
loot-listeners output is synthesized in memory (observed x intended), and an
`nft -j list ruleset` dump is read back through nft-to-aerleon, so

    firru diff pol/web1.yml hosts/web1/loot-host/nft.json --zone-prefix web1

is deployment drift -- what was committed against what the host is running --
in the same six classes as every other diff.

One change sits outside the classes entirely: the terminal. A filter ending in
an open `allow-ANY` versus one ending in `log-drop-egress-ANY` is the
enforcement decision for the host, so the swap is emitted only as a *comment*:

    firru rm pol.yml allow-ANY
    firru add-term pol.yml log-drop-egress-ANY --from egress.yml --direction out
"""

import argparse
import pathlib
import sys
from collections import Counter, defaultdict

from aerleon.lib import naming

from firru.cli.naming_cache import cached_naming
from ruyaml import YAML
from ruyaml.comments import CommentedMap, CommentedSeq
from ruyaml.error import CommentMark
from ruyaml.tokens import CommentToken

from firru.comments import partition_comment, preceding_raw_comment, set_term_comment
from firru.policy import (
    ANY_PEERS,
    DIR_IN,
    DIR_OUT,
    is_accept_term,
    is_catch_all,
    diff_surface,
    filter_direction,
    filter_directions,
    normalize_source,
    peer_field,
    port_surface,
    source_peers,
    target_names,
    term_covers,
    term_peers,
    term_ports,
    term_surface_keys,
)

yaml_handler = YAML()
yaml_handler.indent(mapping=2, sequence=4, offset=2)
yaml_handler.preserve_quotes = True


def _load(path):
    with open(path) as f:
        return yaml_handler.load(f)


def _ruleset_caveats(stats):
    """The bounds a drift report has to carry, worst first.

    The nft parse is deliberately partial, and the direction of its error is
    the whole reason this exists: an ignored match *narrows* the rule it came
    from, so the term read back is WIDER than what the host enforces. Diffed
    against a committed policy that surfaces as a widening the host may never
    have granted. Staying silent would turn "the parser could not read this
    match" into "the host granted this peer", which is the one error a drift
    report must not make.
    """
    notes = []
    if stats["default"] == "accept":
        notes.append("default ACCEPT (firewall off, or an accepting chain policy): the host "
                     "admits everything no rule denies, which a port surface cannot show — "
                     "'removed' here means not named by a rule, NOT not admitted")
    if stats["partial"]:
        kinds = ", ".join(sorted(stats["ignored_kinds"])) or "unknown"
        notes.append(f"{stats['partial']} term(s) parsed PARTIALLY (ignored: {kinds}) "
                     f"— each reads WIDER than the rule it came from, so a widening "
                     f"reported here may be the parser, not the host")
    if stats["skipped"]:
        notes.append(f"{stats['skipped']} rule(s) not represented at all — the enforced "
                     f"surface may be narrower than this side shows")
    if stats["unnamed_terms"]:
        notes.append(f"{stats['unnamed_terms']} term(s) carry literal addresses no token "
                     f"names — they cannot compare equal to a tokenized policy, and will "
                     f"read as changed on names alone")
    if stats["default"] is None:
        notes.append("no base-chain policy found — the default-deny is unrepresented, so "
                     "'removed' is unreliable on this side")
    if stats["idle"]:
        notes.append(f"{stats['idle']} term(s) deployed but never matched a packet "
                     f"(dead-rule candidates, not drift)")
    return notes


def _load_ruleset(path, data, defs_dir, zone_prefix):
    """An `nft -j list ruleset` dump as a policy doc, converted in memory.

    This is the enforced state read back into the relation, which is what makes
    deployment drift an ordinary `firru diff` instead of a bespoke comparison
    (docs/design.md, compiled × enforced). Nothing is written; the conversion's
    own limits go to stderr so they cannot be mistaken for findings, and so
    `-o sh` on stdout stays pipeable.
    """
    from firru.cli.nft_to_aerleon import convert
    # No host is invented from the filename: the stem of `.../loot-host/nft.json`
    # is "nft", which would label the whole report with a word that names
    # nothing. Unset, the caller falls back to the path, which is unambiguous.
    doc, stats = convert(data, cached_naming(defs_dir), zone_prefix=zone_prefix,
                         counters=True)
    # The side carries its own provenance, so a renderer downstream can say how
    # to read the classes without re-deriving where the document came from.
    doc.setdefault("metadata", {})["source"] = "enforced"
    if not stats["terms"]:
        raise SystemExit(f"{path}: nft -j output, but no filter rules were read "
                         f"({stats['nat']} NAT rule(s) skipped) — nothing to diff")
    for note in _ruleset_caveats(stats):
        print(f"{path}: {note}", file=sys.stderr)
    return doc


def _load_side(path, defs_dir, zone_prefix=None, allow_ruleset=False):
    """A diff/add-term side as a policy doc: YAML as-is, JSON converted in memory.

    Two JSON shapes are accepted and they land in different cells of the matrix
    (docs/design.md). A normalized listener JSON (loot-listeners output, holding
    `listen_ports`) is run through the current code's synthesis, so `firru diff
    loot.json pol.yml` compares what the generator *would* say today against
    what the human last reviewed — observed × intended, reached by generating.
    An `nft -j list ruleset` dump (holding `nftables`) is read back through
    nft-to-aerleon, so `firru diff pol.yml nft.json` compares what was committed
    against what the host is actually running — compiled × enforced.

    A ruleset is refused as an `add-term` source, and the refusal is the point:
    folding the running firewall back into pol/ documents the world instead of
    intending it, which is the failure mode the pipeline exists to reverse.
    Drift is a finding to review, never a patch to take.

    Nothing is written in either case.

    Returns (doc, unknown): `unknown` maps (proto, port) with no service token
    to evidence. Those ports appear in no term, so the caller must report
    them — an unnamed listener that silently vanished from a diff would be
    exactly the alert the diff exists to raise.
    """
    import json as _json
    if str(path).endswith(".json"):
        from pathlib import Path as _Path
        from firru.cli.synth import synth_host
        with open(path, encoding="utf-8-sig") as f:
            data = _json.load(f)
        from firru.cli.winfw_to_aerleon import is_winfw
        if is_winfw(data):
            # Windows Firewall from loot-host.ps1: enforced state like nft.json,
            # under the same refusal as a source to copy from.
            if not allow_ruleset:
                raise SystemExit(
                    f"{path}: a Windows Firewall ruleset is enforced state, not a source to "
                    f"copy from — read the drift with `firru diff POL {path}` and edit the "
                    f"policy deliberately")
            from firru.cli.winfw_to_aerleon import convert as _winfw_convert
            doc, stats = _winfw_convert(data, cached_naming(defs_dir))
            doc.setdefault("metadata", {})["source"] = "enforced"
            for note in _ruleset_caveats(stats):
                print(f"{path}: {note}", file=sys.stderr)
            return doc, None
        if isinstance(data, dict) and "nftables" in data:
            if not allow_ruleset:
                raise SystemExit(
                    f"{path}: an nft ruleset is enforced state, not a source to copy "
                    f"from — read the drift with `firru diff POL {path}` and edit the "
                    f"policy deliberately")
            return _load_ruleset(path, data, defs_dir, zone_prefix), None
        if "listen_ports" not in data:
            raise SystemExit(f"{path}: .json but neither listen_ports "
                             f"(loot-listeners) nor nftables (nft -j list ruleset)")
        meta_path = _Path(defs_dir) / "host_metadata.json"
        all_meta = _json.load(open(meta_path)) if meta_path.exists() else {}
        # Synthesized as `firru synth` would, ephemeral binds dropped: the other
        # side is a policy synthesis made, and a policy never holds them, so
        # keeping them here made every dynamic-range socket (a DNS server's
        # thousands) read as added on every comparison. A new listener in the
        # dynamic range is still seen, by owner, in loot-diff --baseline.
        from firru.defs_dir import resolve
        from firru.owners import load_expected, load_owners
        from firru.src_heuristics import load_profile
        _, doc, unknown = synth_host(data, cached_naming(defs_dir), all_meta,
                                     fallback_name=_Path(path).stem,
                                     owners=load_owners(defs_dir),
                                     expected=load_expected(defs_dir),
                                     profile=load_profile(resolve(defs_dir)))
        doc.setdefault("metadata", {})["source"] = "loot"
        from firru.cli.synth import synth_entries
        dynamic = synth_entries(data, cached_naming(defs_dir), all_meta, _Path(path).stem)[4]
        if dynamic:
            doc["metadata"]["dynamic_left_out"] = len(dynamic)
        return doc, unknown
    return _load(path), None


def _write(path, doc):
    with open(path, "w") as f:
        yaml_handler.dump(doc, f)


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _fmt_ports(ports):
    """Collapse sorted surface keys into 'tcp/22, tcp/49152-65535', prefixing
    the direction only for egress so ingress output reads as it always did."""
    by_proto = {}
    for key in sorted(ports):
        direction, proto, port = key
        label = f"out {proto}" if direction == DIR_OUT else proto
        by_proto.setdefault(label, []).append(port)
    chunks = []
    for proto in sorted(by_proto):
        runs = []
        for p in by_proto[proto]:
            if runs and p == runs[-1][1] + 1:
                runs[-1] = (runs[-1][0], p)
            else:
                runs.append((p, p))
        chunks.extend(f"{proto}/{lo}" if lo == hi else f"{proto}/{lo}-{hi}" for lo, hi in runs)
    return ", ".join(chunks)


def _src_tokens(src):
    """A peer field as a flat list of tokens ('ANY' if unrestricted)."""
    src = normalize_source(src)
    if src == "ANY":
        return ["ANY"]
    return list(src) if isinstance(src, tuple) else [src]


def _fmt_src(src):
    toks = _src_tokens(src)
    return toks[0] if len(toks) == 1 else "[" + ", ".join(toks) + "]"


def _term_peer_tokens(term, direction):
    """The term's peer tokens, read from the field its direction uses."""
    return _src_tokens(term.get(peer_field(direction)))


def _peer_verb(direction):
    """The firru verb that edits this side's peer field."""
    return "set-destination" if direction == DIR_OUT else "set-source"


def _peer_word(direction):
    """What the peer set is called in a report on this side."""
    return "dest" if direction == DIR_OUT else "source"


def _direction_arg(args):
    """The --direction restriction, or None for both sides."""
    d = getattr(args, "direction", None)
    return None if d in (None, "both") else d


def _flow_evidence(flows_file, host_ips, span=None):
    """``(direction, proto, port) -> Counter(peer_ip)`` from the flow record
    (JSONL or parquet), relative to one host. Peer = the far end: source for
    ingress, destination for egress.

    Reads only the flows that touch this host: on parquet the host addresses
    push down as a predicate (and a store narrowed to a window — a glob of the
    last N hours — prunes to those partitions), so the read is one host's slice,
    not the whole store. That is the operation that matters at exec scale — one
    host against an hour of live traffic decides its block-early posture — where
    a whole-fleet pass over 147M flows is neither needed nor affordable. On a
    per-host JSONL file the filter is a cheap no-op over a small file."""
    from firru.flows import iter_flow_groups
    from firru.flows import Hits
    ev = defaultdict(Hits)
    ips = set(host_ips)
    # Counted groups, as tighten reads them: one row per conversation rather
    # than per flow, and `unanswered` from the store's `responded` column.
    for g in iter_flow_groups(flows_file, host_ips=ips, span=span):
        port = g.get("dst_port")
        proto = g.get("protocol")
        if not port or not proto:
            continue
        if g.get("dst_ip") in ips:
            key, peer = (DIR_IN, proto, int(port)), g.get("src_ip")
        elif g.get("src_ip") in ips:
            key, peer = (DIR_OUT, proto, int(port)), g.get("dst_ip")
        else:
            continue
        ev[key][peer] += g["n"]
        if g["unanswered"]:
            ev[key].unanswered[peer] += g["unanswered"]
    return ev


def _admits(peers, ip):
    """Whether a resolved peer-set (term_peers) covers an address."""
    import ipaddress
    if peers is ANY_PEERS or peers == ANY_PEERS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for p in peers:
        try:
            if addr in ipaddress.ip_network(p, strict=False):
                return True
        except ValueError:
            continue  # an unresolvable token name compares to nothing
    return False


def _host_flow_index(flows_file, docs, defs, span=None, paths=()):
    """Build the ``(direction, proto, port) -> Counter(peer)`` index once for a
    host, from whichever of ``docs`` names it. Returns (ev, ips) or (None, None)
    when the host has no resolvable addresses — the read is the dominant cost of
    a --flows diff, so it is done exactly once and shared.

    The host is named as tighten names it: by a policy file's name where the
    definitions know it, since files are named by the inventory token, which is
    unique; metadata.host is the collector's label, which need not be (two
    zones can each have a `www`)."""
    from firru.cli.propose import get_host_ips
    candidates = [pathlib.Path(p).stem for p in paths if p]
    candidates += [(d.get("metadata") or {}).get("host") for d in docs]
    host_token, ips = None, []
    for tok in candidates:
        if not tok:
            continue
        host_token = host_token or tok
        ips = get_host_ips(tok, defs)
        if ips:
            host_token = tok
            break
    if not ips:
        print(f"Warning: no addresses for host token {host_token!r}; "
              f"--flows evidence skipped", file=sys.stderr)
        return None, None
    return _flow_evidence(flows_file, ips, span), ips


def _diff_evidence(ev, old_doc, new_doc, defs, result):
    """Per-changed-term evidence: ``id(term) -> {"hits": n, "cut": Counter}``.

    ``hits`` is how often the term's surface was exercised in the window;
    ``cut`` counts flows the change would newly block — peers the OLD side
    admitted that the NEW side does not (for a removal: everything observed).
    ``silent`` counts the flows of peers the NEW side admits although none of
    their flows was answered: tried, refused or unheard, never served. When
    there are any, ``keep`` is the NEW side's tokens without those that admit
    only such peers, ``left_out`` the rest, and ``keep_hits`` the flows ``keep``
    still covers.
    This is the paper's two counterfactuals made greppable: *observed* backs
    review-then-deploy, *unexercised* is what block-early accepts on faith
    (no data == can deny, with log-drop as the net), and *contradicted*
    (cut > 0) is never emitted runnable.
    """
    if ev is None:
        return None
    out = {}
    for cls in ("added", "narrowed", "widened", "removed", "cosmetic"):
        for term, ports in result[cls]:
            hits = sum(sum(ev.get(k, {}).values()) for k in ports)
            cut = Counter()
            if cls == "narrowed":
                direction = ports[0][0]
                new_peers = term_peers(defs, term, direction)
                old_peers = term_peers(defs, result["_old"][ports[0]], direction)
                for k in ports:
                    for ip, n in ev.get(k, {}).items():
                        if _admits(old_peers, ip) and not _admits(new_peers, ip):
                            cut[ip] += n
            elif cls == "removed":
                # The surface is gone entirely; every observed flow on it drops.
                for k in ports:
                    cut.update(ev.get(k, {}))
            silent = Counter()
            if cls != "removed":
                new_peers = term_peers(defs, term, ports[0][0])
                seen, unanswered = Counter(), Counter()
                for k in ports:
                    seen.update(ev.get(k, {}))
                    unanswered.update(getattr(ev.get(k), "unanswered", {}))
                silent = Counter({ip: n for ip, n in seen.items()
                                  if unanswered[ip] == n and _admits(new_peers, ip)})
            rec = {"hits": hits, "cut": cut, "silent": silent}
            if silent:
                rec.update(_without_silent(defs, term, ports[0][0], seen, silent))
            out[id(term)] = rec
    return out


def _without_silent(defs, term, direction, seen, silent):
    """Split the term's tokens: those whose observed peers include one that was
    answered, or none observed at all (kept), and those every observed peer of
    which went unanswered (left out). A group with one answered member stays,
    and then still admits its silent members: ``keep`` is empty unless what is
    kept admits none of them, so no runnable line widens."""
    keep, left_out = [], []
    for tok in _term_peer_tokens(term, direction):
        peers = source_peers(defs, tok)
        admitted = [ip for ip in seen if _admits(peers, ip)]
        if admitted and all(ip in silent for ip in admitted):
            left_out.append(tok)
        else:
            keep.append(tok)
    kept = source_peers(defs, keep) if keep else frozenset()
    if any(_admits(kept, ip) for ip in silent):
        keep = []
    keep_hits = sum(n for ip, n in seen.items() if keep and _admits(kept, ip))
    return {"keep": keep, "left_out": left_out, "keep_hits": keep_hits}


def _ev_tag(evidence, term):
    """The evidence word for a runnable line: ' observed (N flows)',
    ' unexercised', or '' when no flows were given."""
    if evidence is None:
        return ""
    rec = evidence.get(id(term))
    if rec is None:
        return ""
    return f" observed ({rec['hits']} flows)" if rec["hits"] else " unexercised"


def _ev_cut(evidence, term):
    """The would-be-cut counter for a term, or None."""
    rec = (evidence or {}).get(id(term))
    return rec["cut"] if rec and rec["cut"] else None


def _ev_silent(evidence, term):
    """Never-answered peers the new term admits, as a Counter of flows, or None.

    The window's policy refused them (or nothing listened), so admitting them
    grants more than was enforced: a widening, whatever the term's class says.
    """
    rec = (evidence or {}).get(id(term))
    return rec["silent"] if rec and rec.get("silent") else None


def _fmt_silent(silent, limit=3):
    return _fmt_cut(silent, limit).replace("observed flow(s)", "never-answered flow(s)", 1)


def _peer_label(ip, annotator):
    """How a peer reads in a report: a host by its inventory token (its v4
    and v6 addresses then count together), an address inside a network token
    as `ip (TOKEN)`, anything else as the address."""
    a = annotator.annotate_ip(ip)
    if a["type"] == "HOST":
        return a["host"]
    if a["type"] == "GROUP":
        return f"{ip} ({(a.get('parents') or [a['host']])[0]})"
    return ip


def _name_peers(evidence, defs_dir):
    """Relabel the peers in each record's `cut` and `silent` by _peer_label.
    Both are only ever reported, so the addresses are not needed after."""
    from firru.annotator import PolicyAnnotator
    annotator = PolicyAnnotator(defs_dir)
    for rec in evidence.values():
        for key in ("cut", "silent"):
            named = Counter()
            for ip, n in rec[key].items():
                named[_peer_label(ip, annotator)] += n
            rec[key] = named


def _fmt_cut(cut, limit=3):
    # Deterministic order: count descending, then peer string — so the example
    # list is stable regardless of the order flows were read (Counter ties would
    # otherwise follow insertion order, which the flow source can change).
    ordered = sorted(cut.items(), key=lambda kv: (-kv[1], kv[0]))
    peers = ", ".join(f"{ip}×{n}" for ip, n in ordered[:limit])
    more = f" +{len(cut) - limit} more" if len(cut) > limit else ""
    return f"{sum(cut.values())} observed flow(s) from {peers}{more}"


def _touched_old_names(result):
    """Names of OLD terms the diff already emits a line for, so the
    zero-evidence pass does not double up on them."""
    names = set()
    for cls in ("narrowed", "widened", "cosmetic"):
        for _, ports in result[cls]:
            t = result["_old"].get(ports[0])
            if t is not None and t.get("name"):
                names.add(t.get("name"))
    for term, _ in result["removed"]:
        if term.get("name"):
            names.add(term.get("name"))
    return names


def _zero_evidence(ev, old_doc, defs, direction, result):
    """OLD accept terms whose port surface saw zero flows in the window and
    that the diff did not otherwise touch. Returns [(name, scored)].

    These are the block-early divergence: a listener with no observed client.
    Review-then-deploy keeps it (absence is not proof it is unused); block-early
    drops it on the bet the window was too small, with the log-drop terminal as
    the net. Only accept terms with a real port surface qualify — loopback,
    icmp, and the catch-all terminal have no surface to be unexercised.
    """
    if ev is None:
        return []
    touched = _touched_old_names(result)
    out = []
    seen = set()
    for filt in old_doc.get("filters", []):
        for d in _sides(filt, direction):
            seq = filt.get("terms", [])
            scored = _scored_term_names(seq)
            for term in seq:
                if not is_accept_term(term):
                    continue
                name = term.get("name")
                if not name or name in touched or name in seen:
                    continue
                keys = term_surface_keys(defs, term, d)
                if not keys:
                    continue
                if sum(sum(ev.get(k, {}).values()) for k in keys) == 0:
                    seen.add(name)
                    out.append((name, name in scored))
    return out


def _merge_unknown(*unknowns):
    """Fold the unknown-port registries of the loot-backed sides into one."""
    merged = {}
    for u in unknowns:
        for key, info in (u or {}).items():
            slot = merged.setdefault(key, {"procs": Counter(), "hosts": set()})
            slot["procs"].update(info.get("procs") or {})
            slot["hosts"].update(info.get("hosts") or ())
    return merged


def _report_undefined(undefined, defs_dir, sh=False):
    """Ports the synthesis could not name. They are in no term, hence in no
    diff class — reported separately so an unnamed listener cannot vanish, and
    always as comments in sh: nothing mechanical happens to an unnamed port."""
    prefix = "# " if sh else "  "
    if sh:
        print(f"# undefined ({len(undefined)}) — no service token, so NOT in the "
              f"diff above. Name each one first, then re-run:")
    else:
        print(f"  undefined ({len(undefined)}) — no service token, NOT diffable; "
              f"an unnamed listener is an alert, not a gap:")
    for (proto, port) in sorted(undefined):
        info = undefined[(proto, port)]
        procs = ", ".join(f"{n}×{c}" for n, c in info["procs"].most_common(3)) or "?"
        line = (f"firru edit-services add {defs_dir}/services.yml "
                f"{proto.upper()}_{port} {port}/{proto}")
        print(f"{prefix}{line}  # undefined: {procs}")


def _fmt_peers(term, direction):
    return _fmt_src(term.get(peer_field(direction)))


# ---------------------------------------------------------------------------
# Term helpers
# ---------------------------------------------------------------------------

def _term_by_name(doc, name):
    """Return (filt, index, term) for the named term, or (None, None, None)."""
    for filt in doc.get("filters", []):
        for i, t in enumerate(filt.get("terms", [])):
            if t.get("name") == name:
                return filt, i, t
    return None, None, None


_is_accept = is_accept_term


def _sides(filt, direction=None):
    """Which sides of the policy this filter enforces, narrowed to the one the
    caller asked for if it asked.

    Empty when the document never states a direction (a zone pair, an ACL bound
    to an interface elsewhere), which drops the filter from the walk rather than
    filing its terms under a default side. Two entries when the filter really is
    both, as a pf rule with no `in`/`out` is.
    """
    dirs = filter_directions(filt)
    return sorted(dirs & {direction}) if direction else sorted(dirs)


def _clone_term(seq, idx):
    """Copy term seq[idx] with its full preceding comment block carried over."""
    nt = CommentedMap()
    for k, v in seq[idx].items():
        nt[k] = v
    _, kept = partition_comment(preceding_raw_comment(seq, idx), owned="")
    if kept:
        set_term_comment(nt, kept, [])
    return nt


# The egress stub `allow-ANY` is an accept, so an insertion that only looks
# for a deny lands after it and is dead on arrival — a rule that reads as
# enforcement and performs none. Hence catch-all, not just deny, is terminal.
_is_catch_all = is_catch_all


def _insert_before_terminal(terms, new_term):
    for i, t in enumerate(terms):
        if not _is_accept(t) or _is_catch_all(t):
            terms.insert(i, new_term)
            return
    terms.append(new_term)


def _terminal_swaps(old_doc, new_doc, direction=None):
    """``[(direction, open_accept_name, new_terminal_name)]`` where OLD's
    filter stays open (a catch-all accept) and NEW's ends in a real terminal.

    This is the one change the diff classes cannot carry: a terminal is not a
    row in the surface, it is the filter's default, and swapping an open end
    for a logged drop is the enforcement decision for the host. It is reported,
    and emitted only as a comment.
    """
    new_term_of = {}
    for filt in new_doc.get("filters", []):
        terms = filt.get("terms", [])
        if terms and not _is_accept(terms[-1]) and _is_catch_all(terms[-1]):
            for d in _sides(filt, direction):
                new_term_of[d] = terms[-1].get("name")
    swaps = []
    for filt in old_doc.get("filters", []):
        for d in _sides(filt):
            if d not in new_term_of:
                continue
            for t in filt.get("terms", []):
                if _is_accept(t) and _is_catch_all(t):
                    swaps.append((d, t.get("name"), new_term_of[d]))
                    break
    return swaps


def _pol_filter_for(pol, output):
    """The filter enforcing the requested side.

    Tested by membership rather than by equality with is_output_filter: a
    filter whose direction the document never states is neither side, and the
    old equality handed it back as the ingress filter.
    """
    want = DIR_OUT if output else DIR_IN
    for filt in pol.get("filters", []):
        if want in filter_directions(filt):
            return filt
    return None


def _file_header(path, limit=4):
    """The leading comment lines of a policy file, without their '#': where a
    generated proposal says what made it (tighten writes its flow window
    there). Only the file's own header, never a term's comments."""
    out = []
    try:
        with open(path, encoding="utf-8-sig") as f:
            for line in f:
                if not line.startswith("#"):
                    break
                text = line[1:].strip()
                if text:
                    out.append(text)
    except OSError:
        pass
    return out[:limit]


def _sh_header(old_path, new_path, flows=None, zero_evidence=False, window=None):
    """Where an -o sh script came from, as '#' lines a shell and `firru mass`
    skip: the two files, the proposal's own header, and the evidence. Inputs
    only, never a time or a version, so the same diff writes the same script.
    It avoids the class and evidence words (narrowed, observed, ...) that
    readers grep for, so a filtered script is only the commands."""
    lines = ["# firru diff -o sh", f"#   from:     {old_path}", f"#   to:       {new_path}"]
    for i, text in enumerate(_file_header(new_path)):
        lines.append(f"#   {'to says:' if i == 0 else '':9} {text}")
    if flows:
        lines.append(f"#   evidence: --flows {flows}" + (" --zero-evidence" if zero_evidence else ""))
        if window:
            lines.append(f"#   window:   {window}")
    else:
        lines.append("#   evidence: none (no --flows given)")
    return lines


def _emit_sh(old_path, new_path, defs_dir, result, direction=None, swaps=None,
             evidence=None, zero_evidence=None, header=None):
    """Emit runnable firru commands that turn OLD into NEW, one per change,
    each naming its term so `| grep SERVICE | sh` applies a subset. Each line
    carries its class as a trailing comment, so `| grep narrowed | sh` takes
    every safe tightening and nothing else. A line that must not run by
    accident (a widening, a change the traffic contradicts, a terminal swap)
    is itself a comment, so `| sh` on the whole output never widens.

    A restricted diff emits restricted commands: the scope that made the
    finding has to travel with the command that acts on it, or running the
    line re-opens the side the diff deliberately left out.
    """
    d = f" --defs {defs_dir}" + (f" --direction {direction}" if direction else "")
    for line in header or ():
        print(line)
    for side, open_name, term_name in swaps or ():
        print(f"# terminal ({side}): {old_path} stays open — {open_name!r} accepts whatever "
              f"the terms above did not match. {new_path} ends in {term_name!r}.")
        print(f"# The swap is the enforcement decision for this host, so it is commented "
              f"out: no grep takes it by accident.")
        print(f"# firru rm {old_path} {open_name} && "
              f"firru add-term {old_path} {term_name} --from {new_path}{d}  # terminal")
    for term, _ in result["added"]:
        line = f"firru add-term {old_path} {term.get('name')} --from {new_path}{d}"
        silent = _ev_silent(evidence, term)
        if silent:
            print(f"# {line}  # widened: would admit {_fmt_silent(silent)}")
        else:
            print(f"{line}  # added{_ev_tag(evidence, term)}")
    for cls in ("narrowed", "widened"):
        for term, ports in result[cls]:
            side = ports[0][0]
            # The command edits OLD, so it must name OLD's term: a proposal
            # that renames while narrowing otherwise emits a command that
            # no-ops with "term not found".
            old_name = result["_old"][ports[0]].get("name")
            line = (f"firru {_peer_verb(side)} {old_path} {old_name} "
                    f"{' '.join(_term_peer_tokens(term, side))} --defs {defs_dir}")
            cut = _ev_cut(evidence, term)
            silent = _ev_silent(evidence, term)
            if cut:
                # The change would block traffic that actually happened; a grep
                # must not be able to take it. Same rule as the terminal.
                print(f"# {line}  # {cls} CONTRADICTED: would cut {_fmt_cut(cut)}")
            elif silent:
                # It would admit peers that were tried and never answered: more
                # than was enforced. Not runnable as proposed; runnable without
                # the tokens that admit only those peers, when any remain.
                rec = evidence[id(term)]
                if rec["keep"] and cls == "narrowed":
                    print(f"firru {_peer_verb(side)} {old_path} {old_name} "
                          f"{' '.join(rec['keep'])} --defs {defs_dir}  # narrowed "
                          f"observed ({rec['keep_hits']} flows), left out never "
                          f"answered: {' '.join(rec['left_out'])}")
                print(f"# {line}  # widened: would admit {_fmt_silent(silent)}")
            elif cls == "widened":
                # It grants peers OLD did not. Review decides that, never a
                # grep, so it is a comment like every other line that must
                # not run by accident: `| sh` on the whole output is safe.
                print(f"# {line}  # widened REVIEW{_ev_tag(evidence, term)}")
            else:
                print(f"{line}  # {cls}{_ev_tag(evidence, term)}")
    for term, ports in result["cosmetic"]:
        old_name = result["_old"][ports[0]].get("name")
        print(f"firru add-term {old_path} {term.get('name')} --from {new_path} "
              f"--replace {old_name}{d}  # cosmetic")
    for term, _ in result["removed"]:
        cut = _ev_cut(evidence, term)
        if cut:
            print(f"# firru rm {old_path} {term.get('name')}  "
                  f"# removed CONTRADICTED: would cut {_fmt_cut(cut)}")
        else:
            print(f"firru rm {old_path} {term.get('name')}  # removed{_ev_tag(evidence, term)}")
    for name, scored in zero_evidence or ():
        # Unexercised listener. Runnable rm so block-early takes it; not tagged
        # "observed", so review-then-deploy's grep leaves it. rm vetoes a scored
        # term by default, so no flag is needed; a scored one is also emitted
        # commented so the reader sees it without running anything.
        if scored:
            print(f"# firru rm {old_path} {name}  # zero-evidence SCORED — kept")
        else:
            print(f"firru rm {old_path} {name}  # zero-evidence (0 flows)")


def _reviewed_sources_kept(result, old_doc, new_doc):
    """Against loot, a policy's sources are not a change to report. Loot says
    what listens, not who may reach it; synthesis fills in the profile's
    default (often ANY). Where the reviewed side is narrower than that, the
    review decided it, so the port leaves `widened` (and its address-family
    line, which follows from the sources) for a count of terms kept. The other
    direction stays: synthesis narrower than the policy is the profile's
    proposal. Returns the terms moved out."""
    def is_loot(d):
        return (d.get("metadata") or {}).get("source") == "loot"
    if is_loot(new_doc) == is_loot(old_doc):
        return []
    cls = "widened" if is_loot(new_doc) else "narrowed"
    kept = result[cls]
    if not kept:
        return []
    ports = {pp for _, ps in kept for pp in ps}
    result[cls] = []
    result["modified"] = [(t, ps) for t, ps in result.get("modified", [])
                          if not set(ps) <= ports]
    result["families"] = [f for f in result["families"] if not set(f[1]) <= ports]
    return kept


def _print_diff(name, result, swaps=None, evidence=None, zero_evidence=None):
    added, removed = result["added"], result["removed"]
    narrowed, widened = result["narrowed"], result["widened"]
    cosmetic, families = result["cosmetic"], result["families"]
    old_s = result["_old"]
    kept = result.get("kept") or []
    if not (added or removed or narrowed or widened or cosmetic or families or swaps):
        print(f"{name}: no surface changes" + (
            f" (reviewed sources kept on {len(kept)} term(s))" if kept else ""))
        return
    print(f"{name}:")
    if kept:
        print(f"  reviewed sources kept on {len(kept)} term(s): "
              + ", ".join(sorted({t.get('name', '?') for t, _ in kept})))
    for side, open_name, term_name in swaps or ():
        print(f"  terminal ({side}) — {open_name} keeps the filter open; the proposal "
              f"ends in {term_name}. The swap is the enforcement decision (see -o sh).")
    if added:
        word = "relations" if all(p[0][0] == DIR_OUT for _, p in added) else "listeners"
        print(f"  added ({len(added)}) — new {word}, safe to apply:")
        for term, ports in added:
            d = ports[0][0]
            print(f"    + {term.get('name',''):24s} {_fmt_ports(ports):22s} "
                  f"{_peer_word(d)} {_fmt_peers(term, d)}")
    if narrowed:
        print(f"  narrowed ({len(narrowed)}) — fewer peers, safe to apply:")
        for term, ports in narrowed:
            d = ports[0][0]
            cut = _ev_cut(evidence, term)
            silent = _ev_silent(evidence, term)
            note = (f"  !! CONTRADICTED: cuts {_fmt_cut(cut)}" if cut
                    else f"  !! WIDENED: admits {_fmt_silent(silent)}" if silent
                    else _ev_tag(evidence, term).replace(" ", "  ", 1))
            print(f"    > {term.get('name',''):24s} {_fmt_ports(ports):22s} {_peer_word(d)} "
                  f"{_fmt_peers(old_s[ports[0]], d)} -> {_fmt_peers(term, d)}{note}")
    if widened:
        print(f"  widened ({len(widened)}) — grants new peers, REVIEW:")
        for term, ports in widened:
            d = ports[0][0]
            print(f"    ! {term.get('name',''):24s} {_fmt_ports(ports):22s} {_peer_word(d)} "
                  f"{_fmt_peers(old_s[ports[0]], d)} -> {_fmt_peers(term, d)}")
    if families:
        print(f"  address family ({len(families)}) — coverage changed:")
        for term, ports, old_fam, new_fam in families:
            fam = lambda f: "+".join(f"v{x}" for x in sorted(f)) or "none"
            print(f"    # {term.get('name',''):24s} {_fmt_ports(ports):22s} {fam(old_fam)} -> {fam(new_fam)}")
    if removed:
        print(f"  removed ({len(removed)}) — no longer observed, advisory (rm vetoes a scored term):")
        for term, ports in removed:
            cut = _ev_cut(evidence, term)
            note = (f"  !! CONTRADICTED: cuts {_fmt_cut(cut)}" if cut
                    else _ev_tag(evidence, term).replace(" ", "  ", 1))
            print(f"    - {term.get('name',''):24s} {_fmt_ports(ports)}{note}")
    if cosmetic:
        print(f"  cosmetic ({len(cosmetic)}) — rename/regroup, same enforcement:")
        for term, ports in cosmetic:
            print(f"    ~ {term.get('name',''):24s} {_fmt_ports(ports)}")
    if zero_evidence:
        kept = [n for n, sc in zero_evidence if sc]
        drop = [n for n, sc in zero_evidence if not sc]
        print(f"  zero-evidence ({len(zero_evidence)}) — accept terms with no flows in "
              f"the window; block-early drops, review keeps:")
        for n in drop:
            print(f"    x {n}")
        for n in kept:
            print(f"    = {n}  (scored — kept even by block-early)")
    if evidence is not None and (narrowed or removed or zero_evidence):
        print("  postures: review-then-deploy takes `observed` only; block-early also"
              " takes `unexercised` and drops zero-evidence listeners (no data == can"
              " deny, log-drop as the net). CONTRADICTED and widenings are never runnable.")


def cmd_diff(args):
    from firru.project import flows_for
    try:
        args.flows, args.flow_span, args.flow_window = flows_for(
            args, getattr(args, "flows", None))
    except ValueError as e:
        sys.exit(f"firru diff: {e}")
    defs = cached_naming(args.defs)
    if getattr(args, "out", None):
        real = sys.stdout
        with open(args.out, "w") as f:
            sys.stdout = f
            try:
                _cmd_diff_body(args, defs)
            finally:
                sys.stdout = real
        # Wrote the file. The "1 == has changes" exit code is a stdout-mode
        # affordance (`if firru diff ...; then`); in file mode it would make a
        # normal diff read as a failure under `firru mass`, so report success.
        return 0
    return _cmd_diff_body(args, defs)


def _cmd_diff_body(args, defs):
    zp = getattr(args, "zone_prefix", None)
    old_doc, old_unknown = _load_side(args.old, args.defs, zp, allow_ruleset=True)
    new_doc, new_unknown = _load_side(args.new, args.defs, zp, allow_ruleset=True)
    if all((d.get("metadata") or {}).get("source") == "loot" for d in (old_doc, new_doc)):
        # Two synthesized loots compare what the heuristics make of each
        # listener and lose the process and the bind address; loot-diff
        # compares the listeners themselves. diff needs a policy on one side.
        raise SystemExit(f"firru diff: {args.old} and {args.new} are both loot: "
                         f"`firru loot-diff {args.old} {args.new}` compares listeners "
                         f"(--baseline for a stock install)")
    result = diff_surface(old_doc, new_doc, defs, _direction_arg(args))
    result["kept"] = _reviewed_sources_kept(result, old_doc, new_doc)
    swaps = _terminal_swaps(old_doc, new_doc, _direction_arg(args))
    undefined = _merge_unknown(old_unknown, new_unknown)
    ev = None
    if getattr(args, "flows", None):
        ev, _ = _host_flow_index(args.flows, (new_doc, old_doc), defs,
                                 getattr(args, "flow_span", None), (args.new, args.old))
    evidence = _diff_evidence(ev, old_doc, new_doc, defs, result) if ev is not None else None
    if evidence:
        _name_peers(evidence, args.defs)
    zero_ev = (_zero_evidence(ev, old_doc, defs, _direction_arg(args), result)
               if ev is not None and getattr(args, "zero_evidence", False)
               else None)
    enforced = [p for p, d in ((args.old, old_doc), (args.new, new_doc))
                if (d.get("metadata") or {}).get("source") == "enforced"]
    if args.output == "sh":
        if enforced:
            # Every emitted command edits the policy. Generated from a ruleset
            # they would rewrite pol/ to agree with whatever the host is running
            # — a hand-patched SSH widened to ANY would be applied as intent.
            # Drift is a finding to review, never a patch to take.
            raise SystemExit(
                f"{enforced[0]}: refusing to emit edits from enforced state — "
                f"these commands would rewrite the policy to match the host, "
                f"which is documenting the world instead of intending it. Read "
                f"the drift without -o sh and decide term by term.")
        _emit_sh(args.old, args.new, args.defs, result, _direction_arg(args),
                 swaps, evidence, zero_ev,
                 header=_sh_header(args.old, args.new, getattr(args, "flows", None),
                                   getattr(args, "zero_evidence", False),
                                   getattr(args, "flow_window", None)))
        if undefined:
            _report_undefined(undefined, args.defs, sh=True)
    else:
        name = (new_doc.get("metadata") or {}).get("host") or args.new
        if enforced:
            # The class names were written for synthesis, where NEW is a
            # proposal. Against a ruleset they mean something else, and a reader
            # who carries the synthesis reading across gets each one backwards.
            print("reading enforced state: 'removed' = committed but not running "
                  "(stale or never reloaded); 'widened' = the host grants more "
                  "than the policy (hand-patched or generated wider); 'added' = "
                  "running but never committed.")
        _print_diff(name, result, swaps, evidence, zero_ev)
        if undefined:
            _report_undefined(undefined, args.defs, sh=False)
        for path, d in ((args.old, old_doc), (args.new, new_doc)):
            n = (d.get("metadata") or {}).get("dynamic_left_out")
            if n:
                print(f"  dynamic range: {n} listener(s) in {path} left out, as synthesis "
                      f"leaves them; loot-diff --baseline compares them by owner")
    changed = any(result[k] for k in
                  ("added", "removed", "narrowed", "widened", "cosmetic", "families"))
    return 1 if (changed or undefined or zero_ev) else 0


# ---------------------------------------------------------------------------
# add-term
# ---------------------------------------------------------------------------

def _find_term(doc, name, direction=None):
    """(filter, index, term, side) of the term called `name`, on `direction`'s
    side when given; None when there is none."""
    for filt in doc.get("filters", []):
        terms = filt.get("terms", [])
        for side in _sides(filt, direction):
            for idx, term in enumerate(terms):
                if term.get("name") == name:
                    return filt, idx, term, side
    return None


def cmd_add_term(args):
    """Copy terms by name from another policy (or loot) into POL, before its
    terminal, carrying their comments. With --replace OLD, the one term takes
    OLD's place: a rename or regroup with the same ports, edited in place so
    OLD's comments stay. Adding a term grants something, so the lines firru
    emits for it are reviewed, not grepped."""
    defs = cached_naming(args.defs)
    direction = _direction_arg(args)
    pol = _load(args.pol)
    new_doc, from_unknown = _load_side(args.from_, args.defs)
    if args.replace and len(args.terms) != 1:
        print("--replace takes the place of one term: name one", file=sys.stderr)
        return 1
    wrote = False
    for name in args.terms:
        found = _find_term(new_doc, name, direction)
        if found is None:
            print(f"term {name!r} not found in {args.from_}", file=sys.stderr)
            return 1
        filt, idx, term, side = found
        if args.replace:
            old = _find_term(pol, args.replace, side)
            if old is None:
                print(f"term {args.replace!r} not found in {args.pol}", file=sys.stderr)
                return 1
            old_term = old[2]
            # A port folded into a group token reads as cosmetic at that port,
            # yet the group's token on the old term would widen it to every
            # port the group holds. A rename keeps the ports, or is not one.
            if term_ports(defs, old_term) != term_ports(defs, term):
                print(f"{args.pol}: {args.replace} and {name} cover different ports: "
                      f"not a rename. firru add-term {args.pol} {name} --from "
                      f"{args.from_}, then decide on {args.replace}", file=sys.stderr)
                return 1
            old_term["name"] = term.get("name")
            if "destination-port" in term:
                old_term["destination-port"] = term.get("destination-port")
            print(f"{args.pol}: {args.replace} -> {name}  (rename)")
            wrote = True
            continue
        if _find_term(pol, name, side) is not None:
            print(f"{args.pol}: already has {name}", file=sys.stderr)
            continue
        target = _pol_filter_for(pol, side == DIR_OUT)
        if target is None:
            print(f"{args.pol}: no {'output' if side == DIR_OUT else 'input'} filter "
                  f"for {name!r}", file=sys.stderr)
            return 1
        terms = target.setdefault("terms", [])
        clone = _clone_term(filt["terms"], idx)
        # Before any open catch-all accept too, so a terminal from NEW is live
        # whichever order its rm and this run in; the shadowed accept is then
        # dead and named for removal.
        _insert_before_terminal(terms, clone)
        wrote = True
        dead = None
        if not _is_accept(clone) and _is_catch_all(clone):
            i = terms.index(clone)
            dead = next((t for t in terms[i + 1:] if _is_accept(t) and _is_catch_all(t)), None)
        print(f"{args.pol}: + {name}"
              + (f"  (terminal: {dead.get('name')!r} is now dead; firru rm {args.pol} "
                 f"{dead.get('name')})" if dead else ""))
    if from_unknown:
        _report_undefined(from_unknown, args.defs, sh=False)
    if wrote:
        _write(args.pol, pol)
    return 0


# ---------------------------------------------------------------------------
# set-source / rm
# ---------------------------------------------------------------------------

def _detach_value_comments(term, field):
    """Raw comment text anchored on or inside the field's current value.

    Replacing a value discards whatever ruyaml had attached to it: the EOL
    comment of a scalar, and any comment lines anchored to the items of a
    list — which is where a human line following the list (a scoring note,
    typically) actually lives. Harvest them before the swap so the contract's
    inviolable class survives a mechanical edit.
    """
    out = []

    def _grab(slots):
        for i, tok in enumerate(slots):
            for t in (tok if isinstance(tok, list) else [tok]):
                if t is not None:
                    out.append(t.value)
            slots[i] = None

    ca = term.ca.items.get(field)
    if ca:
        _grab(ca)
    old = term.get(field)
    if isinstance(old, CommentedSeq):
        for slots in old.ca.items.values():
            _grab(slots)
    return "".join(out)


def _attach_tail_comment(term, field, raw):
    """Re-anchor harvested comment text after the field's new value."""
    if not raw:
        return
    raw = raw if raw.endswith("\n") else raw + "\n"
    val = term.get(field)
    if isinstance(val, CommentedSeq) and len(val):
        # sequence items carry their post-comment in slot 0 (mappings use 2)
        val.ca.items[len(val) - 1] = [CommentToken(raw, CommentMark(0)), None, None, None]
    else:
        slots = term.ca.items.setdefault(field, [None, None, None, None])
        slots[2] = CommentToken(raw, CommentMark(0))


def _set_peer_value(term, field, toks):
    """Set (or clear, for ANY) a term's peer field without losing the comments
    anchored to the old value."""
    raw = _detach_value_comments(term, field)
    if not toks:
        term.pop(field, None)
        term.ca.items.pop(field, None)
        if raw:
            # nowhere on the field to hang it any more; put it before the key
            # that follows, i.e. leave it on the term itself
            slots = term.ca.items.setdefault("action", [None, None, None, None])
            slots[2] = CommentToken(raw if raw.endswith("\n") else raw + "\n",
                                    CommentMark(0))
        return
    if len(toks) == 1:
        term[field] = toks[0]
    else:
        seq = CommentedSeq(toks)
        term[field] = seq
    _attach_tail_comment(term, field, raw)


def _cmd_set_peers(args, verb_direction):
    """Set a term's peer field. `verb_direction` is the side the invoked verb
    edits; a term on the other side is refused rather than rewritten.

    The refusal is the point. A `set-source` against an egress term writes a
    field nftables will not read there, leaving the term as permissive as it
    was while the command reports success.
    """
    pol = _load(args.pol)
    filt, _, term = _term_by_name(pol, args.term)
    if term is None:
        print(f"term {args.term!r} not found in {args.pol}", file=sys.stderr)
        return 1
    direction = filter_direction(filt)
    if direction is None:
        print(f"{args.term!r} sits in a filter that states no direction "
              f"({', '.join(target_names(filt)) or 'no target'}); firru cannot "
              f"tell which peer field applies", file=sys.stderr)
        return 1
    if direction != verb_direction:
        print(f"{args.term!r} is {'an egress' if direction == DIR_OUT else 'an ingress'} "
              f"term; use firru {_peer_verb(direction)}", file=sys.stderr)
        return 1
    field = peer_field(direction)
    toks = [t for t in args.peers if t.upper() != "ANY"]
    _set_peer_value(term, field, toks)
    _write(args.pol, pol)
    print(f"{args.pol}: {args.term} {_peer_word(direction)} -> {_fmt_src(term.get(field))}")
    return 0


def cmd_set_source(args):
    return _cmd_set_peers(args, DIR_IN)


def cmd_set_destination(args):
    return _cmd_set_peers(args, DIR_OUT)


# ---------------------------------------------------------------------------
# add-source / remove-source / set-action
# ---------------------------------------------------------------------------
# The verb is the class of change: remove narrows, add widens. A line edits
# only the peers it names, so lines apply in any order, one at a time, and
# onto a policy edited by hand since they were written, without undoing
# what they do not name.

def _peer_term(args, verb):
    """(doc, term, field, direction) for an add/remove verb, or an exit code.
    The verb says which field it edits; the term's filter must agree."""
    pol = _load(args.pol)
    filt, _, term = _term_by_name(pol, args.term)
    if term is None:
        print(f"term {args.term!r} not found in {args.pol}", file=sys.stderr)
        return 1
    direction = filter_direction(filt)
    if direction is None:
        print(f"{args.term!r} sits in a filter that states no direction "
              f"({', '.join(target_names(filt)) or 'no target'}); firru cannot "
              f"tell which peer field applies", file=sys.stderr)
        return 1
    want = DIR_OUT if verb.endswith("destination") else DIR_IN
    if direction != want:
        other = verb.replace("source", "destination") if want == DIR_IN \
            else verb.replace("destination", "source")
        print(f"{args.term!r} is {'an egress' if direction == DIR_OUT else 'an ingress'} "
              f"term; use firru {other}", file=sys.stderr)
        return 1
    return pol, term, peer_field(direction), direction


def _named_peers(term, field):
    """The peers a term names; [] when it is ANY."""
    return [t for t in _src_tokens(term.get(field)) if str(t).upper() != "ANY"]


def _cmd_remove_peers(args, verb):
    got = _peer_term(args, verb)
    if isinstance(got, int):
        return got
    pol, term, field, direction = got
    have = _named_peers(term, field)
    if not have:
        print(f"{args.pol}: {args.term} {_peer_word(direction)} is ANY: nothing to "
              f"remove from; firru {_peer_verb(direction)} narrows it", file=sys.stderr)
        return 1
    drop = set(args.peers)
    gone = [p for p in args.peers if p not in have]
    for p in gone:
        print(f"{args.pol}: {args.term} has no {p} (already removed)", file=sys.stderr)
    keep = [t for t in have if t not in drop]
    if keep == have:
        return 0
    if keep:
        _set_peer_value(term, field, keep)
        _write(args.pol, pol)
        print(f"{args.pol}: {args.term} {_peer_word(direction)} -> {_fmt_src(term.get(field))}")
        return 0
    # Nobody is left. An empty peer list is ANY in Aerleon, the opposite of
    # what removing the last one means, so the term denies instead, logged:
    # what it refuses stays visible.
    _set_peer_value(term, field, [])
    term["action"] = "deny"
    _set_logging(term, True)
    _write(args.pol, pol)
    print(f"{args.pol}: {args.term} -> deny, logged (its last {_peer_word(direction)} removed)")
    return 0


def _cmd_add_peers(args, verb):
    got = _peer_term(args, verb)
    if isinstance(got, int):
        return got
    pol, term, field, direction = got
    have = _named_peers(term, field)
    if not have:
        print(f"{args.pol}: {args.term} {_peer_word(direction)} is already ANY", file=sys.stderr)
        return 0
    new = [p for p in args.peers if p not in have]
    if not new:
        return 0
    _set_peer_value(term, field, have + new)
    _write(args.pol, pol)
    print(f"{args.pol}: {args.term} {_peer_word(direction)} -> {_fmt_src(term.get(field))}")
    return 0


def cmd_remove_source(args):
    return _cmd_remove_peers(args, "remove-source")


def cmd_remove_destination(args):
    return _cmd_remove_peers(args, "remove-destination")


def cmd_add_source(args):
    return _cmd_add_peers(args, "add-source")


def cmd_add_destination(args):
    return _cmd_add_peers(args, "add-destination")


ACTIONS = ("accept", "deny", "reject")


def _set_logging(term, on):
    """Logging beside the action, not appended: a term's last key carries
    the comment that trails it, and a key after it would sit below that."""
    if not on:
        term.pop("logging", None)
        return
    if "logging" in term:
        term["logging"] = True
        return
    keys = list(term.keys())
    at = keys.index("action") + 1 if "action" in keys else len(keys)
    term.insert(at, "logging", True)
    # A comment after the action line now follows the logging line instead.
    slots = term.ca.items.get("action")
    if slots and len(slots) > 2 and slots[2] is not None:
        term.ca.items.setdefault("logging", [None, None, None, None])[2] = slots[2]
        slots[2] = None


def cmd_set_action(args):
    """Set a term's action; --log turns logging on, --no-log off. A deny
    keeps the term, so what it refuses can be logged, and the next synthesis
    finds the port decided rather than proposing it again."""
    pol = _load(args.pol)
    _, _, term = _term_by_name(pol, args.term)
    if term is None:
        print(f"term {args.term!r} not found in {args.pol}", file=sys.stderr)
        return 1
    if args.action != "accept" and not args.force \
            and args.term in _scored_term_names(_filter_terms(pol, args.term)):
        print(f"{args.pol}: kept {args.term} (scored — do not block; --force to override)")
        return 0
    term["action"] = args.action
    if args.log is not None:
        _set_logging(term, args.log)
    _write(args.pol, pol)
    logged = ", logged" if term.get("logging") else ""
    print(f"{args.pol}: {args.term} -> {args.action}{logged}")
    return 0


def _filter_terms(pol, name):
    filt, _, _ = _term_by_name(pol, name)
    return filt.get("terms", []) if filt is not None else []


# Markers of a human "must stay open" decision. Today scoring lives in these
# inviolable comments (docs/comment-contract.md); TODO(scoring-file): read a
# machine-readable environment file instead — it is authoritative and changes
# on the fly during an exercise, where a comment is both flaky to parse and
# stale the moment the scoring config is updated.
_SCORE_MARKERS = ("scoring", "do not block", "[score]")


def _scored_term_names(seq):
    """Names of terms carrying a human scoring / 'do not block' comment.

    The comment trails the term it protects, so ruyaml stores it on this term's
    last key and it reads back as the block preceding the *next* term. Both that
    position and any comment attached to the term itself are scanned; the check
    is deliberately broad, because a false positive only makes a drop less
    aggressive while a miss would remove a must-open port.
    """
    protected = set()
    n = len(seq)
    for i in range(n):
        term = seq[i]
        name = term.get("name") if hasattr(term, "get") else None
        if not name:
            continue
        blocks = []
        if i + 1 < n:
            blocks.append(preceding_raw_comment(seq, i + 1))
        ca = getattr(term, "ca", None)
        items = getattr(ca, "items", None) if ca is not None else None
        if items:
            for slots in items.values():
                for tok in (slots if isinstance(slots, list) else [slots]):
                    if tok is not None and getattr(tok, "value", None):
                        blocks.append(tok.value)
        text = " ".join(b for b in blocks if b).lower()
        if any(m in text for m in _SCORE_MARKERS):
            protected.add(name)
    return protected


def cmd_rm(args):
    pol = _load(args.pol)
    filt, idx, term = _term_by_name(pol, args.term)
    if term is None:
        print(f"term {args.term!r} not found in {args.pol}", file=sys.stderr)
        return 1
    if not getattr(args, "force", False):
        if args.term in _scored_term_names(filt.get("terms", [])):
            print(f"{args.pol}: kept {args.term} (scored — do not block; --force to override)")
            return 0
    del filt["terms"][idx]
    _write(args.pol, pol)
    print(f"{args.pol}: removed {args.term}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Apply deterministic edits to a human-edited policy.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_diff = sub.add_parser("diff", help="Preview (or emit commands for) the delta between two generated policies",
                            description="What changes between two policies (OLD, NEW), term by term: "
                                        "narrowed, widened, added, removed, cosmetic. With --flows, "
                                        "which changes the traffic backs or contradicts; with -o sh, "
                                        "each change as a firru command to keep or drop with grep. "
                                        "NEW may be an nft -j or firewall.json dump of the running "
                                        "firewall. Exits 1 when there are changes, like diff.")
    p_diff.add_argument("old", metavar="OLD", help="Baseline generated policy")
    p_diff.add_argument("new", metavar="NEW", help="Newer generated policy")
    p_diff.add_argument("--defs", "-d", default="def", help="Aerleon definitions directory")
    p_diff.add_argument("--direction", choices=["in", "out", "both"], default="both",
                        help="Restrict to one side of the policy. Use --direction out\n                             with a generator that proposes only egress: otherwise the\n                             absent ingress filter reads as wholly removed.")
    p_diff.add_argument("--flows", metavar="FLOWS", default=None,
                        help="Normalized flows (JSONL, or a parquet store; with a window "
                             "and no --flows, the project's store): tag each change "
                             "observed/unexercised, "
                             "and comment out changes the traffic contradicts. Use a window "
                             "*after* NEW was generated and this is holdout validation.")
    p_diff.add_argument("--zero-evidence", action="store_true",
                        help="Also emit a rm for every accept term that saw no flows in the "
                             "window (the block-early bet: no client == drop it, log-drop as "
                             "the net). Needs --flows. Scored terms are emitted commented.")
    p_diff.add_argument("--zone-prefix", default=None,
                        help="Chain-name prefix that aerleon-to-nftables added, stripped "
                             "when a side is an `nft -j list ruleset` dump so term names "
                             "line up with the policy they were generated from. Without "
                             "it the drift reads as cosmetic on every term.")
    p_diff.add_argument("--out", metavar="FILE", default=None,
                        help="Write the diff/script to FILE instead of stdout, so a stream "
                             "of `firru diff ... --out f` commands can run under `firru mass` "
                             "(one process, defs cached) for a whole fleet.")
    p_diff.add_argument("-o", "--output", choices=["human", "sh"], default="human",
                        help="human report (default) or runnable 'sh' commands")
    from firru.project import add_window_arguments
    add_window_arguments(p_diff)
    p_diff.set_defaults(func=cmd_diff)

    p_add = sub.add_parser("add-term", help="Copy terms by name from another policy or loot",
                           description="Copy each TERM from NEW (a policy, or loot synthesized "
                                       "in memory) into POL, before its terminal, with its "
                                       "comments. A term POL has is left alone. With --replace "
                                       "OLD, the term takes OLD's place: a rename with the same "
                                       "ports, so OLD's comments stay.")
    p_add.add_argument("pol", metavar="POL", help="Policy YAML to edit in place")
    p_add.add_argument("terms", metavar="TERM", nargs="+", help="Term name(s) in NEW")
    p_add.add_argument("--from", dest="from_", metavar="NEW", required=True,
                       help="Policy or loot to copy from")
    p_add.add_argument("--replace", metavar="OLD", default=None,
                       help="Rename OLD to TERM in place (same ports, same enforcement)")
    p_add.add_argument("--defs", "-d", default="def", help="Aerleon definitions directory")
    p_add.add_argument("--direction", choices=["in", "out", "both"], default="both",
                       help="Take TERM from this side of NEW only")
    p_add.set_defaults(func=cmd_add_term)

    p_set = sub.add_parser("set-source",
                           help="Set an ingress term's source-address (ANY = unrestricted)",
                           description="Set the source-address of ingress term TERM in POL, in "
                                       "place, keeping its comments.")
    p_set.add_argument("pol", metavar="POL", help="Policy YAML to edit in place")
    p_set.add_argument("term", metavar="TERM", help="Term name")
    p_set.add_argument("peers", metavar="SRC", nargs="+", help="Source token(s), or ANY")
    p_set.add_argument("--defs", "-d", default="def")  # accepted for emit-sh symmetry; unused
    p_set.set_defaults(func=cmd_set_source)

    p_setd = sub.add_parser("set-destination",
                            help="Set an egress term's destination-address (ANY = unrestricted)",
                            description="Set the destination-address of egress term TERM in POL, "
                                        "in place, keeping its comments. Also: firru set-dest.")
    p_setd.add_argument("pol", metavar="POL", help="Policy YAML to edit in place")
    p_setd.add_argument("term", metavar="TERM", help="Term name")
    p_setd.add_argument("peers", metavar="DST", nargs="+", help="Destination token(s), or ANY")
    p_setd.add_argument("--defs", "-d", default="def")  # accepted for emit-sh symmetry; unused
    p_setd.set_defaults(func=cmd_set_destination)

    for verb, word, func in (
            ("add-source", "Add sources to", cmd_add_source),
            ("remove-source", "Remove sources from", cmd_remove_source),
            ("add-destination", "Add destinations to", cmd_add_destination),
            ("remove-destination", "Remove destinations from", cmd_remove_destination)):
        side = "ingress" if verb.endswith("source") else "egress"
        p = sub.add_parser(verb, help=f"{word} an {side} term",
                           description=f"{word} {side} term TERM in POL, in place, keeping "
                                       "its comments. Only the named peers change, so the "
                                       "line holds on a policy edited since it was written."
                                       + (" Removing the last one makes the term a logged "
                                          "deny: an empty list would be ANY."
                                          if verb.startswith("remove") else
                                          " A term that is ANY stays ANY."))
        p.add_argument("pol", metavar="POL", help="Policy YAML to edit in place")
        p.add_argument("term", metavar="TERM", help="Term name")
        p.add_argument("peers", metavar="PEER", nargs="+", help="Token(s)")
        p.add_argument("--defs", "-d", default="def")  # accepted for emit-sh symmetry; unused
        p.set_defaults(func=func)

    p_act = sub.add_parser("set-action", help="Set a term's action (accept, deny, reject)",
                           description="Set the action of term TERM in POL, in place. A term "
                                       "carrying a [score] note is not denied unless --force.")
    p_act.add_argument("pol", metavar="POL", help="Policy YAML to edit in place")
    p_act.add_argument("term", metavar="TERM", help="Term name")
    p_act.add_argument("action", choices=ACTIONS)
    p_act.add_argument("--log", dest="log", action="store_true", default=None,
                       help="Log what the term matches")
    p_act.add_argument("--no-log", dest="log", action="store_false",
                       help="Stop logging what the term matches")
    p_act.add_argument("--force", action="store_true",
                       help="Deny even a term carrying a scoring / 'do not block' comment")
    p_act.add_argument("--defs", "-d", default="def")  # accepted for emit-sh symmetry; unused
    p_act.set_defaults(func=cmd_set_action)

    p_rm = sub.add_parser("rm", help="Remove a term by name",
                          description="Remove term TERM from POL, in place. A term carrying a "
                                      "[score] note is refused unless --force.")
    p_rm.add_argument("pol", metavar="POL", help="Policy YAML to edit in place")
    p_rm.add_argument("term", metavar="TERM", help="Term name")
    p_rm.add_argument("--force", action="store_true",
                      help="Remove even a term carrying a scoring / 'do not block' comment. "
                           "By default rm refuses one — the veto is on, not opt-in.")
    p_rm.set_defaults(func=cmd_rm)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
