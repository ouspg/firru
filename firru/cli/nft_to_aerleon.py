#!/usr/bin/env python3
"""
nft-to-aerleon — read a running nftables ruleset into firru policy YAML.

The loot was the wrong shape for this. A running ruleset is not host inventory
with a number attached; it is policy. Once it is policy YAML, everything firru
already does applies to a host nobody generated: `merge-zones` folds it into a
central firewall, `policy-diff` puts it beside the committed policy, and the converters render it
for a different target than the one it came from.

    # on the host
    nft -j list ruleset > fw.json

    nft-to-aerleon fw.json --defs def/ --host web1.example.org -o web1.yml
    firru merge-zones --policy web1.yml ...

The parse is deliberately partial. A ruleset from a Calico node, a hand-written
firewall or an appliance carries matches this parser has no representation for,
and refusing a rule because of one of them converts nothing. Ignoring them
converts nearly all of it, which is worth much more -- on the condition that the
reader is told what was ignored and which way the error runs. An ignored match
almost always *narrows* the rule, so the term that comes out is wider than the
rule that went in. Every such term says so in a comment, the summary counts
them, and the ignored match kinds are named, so "90% of this host" is a number
rather than a hope.

Addresses come back as numbers and a policy is written in tokens, so a set is
named only when a token expands to exactly it; a token covering more would
widen the rule and is never chosen. Addresses no token names are carried as
literals rather than dropped, because dropping an address match does not narrow
a term, it deletes the match. Literals make the file diff-ready and readable
rather than compilable, and the summary says how many terms are in that state.

With counters on (the default) the packet count comes across as a comment, which
is how a deployed rule that has never matched becomes visible.
"""

import argparse
import json
import subprocess
import sys

from collections import Counter

from ruyaml import YAML
from ruyaml.comments import CommentedMap, CommentedSeq

from firru.comments import TAG_AUTO, set_term_comment, tagged
from firru.nftparse import (_collapse, chains_with_rules, merge_rules,
                            resolve_tokens)

yaml_handler = YAML()
yaml_handler.indent(mapping=2, sequence=4, offset=2)


def _port_spec(ports):
    return [str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ports]


def term_for(name, match, defs):
    """One merged chain -> (term, unnamed addresses)."""
    term = CommentedMap()
    term["name"] = name
    if match["protocol"]:
        term["protocol"] = match["protocol"]
    unnamed = {}
    for key in ("source-address", "destination-address"):
        toks, left = resolve_tokens(match[key], defs)
        # Addresses no token names are carried through as literals rather than
        # dropped. Dropping them does not narrow the term, it deletes the match
        # and widens it to everything, which is the one error this file must
        # not contain: it exists to be diffed against the committed policy, and
        # a rule that reads as wider than it is turns a clean diff into a lie.
        values = list(toks) + [str(n) for n in left]
        if values:
            term[key] = values[0] if len(values) == 1 else values
        if left:
            unnamed[key] = [str(n) for n in left]
    for key in ("source-port", "destination-port"):
        if match[key]:
            spec = _port_spec(match[key])
            term[key] = spec[0] if len(spec) == 1 else spec
    for key in ("source-interface", "destination-interface"):
        if match.get(key):
            term[key] = match[key]
    term["action"] = match["action"]
    if match["established"]:
        term["option"] = ["established"]
    if match["logging"]:
        term["logging"] = True

    notes = []
    if match["counted"]:
        notes.append(tagged(TAG_AUTO, f"{match['packets']} packet(s) since the "
                                      f"ruleset was loaded"
                                      + (" — never matched" if not match["packets"]
                                         else "")))
    if match.get("ignored"):
        notes.append(tagged(TAG_AUTO,
                            f"PARTIAL: ignored match(es) {', '.join(match['ignored'])}"
                            f" — this term is WIDER than the rule it came from"))
    for key, addrs in unnamed.items():
        notes.append(tagged(TAG_AUTO,
                            f"UNNAMED {key}: {len(addrs)} address(es) carried as "
                            f"literals — no token expands to exactly these, and a "
                            f"token that covers more would widen the rule"))
    if notes:
        set_term_comment(term, notes, [])
    return term, unnamed


def _each(rules):
    """Base-chain rules as one match each, in order, not merged.

    A generated chain holds one term split across address families and merging
    is right. A hooked chain holds a sequence of unrelated decisions, and
    merging those would fuse rules that only happen to share a protocol.
    """
    out = []
    for r in rules:
        m = dict(r)
        m["counted"] = r.get("packets") is not None
        m["packets"] = r.get("packets") or 0
        m["ignored"] = r.get("ignored") or []
        for k in ("source-address", "destination-address"):
            m[k] = _collapse(m.get(k) or [])
        out.append(m)
    return out


def _describe_match(m):
    """A readable term name for a rule that never had one."""
    bits = [m["action"]]
    if m["protocol"]:
        bits.append(str(m["protocol"]))
    ports = m["destination-port"] or m["source-port"]
    if ports:
        lo, hi = ports[0]
        bits.append(str(lo) if lo == hi else f"{lo}-{hi}")
    elif m["established"]:
        bits.append("established")
    iface = m.get("source-interface") or m.get("destination-interface")
    if iface:
        bits.append(iface.replace("+", "any").strip("*"))
    return "-".join(bits)


def _unique(name, used):
    if name not in used:
        used.add(name)
        return name
    i = 2
    while f"{name}-{i}" in used:
        i += 1
    used.add(f"{name}-{i}")
    return f"{name}-{i}"


def convert(doc, defs, zone_prefix=None, counters=True, host=None, zone=None):
    """Ruleset -> (policy document, stats)."""
    terms = CommentedSeq()
    stats = {"chains": 0, "terms": 0, "unnamed_terms": 0, "base": 0, "idle": 0,
             "partial": 0, "skipped": 0, "nat": 0, "ignored_kinds": Counter(),
             "default": None}
    chains, skipped, nat = chains_with_rules(doc)
    stats["nat"] = sum(nat.values())
    for kinds in skipped.values():
        for k in kinds:
            stats["skipped"] += 1
            stats["ignored_kinds"].update(k or ["no verdict"])
    used = set()
    for chain, (meta, rules) in sorted(chains.items()):
        if meta["base"]:
            stats["base"] += 1
            if meta.get("policy") and meta.get("hook") in ("input", None):
                stats["default"] = stats["default"] or meta["policy"]
            # A base chain is not always just a dispatcher. Aerleon gives every
            # term its own chain and hooks a bare one, but Calico, an appliance
            # and anything hand-written put the rules straight into the hooked
            # chain. Skipping base chains reads the first shape perfectly and
            # the second as an empty policy, so both are read.
            matches = [(m, f"{chain}-{_describe_match(m)}") for m in _each(rules)]
        else:
            stats["chains"] += 1
            name = chain
            if zone_prefix and name.startswith(zone_prefix + "_"):
                name = name[len(zone_prefix) + 1:]
            merged = merge_rules(rules)
            matches = [(m, name if len(merged) == 1 else f"{name}-{i + 1}")
                       for i, m in enumerate(merged)]
        for match, term_name in matches:
            if not counters:
                match = dict(match, counted=False)
            term_name = _unique(term_name, used)
            term, unnamed = term_for(term_name, match, defs)
            terms.append(term)
            stats["terms"] += 1
            if unnamed:
                stats["unnamed_terms"] += 1
            if match.get("ignored"):
                stats["partial"] += 1
                stats["ignored_kinds"].update(match["ignored"])
            if match["counted"] and not match["packets"]:
                stats["idle"] += 1
    # The base chain's policy is the terminal the rest of firru expects to see
    # as a term; a host imported without it would merge into a zone as a set of
    # accepts with nothing behind them.
    if stats["default"] in ("drop", "reject"):
        terminal = CommentedMap()
        terminal["name"] = "drop-ANY"
        terminal["action"] = "deny" if stats["default"] == "drop" else "reject"
        set_term_comment(terminal, [tagged(
            TAG_AUTO, "from the base chain's policy, not from a rule")], [])
        terms.append(terminal)

    doc_out = CommentedMap()
    if host or zone:
        meta = CommentedMap()
        if host:
            meta["host"] = host
        if zone:
            meta["zone"] = zone
        doc_out["metadata"] = meta
    doc_out["filters"] = [{"header": {"targets": {"nftables": "mixed input"}},
                           "terms": terms}]
    return doc_out, stats


def read_ruleset(path):
    if path == "--run":
        out = subprocess.run(["nft", "-j", "list", "ruleset"],
                             capture_output=True, text=True, check=True)
        return json.loads(out.stdout)
    if path == "-":
        return json.load(sys.stdin)
    with open(path) as f:
        return json.load(f)


def main():
    p = argparse.ArgumentParser(
        description="Read a running nftables ruleset back into aerleon policy YAML.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="On the host:  nft -j list ruleset > fw.json")
    p.add_argument("ruleset", help="nft -j output; '-' for stdin, '--run' to run "
                                   "nft here (needs root)")
    p.add_argument("--defs", "-d", default="def", help="Aerleon definitions, for "
                                                       "naming addresses back")
    p.add_argument("--zone-prefix", default=None,
                   help="Chain-name prefix added by aerleon-to-nftables, stripped "
                        "so term names match the policy they came from")
    p.add_argument("--host", default=None,
                   help="Hostname to record in metadata, so merge-zones "
                        "accepts the result")
    p.add_argument("--zone", default=None, help="Zone to record in metadata")
    p.add_argument("--no-counters", action="store_true",
                   help="Leave packet counts out of the emitted comments")
    p.add_argument("-o", "--output", default="-", metavar="YML",
                   help="Where to write the policy (default: stdout)")
    args = p.parse_args()

    try:
        doc = read_ruleset(args.ruleset)
    except FileNotFoundError:
        print(f"nft-to-aerleon: no such file: {args.ruleset}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"nft-to-aerleon: {args.ruleset} is not nft -j output: {e}",
              file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as e:
        print(f"nft-to-aerleon: nft failed: {e.stderr.strip()}", file=sys.stderr)
        return 1

    from aerleon.lib import naming
    try:
        defs = naming.Naming(args.defs)
    except Exception as e:
        print(f"Warning: no definitions from {args.defs} ({e}); every address "
              f"will come back unnamed", file=sys.stderr)
        defs = None

    policy, stats = convert(doc, defs, args.zone_prefix, not args.no_counters,
                            host=args.host, zone=args.zone)

    if args.output == "-":
        yaml_handler.dump(policy, sys.stdout)
    else:
        with open(args.output, "w") as f:
            yaml_handler.dump(policy, f)

    understood = stats["terms"]
    total = understood + stats["skipped"]
    pct = (100 * understood / total) if total else 100
    msg = (f"{understood} term(s) from {stats['chains']} chain(s), "
           f"{stats['base']} base chain(s) read for the default policy "
           f"({stats['default'] or 'none'}); {pct:.0f}% of rules understood")
    if stats["unnamed_terms"]:
        msg += (f"; {stats['unnamed_terms']} term(s) carry literal addresses no "
                f"token names — diff-ready, not compilable")
    if stats["idle"]:
        msg += f"; {stats['idle']} term(s) have never matched"
    if stats["partial"]:
        msg += (f"; {stats['partial']} term(s) dropped a narrowing match and are "
                f"WIDER than the rule")
    print(msg, file=sys.stderr)
    if stats["nat"]:
        print(f"  {stats['nat']} address-translation rule(s) are not filter policy "
              f"and are left out of both counts", file=sys.stderr)
    if stats["ignored_kinds"]:
        print("  ignored: " + ", ".join(f"{k} x{n}" for k, n in
                                        stats["ignored_kinds"].most_common(8)),
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
