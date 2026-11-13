#!/usr/bin/env python3
"""
winfw-to-aerleon — read a running Windows Firewall (firewall.json from
loot-host.ps1) into firru policy YAML: the Windows counterpart of
nft-to-aerleon, so `firru diff POL firewall.json` reads deployment drift on
Windows as it does on Linux.

    winfw-to-aerleon loot/dc01/loot-host/firewall.json --defs def/ -o dc01.yml
    firru diff policies/pol/dc01.yml loot/dc01/loot-host/firewall.json

Inbound rules only, for the profiles live on the host's interfaces. The parse
is deliberately partial in the same direction as nft-to-aerleon: what aerleon
cannot express is dropped from the match and the term says so, and dropping a
match widens a term, never narrows it.

- Program, service and package scoping have no aerleon field. A rule for one
  program on port Any reads as port Any for everyone: the widest case, and
  flagged PARTIAL like every other dropped match.
- Remote-address keywords (LocalSubnet, Intranet, PlayToDevice ...) are
  dropped the same way; literal addresses are named by token when a token
  covers exactly them, else carried as literals.
- The RPC port keyword is read as the dynamic range 49152-65535; RPCEPMap is
  135, IPHTTPS 443. Other port keywords cannot be read, and the rule is
  skipped (counted): turning an unknown port into Any would widen it to all.
- Block rules come first. In Windows a Block rule beats any Allow regardless
  of order; first-match with blocks ahead reproduces that.
- A profile with the firewall off becomes one accept-everything term, which
  is what the host enforces there.
"""

import argparse
import json
import sys
from collections import Counter

from ruyaml.comments import CommentedMap, CommentedSeq

from firru import winfw
from firru.comments import TAG_AUTO, set_term_comment, tagged
from firru.nftparse import resolve_tokens


def _port_spec(ports):
    return [str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ports]


def convert(fw, defs, host=None, profiles=None):
    """firewall.json -> (policy document, stats), stats shaped like nft-to-aerleon's."""
    stats = {"chains": 0, "terms": 0, "unnamed_terms": 0, "base": 0, "idle": 0,
             "partial": 0, "skipped": 0, "nat": 0, "ignored_kinds": Counter(),
             "default": None}
    profiles = frozenset(profiles) if profiles else winfw.active_profiles(fw)
    state = winfw.profile_state(fw)
    off = winfw.firewall_off(fw, profiles)
    terms = CommentedSeq()
    used = set()

    if off:
        t = CommentedMap()
        t["name"] = "firewall-off"
        t["action"] = "accept"
        set_term_comment(t, [tagged(TAG_AUTO, f"Windows Firewall is off on the "
                                              f"{', '.join(off)} profile: everything inbound is admitted")], [])
        terms.append(t)
        stats["terms"] += 1
        stats["default"] = "accept"
    else:
        inbound = [r for r in winfw.rules(fw) if winfw.applies(r, profiles)]
        ordered = [r for r in inbound if r["action"] == "deny"] + \
                  [r for r in inbound if r["action"] == "accept"]
        for r in ordered:
            ignored = []
            if r["protocol"] not in ("tcp", "udp"):
                # Ports mean nothing off TCP/UDP; ICMP rules even carry a stray
                # RPC keyword in LocalPort. The ICMP type is what scopes them.
                r = dict(r, ports=[], port_keywords=[], port_any=True)
                if r.get("icmp_types"):
                    ignored.append("ICMP type " + "/".join(r["icmp_types"]))
            if r["port_keywords"]:
                unknown = [k for k in r["port_keywords"] if k.lower() != "rpc"]
                if unknown or not r["ports"] and not any(k.lower() == "rpc" for k in r["port_keywords"]):
                    stats["skipped"] += 1
                    stats["ignored_kinds"].update(f"port keyword {k}" for k in unknown)
                    continue
            ports = list(r["ports"])
            if any(k.lower() == "rpc" for k in r["port_keywords"]):
                ports.append(winfw.RPC_DYNAMIC)
                ignored.append("RPC keyword (read as the dynamic range)")
            for key, label in (("program", "program"), ("service", "service"), ("package", "package")):
                if r.get(key):
                    ignored.append(label)
            if r["remote_keywords"]:
                ignored.append("remote " + "/".join(r["remote_keywords"]))
            if r["protocol"] not in (None, "tcp", "udp", "icmp", "icmpv6"):
                ignored.append(f"protocol {r['protocol']}")

            term = CommentedMap()
            name = r["name"]
            i = 2
            while name in used:
                name = f"{r['name']}-{i}"
                i += 1
            used.add(name)
            term["name"] = name
            if r["protocol"] in ("tcp", "udp", "icmp", "icmpv6"):
                term["protocol"] = r["protocol"]
            unnamed = []
            if r["remote"] and not r["remote_keywords"]:
                toks, left = resolve_tokens(r["remote"], defs)
                values = list(toks) + [str(n) for n in left]
                term["source-address"] = values[0] if len(values) == 1 else values
                unnamed = [str(n) for n in left]
            if ports and r["protocol"] in ("tcp", "udp"):
                spec = _port_spec(sorted(set(ports)))
                term["destination-port"] = spec[0] if len(spec) == 1 else spec
            term["action"] = r["action"]

            notes = [tagged(TAG_AUTO, r["display"])] if r["display"] and r["display"] != r["name"] else []
            if ignored:
                notes.append(tagged(TAG_AUTO, f"PARTIAL: ignored {', '.join(ignored)} — this term is "
                                              f"WIDER than the rule it came from"))
                stats["partial"] += 1
                # Summary by kind; the term comment keeps the detail.
                stats["ignored_kinds"].update(
                    "ICMP type" if i.startswith("ICMP type") else
                    "remote keyword" if i.startswith("remote ") else i for i in ignored)
            if unnamed:
                notes.append(tagged(TAG_AUTO, f"UNNAMED source-address: {len(unnamed)} address(es) "
                                              f"carried as literals"))
                stats["unnamed_terms"] += 1
            if notes:
                set_term_comment(term, notes, [])
            terms.append(term)
            stats["terms"] += 1

        actions = {state.get(p, (True, "Block"))[1].lower() for p in profiles}
        stats["default"] = "accept" if "allow" in actions else "drop"
        if stats["default"] == "drop":
            t = CommentedMap()
            t["name"] = "drop-ANY"
            t["action"] = "deny"
            # As in synth: rendered on Windows it would be a block rule, and a
            # block rule beats every allow. The header's `block` carries it.
            t["platform-exclude"] = ["windows_advfirewall"]
            set_term_comment(t, [tagged(TAG_AUTO, "from the profile's default inbound action, "
                                                  "not from a rule")], [])
            terms.append(t)

    doc = CommentedMap()
    meta = CommentedMap()
    if host:
        meta["host"] = host
    meta["profiles"] = sorted(profiles)
    doc["metadata"] = meta
    # The profile default, in the header as synth writes it: `block` is what
    # enforces default deny on Windows, the drop-ANY term only records it.
    header = "in mixed block" if stats.get("default") == "drop" else "in mixed"
    doc["filters"] = [{"header": {"targets": {"windows_advfirewall": header}}, "terms": terms}]
    return doc, stats


def is_winfw(data):
    return isinstance(data, dict) and "rules" in data and "profiles" in data


def main():
    from firru.cli.edit import yaml_handler
    from firru.cli.naming_cache import cached_naming
    ap = argparse.ArgumentParser(description="Windows Firewall (loot-host.ps1 firewall.json) "
                                             "-> firru policy YAML, inbound, live profiles.")
    ap.add_argument("firewall_json")
    ap.add_argument("--defs", "-d", default="def")
    ap.add_argument("--host")
    ap.add_argument("--profile", action="append", choices=sorted(winfw.ALL_PROFILES),
                    help="Evaluate for this profile instead of the interfaces' (repeatable)")
    ap.add_argument("-o", "--output", default="-")
    a = ap.parse_args()
    with open(a.firewall_json, encoding="utf-8-sig") as f:
        fw = json.load(f)
    if not is_winfw(fw):
        ap.error(f"{a.firewall_json}: not a loot-host.ps1 firewall.json")
    doc, stats = convert(fw, cached_naming(a.defs), host=a.host, profiles=a.profile)
    from firru.cli.edit import _ruleset_caveats
    for note in _ruleset_caveats(stats):
        print(f"{a.firewall_json}: {note}", file=sys.stderr)
    if a.output == "-":
        yaml_handler.dump(doc, sys.stdout)
    else:
        with open(a.output, "w") as f:
            yaml_handler.dump(doc, f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
