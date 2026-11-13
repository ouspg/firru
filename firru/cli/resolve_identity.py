#!/usr/bin/env python3
"""
resolve-identity — bind loot to inventory by evidence, and say which evidence.

    resolve-identity --loot loot-ossec/ --defs def/ --assert identity-assertions.yml

Synthesis looks a host's loot up in the inventory by name, which fails in both
directions on real data. A collector reports the short label (`DC1`) while the
inventory is keyed by FQDN, and a short label is not unique -- `ns1` names a
different host in each of three zones, so guessing one would be worse than
leaving it unbound. Unbound means no zone, which means the management terms
have no source to name and the policy silently comes out wider than intended.

THREE SOURCES OF IDENTITY, IN DESCENDING ORDER OF WHAT THEY PROVE:

  name       the collector's label matches exactly one inventory token. Cheap
             and already how it worked; keeps working.
  address    the loot carries the host's own address and the inventory names
             it. This is the one that resolves ambiguity, because an address
             belongs to one host where a label may belong to three. On the
             LSPR24 OSSEC archive it binds 54 of 59 hosts, including all six
             the name alone could not.
  asserted   a human wrote it down, because no evidence in the data decides
             it. Each assertion carries its reasoning in the file.

The point of the split is that the third kind is visible. `via` is recorded
per host in host_metadata.json and printed in the summary, so "we decided this"
never gets mistaken for "the data said this" -- which is exactly the confusion
that makes an inherited inventory untrustworthy a year later.

WHAT DOES NOT RESOLVE IS ALSO EVIDENCE. A host with an agent but no asset
record is not a gap in the inventory; on an exercise network it is usually the
blue team's own infrastructure, which has no exercise asset because it is not
part of the exercise estate. The Wazuh manager reports itself as agent id 000
with no address for exactly that reason, and that is worth asserting rather
than inferring.
"""

import argparse
import json
import pathlib
import sys

import yaml

from firru.tokens import normalize_token


def address_index(networks):
    """address -> the single token holding it, skipping any it shares."""
    owners = {}
    for token, spec in (networks or {}).items():
        for v in (spec or {}).get("values", []):
            if isinstance(v, dict) and "address" in v:
                owners.setdefault(v["address"], set()).add(token)
    return {a: next(iter(t)) for a, t in owners.items() if len(t) == 1}


def load_assertions(path):
    if not path:
        return {}
    doc = yaml.safe_load(pathlib.Path(path).read_text()) or {}
    return doc.get("identities", {}) or {}


def resolve(loot_dir, meta, by_address, asserted):
    """One decision per loot host: (token, via, evidence)."""
    out = {}
    for path in sorted(pathlib.Path(loot_dir).glob("*.json")):
        doc = json.loads(path.read_text())
        fm = doc.get("metadata", {})
        name = fm.get("hostname") or path.stem
        token = normalize_token(name)
        # Entries this tool wrote before are its own prior output, not
        # inventory facts, so they must not make a host look name-resolvable
        # on the next run. Without this the first answer sticks forever: a
        # `dc1` bound to the wrong zone once stayed bound to it, reported as
        # "by name", through every regeneration.
        if token in meta and "via" not in meta[token]:
            out[name] = (token, "name", token)
            continue
        ip = fm.get("ip")
        if ip and ip in by_address:
            out[name] = (by_address[ip], "address", ip)
            continue
        if token in asserted or name in asserted:
            rec = asserted.get(token) or asserted[name]
            why = " ".join((rec.get("why") or "").split())
            out[name] = (rec.get("token") or token, "asserted",
                         why[:60] + ("..." if len(why) > 60 else ""))
            continue
        out[name] = (None, "unresolved",
                     f"agent_id={fm.get('agent_id')} ip={ip}")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--loot", required=True, metavar="DIR")
    ap.add_argument("--defs", default="def", metavar="DIR")
    ap.add_argument("--assert", dest="assertions", metavar="FILE",
                    help="YAML of identities no evidence in the data decides")
    ap.add_argument("--dry-run", action="store_true",
                    help="report the decisions without writing them back")
    args = ap.parse_args()

    defs = pathlib.Path(args.defs)
    meta = json.loads((defs / "host_metadata.json").read_text())
    networks = (yaml.safe_load((defs / "networks.yml").read_text()) or {}).get("networks", {})
    by_address = address_index(networks)
    asserted = load_assertions(args.assertions)

    decisions = resolve(args.loot, meta, by_address, asserted)

    added = 0
    for name, (token, via, evidence) in sorted(decisions.items()):
        key = normalize_token(name)
        # An entry we wrote before is ours to refresh; one the inventory
        # carried is not. Without the distinction the tool is write-once and
        # a re-run after the inventory changes silently keeps the old answer.
        if via in ("name", "unresolved"):
            continue
        if key in meta and "via" not in meta[key]:
            continue
        base = meta.get(token, {})
        entry = {"zone": base.get("zone"), "via": via, "evidence": evidence}
        if via == "address":
            # An address-resolved host is the same host, so it inherits the
            # segment and the band token rather than being re-derived.
            entry["alias_of"] = token
            for k in ("segment", "gt", "mgmt"):
                if k in base:
                    entry[k] = base[k]
        else:
            rec = asserted.get(key) or asserted.get(name) or {}
            entry["zone"] = rec.get("zone", entry["zone"])
            for k in ("os", "role", "segment"):
                if rec.get(k):
                    entry[k] = rec[k]
            # An asserted host has no derived band unless the assertion names
            # one. `gt: null` makes synthesis name MGMT_HOSTS alone instead of
            # a token nothing defines -- which is the truthful answer for a
            # host the inventory does not place in any segment.
            entry["gt"] = rec.get("gt")
            entry["mgmt"] = rec.get("mgmt", base.get("mgmt"))
        meta[key] = entry
        added += 1

    if not args.dry_run and added:
        (defs / "host_metadata.json").write_text(
            json.dumps(meta, indent=2, sort_keys=True) + "\n")

    counts = {}
    for _, (_, via, _) in decisions.items():
        counts[via] = counts.get(via, 0) + 1
    print(f"{len(decisions)} loot hosts: "
          + ", ".join(f"{v} by {k}" for k, v in sorted(counts.items())))
    for name, (token, via, evidence) in sorted(decisions.items()):
        if via != "name":
            print(f"  {name:<16} {via:<11} {token or '-'}   [{evidence}]")
    print(f"{added} entries {'would be' if args.dry_run else ''} added to "
          f"{defs / 'host_metadata.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
