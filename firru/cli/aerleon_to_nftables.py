#!/usr/bin/env python3
"""
aerleon-to-nftables — Generate nftables chain/set fragments from aerleon zone YAMLs.

Reads zone policy YAMLs (output of aerleon-merge-zones --target nftables) and
emits bare nftables chain and set blocks — no table wrapper — suitable for
inclusion in a master nftables.conf:

    table inet filter {
        include "zones/fw-int1.nft"
        include "zones/fw-int2.nft"
    }

Usage:
    aerleon-to-nftables --zones zones/fw-int1.yml zones/fw-int2.yml --defs def/ --outdir nft/
    aerleon-to-nftables --zones 'zones/fw-*.yml' --defs def/ --outdir nft/
"""

import argparse
import glob as _glob
import re
import sys
import yaml
from pathlib import Path

from aerleon import api
from aerleon.lib import naming


def load_zone(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def _strip_comments(filters):
    """
    Remove 'comment' from all terms before passing to aerleon.
    nftables enforces a 128-byte limit on rule comments; zone YAML is the
    human-readable artifact and prose comments belong there, not in nft rules.
    """
    out = []
    for f in filters:
        f = dict(f)
        f["terms"] = [
            {k: v for k, v in t.items() if k != "comment"}
            for t in f.get("terms", [])
        ]
        out.append(f)
    return out


def generate_nft(zone_doc: dict, zone_name: str, defs: naming.Naming) -> str:
    """
    Run aerleon's nftables generator on zone_doc, return bare chain/set content
    (table wrapper stripped).
    """
    policy = {
        "filename": zone_name,
        "filters":  _strip_comments(zone_doc.get("filters", [])),
    }

    result = api.Generate(
        policies=[policy],
        definitions=defs,
        optimize=True,
    )

    if result is None:
        return f"# ERROR: aerleon generated no output for {zone_name}\n"

    # aerleon returns {filename.nft: content, ...} — find our file
    nft_content = None
    for key, val in result.items():
        if key.endswith(".nft"):
            nft_content = val
            break

    if nft_content is None:
        return f"# ERROR: no .nft output found for {zone_name}\n"

    return _strip_table_wrapper(nft_content, zone_name)



#: Verdicts a generated rule can end on. `jump`/`goto` are deliberately left
#: alone: the chain being jumped to counts its own rules, and counting both
#: would double every packet in any summary that adds them up.
_VERDICT = re.compile(r'^(\s*)(.*\S)\s+(accept|drop|reject|queue|continue|return)\s*$')


def add_counters(content: str) -> str:
    """Insert a `counter` before each rule's verdict.

    Without this the running ruleset can say whether a term is deployed but not
    whether it has ever matched, and `firru loot-firewall` has to report "no
    counters" rather than a finding. nftables keeps a counter per rule at
    negligible cost, and the numbers survive until the ruleset is reloaded,
    which is a longer and more honest window than any capture.

    Chain headers (`type filter hook input priority 0; policy drop;`) are not
    rules and are left alone; so is anything already carrying a counter.
    """
    out = []
    for line in content.splitlines():
        stripped = line.strip()
        m = _VERDICT.match(line)
        if (m and not stripped.startswith(("type ", "policy ", "#"))
                and "counter" not in stripped and ";" not in stripped):
            out.append(f"{m.group(1)}{m.group(2)} counter {m.group(3)}")
        else:
            out.append(line)
    return "\n".join(out) + ("\n" if content.endswith("\n") else "")


#: A rule's address family, from the match Aerleon puts first.
_V6_RULE = re.compile(r'^\s*ip6\s')
_V4_RULE = re.compile(r'^\s*ip\s')
#: Protocol matches that only exist in one family.
_V4_ONLY = re.compile(r'\bip protocol icmp\b')
_V6_ONLY = re.compile(r'\b(meta l4proto icmpv6|ip6 nexthdr icmpv6)\b')


def drop_family_mismatch(content: str):
    """Remove rules whose protocol match cannot occur in their address family.

    Aerleon renders every term for both families in a `mixed` filter, without
    asking whether the protocol exists in both. An ICMP term therefore comes
    out as a correct IPv4 rule plus `ip6 daddr ... ip protocol icmp`, which is
    not a rule nftables will accept: the whole ruleset is rejected at load. An
    ICMPv6 term comes out the other way round as `ip daddr ... meta l4proto
    icmpv6`, which does load and can never match, so it is a rule that is
    always at zero -- the exact thing a counter is for.

    Both are dropped, and each leaves a comment where it was. A rule that
    disappears without saying so is how a ruleset stops meaning what its
    author read.

    Returns (content, dropped) so the caller can report the count.
    """
    out, dropped = [], 0
    for line in content.splitlines():
        bad = ((_V6_RULE.match(line) and _V4_ONLY.search(line))
               or (_V4_RULE.match(line) and _V6_ONLY.search(line)))
        if bad:
            indent = line[:len(line) - len(line.lstrip())]
            out.append(f"{indent}# dropped: protocol match does not exist in this "
                       f"address family (aerleon renders both families for every term)")
            dropped += 1
        else:
            out.append(line)
    return "\n".join(out) + ("\n" if content.endswith("\n") else ""), dropped

def _strip_table_wrapper(content: str, zone_name: str) -> str:
    """
    Remove the outer 'table <af> <name> { ... }' wrapper emitted by aerleon,
    leaving bare chain/set blocks dedented by one level (4 spaces).
    """
    lines = content.splitlines()
    out = [f"# generated from {zone_name} — include inside 'table inet filter {{ }}'", ""]

    inside = False
    depth  = 0

    for line in lines:
        stripped = line.strip()

        if not inside:
            # Look for the table opening line
            if re.match(r'^table\s+\w+\s+\w+\s*\{', stripped):
                inside = True
                depth  = 1
            continue

        # Track brace depth to find the table closing brace
        depth += stripped.count('{') - stripped.count('}')

        if depth <= 0:
            # This is the closing brace of the table — we're done
            break

        # Strip one level of indentation (4 spaces added by aerleon's ChainFormat)
        if line.startswith('    '):
            out.append(line[4:])
        else:
            out.append(line)

    out.append("")
    result = "\n".join(out)

    # Scope all chain names to zone to avoid conflicts when multiple zone
    # files are included in the same table. We prefix every chain name that
    # appears after 'chain ' or 'jump ' with the zone name.
    safe = re.sub(r'[^a-zA-Z0-9]', '_', zone_name).lower()
    result = re.sub(r'\bchain ([a-zA-Z0-9_-]+)', rf'chain {safe}_\1', result)
    result = re.sub(r'\bjump ([a-zA-Z0-9_-]+)',  rf'jump {safe}_\1',  result)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Generate bare nftables chain fragments from aerleon zone YAMLs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aerleon-to-nftables --zones zones/fw-int1.yml zones/fw-int2.yml --defs def/ --outdir nft/
  aerleon-to-nftables --zones 'zones/fw-*.yml' --defs def/ --outdir nft/

Master nftables.conf:
  table inet filter {
      include "nft/fw-int1.nft"
      include "nft/fw-int2.nft"
  }
        """,
    )
    parser.add_argument("--zones",  "-z", nargs="+", required=True,
                        help="Zone YAML files or glob patterns")
    parser.add_argument("--defs",   "-d", default="def",
                        help="Aerleon definitions directory (default: def)")
    parser.add_argument("--outdir", "-o", default="nft",
                        help="Output directory for .nft files (default: nft/)")
    parser.add_argument("--counters", action="store_true",
                        help="Emit a `counter` on every rule, so the running "
                             "ruleset can say which terms have ever matched "
                             "(firru loot-firewall reads them)")
    args = parser.parse_args()

    # Expand globs
    zone_files = []
    for pat in args.zones:
        expanded = _glob.glob(pat)
        if expanded:
            zone_files.extend(expanded)
        elif Path(pat).exists():
            zone_files.append(pat)
        else:
            print(f"Warning: no files matched {pat!r}", file=sys.stderr)

    if not zone_files:
        print("No zone files found.", file=sys.stderr)
        sys.exit(1)

    defs    = naming.Naming(args.defs)
    outdir  = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    for path in sorted(set(zone_files)):
        zone_doc  = load_zone(path)
        zone_name = Path(path).stem          # fw-int1
        out_path  = outdir / f"{zone_name}.nft"

        nft = generate_nft(zone_doc, zone_name, defs)
        nft, mismatched = drop_family_mismatch(nft)
        if args.counters:
            nft = add_counters(nft)

        out_path.write_text(nft)
        chain_count = len(re.findall(r'^\s*chain\s+', nft, re.MULTILINE))
        note = f", {mismatched} family-mismatched rule(s) dropped" if mismatched else ""
        print(f"Written {out_path} ({chain_count} chains{note})")


if __name__ == "__main__":
    main()
