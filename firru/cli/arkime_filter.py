#!/usr/bin/env python3
"""
arkime-filter — Generate Arkime search filter expressions from aerleon tokens.

Resolves aerleon network tokens to IPs/subnets and emits an Arkime filter
expression for copy-paste into the web UI.

Common uses:

  # Rogue devices in a zone (subnet minus known hosts)
  arkime-filter --include ZONE_INT_NET --exclude ZONE_INT_ALL_HOSTS --defs def/

  # Traffic between two zones (both directions)
  arkime-filter --from ZONE_INT_NET --to ZONE_DMZ_NET --defs def/

  # Cross-zone traffic from unknown hosts only
  arkime-filter --from ZONE_INT_NET --to ZONE_DMZ_NET \\
                --exclude ZONE_INT_ALL_HOSTS --exclude ZONE_DMZ_ALL_HOSTS --defs def/

  # Freeform: any of these, but not those
  arkime-filter --include TOKEN_A --include TOKEN_B --exclude TOKEN_C --defs def/
"""

import argparse
import ipaddress
import sys

from aerleon.lib import naming


def resolve(token, defs):
    try:
        addrs = defs.GetNetAddr(token)
        return [ipaddress.ip_network(str(a), strict=False) for a in addrs]
    except Exception as e:
        print(f"Warning: could not resolve {token!r}: {e}", file=sys.stderr)
        return []


def _fmt(net):
    if net.prefixlen == (32 if net.version == 4 else 128):
        return str(net.network_address)
    return str(net)


def build_filter(from_nets, to_nets, include_nets, exclude_nets):
    """
    Result:  (zone-pair clause) AND (include clause) AND NOT (excludes)

    zone-pair: (src in FROM && dst in TO) || (src in TO && dst in FROM)
    include:   ip == A || ip == B || ...
    excludes:  ip != X && ip != Y && ...
    """
    parts = []

    if from_nets and to_nets:
        from_src = " || ".join(f"ip.src == {_fmt(n)}" for n in from_nets)
        from_dst = " || ".join(f"ip.dst == {_fmt(n)}" for n in from_nets)
        to_src   = " || ".join(f"ip.src == {_fmt(n)}" for n in to_nets)
        to_dst   = " || ".join(f"ip.dst == {_fmt(n)}" for n in to_nets)
        fwd = f"({from_src}) && ({to_dst})"
        rev = f"({to_src}) && ({from_dst})"
        parts.append(f"(({fwd}) || ({rev}))")
    elif from_nets:
        clauses = " || ".join(f"ip == {_fmt(n)}" for n in from_nets)
        parts.append(f"({clauses})" if len(from_nets) > 1 else clauses)
    elif to_nets:
        clauses = " || ".join(f"ip == {_fmt(n)}" for n in to_nets)
        parts.append(f"({clauses})" if len(to_nets) > 1 else clauses)

    if include_nets:
        clauses = " || ".join(f"ip == {_fmt(n)}" for n in include_nets)
        parts.append(f"({clauses})" if len(include_nets) > 1 else clauses)

    for net in exclude_nets:
        parts.append(f"ip != {_fmt(net)}")

    return " && ".join(parts)


def main():
    parser = argparse.ArgumentParser(
        description="Generate Arkime filter expressions from aerleon tokens.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--from", dest="from_tokens", metavar="TOKEN",
                        action="append", default=[],
                        help="Source zone/token for zone-pair filter (repeatable)")
    parser.add_argument("--to", dest="to_tokens", metavar="TOKEN",
                        action="append", default=[],
                        help="Destination zone/token for zone-pair filter (repeatable)")
    parser.add_argument("--include", "-i", metavar="TOKEN", action="append", default=[],
                        help="Include traffic involving this token (repeatable)")
    parser.add_argument("--exclude", "-e", metavar="TOKEN", action="append", default=[],
                        help="Exclude traffic involving this token (repeatable)")
    parser.add_argument("--defs", "-d", default="def",
                        help="Aerleon definitions directory (default: def)")
    args = parser.parse_args()

    if not args.from_tokens and not args.to_tokens and not args.include and not args.exclude:
        parser.error("specify at least one --from/--to/--include/--exclude token")

    defs = naming.Naming(args.defs)

    def resolve_all(tokens, label):
        nets = []
        for token in tokens:
            resolved = resolve(token, defs)
            if resolved:
                nets.extend(resolved)
                print(f"  {label} {token}: {len(resolved)} network(s)", file=sys.stderr)
        return nets

    from_nets    = resolve_all(args.from_tokens, "from   ")
    to_nets      = resolve_all(args.to_tokens,   "to     ")
    include_nets = resolve_all(args.include,     "include")
    exclude_nets = resolve_all(args.exclude,     "exclude")

    filt = build_filter(from_nets, to_nets, include_nets, exclude_nets)
    if not filt:
        print("No filter generated.", file=sys.stderr)
        sys.exit(1)

    print(filt)


if __name__ == "__main__":
    main()
