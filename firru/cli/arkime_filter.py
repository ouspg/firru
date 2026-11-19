#!/usr/bin/env python3
"""
arkime-filter — Generate Arkime search filter expressions from aerleon tokens.

Resolves aerleon network tokens to IPs/subnets and emits an Arkime filter
expression for copy-paste into the web UI.

An endpoint matches when its address is in an included token and in no
excluded one; a session matches when one of its endpoints does (--include),
or one endpoint is on each side of the pair (--from/--to, either direction).
An exclude is applied per endpoint, never to the whole session: `ip != X`
would drop every session X takes part in, including the rogue device's
sessions with X, which is the traffic the first example below is after.
With --exclude alone, a session matches when neither endpoint is excluded.

Common uses:

  # Rogue devices in a zone (subnet minus known hosts)
  arkime-filter --include ZONE_INT_NET --exclude ZONE_INT_ALL_HOSTS --defs def/

  # Traffic between two zones (both directions)
  arkime-filter --from ZONE_INT_NET --to ZONE_DMZ_NET --defs def/

  # Cross-zone traffic from hosts the inventory does not know
  arkime-filter --from ZONE_INT_NET --to ZONE_DMZ_NET \\
                --exclude ZONE_INT_ALL_HOSTS --defs def/

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
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)


def _values(nets):
    """Arkime's list form, the networks collapsed per family: one host is a
    bare address, several are [a,b,...]."""
    out = []
    for version in (4, 6):
        same = [n for n in nets if n.version == version]
        out += [_fmt(n) for n in ipaddress.collapse_addresses(same)]
    return out[0] if len(out) == 1 else "[" + ",".join(out) + "]"


def _endpoint(side, nets, exclude_nets):
    """This endpoint is in nets and not in exclude_nets."""
    clause = f"ip.{side} == {_values(nets)}"
    if exclude_nets:
        clause = f"{clause} && ip.{side} != {_values(exclude_nets)}"
    return clause


def _either(nets, exclude_nets):
    """One of the two endpoints is in nets and not in exclude_nets."""
    return (f"({_endpoint('src', nets, exclude_nets)}) || "
            f"({_endpoint('dst', nets, exclude_nets)})")


def build_filter(from_nets, to_nets, include_nets, exclude_nets):
    """
    Result:  (zone-pair clause) && (include clause), excludes applied to each
    endpoint the clauses test; with neither, no endpoint excluded.

    zone-pair: (src in FROM && dst in TO) || (src in TO && dst in FROM)
    include:   src in INCLUDE || dst in INCLUDE
    """
    parts = []

    if from_nets and to_nets:
        fwd = f"{_endpoint('src', from_nets, exclude_nets)} && {_endpoint('dst', to_nets, exclude_nets)}"
        rev = f"{_endpoint('src', to_nets, exclude_nets)} && {_endpoint('dst', from_nets, exclude_nets)}"
        parts.append(f"(({fwd}) || ({rev}))")
    elif from_nets or to_nets:
        parts.append(f"({_either(from_nets or to_nets, exclude_nets)})")

    if include_nets:
        parts.append(f"({_either(include_nets, exclude_nets)})")

    if not parts and exclude_nets:
        parts.append(f"ip.src != {_values(exclude_nets)} && ip.dst != {_values(exclude_nets)}")

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
                        help="An address in this token does not count as a match "
                             "(repeatable); alone, traffic involving it is left out")
    parser.add_argument("--defs", "-d", default="def",
                        help="Aerleon definitions directory (default: def)")
    args = parser.parse_args()

    if not args.from_tokens and not args.to_tokens and not args.include and not args.exclude:
        parser.error("specify at least one --from/--to/--include/--exclude token")

    defs = naming.Naming(args.defs)

    unresolved = []

    def resolve_all(tokens, label):
        nets = []
        for token in tokens:
            resolved = resolve(token, defs)
            if resolved:
                nets.extend(resolved)
                print(f"  {label} {token}: {len(resolved)} network(s)", file=sys.stderr)
            else:
                unresolved.append(token)
        return nets

    from_nets    = resolve_all(args.from_tokens, "from   ")
    to_nets      = resolve_all(args.to_tokens,   "to     ")
    include_nets = resolve_all(args.include,     "include")
    exclude_nets = resolve_all(args.exclude,     "exclude")

    # A token that names nothing would silently widen the filter: a missing
    # --exclude matches more, a missing --to turns a pair into either side.
    if unresolved:
        print(f"No filter generated: {', '.join(unresolved)} resolved to nothing.",
              file=sys.stderr)
        sys.exit(2)

    filt = build_filter(from_nets, to_nets, include_nets, exclude_nets)
    if not filt:
        print("No filter generated.", file=sys.stderr)
        sys.exit(1)

    print(filt)


if __name__ == "__main__":
    main()
