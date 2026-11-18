"""Hierarchical heavy hitters over addresses: which hosts and prefixes carry
the weight, each net of the longer prefixes already reported."""

import ipaddress

#: A prefix is a heavy hitter when it carries at least this share of the flows.
SHARE = 0.05


def heavy_hitters(weights, share=SHARE):
    """Hierarchical heavy hitters (Cormode et al., VLDB 2003) over {ip: weight}.

    Bottom-up from host routes: a prefix is reported when its weight, less what
    its reported longer prefixes already carry, is at least `share` of the
    total. Each family walks its own tree; the share is of both. Returns
    [(network, weight)], heaviest first; at most 1/share entries.
    """
    total = sum(weights.values())
    if not total:
        return []
    by_family = {}
    for ip, n in weights.items():
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        fam = by_family.setdefault(a.version, {})
        fam[int(a)] = fam.get(int(a), 0) + n
    out = []
    for version, cur in by_family.items():
        bits = 32 if version == 4 else 128
        rep = []                                   # (prefix, length, net weight)
        for length in range(bits, 7, -1):
            mask = ((1 << bits) - 1) ^ ((1 << (bits - length)) - 1)
            agg = {}
            for v, n in cur.items():
                agg[v & mask] = agg.get(v & mask, 0) + n
            for p, n in agg.items():
                done = sum(d for p0, l0, d in rep if l0 > length and p0 & mask == p)
                if n - done >= share * total:
                    rep.append((p, length, n - done))
        cls = ipaddress.IPv4Network if version == 4 else ipaddress.IPv6Network
        out += [(cls((p, length)), d) for p, length, d in rep]
    return sorted(out, key=lambda r: (-r[1], r[0].version, r[0]))
