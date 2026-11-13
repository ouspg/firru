"""
firru.annotator — PolicyAnnotator: IP → aerleon token resolution.

Builds a prefix tree from aerleon network definitions and
annotates IP addresses with their most specific matching token and
parent groups. Used by tighten.py to suggest source restrictions.
"""

import ipaddress
from firru.prefixes import PrefixTree
from aerleon.lib import naming


class PolicyAnnotator:
    """
    Resolves IP addresses to aerleon network tokens using prefix matching.

    Builds two prefix trees (IPv4 + IPv6) from all tokens in the aerleon
    definitions directory. For each /32 or /128 host entry it also computes
    a sorted list of parent tokens (lists > subnets, tighter prefix = higher
    priority) for use in source tightening suggestions.

    Usage:
        annotator = PolicyAnnotator('./def')
        result = annotator.annotate_ip('192.0.2.54')
        # {'host': 'WEB01', 'parents': ['DMZ_WEB_SERVERS', 'NET_DMZ'], ...}
    """

    # Tokens that are too broad to be useful as source suggestions
    SKIP_LIST = {
        'INTERNET', 'ANY', 'ANY_V4', 'ANY_V6',
        'RFC1918', 'INET6', 'OFF_NET', 'INTERNAL', 'WORLD', 'BOGON',
    }

    def __init__(self, defs_folder: str):
        self.naming        = naming.Naming(defs_folder)
        self.token_meta    = {}        # token -> {cidr: int, is_list: bool}
        self.pyt_v4        = PrefixTree(32)
        self.pyt_v6        = PrefixTree(128)
        self.group_members = {}        # group_token -> frozenset of member host tokens
        self._build_trees()
        self.group_members = {g: frozenset(m) for g, m in self.group_members.items()}
        self._port_map     = self._build_port_map()  # (port, proto) -> token

    def _build_port_map(self) -> dict:
        """Reverse map (port, proto) -> service token, built once at init."""
        port_map = {}
        for token in self.naming.GetServiceNames():
            try:
                entries = self.naming.GetService(token)
            except Exception:
                continue
            for entry in entries:
                try:
                    port_str, proto = entry.split('/')
                    if '-' in port_str:
                        lo, hi = port_str.split('-')
                        for p in range(int(lo), int(hi) + 1):
                            port_map.setdefault((p, proto.lower()), token)
                    else:
                        port_map.setdefault((int(port_str), proto.lower()), token)
                except Exception:
                    continue
        return port_map

    def annotate_port(self, port: int, proto: str) -> str | None:
        """Return the service token for (port, proto), or None if unknown."""
        if port is None:
            return None
        return self._port_map.get((int(port), proto.lower()))

    # ------------------------------------------------------------------
    # Tree construction
    # ------------------------------------------------------------------

    def _is_alias(self, token: str) -> bool:
        """
        True if the token defines no address of its own and only names others.

        Definitions like

            VENDOR_GATEWAY:
              values:
                - address: gw_example_org

        exist so a firewall rule has something to point at; the host it resolves
        to is the real name for that address. Both cover the same /32, so a tie
        on prefix length has to be broken by which one actually defines it,
        otherwise an address gets reported under a placeholder and the host it
        belongs to never appears.
        """
        unit = self.naming.networks.get(token)
        items = getattr(unit, 'items', None) or []
        if not items:
            return False
        for item in items:
            try:
                ipaddress.ip_network(str(item).split('#')[0].strip(), strict=False)
                return False   # at least one literal address: not an alias
            except ValueError:
                continue
        return True

    def _build_trees(self):
        # Pass 1: insert all prefixes, track token metadata
        for token in self.naming.networks:
            try:
                nets = self.naming.GetNet(token)
            except Exception:
                continue

            max_pfx = max((n.prefixlen for n in nets), default=0)
            is_list = any(
                n.prefixlen >= (128 if n.version == 6 else 32) for n in nets
            )
            self.token_meta[token] = {
                'cidr': max_pfx,
                'is_list': is_list,
                'alias': self._is_alias(token),
                'size': len(nets),
            }

            for net in nets:
                tree    = self.pyt_v6 if net.version == 6 else self.pyt_v4
                net_str = str(net)
                is_grp  = net.prefixlen < (128 if net.version == 6 else 32)

                if tree.has_key(net_str):
                    data = tree.get(net_str)
                    if token not in data['tokens']:
                        data['tokens'].append(token)
                    if is_grp:
                        data['type'] = 'GROUP'
                    elif data['type'] != 'HOST':
                        # /32 or /128 host token — promote to HOST regardless
                        # of what a previously inserted subnet token set
                        data['type'] = 'HOST'
                    tree.insert(net_str, data)
                else:
                    tree.insert(net_str, {
                        'type':   'GROUP' if is_grp else 'HOST',
                        'tokens': [token],
                        'cidr':   net.prefixlen,
                    })

        # Pass 2: compute parent hierarchy for host entries (/32, /128)
        for token in self.naming.networks:
            try:
                nets = self.naming.GetNet(token)
            except Exception:
                continue

            for net in nets:
                tree  = self.pyt_v6 if net.version == 6 else self.pyt_v4
                limit = 128 if net.version == 6 else 32
                if net.prefixlen != limit:
                    continue

                net_str = str(net)

                try:
                    explicit = self.naming.GetNetParents(token)
                except Exception:
                    explicit = []

                # Geometric parents: temporarily remove this entry so the
                # tree lookup returns the enclosing prefix
                geo_tokens = []
                if tree.has_key(net_str):
                    orig = tree.get(net_str)
                    tree.delete(net_str)
                    geo_match  = tree.get(net_str)
                    geo_tokens = geo_match['tokens'] if geo_match else []
                    tree.insert(net_str, orig)

                all_parents = list(set(explicit + geo_tokens))

                def _priority(t, meta=self.token_meta):
                    m = meta.get(t, {'cidr': 0, 'is_list': False})
                    return (1000 if m['is_list'] else 0) + m['cidr']

                valid = [
                    p for p in all_parents
                    if p != token
                    and p not in self.SKIP_LIST
                    and (
                        self.token_meta.get(p, {}).get('cidr', 0) < limit
                        or self.token_meta.get(p, {}).get('is_list', False)
                    )
                ]
                valid.sort(key=lambda p: (-_priority(p), p))  # ties by name, not set order

                # Build inverse index: group → set of member host tokens.
                # Only include explicitly-defined host lists (is_list=True), not
                # subnet tokens — subnets are too broad and not human-curated groups.
                for p in valid:
                    if not self.token_meta.get(p, {}).get('is_list'):
                        continue
                    if p not in self.group_members:
                        self.group_members[p] = set()
                    self.group_members[p].add(token)

                existing = tree.get(net_str) if tree.has_key(net_str) else {}
                existing_tokens = existing.get('tokens', [])
                if token not in existing_tokens:
                    existing_tokens = existing_tokens + [token]
                # Several tokens may define one address (a host and an
                # all-hosts list): its parents are all of theirs, whichever
                # token was read last.
                merged = set(existing.get('parents', [])) | set(valid)
                tree.insert(net_str, {
                    'type':    'HOST',
                    'tokens':  existing_tokens,
                    'parents': sorted(merged, key=lambda p: (-_priority(p), p)),
                    'cidr':    net.prefixlen,
                })

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def annotate_ip(self, ip_str: str) -> dict:
        """
        Resolve an IP address to its aerleon token and parent groups.

        Returns a dict:
            host     — most specific token, or 'EXTERNAL'/'UNKNOWN'
            parents  — sorted list of parent group tokens (tightest first)
            type     — 'HOST' | 'GROUP' | 'EXTERNAL' | 'ANY' | 'ERR'
            action   — 'OK' | 'IGNORE' | 'INVESTIGATE' | 'CREATE_TOKEN' | 'ERR'
        """
        if not ip_str or str(ip_str) in ('0.0.0.0', '::', 'nan', 'None'):
            return {'host': 'ANY', 'parents': [], 'type': 'ANY', 'action': 'IGNORE'}

        tree = self.pyt_v6 if ':' in str(ip_str) else self.pyt_v4
        try:
            match = tree.get(str(ip_str))
        except Exception:
            return {'host': 'INVALID', 'parents': [], 'type': 'ERR', 'action': 'ERR'}

        if not match:
            return {'host': 'EXTERNAL', 'parents': [], 'type': 'EXTERNAL', 'action': 'OK'}

        all_tokens = match.get('tokens', [])
        clean      = [t for t in all_tokens if t not in self.SKIP_LIST]
        # Prefer a token that defines the address over one that only points at
        # another token, then a host list over a subnet, then the smallest
        # list (the host's own token over an all-hosts list), then the name:
        # never the order the definition files were read in.
        clean.sort(key=lambda t: (self.token_meta.get(t, {}).get('alias', False),
                                  self.token_meta.get(t, {}).get('is_list', True),
                                  self.token_meta.get(t, {}).get('size', 0), t))
        primary    = clean[0] if clean else (all_tokens[0] if all_tokens else 'UNKNOWN')

        if match['type'] == 'HOST':
            return {
                'host':    primary,
                'parents': [p for p in match.get('parents', []) if p != primary],
                'type':    'HOST',
                'action':  'OK',
            }

        # GROUP or POTENTIAL_PARENT — IP is in a known subnet but has no host token
        if not clean:
            return {'host': 'EXTERNAL', 'parents': [], 'type': 'EXTERNAL', 'action': 'OK'}

        return {
            'host':    f'REQ_TOKEN_{ip_str}',
            'parents': clean,
            'type':    'GROUP',
            'action':  'CREATE_TOKEN',
        }
