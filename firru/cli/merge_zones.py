#!/usr/bin/env python3
"""
merge-zones — Merge per-host aerleon YAMLs into per-zone firewall policy YAMLs.

Usage:
    firru merge-zones \\
        --hosts  'policies/pol/*.yml' \\
        --defs   def \\
        --outdir zones/ \\
        --terminal log-accept

Each host YAML must have:
    metadata:
      host: hostname
      zone: NET_DMZ        # must match a network object in defs

Output: one aerleon YAML per zone under --outdir, e.g. zones/NET_DMZ.yml

Terminal rule modes (--terminal):
  log-accept  Initial deployment: accept + log everything unmatched.
              Use until the explicit rules cover all legitimate traffic.
  log-drop    Rules settled: drop + log unmatched traffic.
              Use to catch false positives before going silent.
  drop        Confident: silent drop. Use when the log has been quiet.

Rule ordering in emitted zone policy:
  1. Allow terms  — merged from host policies (external sources only)
  2. Deny terms   — ports open on hosts but intra-zone-only; explicit so the
                    terminal rule is unambiguous about what it's catching
  3. Ghost-host   — drops traffic to/from zone IPs not present in the policy
                    inventory (rogue hosts, newly deployed, unmanaged)
  4. Terminal     — log-accept / log-drop / drop

Logic:
  - Intra-zone source terms are skipped (host firewall handles them); the
    corresponding port gets an explicit deny so centralized FW won't pass it
  - Terms with identical (proto, port, source) across hosts are merged into one
  - Terms with same (proto, port) but differing sources emit a policy warning
  - Placeholder egress (allow-ANY only) is skipped with a note
  - Real egress restrictions are included with a warning to review
"""

import argparse
import collections
import glob
import ipaddress
import os
import sys
import yaml
from aerleon.lib import naming

from firru.policy import DIR_OUT, filter_directions
from firru.stance import terminal_term
from firru.tokens import normalize_token


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def resolve_nets(name, defs):
    """Return flat list of address objects, or None for ANY."""
    if name is None or name in ("ANY", "ANY_V4", "ANY_V6"):
        return None
    names = name if isinstance(name, list) else [name]
    addrs = []
    for n in names:
        addrs.extend(defs.GetNetAddr(n))
    if not addrs:
        raise ValueError(f"Unknown or empty network object: {name!r}")
    return addrs


def nets_to_networks(addrs):
    return [ipaddress.ip_network(str(a), strict=False) for a in addrs]


_LINK_LOCAL_V4  = ipaddress.ip_network("169.254.0.0/16")
_LINK_LOCAL_V6  = ipaddress.ip_network("fe80::/10")
_MULTICAST_V4   = ipaddress.ip_network("224.0.0.0/4")
_MULTICAST_V6   = ipaddress.ip_network("ff00::/8")


def is_link_local_or_multicast(nets):
    """True if all addresses are link-local or multicast (never cross zone boundaries)."""
    for addr in nets:
        net = ipaddress.ip_network(str(addr), strict=False)
        if net.version == 4:
            if not (net.subnet_of(_LINK_LOCAL_V4) or net.subnet_of(_MULTICAST_V4)):
                return False
        else:
            if not (net.subnet_of(_LINK_LOCAL_V6) or net.subnet_of(_MULTICAST_V6)):
                return False
    return True


def is_loopback_term(term, defs, field="source-address"):
    """
    True if a term's addresses are loopback, so it is host-local.

    Matched on the resolved addresses rather than on the token being spelled
    LOOPBACK, so a differently-named token or a literal 127.0.0.0/8 is caught
    too. Synthesis decides the same question the same way (a loopback bind is
    not a policy subject), and the two stages should not disagree because one
    of them matches a name.
    """
    name = term.get(field)
    if name == "LOOPBACK":
        return True
    if not name or isinstance(name, list):
        return False
    try:
        addrs = resolve_nets(name, defs)
    except ValueError:
        return False
    if not addrs:
        return False
    # resolve_nets returns Aerleon address objects; convert as the link-local
    # test does rather than assuming they carry ipaddress's predicates.
    return all(n.is_loopback for n in nets_to_networks(addrs))


def is_intrazone(src_nets, zone_networks):
    """True if every source address is contained within the zone networks."""
    for src in src_nets:
        src_net = ipaddress.ip_network(str(src), strict=False)
        same_version = [z for z in zone_networks if z.version == src_net.version]
        if not same_version:
            return False  # no zone net of this version → treat as external
        if not any(src_net.subnet_of(z) for z in same_version):
            return False
    return True


def zone_networks(zone_name, defs):
    nets = defs.GetNetAddr(zone_name)
    if not nets:
        raise ValueError(f"Zone network object not found: {zone_name!r}")
    return nets_to_networks(nets)


def is_placeholder_egress(terms):
    """True if egress filter is just allow-ANY with no real policy."""
    real = [t for t in terms if t.get("action", "accept").lower() not in ("drop", "deny")]
    return len(real) == 1 and real[0].get("source-address") is None and \
           real[0].get("destination-port") is None and \
           real[0].get("protocol") is None


# ---------------------------------------------------------------------------
# Term key for merging/linting
# ---------------------------------------------------------------------------

def term_key(term):
    port = term.get("destination-port")
    if isinstance(port, list):
        port = tuple(sorted(port))
    return (
        term.get("protocol"),
        port,
    )


# ---------------------------------------------------------------------------
# Per-host term collection
# ---------------------------------------------------------------------------

def collect_terms(host, zone_name, z_nets, filters, defs):
    """
    Returns:
        ingress_terms:   list of (term_dict, host) — terms with external sources
        intrazone_terms: list of (term_dict, host) — terms where all sources are
                         intra-zone (host FW handles them; emit explicit deny at
                         zone FW so terminal rule is unambiguous)
        egress_terms:    list of (term_dict, host) — real egress terms (not allow-ANY)
    """
    ingress = []
    intrazone = []
    egress = []

    for f in filters:
        # Read every target, not just nftables, and match the direction as a
        # word: the windows spelling is a bare "out" (firru.policy).
        is_output = DIR_OUT in filter_directions(f)
        terms = f.get("terms", [])

        if is_output:
            if not is_placeholder_egress(terms):
                open_end = any(
                    t.get("action", "accept").lower() not in ("deny", "drop", "reject")
                    and not any(t.get(k) for k in
                                ("protocol", "destination-port", "source-port",
                                 "source-address", "destination-address"))
                    for t in terms)
                if open_end:
                    print(f"  note: {host} egress has real terms but still ends "
                          f"open (allow-ANY); the zone terminal now decides what "
                          f"the host left undecided", file=sys.stderr)
                for term in terms:
                    action = term.get("action", "accept").lower()
                    if action in ("drop", "deny", "reject"):
                        continue
                    if is_loopback_term(term, defs, "destination-address") \
                            or is_loopback_term(term, defs):
                        continue
                    if term.get("protocol") in ("icmp", "icmpv6"):
                        continue
                    # Skip the allow-ANY fallback placeholder
                    if (term.get("destination-port") is None and
                            term.get("destination-address") is None and
                            term.get("protocol") is None):
                        continue
                    # Skip intrazone egress — host FW handles it
                    dst_name = term.get("destination-address")
                    if dst_name and dst_name not in ("ANY", "ANY_V4", "ANY_V6"):
                        try:
                            dst_nets = resolve_nets(dst_name, defs)
                            if dst_nets and is_intrazone(dst_nets, z_nets):
                                continue
                            if dst_nets and is_link_local_or_multicast(dst_nets):
                                continue
                        except ValueError:
                            pass
                    egress.append((dict(term), host))
            continue

        for term in terms:
            action = term.get("action", "accept").lower()
            if action in ("drop", "deny", "reject"):
                continue

            src_name = term.get("source-address")

            # Loopback and INTERNAL-suffixed tokens are host-local. A central
            # firewall never sees loopback traffic, so such a term must not
            # reach the merged policy at all.
            if is_loopback_term(term, defs):
                continue
            src_names = src_name if isinstance(src_name, list) else [src_name]
            if src_name and all('INTERNAL' in s for s in src_names):
                intrazone.append((dict(term), host))
                continue

            if src_name is None or src_name in ("ANY", "ANY_V4", "ANY_V6"):
                ingress.append((dict(term), host))
                continue

            try:
                src_nets = resolve_nets(src_name, defs)
            except ValueError as e:
                print(f"  Warning [{host}]: {e} — skipping term {term.get('name')!r}",
                      file=sys.stderr)
                continue

            if src_nets and is_link_local_or_multicast(src_nets):
                # Link-local/multicast never crosses zone boundaries — skip entirely
                continue

            if src_nets and is_intrazone(src_nets, z_nets):
                # Host FW handles intra-zone; record for explicit deny at zone FW
                intrazone.append((dict(term), host))
                continue

            ingress.append((dict(term), host))

    return ingress, intrazone, egress


# ---------------------------------------------------------------------------
# Merge + lint
# ---------------------------------------------------------------------------

def _zone_group_candidates(zone_name, defs):
    """
    Return zone-prefixed group tokens from defs, sorted smallest-first
    (fewest resolved addresses = tightest group).
    """
    candidates = []
    prefix = zone_name + "_"
    try:
        all_net_names = list(defs.networks.keys())
    except AttributeError:
        return []
    for token in all_net_names:
        if not token.startswith(prefix):
            continue
        try:
            addrs = defs.GetNetAddr(token)
        except Exception:
            continue
        if addrs:
            candidates.append((len(addrs), token, addrs))
    candidates.sort()
    return candidates


def collapse_destination(hosts, zone_name, all_zone_hosts, defs=None, threshold=0.8):
    """
    Replace destination-address with the smallest zone group token that covers
    all observed hosts.  Falls back to explicit host list if no group fits.

    Returns (destination_str, comment_or_None).
    """
    if defs is not None:
        # Resolve each host token to its addresses for IP-based matching
        host_addrs = set()
        for h in hosts:
            try:
                host_addrs.update(str(a) for a in defs.GetNetAddr(normalize_token(h)))
            except Exception:
                pass

        # Build reverse map: address string -> token, using only single-host
        # tokens (those resolving to a single address) so we get host names
        # rather than group names in the "also covers" note.
        addr_to_token = {}
        try:
            for net_token in defs.networks.keys():
                if not net_token.startswith(zone_name + "_"):
                    continue
                try:
                    addrs = defs.GetNetAddr(net_token)
                    if len(addrs) == 1:
                        addr_to_token[str(addrs[0])] = net_token
                except Exception:
                    pass
        except AttributeError:
            pass

        for _, token, group_addrs in _zone_group_candidates(zone_name, defs):
            group_addr_strs = {str(a) for a in group_addrs}
            if not host_addrs.issubset(group_addr_strs):
                continue
            extra_addrs = group_addr_strs - host_addrs
            if not extra_addrs:
                return token, None
            if len(host_addrs) / len(group_addr_strs) >= threshold:
                # Map extra IPs to tokens, excluding the group token itself
                extra_tokens = sorted(dict.fromkeys(
                    addr_to_token.get(a, a) for a in sorted(extra_addrs)
                ))
                return token, f"also covers: {', '.join(extra_tokens[:6])}"
            continue

    # Fallback: explicit union of the contributing hosts. Never the bare
    # zone subnet — that would also cover ghost addresses that the ordered
    # drop-ghost-hosts term is meant to catch (the SSH-to-ghost over-allow).
    return " ".join(normalize_token(h) for h in sorted(hosts)), None


def _dedup_names(terms):
    """Append -2, -3, ... to any duplicate term names within a list."""
    seen = collections.Counter(t["name"] for t in terms)
    dupes = {name for name, count in seen.items() if count > 1}
    counts = collections.defaultdict(int)
    for t in terms:
        name = t["name"]
        if name in dupes:
            counts[name] += 1
            t["name"] = f"{name}-{counts[name]}"
    return terms


def merge_terms(host_terms_list, zone_name, all_zone_hosts=None, defs=None):
    """
    host_terms_list: list of (term_dict, host_name)

    Returns:
        merged_terms: list of term dicts (with destination-address set)
        warnings:     list of warning strings for policy inconsistencies
    """
    groups = collections.defaultdict(lambda: collections.defaultdict(list))

    for term, host in host_terms_list:
        key = term_key(term)
        src = term.get("source-address")  # None = ANY
        src_key = tuple(sorted(src)) if isinstance(src, list) else src
        groups[key][src_key].append((term, host))

    merged = []
    warnings = []

    for key, src_map in groups.items():
        proto, port = key
        # A port can carry more than one source across the zone (management
        # ports restricted to MGMT_HOSTS on most hosts, opened wider on a few
        # workstations). That is worth a warning, but it is NOT a reason to
        # stop merging: each *distinct* source still collapses to one term, and
        # only a source no other host shares stays per-host. Disambiguate names
        # by source when the port has several, so the shared terms do not clash.
        multi = len(src_map) > 1
        if multi:
            src_summary = {
                (src if src else "ANY"): sorted(normalize_token(h) for _, h in entries)
                for src, entries in src_map.items()
            }
            warnings.append(
                f"Policy inconsistency in {zone_name} for "
                f"proto={proto or 'any'} port={port or 'any'}:\n" +
                "\n".join(f"    {src}: {hosts}" for src, hosts in src_summary.items()) +
                "\n  Consider whether all hosts should use the same source restriction."
            )
        # specific sources before ANY-ish ones, deterministic regardless of type
        for src_key, entries in sorted(
                src_map.items(),
                key=lambda x: (x[0] is None or x[0] in ("ANY", "ANY_V4", "ANY_V6"),
                               str(x[0]))):
            merged.append(_merge_source_group(
                proto, port, entries, zone_name, all_zone_hosts, defs,
                name_with_source=multi))

    return _dedup_names(merged), warnings


def _source_label(src):
    """A filename-safe token for a source, for disambiguating merged names."""
    if src is None:
        return "ANY"
    if isinstance(src, (list, tuple)):
        return "-".join(str(t) for t in src)
    return str(src)


def _merge_source_group(proto, port, entries, zone_name, all_zone_hosts, defs,
                        name_with_source=False):
    """Collapse the hosts that share one source at one (proto, port) into a
    single zone term. A source only one host uses stays that host's own term —
    there is nothing to merge it with."""
    hosts = [h for _, h in entries]
    base_term = dict(entries[0][0])
    if len(hosts) == 1:
        base_term["destination-address"] = normalize_token(hosts[0])
        base_term["name"] = f"{normalize_token(hosts[0])}-{base_term['name']}"
    else:
        dst, also = collapse_destination(hosts, zone_name, all_zone_hosts or [], defs=defs)
        base_term["destination-address"] = dst
        label = f"allow-{proto or 'any'}-{port or 'any'}"
        if name_with_source:
            label = f"{label}-from-{_source_label(base_term.get('source-address'))}"
        base_term["name"] = f"{label}-shared"
        if also:
            base_term["comment"] = also
    base_term.pop("source-interface", None)
    return base_term


def merge_egress_terms(egress_terms_list, zone_name, all_zone_hosts, defs=None):
    """
    Merge per-host egress terms into zone-level egress terms.
    Groups by (proto, port, destination-address); collapses source-address
    (originating hosts) using collapse_destination.

    Returns list of merged term dicts.
    """
    groups = collections.defaultdict(list)

    for term, host in egress_terms_list:
        dst_key = term.get("destination-address")
        dst_key = tuple(sorted(dst_key)) if isinstance(dst_key, list) else dst_key
        key = (term.get("protocol"), term.get("destination-port"), dst_key)
        groups[key].append((term, host))

    merged = []
    for (proto, port, dst_key), entries in groups.items():
        hosts = [h for _, h in entries]
        base_term = dict(entries[0][0])

        src, also = collapse_destination(hosts, zone_name, all_zone_hosts, defs=defs)
        base_term["source-address"] = src
        if also:
            base_term["comment"] = also

        label = port or proto or "any"
        if len(hosts) == 1:
            base_term["name"] = f"{normalize_token(hosts[0])}-egress-{label}"
        else:
            base_term["name"] = f"egress-{label}-shared"

        base_term.pop("source-interface", None)
        merged.append(base_term)

    return _dedup_names(merged)


def build_explicit_denies(intrazone_terms):
    """
    Build deny terms for ports that are open on hosts but have no legitimate
    external traffic (all observed sources were intra-zone).  Emitting these
    explicitly means the terminal rule only fires for genuinely unknown traffic,
    which is what makes the log-accept → log-drop → drop progression safe.
    """
    groups = collections.defaultdict(set)   # (proto, port) -> set of hosts
    names  = {}                              # (proto, port) -> first term name seen

    for term, host in intrazone_terms:
        key = term_key(term)
        groups[key].add(host)
        names.setdefault(key, term.get("name", ""))

    denies = []
    for (proto, port), hosts in sorted(groups.items()):
        sorted_hosts = sorted(hosts)
        dst = (" ".join(normalize_token(h) for h in sorted_hosts)
               if len(sorted_hosts) > 1
               else normalize_token(sorted_hosts[0]))
        entry = {
            "name":                f"deny-ext-{proto or 'any'}-{port or 'any'}",
            "action":              "deny",
            "destination-address": dst,
            "comment":             (
                "intra-zone only — port is open on host(s) but no legitimate "
                "external traffic observed; host firewall handles intra-zone access"
            ),
        }
        if proto:
            entry["protocol"] = proto
        if port:
            entry["destination-port"] = port
        denies.append(entry)

    return denies


def build_ghost_host_drop(zone_name):
    """
    Explicit deny for any IP in the zone subnet not covered by an allow rule above.
    Prevents ghost/rogue/newly-deployed hosts from inheriting implicit access by
    virtue of being in the zone subnet.
    """
    return {
        "name":                "drop-ghost-hosts",
        "action":              "deny",
        "destination-address": zone_name,
        "comment": (
            f"Ghost host catch-all: drops traffic to IPs in {zone_name} not matched "
            "by any allow term above.  All legitimate hosts should appear in "
            "policies/pol/ and be covered by explicit allow terms."
        ),
    }


def build_terminal_rule(mode):
    """
    mode: 'log-accept' | 'log-drop' | 'drop'

    log-accept  Initial deployment.  Log everything unmatched so you can see
                what would have been dropped.  Promote to log-drop once the
                explicit rules cover all legitimate traffic.
    log-drop    Rules settled.  Drop + log so false positives surface before
                going silent.  Promote to drop when the log is quiet.
    drop        Confident.  Silent drop.

    The stages are defined in firru.stance, which `firru stance` reads back.
    """
    return terminal_term(mode)


# ---------------------------------------------------------------------------
# Build per-zone output
# ---------------------------------------------------------------------------

def _has_addresses(token, defs):
    for tok in dict.fromkeys((token, normalize_token(token))):
        try:
            if defs.GetNetAddr(tok):
                return True
        except Exception:
            pass
    return False


def build_zones(host_yamls, defs):
    zones = collections.defaultdict(
        lambda: {"ingress": [], "intrazone": [], "egress": [], "hosts": set()}
    )

    for path in sorted(host_yamls):
        # tighten writes its reports beside the policies it tightened, so a
        # glob over that directory picks them up; they are not policies.
        if path.endswith((".blocked.yml", ".dead.yml", ".groups.yml")):
            continue
        doc = load_yaml(path)
        meta = doc.get("metadata", {})
        host = meta.get("host")
        zone_name = meta.get("zone")

        # The file is named by the host's inventory token, which is unique;
        # metadata.host is the collector's label, which need not be.
        stem = os.path.splitext(os.path.basename(path))[0]
        if _has_addresses(stem, defs):
            host = stem

        if not host or not zone_name:
            print(f"Skipping {path}: missing metadata.host or metadata.zone",
                  file=sys.stderr)
            continue
        # A zone policy names its hosts as destinations, and a token the
        # definitions do not have would not compile. Leaving the host out
        # says so; inventing an address for it would not.
        if not _has_addresses(host, defs):
            print(f"Skipping {path}: no addresses for {host!r} in the definitions, "
                  f"so zone {zone_name} cannot name it", file=sys.stderr)
            continue

        try:
            z_nets = zone_networks(zone_name, defs)
        except ValueError as e:
            print(f"Skipping {path}: {e}", file=sys.stderr)
            continue

        ingress, intrazone, egress = collect_terms(
            host, zone_name, z_nets, doc.get("filters", []), defs
        )

        zones[zone_name]["hosts"].add(host)
        zones[zone_name]["ingress"].extend(ingress)
        zones[zone_name]["intrazone"].extend(intrazone)
        zones[zone_name]["egress"].extend(egress)

    return zones


def emit_zone_yaml(zone_name, data, terminal="log-accept", target="nftables", defs=None):
    merged_terms, warnings = merge_terms(data["ingress"], zone_name, data["hosts"], defs=defs)

    if warnings:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"Policy warnings for zone {zone_name}:", file=sys.stderr)
        for w in warnings:
            print(f"  {w}", file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)

    explicit_denies = build_explicit_denies(data["intrazone"])
    ghost_drop      = build_ghost_host_drop(zone_name)
    terminal_rule   = build_terminal_rule(terminal)
    ingress_terms   = merged_terms + explicit_denies + [ghost_drop, terminal_rule]

    filters = [
        {
            "header": {"targets": {target: "mixed input"}},
            "terms":  ingress_terms,
        }
    ]

    egress_terms = merge_egress_terms(data["egress"], zone_name, data["hosts"], defs=defs)
    if egress_terms:
        # The egress terminal follows --terminal, exactly like ingress. It used
        # to be a hardcoded deny-ANY, which contradicted the log-accept
        # progression: a host still in the observe stage (log-accept terms, an
        # open end) would have its unmatched egress silently dropped at the
        # zone edge — the breakage log-accept exists to prevent, enforced one
        # layer up where the host cannot see it.
        eg_terminal = dict(build_terminal_rule(terminal))
        eg_terminal["name"] += "-egress"
        egress_terms.append(eg_terminal)
        filters.append({
            "header": {"targets": {target: "mixed output"}},
            "terms":  egress_terms,
        })

    return {
        "metadata": {
            "host":  zone_name,
            "zone":  zone_name,
            "hosts": sorted(data["hosts"]),
        },
        "filters": filters,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Merge per-host aerleon YAMLs into per-zone firewall policy."
    )
    parser.add_argument("--hosts",    required=True,
                        help="Glob pattern for host policy YAMLs, e.g. 'policies/pol/*.yml'")
    parser.add_argument("--defs",     default="def",
                        help="Aerleon definitions directory (default: def)")
    parser.add_argument("--outdir",   default="zones",
                        help="Output directory for zone YAMLs (default: zones/)")
    parser.add_argument("--target",   default="nftables",
                        help="Aerleon target platform (default: nftables)")
    parser.add_argument("--terminal", default="log-accept",
                        choices=["log-accept", "log-drop", "drop"],
                        help=(
                            "Terminal catch-all rule mode (default: log-accept). "
                            "log-accept: initial deployment, accept+log unmatched. "
                            "log-drop: rules settled, drop+log to catch false positives. "
                            "drop: confident, silent drop."
                        ))
    args = parser.parse_args()

    host_yamls = glob.glob(args.hosts)
    if not host_yamls:
        print(f"No files matched: {args.hosts}", file=sys.stderr)
        sys.exit(1)

    defs = naming.Naming(args.defs)
    os.makedirs(args.outdir, exist_ok=True)

    zones = build_zones(host_yamls, defs)

    class NoAliasDumper(yaml.Dumper):
        def ignore_aliases(self, data):
            return True

    for zone_name, data in zones.items():
        out = emit_zone_yaml(zone_name, data, terminal=args.terminal, target=args.target, defs=defs)
        outpath = os.path.join(args.outdir, f"{zone_name}.yml")
        with open(outpath, "w") as f:
            yaml.dump(out, f, Dumper=NoAliasDumper,
                      default_flow_style=False, sort_keys=False)
        allow_count = sum(
            1 for t in out["filters"][0]["terms"]
            if t.get("action", "accept").lower() not in ("drop", "deny")
            and t.get("logging") is None  # exclude terminal log-accept
        )
        deny_count = sum(
            1 for t in out["filters"][0]["terms"]
            if t.get("action", "accept").lower() in ("drop", "deny")
            and t.get("name") not in ("drop-ghost-hosts",)
            and t.get("logging") is None
        )
        print(
            f"Written {outpath} "
            f"({allow_count} allow, {deny_count} intra-zone deny, "
            f"ghost-drop, {args.terminal} terminal — "
            f"{len(data['hosts'])} hosts)"
        )


if __name__ == "__main__":
    main()
