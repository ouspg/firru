#!/usr/bin/env python3
"""
flow-verdict — Annotate flows with the policy verdict and practice outcome,
for the policy-vs-practice 2x2 analysis.

For each flow it resolves the destination to a known host, evaluates that
host's ingress policy against the flow 5-tuple (first-match firewall
semantics), and emits the flow annotated with:

  direction       ingress | egress | unknown
  host            matched host token (or null)
  policy_verdict  allow | deny | unknown-host
  matched_term    name of the deciding term (or null)
  practice        admitted | blocked | unknown   (from responded/incomplete)
  src_zone        zone of the source address ({ZONE}_HOSTS membership), or null
  dst_zone        zone of the destination address, or null
  intra_zone      true when src and dst are in the same zone (host-FW-only path)
  rt_src, rt_dst  red-team membership (only if --rt-ips given)
  policy_commit   commit whose policy was used (time-accurate mode only)

The per-flow verdict is Python (Aerleon naming/term semantics, not SQL).
Aggregate the output with DuckDB -- see flow_analysis.sql -- for the 2x2
matrix and the per-zone / per-phase / RT breakdowns.

Two matching modes:
  snapshot (default)   match every flow against the --pol tree as it is now.
  time-accurate        with --history-repo/--pol-path, match each flow
                       against the policy in force at the flow's timestamp:
                       the commit timeline is built once, each flow bisected
                       to the active commit, and per-commit matchers are built
                       lazily and cached. Flows without a timestamp, or before
                       any policy existed, fall back to the --pol snapshot.
                       NOTE: term selection is time-accurate per commit, but
                       token->CIDR/port resolution uses the single --defs dir
                       given (a documented approximation; def/ also evolves).

Counterfactual variants: each ingress flow can additionally be scored against
any number of alternative policy trees in the same pass, emitted as
verdict_<name> (allow | deny | no-policy | null for egress/unknown flows):

  --variant NAME=DIR            snapshot matcher over a policy dir
                                (e.g. final=policies/pol, nosample=policies/nosample)
  --history-variant NAME=PATH   time-accurate matcher over another path in
                                --history-repo (e.g. proposed=policies/tighten);
                                .blocked.yml / .dead.yml / -netns files are skipped.

The counterfactual verdicts measure exposure ("this flow would have met a
deny"), not prevented outcomes -- an enforced variant would have changed
attacker behavior. Compare variants against each other; the shared --defs
approximation cancels in the comparison.

Flow schema: docs/flow-record.md. Only the 5-tuple is required here;
timestamp/responded/resp_pkts/incomplete are used when present. The input
record is passed through unchanged and the fields above are added to it, so an
annotated flow is still a flow record and can be read back by anything that
reads one.

Usage:
    flow-verdict --pol policies/pol --defs def \\
        [--rt-ips rt_ips.yml] flows.jsonl > annotated.jsonl

    # time-accurate against git history
    flow-verdict --pol policies/pol --defs def \\
        --history-repo . --pol-path policies/pol \\
        --rt-ips rt_ips.yml flows.jsonl > annotated.jsonl
"""

import argparse
import bisect
import glob
import json
import os
import sys
from collections import OrderedDict
from datetime import datetime
from ipaddress import ip_address, ip_network

from firru.prefixes import PrefixTree
import yaml

from firru.policy import (DIR_IN, filter_directions, is_input_filter,
                          is_transit_filter, target_names)
from aerleon.lib import naming

ANY_TOKENS = {"ANY", "ANY_V4", "ANY_V6", "INTERNET", "WORLD", "OFF_NET"}

# libyaml where PyYAML was built with it: a run reads every policy in up to
# three trees, and the pure-Python parser was a quarter of a short run.
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _load_yaml(stream):
    return yaml.load(stream, Loader=_YAML_LOADER)


# ---------------------------------------------------------------------------
# Definition resolvers (thin wrappers over aerleon naming)
# ---------------------------------------------------------------------------

# One --defs dir per run (documented above), so module-level memoization is
# safe and pays for itself: with several matchers per flow the same tokens
# are resolved millions of times.
_NETS_CACHE = {}
_PORTS_CACHE = {}


def resolve_nets(token, defs):
    """Resolve a network token (or list) to ip_network objects.
    Returns None for ANY-style wildcards (match everything)."""
    if token is None:
        return None
    key = token if isinstance(token, str) else tuple(token)
    if key in _NETS_CACHE:
        return _NETS_CACHE[key]
    tokens = [token] if isinstance(token, str) else list(token)
    nets = []
    for tok in tokens:
        if tok in ANY_TOKENS:
            nets = None
            break
        try:
            for n in defs.GetNetAddr(tok):
                nets.append(ip_network(str(n), strict=False))
        except Exception:
            continue
    _NETS_CACHE[key] = nets
    return nets


def _literal_ports(tok):
    """Ports for a term that names them outright: 829, "829", or "1812-1813".

    Returns None when the token is a service name for the definitions to
    resolve. A literal carries no protocol of its own, so it applies to
    whatever protocol the term already matched on.
    """
    if isinstance(tok, int):
        return {tok}
    text = str(tok).strip()
    if text.isdigit():
        return {int(text)}
    lo, sep, hi = text.partition("-")
    if sep and lo.isdigit() and hi.isdigit():
        return set(range(int(lo), int(hi) + 1))
    return None


def resolve_ports(svc_token, proto, defs):
    """Resolve a service token (or list) to a set of int ports for `proto`.
    Returns None when the term has no destination-port (any port)."""
    if not svc_token:
        return None
    # A term may name a service token, or give the port literally. Hand-edited
    # policies do the latter under time pressure -- `destination-port: 829`
    # and `[1812, 1813]` get written mid-incident --
    # and that is valid Aerleon, so it has to resolve rather than crash.
    tokens = ([svc_token] if isinstance(svc_token, (str, int))
              else list(svc_token))
    key = (tuple(str(t) for t in tokens), proto)
    if key in _PORTS_CACHE:
        return _PORTS_CACHE[key]
    ports = set()
    for tok in tokens:
        literal = _literal_ports(tok)
        if literal is not None:
            ports.update(literal)
            continue
        try:
            for entry in defs.GetService(tok):
                pstr, sproto = entry.split("/")
                if proto and sproto.lower() != proto.lower():
                    continue
                if "-" in pstr:
                    lo, hi = (int(x) for x in pstr.split("-"))
                    ports.update(range(lo, hi + 1))
                else:
                    ports.add(int(pstr))
        except Exception:
            continue
    _PORTS_CACHE[key] = ports
    return ports


# ---------------------------------------------------------------------------
# Matcher: (host_trie_v4, host_trie_v6, host_terms)
# ---------------------------------------------------------------------------

def is_ingress(filt):
    """Whether this filter is the host's inbound half.

    Delegates to firru.policy so the whole toolchain agrees on what a direction
    looks like. This used to test `"input" in value`, which is how every windows
    host's policy went unread: aerleon's windows_advfirewall target says "in",
    not "input", so no filter matched, host_terms came back empty, and every
    flow to those 48 hosts scored deny with no matched_term -- indistinguishable
    in the output from a policy that really denies everything.
    """
    return is_input_filter(filt)


def _report_unread(unread):
    """Name the filters whose direction the document never stated.

    Silence is what made the windows bug survive a published paper: a host with
    no readable ingress filter scores every inbound flow as deny/no-term, which
    looks exactly like a host that denies everything. A generator we cannot read
    has to announce itself, once, by host.
    """
    if not unread:
        return
    print(f"warning: {len(unread)} filter(s) state no direction and were not "
          f"read as ingress; their generators bind direction outside the policy "
          f"file (a zone pair, or an interface):", file=sys.stderr)
    for host, gens in sorted(unread)[:10]:
        print(f"  {host}: {', '.join(gens) or '(no target)'}", file=sys.stderr)
    if len(unread) > 10:
        print(f"  ... and {len(unread) - 10} more", file=sys.stderr)


def build_matcher(docs, defs):
    """Build a matcher from parsed policy dicts."""
    t4, t6 = PrefixTree(32), PrefixTree(128)
    host_terms = {}
    unread = []
    for doc in docs:
        if not doc:
            continue
        host = (doc.get("metadata") or {}).get("host")
        if not host:
            continue
        terms = []
        for filt in (doc.get("filters") or []):
            dirs = filter_directions(filt)
            if DIR_IN in dirs:
                terms.extend(filt.get("terms", []))
            elif not dirs and not is_transit_filter(filt):
                # Neither half, and not transit either: the document does not
                # say. Collected rather than silently treated as one side.
                unread.append((host, target_names(filt)))
        host_terms[host] = terms
        for n in (resolve_nets(host, defs) or []):
            tree = t6 if n.version == 6 else t4
            tree[str(n)] = host
    _report_unread(unread)
    return t4, t6, host_terms


# Non-policy artifacts that live beside proposals in a tighten tree.
SKIP_SUFFIXES = (".blocked.yml", ".dead.yml")


def load_matcher_dir(pol_dir, defs):
    docs = []
    for path in sorted(glob.glob(os.path.join(pol_dir, "*.yml"))):
        base = os.path.basename(path)
        if "-netns" in base or base.endswith(SKIP_SUFFIXES):
            continue
        try:
            docs.append(_load_yaml(open(path)))
        except Exception:
            continue
    return build_matcher(docs, defs)


def lookup_host(ip_str, matcher):
    t4, t6, _ = matcher
    try:
        tree = t6 if ":" in ip_str else t4
        return tree.get(ip_str)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Zone classification: which zone an address sits in, by {ZONE}_HOSTS token.
# The centralized firewall only sees cross-zone traffic, so intra-zone denials
# are attributable to the host firewall layer alone -- worth labelling.
# ---------------------------------------------------------------------------

def collect_zones(pol_dir):
    """Distinct metadata.zone values across the host policies in pol_dir."""
    zones = set()
    for path in sorted(glob.glob(os.path.join(pol_dir, "*.yml"))):
        try:
            doc = _load_yaml(open(path))
        except Exception:
            continue
        z = ((doc or {}).get("metadata") or {}).get("zone")
        if z:
            zones.add(z)
    return zones


def build_zone_tries(zones, defs):
    """Trie of address -> zone, resolving each zone's {ZONE}_HOSTS token."""
    z4, z6 = PrefixTree(32), PrefixTree(128)
    for zone in zones:
        for n in (resolve_nets(f"{zone}_HOSTS", defs) or []):
            tree = z6 if n.version == 6 else z4
            tree[str(n)] = zone
    return z4, z6


def lookup_zone(ip_str, ztries):
    if not ip_str or ztries is None:
        return None
    z4, z6 = ztries
    try:
        tree = z6 if ":" in ip_str else z4
        return tree.get(ip_str)
    except Exception:
        return None


def _parse_addr(ip_str, _cache={}):
    try:
        return _cache[ip_str]
    except KeyError:
        try:
            addr = ip_address(ip_str)
        except ValueError:
            addr = None
        if len(_cache) < 200000:
            _cache[ip_str] = addr
        return addr


def term_matches(term, proto, dport, src_ip, defs):
    tproto = term.get("protocol")
    if tproto:
        tprotos = [tproto] if isinstance(tproto, str) else tproto
        if proto not in [p.lower() for p in tprotos]:
            return False
    ports = resolve_ports(term.get("destination-port"), proto, defs)
    if ports is not None and dport not in ports:
        return False
    nets = resolve_nets(term.get("source-address"), defs)
    if nets is not None:
        addr = _parse_addr(src_ip)
        if addr is None:
            return False
        if not any(addr in n for n in nets):
            return False
    return True


# (matcher, defs) -> their verdicts by (host, proto, dport, src_ip). Traffic
# repeats those four fields ~30x within an hour, and the first-match walk over
# every term's networks is most of the run. Each entry holds its matcher and
# defs, so an id() is never reused while it is cached; both levels are bounded,
# as time-accurate mode builds a matcher per commit.
_VERDICTS = {}
_VERDICT_MATCHERS = 16
_VERDICT_KEYS = 1 << 18


def ingress_verdict(host, matcher, proto, dport, src_ip, defs):
    k = (id(matcher), id(defs))
    entry = _VERDICTS.get(k)
    if entry is None:
        if len(_VERDICTS) >= _VERDICT_MATCHERS:
            del _VERDICTS[next(iter(_VERDICTS))]
        entry = _VERDICTS[k] = (matcher, defs, {})
    memo = entry[2]
    key = (host, proto, dport, src_ip)
    try:
        return memo[key]
    except KeyError:
        pass
    if len(memo) >= _VERDICT_KEYS:
        memo.clear()
    memo[key] = out = _first_match(host, matcher, proto, dport, src_ip, defs)
    return out


def _first_match(host, matcher, proto, dport, src_ip, defs):
    _, _, host_terms = matcher
    for term in host_terms.get(host, []):
        if term_matches(term, proto, dport, src_ip, defs):
            action = term.get("action", "accept").lower()
            return ("allow" if action == "accept" else "deny"), term.get("name")
    return "deny", None


# ---------------------------------------------------------------------------
# Time-accurate matchers from git history
# ---------------------------------------------------------------------------

class HistoryMatchers:
    """Policy matchers indexed by commit time, built lazily and cached."""

    def __init__(self, repo, pol_path, defs, cache_size=8):
        from firru.githist import git, BlobReader, list_blobs
        self._git, self._list_blobs = git, list_blobs
        self.repo, self.pol_path, self.defs = repo, pol_path, defs
        self.reader = BlobReader(repo)
        log = git(repo, "log", "--reverse", "--format=%H %cI", "--", pol_path)
        self.commits = []          # (epoch_ts, sha)
        for line in log.splitlines():
            sha, iso = line.split(" ", 1)
            self.commits.append((int(datetime.fromisoformat(iso).timestamp()), sha))
        self.times = [c[0] for c in self.commits]
        # LRU cache of built matchers. With time-ordered input only a couple
        # of commits are ever live, so this bounds memory regardless of how
        # many commits the history has.
        self.cache = OrderedDict()
        self.cache_size = max(1, cache_size)
        print(f"History: {len(self.commits)} commits "
              f"({self.commits[0][0] if self.commits else '-'}..."
              f"{self.commits[-1][0] if self.commits else '-'}), "
              f"matcher cache={self.cache_size}.", file=sys.stderr)

    def at(self, flow_ts):
        """(matcher, sha) for the policy in force at flow_ts, or (None, None)."""
        i = bisect.bisect_right(self.times, flow_ts) - 1
        if i < 0:
            return None, None
        sha = self.commits[i][1]
        if sha in self.cache:
            self.cache.move_to_end(sha)
        else:
            docs = []
            for blob_sha, name in self._list_blobs(self.repo, sha, self.pol_path):
                base = name.rsplit("/", 1)[-1]
                if "-netns" in base or base.endswith(SKIP_SUFFIXES):
                    continue
                try:
                    docs.append(_load_yaml(self.reader.read(blob_sha)))
                except Exception:
                    continue
            self.cache[sha] = build_matcher(docs, self.defs)
            while len(self.cache) > self.cache_size:
                self.cache.popitem(last=False)   # evict least-recently-used
        return self.cache[sha], sha


# ---------------------------------------------------------------------------
# Per-flow evaluation
# ---------------------------------------------------------------------------

def practice_outcome(flow):
    """admitted | blocked | unknown, from whatever the source could observe.

    A null `responded` is `unknown` and stops here rather than falling through
    to `incomplete`. The record allows null for "not answered yet" -- a
    conntrack NEW event is the case -- and a flow created a moment ago is not
    a flow that was refused. Reading it as blocked would put every connection
    attempt in the deny column of the 2x2, which is the one place in firru
    where that mistake becomes a published number. `incomplete` is no better
    on such a flow: it is true simply because no reply has arrived yet.
    """
    if "responded" in flow:
        if flow["responded"] is None:
            return "unknown"
        return "admitted" if flow["responded"] else "blocked"
    if "incomplete" in flow:
        return "blocked" if flow["incomplete"] else "admitted"
    return "unknown"


def variant_verdict(flow, matcher, defs):
    """Ingress verdict of an alternative policy tree for an already-evaluated
    flow: allow | deny | no-policy (host absent from that tree)."""
    dst_ip = flow.get("dst_ip")
    host = lookup_host(dst_ip, matcher) if dst_ip else None
    if host is None:
        return "no-policy"
    verdict, _term = ingress_verdict(
        host, matcher, (flow.get("protocol") or "").lower(),
        flow.get("dst_port"), flow.get("src_ip"), defs)
    return verdict


def evaluate(flow, matcher, defs, rt, ztries=None):
    proto = (flow.get("protocol") or "").lower()
    dst_ip, src_ip = flow.get("dst_ip"), flow.get("src_ip")
    dport = flow.get("dst_port")

    host = lookup_host(dst_ip, matcher) if dst_ip else None
    if host is not None:
        flow["direction"], flow["host"] = "ingress", host
        flow["policy_verdict"], flow["matched_term"] = ingress_verdict(
            host, matcher, proto, dport, src_ip, defs)
    elif src_ip and lookup_host(src_ip, matcher):
        flow["direction"] = "egress"
        flow["host"] = lookup_host(src_ip, matcher)
        flow["policy_verdict"], flow["matched_term"] = "egress-unevaluated", None
    else:
        flow["direction"], flow["host"] = "unknown", None
        flow["policy_verdict"], flow["matched_term"] = "unknown-host", None

    flow["practice"] = practice_outcome(flow)
    if ztries is not None:
        sz, dz = lookup_zone(src_ip, ztries), lookup_zone(dst_ip, ztries)
        flow["src_zone"], flow["dst_zone"] = sz, dz
        flow["intra_zone"] = bool(sz and dz and sz == dz)
    if rt is not None:
        flow["rt_src"], flow["rt_dst"] = rt(src_ip), rt(dst_ip)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--pol", required=True, help="policy dir (snapshot / fallback)")
    ap.add_argument("--defs", required=True, help="aerleon definitions dir")
    ap.add_argument("--rt-ips", metavar="FILE",
                    help="red-team address list: a YAML list, a mapping, or "
                         "one CIDR per line (see firru.iptrees)")
    ap.add_argument("--rt-key", metavar="KEY", default=None,
                    help="key holding the CIDRs, if --rt-ips is a mapping with "
                         "more than one list (default: the only list in it)")
    ap.add_argument("--history-repo", help="git repo for time-accurate matching")
    ap.add_argument("--pol-path", help="policy path within the repo (e.g. policies/pol)")
    ap.add_argument("--cache-commits", type=int, default=8,
                    help="LRU size for per-commit matchers (time-accurate mode); "
                         "small is fine for time-sorted input (default 8)")
    ap.add_argument("--variant", action="append", default=[],
                    metavar="NAME=DIR",
                    help="score ingress flows against this policy dir too; "
                         "emitted as verdict_NAME (repeatable)")
    ap.add_argument("--history-variant", action="append", default=[],
                    metavar="NAME=PATH",
                    help="score ingress flows against the policy at PATH in "
                         "--history-repo, time-accurately; emitted as "
                         "verdict_NAME (repeatable)")
    ap.add_argument("files", nargs="*", help="flows JSONL (default: stdin)")
    args = ap.parse_args()

    defs = naming.Naming(args.defs)
    snapshot = load_matcher_dir(args.pol, defs)
    _, _, snap_terms = snapshot
    print(f"Snapshot: {len(snap_terms)} host policies.", file=sys.stderr)

    # Zone classification is defs-level (zone membership tokens) and stable
    # across commits, so build it once from the --pol snapshot's zones.
    zones = collect_zones(args.pol)
    ztries = build_zone_tries(zones, defs)
    print(f"Zones: {len(zones)} ({sum(len(t) for t in ztries)} prefixes).",
          file=sys.stderr)

    history = None
    if args.history_repo:
        if not args.pol_path:
            sys.exit("--history-repo requires --pol-path")
        history = HistoryMatchers(args.history_repo, args.pol_path, defs,
                                  cache_size=args.cache_commits)

    def parse_kv(spec, flag):
        if "=" not in spec:
            sys.exit(f"{flag} expects NAME=VALUE, got {spec!r}")
        return spec.split("=", 1)

    variants = []                      # (name, static matcher or None, history or None)
    for spec in args.variant:
        name, vdir = parse_kv(spec, "--variant")
        m = load_matcher_dir(vdir, defs)
        print(f"Variant {name}: {len(m[2])} host policies ({vdir}).",
              file=sys.stderr)
        variants.append((name, m, None))
    for spec in args.history_variant:
        name, vpath = parse_kv(spec, "--history-variant")
        if not args.history_repo:
            sys.exit("--history-variant requires --history-repo")
        hm = HistoryMatchers(args.history_repo, vpath, defs,
                             cache_size=args.cache_commits)
        variants.append((name, None, hm))

    rt = None
    if args.rt_ips:
        from firru.iptrees import AddressListError, load_trees
        try:
            rt4, rt6 = load_trees(args.rt_ips, key=args.rt_key)
        except (AddressListError, OSError) as exc:
            # Carrying on would annotate every flow rt_src: false, which is a
            # claim about the traffic and not about the file.
            print(f"flow-verdict: {exc}", file=sys.stderr)
            return 1

        def rt(ip):
            if not ip:
                return None
            try:
                return ip in (rt6 if ":" in ip else rt4)
            except Exception:
                return False

    def streams():
        if args.files:
            for f in args.files:
                yield from open(f)
        else:
            yield from sys.stdin

    n = fellback = 0
    for line in streams():
        line = line.strip()
        if not line:
            continue
        try:
            flow = json.loads(line)
        except json.JSONDecodeError:
            continue

        matcher, sha = snapshot, None
        if history is not None:
            ts = flow.get("timestamp")
            if ts is not None:
                m, sha = history.at(ts)
                if m is not None:
                    matcher = m
                else:
                    fellback += 1            # flow predates any policy
            else:
                fellback += 1                # no timestamp
        if history is not None:
            flow["policy_commit"] = sha

        evaluate(flow, matcher, defs, rt, ztries)

        for name, static_m, hist_m in variants:
            v = None
            if flow["direction"] == "ingress":
                vm = static_m
                if hist_m is not None:
                    ts = flow.get("timestamp")
                    vm = hist_m.at(ts)[0] if ts is not None else None
                v = variant_verdict(flow, vm, defs) if vm is not None else None
            flow[f"verdict_{name}"] = v

        sys.stdout.write(json.dumps(flow) + "\n")
        n += 1

    msg = f"Annotated {n} flows."
    if history is not None:
        msg += f" {fellback} fell back to snapshot (no ts / pre-policy)."
    print(msg, file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
