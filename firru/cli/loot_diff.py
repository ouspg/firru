#!/usr/bin/env python3
"""
loot-diff — Compare two loot-listeners snapshots of the same estate.

Answers the question a second collection run is for: what is listening now that
was not listening before, what went away, and where is a familiar port suddenly
served by a different binary.

Usage:
    # two snapshots, taken days apart
    loot-listeners fam-ssdata/  --output fam/
    loot-listeners exec-ssdata/ --output exec/
    loot-diff fam/ exec/

    # keep the bind address in the identity (noisier: link-local and DHCP churn)
    loot-diff fam/ exec/ --key bind

    # machine-readable, for feeding a policy patch
    loot-diff fam/ exec/ --json delta.json

Either side may be a directory of <hostname>.json files or a single such file.

Against a baseline instead of an earlier run:

    # every host in exec/ against one stock Windows Server DC
    loot-diff --baseline baselines/dc.json exec/

    # several baselines, one per role, chosen by hostname
    loot-diff --baseline baselines/ exec/ --assign 'dc*=win2022-dc' --assign '*=win2022'

    # a stock install by name, from a firru-os-baselines checkout
    # ($FIRRU_BASELINES, else ~/firru-os-baselines); also `firru diff --baseline`
    firru diff --baseline win2022-dc hosts/dc01/
    loot-diff --baseline list

    # what synthesis should see: the loot less what the baseline explains,
    # which a curated role covers instead (firru synth --role)
    loot-diff --baseline win2022-dc hosts/dc01/ --residual residual/ -q

Either side may also be raw loot (loot-host output, a host tree): it is run
through loot-listeners in-process.

A baseline is a loot-listeners document from a stock install of the OS or role
(firru-os-baselines). Each host is compared with its baseline rather than with
its own past: what the host adds to stock, what stock listens on that the host
does not (hardened, or the role is not running), where a stock port is served
by another process, and where a port stock binds to loopback only listens
beyond it (scope widened). Loopback listeners are otherwise left out on both
sides, since many collections drop them.

Listener identity is (protocol, port) by default. Bind addresses are deliberately
not part of it: a host that picked up a new IPv6 privacy address between runs has
not opened anything, and per-address duplicates would bury the real changes. The
addresses and process names seen for a port are still carried along as context,
and a port whose serving process changed is reported under 'changed'. A port that
is attributed on one side and UNKNOWN on the other is an annotation gap — the ps
data was missing, not the service — and is bucketed under 'unattributed'.

Hosts present in only one snapshot are reported as a host-set delta, not as
hundreds of added or removed listeners — a host that was not collected twice has
no comparable state. --new-hosts opts their listeners into the added list.
"""

import argparse
import fnmatch
import ipaddress
import json
import os
import sys
from collections import Counter
from pathlib import Path

from firru.defs_dir import STOCK_BASELINE
from firru.tokens import is_loopback, normalize_token

# Listener identity. Everything not in the key is context, merged across the
# records that share a key.
#: Per-OS defaults: Linux's net.ipv4.ip_local_port_range, and the Windows
#: dynamic range since Vista. A fallback either way -- the host's own range is
#: a fact the loot run could collect, and should, rather than a constant here.
#: `--ephemeral` overrides both.
#:
#: Measured across repeated loot snapshots of one estate, and the split matters. Linux churn
#: by band: 0.28 below 32768, 0.85 in 32768-49151, 1.00 in 49152-60999, with
#: nothing above. Windows: 0.00-0.02 everywhere below 49152, then 0.31 and
#: 0.38 in the two bands above it. Applying the Linux range to Windows
#: therefore does two wrong things at once -- it calls 32768-49151 ephemeral
#: where Windows keeps those ports across restarts, and it stops at 60999
#: while Windows churn continues past it.
# Ephemeral ranges live in firru.ephemeral so the socket side and the flow
# side cannot drift apart; re-exported here for existing callers.
from firru.ephemeral import (  # noqa: E402
    EPHEMERAL_BY_OS, DEFAULT_EPHEMERAL, ephemeral_for, is_ephemeral,
)

KEY_MODES = {
    'port': lambda r: (r.get('protocol', ''), r.get('port')),
    'bind': lambda r: (r.get('protocol', ''), r.get('port'), r.get('bind_address', '')),
    'proc': lambda r: (r.get('protocol', ''), r.get('port'),
                       (r.get('process') or {}).get('name') or 'UNKNOWN'),
}


def load_snapshot(path):
    """
    Read a loot-listeners output tree (or single file) into {hostname: doc}.

    The hostname comes from the document's own metadata when present, so a
    renamed file does not silently become a new host.
    """
    p = Path(path)
    if p.is_file():
        files = [p]
    elif p.is_dir():
        files = sorted(f for f in p.iterdir() if f.is_file() and f.suffix == '.json')
    else:
        raise FileNotFoundError(path)

    hosts, skipped = {}, []
    for f in files:
        try:
            with open(f) as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            skipped.append(f"{f}: {e}")
            continue
        if not isinstance(doc, dict) or 'listen_ports' not in doc:
            skipped.append(f"{f}: not a loot-listeners document")
            continue
        hostname = (doc.get('metadata') or {}).get('hostname') or f.stem
        hosts[hostname] = doc
    if not hosts:
        # Raw loot (a loot-host directory) is all other JSON; load_any reads it
        # as such, so the files are not worth a warning each.
        raise ValueError(f"no loot-listeners documents found under: {path}")
    for msg in skipped:
        print(f"Warning: skipping {msg}", file=sys.stderr)
    return hosts


def normalize_raw(path, loopback=False):
    """
    Raw loot (loot-host output, a firru-os-baselines run, a tree of hosts) to
    {hostname: doc}, the way loot-listeners would write it. Saves the separate
    loot-listeners step when all that is wanted is the comparison. loopback
    keeps loopback binds, which loot-listeners leaves out: a baseline needs
    them to tell a widened listener (stock on 127.0.0.1, here on any) from an
    added one.
    """
    from firru.discovery import get_discovery_list
    from firru.cli.loot_listeners import process_host, _windows_findings
    hosts = {}
    for entry in get_discovery_list(str(path)):
        try:
            metadata, listen_ports = process_host(entry, loopback)
        except Exception as e:  # noqa: BLE001 -- one bad host must not stop the rest
            print(f"Warning: {entry['hostname']}: {e}", file=sys.stderr)
            continue
        doc = {'metadata': metadata, 'listen_ports': listen_ports}
        findings = _windows_findings(entry, metadata, listen_ports)
        if findings:
            doc['findings'] = findings
        hosts[metadata['hostname']] = doc
    if not hosts:
        raise ValueError(f"no loot-listeners documents or raw loot found under: {path}")
    return hosts


def load_any(path):
    """loot-listeners documents if there are any, raw loot otherwise."""
    p = Path(path)
    if p.is_dir() and not any(f.suffix == '.json' and f.is_file() for f in p.iterdir()):
        return normalize_raw(p)
    try:
        return load_snapshot(p)
    except ValueError:
        if p.is_dir():
            return normalize_raw(p)
        raise


# --- Named baselines -------------------------------------------------------
#
# `--baseline win2022-dc` finds the run in a firru-os-baselines checkout:
# $FIRRU_BASELINES (os.pathsep-separated), else ~/firru-os-baselines or
# ~/baselines, and then in the records firru ships (baseline/ beside def/,
# made by `firru baseline-synth`: one <run>.json.gz per stock install). Every word of the name must appear in the run's name; among
# the matches the one with the fewest other words wins, counting only words
# that select a different install (a role, a collection variant), not the
# edition, the network profile, build numbers or the run number.

_NEUTRAL = {'std', 'desktop', 'pro', 'public', 'iso', 'minimal'}
_ALIASES = {'windows': 'win', 'ubuntu-server': 'ubuntu'}


SHIPPED = STOCK_BASELINE


def baseline_roots():
    env = os.environ.get('FIRRU_BASELINES')
    if env:
        return [Path(x).expanduser() for x in env.split(os.pathsep) if x]
    return [Path(x).expanduser() for x in ('~/firru-os-baselines', '~/baselines')] + [SHIPPED]


def _words(name):
    import re
    out = []
    for part in re.split(r'[-+_.\s]+', name.lower()):
        if re.fullmatch(r'[rgd]\d+[a-z]?', part):   # run (r2), golden set (g1, g2b, g3k), delta (d3): one word
            out.append(part)
            continue
        out += [w for w in re.split(r'(?<=[a-z])(?=\d)|(?<=\d)(?=[a-z])', part) if w]
    return out


def available_baselines():
    """{run name: path} of the runs under the roots: directories holding
    loot-host/ (a checkout: under runs/, or at its top before 2026-10-23), or
    <run>.json.gz records (baseline/)."""
    runs = {}
    for root in baseline_roots():
        for top in (root / 'runs', root):
            if not top.is_dir():
                continue
            for d in sorted(top.iterdir()):
                    if d.name.endswith('.json.gz'):
                        name = d.name[:-len('.json.gz')]
                    elif (d / 'loot-host').is_dir():
                        name = d.name
                    else:
                        continue
                    runs.setdefault(name, d)
    return runs


def load_record(path):
    """The loot-listeners documents of a shipped baseline record."""
    import gzip
    with gzip.open(path, 'rt', encoding='utf-8') as f:
        return json.load(f)['documents']


def resolve_baseline_name(name, runs=None):
    """Run name for a loose baseline name, or ValueError naming the candidates."""
    import re
    runs = available_baselines() if runs is None else runs
    if name in runs:
        return name
    want = [_ALIASES.get(w, w) for w in _words(name)]
    if 'win' in want and 'server' in want:
        want.remove('server')       # the Windows runs say std/dc, not server
    scored = []
    for run in runs:
        have = _words(run)
        if not all(w in have for w in want):
            continue
        extra = [w for w in have if w not in want and w not in _NEUTRAL
                 and not w.isdigit() and not re.fullmatch(r'[rgd]\d+[a-z]?', w)]
        scored.append((len(extra), run))
    if not scored:
        raise ValueError(f"no baseline matches {name!r}; available: "
                         + ', '.join(sorted(runs)) if runs else
                         f"no baselines found (set FIRRU_BASELINES to a firru-os-baselines checkout)")
    best = min(c for c, _ in scored)
    top = sorted(r for c, r in scored if c == best)
    installs = {re.sub(r'-[rgd]\d+[a-z]?$', '', r) for r in top}
    if len(installs) > 1:
        raise ValueError(f"baseline {name!r} is ambiguous: " + ', '.join(top))
    # A golden set (-gN, every collector settled) or a delta run (-dN) over
    # earlier runs (-rN); the latest set, a rerun (g2b) over its first try.
    def setkey(r):
        m = re.search(r'-[gd](\d+)([a-z]?)$', r)
        return (int(m.group(1)), m.group(2) != 'k', m.group(2))
    golden = sorted((r for r in top if re.search(r'-[gd]\d+[a-z]?$', r)), key=setkey)
    return golden[-1] if golden else top[0]


def load_baseline(ref):
    """A baseline given as a path (documents, raw loot or a shipped record) or
    as a run name."""
    if str(ref).endswith('.json.gz') and Path(ref).is_file():
        return load_record(ref)
    if (Path(ref) / 'loot-host').is_dir():
        return normalize_raw(ref, loopback=True)    # a checkout run
    if Path(ref).exists():
        return load_any(ref)
    runs = available_baselines()
    run = resolve_baseline_name(ref, runs)
    if run != ref:
        print(f"baseline {ref!r} -> {run} ({runs[run]})", file=sys.stderr)
    return load_run(runs[run])


def load_run(path):
    """The documents of one available baseline: a shipped record or a checkout run."""
    if path.name.endswith('.json.gz'):
        return load_record(path)
    return normalize_raw(path, loopback=True)


def _family(doc):
    os_name = str(((doc or {}).get('metadata') or {}).get('os') or '').lower()
    return 'windows' if os_name.startswith('win') else os_name.split()[0] if os_name else ''


def closest_available(new, glob='*', key='port', ephemeral=None):
    """closest_baselines over every available run whose name matches glob:
    ({host: name}, {name: doc}), or None when there is none to compare with."""
    runs = {r: load_run(p) for r, p in available_baselines().items()
            if fnmatch.fnmatchcase(r, glob)}
    runs = {r: next(iter(d.values())) if isinstance(d, dict) and 'listen_ports' not in d else d
            for r, d in runs.items()}
    if not runs:
        return None
    return closest_baselines(runs, new, key=key, ephemeral=ephemeral)


def closest_baselines(runs, new, key='port', ephemeral=None, max_layers=4):
    """
    For each host in new, the baseline that explains most of its listeners,
    plus the layers that each explain something more: {host: name} and the
    merged documents {name: doc}, ready for diff_baseline.

    Metadata cannot tell that a host runs PostgreSQL; its listeners can. A
    listener is explained by a run that has the same key with a process name
    in common (or no name on either side). Candidates are the runs of the
    host's OS family. Greedy: the best single run (ties: the one with fewer
    listeners of its own, the closer fit), then while some layer adds an
    explained listener, the one that adds most. A layer is a run like any
    other, so `ubuntu-server-g1 + postgresql-server-g1` needs no layer list.
    """
    keyfn = KEY_MODES[key]
    # A run's loopback binds count: stock PostgreSQL on 127.0.0.1 explains a
    # host's 5432 on any address, which the comparison then reports as widened.
    idx = {r: index_listeners(d, keyfn) for r, d in runs.items()}
    fam = {r: _family(d) for r, d in runs.items()}

    def owners(procs):
        # systemd holding a socket-activated unit's port (Ubuntu's ssh.socket)
        # speaks for whatever the unit runs: no name to compare.
        return _named(procs) - {'systemd'}

    def explains(r, h_idx):
        out = set()
        for k, ctx in h_idx.items():
            b = idx[r].get(k)
            if b is not None and (not owners(ctx['procs']) or not owners(b['procs'])
                                  or owners(ctx['procs']) & owners(b['procs'])):
                out.add(k)
        return out

    assign, merged, guessed = {}, {}, []
    for host in sorted(new):
        rng = ephemeral_for(new[host], ephemeral)
        h_idx, _ = _split_dynamic(index_listeners(new[host], keyfn, loopback=False), rng)
        # The host's release when its loot recorded one, else its OS family.
        rel = ((new[host].get('metadata') or {}).get('release') or '').lower()
        cands = ([r for r in runs if rel and r.lower().startswith(rel)]
                 or [r for r in runs if fam[r] == _family(new[host])] or list(runs))
        if not rel and len({r.split('-')[0] for r in cands}) > 1:
            guessed.append(host)
        ex = {r: explains(r, h_idx) for r in cands}
        # Ties: plain stock before a layer run (a layer has to earn its place).
        base = min(cands, key=lambda r: (-len(ex[r]), '+' in r, len(idx[r]), r))
        chosen, covered = [base], set(ex[base])
        while len(chosen) <= max_layers:
            gain = {r: len(ex[r] - covered) for r in cands if r not in chosen}
            # Ties: the layer from the base's own release (longest shared
            # name prefix), then the smaller run.
            best = min(gain, key=lambda r: (-gain[r], -len(os.path.commonprefix([base, r])),
                                            len(idx[r]), r), default=None)
            if best is None or gain[best] == 0:
                break
            chosen.append(best)
            covered |= ex[best]
        name = ' + '.join(chosen)
        if name not in merged:
            docs = [runs[r] for r in chosen]
            merged[name] = {'metadata': dict(docs[0].get('metadata') or {}),
                            'listen_ports': [p for d in docs for p in d.get('listen_ports', [])]}
        assign[host] = name
    if guessed:
        # Loot from before loot-host recorded /etc/os-release: an AlmaLinux
        # run with the most common listeners wins over the host's own distro.
        print(f"loot-diff: {len(guessed)} host(s) without a release in their loot "
              f"({', '.join(guessed[:3])}{', ...' if len(guessed) > 3 else ''}): each "
              f"one's baseline is picked from every run of its OS family; to pin "
              f"it, write the release (ubuntu-24.04, almalinux-9, win2022) to "
              f"release.added beside the loot, or set metadata.release",
              file=sys.stderr)
    return assign, merged


def _loopback(bind):
    return is_loopback(bind)


def index_listeners(doc, keyfn, loopback=True):
    """
    Collapse a document's listen_ports into {key: context}.

    loopback=False leaves out records bound to a loopback address; a port also
    bound to a reachable address keeps that record.
    """
    index = {}
    for rec in doc.get('listen_ports', []):
        if not loopback and _loopback(rec.get('bind_address') or ''):
            continue
        try:
            key = keyfn(rec)
        except Exception:
            continue
        if key[1] is None:
            continue
        proc = (rec.get('process') or {}).get('name') or 'UNKNOWN'
        ctx = index.setdefault(key, {'procs': set(), 'binds': set(), 'flags': set(), 'exes': {}})
        ctx['procs'].add(proc)
        exe = _exe((rec.get('process') or {}).get('exe'))
        if exe:
            ctx['exes'].setdefault(proc, set()).add(exe)
        if rec.get('bind_address'):
            ctx['binds'].add(rec['bind_address'])
        ctx['flags'].update(rec.get('flags') or [])
    return index


def _exe(path):
    """An executable path for comparison: Windows paths case-folded, with
    either slash. A process can call itself anything; the file it runs from
    is harder to fake."""
    if not path:
        return None
    path = path.strip()
    if len(path) > 2 and path[1] == ':':
        return path.replace('/', '\\').lower()
    return path


def _group_exes(idx, keys, proc):
    """The executables a dynamic-port group's process ran from."""
    return set().union(*(idx[k].get('exes', {}).get(proc, set()) for k in keys))


def _named(procs):
    """The process names in procs that the collection actually attributed.
    N/A is what netstat-shaped Windows loot says when it could not tell."""
    return {p for p in procs if p not in ('UNKNOWN', 'N/A')}


def pair_rebound(old_idx, new_idx, added, removed, ephemeral):
    """
    Pull dynamically-bound sockets out of the added/removed sets.

    A process that binds an ephemeral port takes a different one each restart —
    a DNS or NTP client socket, a container runtime, a JVM's dynamic port. Read
    as a diff that is one port closed and another opened, when nothing about the
    host's service surface changed.

    The pairing is structural: same protocol, same process name, both the port
    that went and the port that came inside the host's ephemeral range. It says
    "dynamically bound", not "benign" — an implant that rebinds every reboot
    pairs up exactly the same way, and that is the point: the class is a
    statement about how the port was chosen, never about who chose it.

    Deliberately conservative. A port that moved outside the ephemeral range is
    a real service moving (postgres 5432 to 5433) and stays a genuine add plus
    remove. An unattributed port never pairs, because a missing process name is
    not evidence of anything.

    `added` and `removed` are mutated; the paired entries are returned.
    """
    lo, hi = ephemeral

    def index(keys, surface):
        out = {}
        for key in keys:
            if not lo <= key[1] <= hi:
                continue
            procs = _named(surface[key]['procs'])
            if not procs:
                continue
            out.setdefault((key[0], frozenset(procs)), []).append(key)
        return out

    was_idx = index(removed, old_idx)
    now_idx = index(added, new_idx)

    rebound = []
    for group in sorted(set(was_idx) & set(now_idx), key=lambda g: (g[0], sorted(g[1]))):
        proto, procs = group
        gone, came = sorted(was_idx[group]), sorted(now_idx[group])
        rebound.append({
            'protocol':  proto,
            'processes': sorted(procs),
            'was':       [k[1] for k in gone],
            'now':       [k[1] for k in came],
        })
        removed -= set(gone)
        added -= set(came)
    return rebound


def _entry(key, ctx):
    """Serialisable form of one listener, with its context sorted for stable output."""
    return {
        'protocol':  key[0],
        'port':      key[1],
        'processes': sorted(ctx['procs']),
        'binds':     sorted(ctx['binds']),
        'flags':     sorted(ctx['flags']),
    }


def _compare(o, n, rng, loopback_only=None):
    """
    One host's listener index o (earlier, or the baseline) against n.

    With loopback_only (keys o holds on loopback alone), an added key in it is
    reported under 'widened' instead: the same listener, bound beyond loopback.
    """
    added_keys, removed_keys = set(n) - set(o), set(o) - set(n)
    widened_keys = added_keys & loopback_only if loopback_only is not None else set()
    added_keys -= widened_keys
    rebound = pair_rebound(o, n, added_keys, removed_keys, rng)
    added   = [_entry(k, n[k]) for k in sorted(added_keys, key=lambda k: (k[1], k))]
    removed = [_entry(k, o[k]) for k in sorted(removed_keys, key=lambda k: (k[1], k))]
    changed, unattributed = [], []
    for k in sorted(set(o) & set(n), key=lambda k: (k[1], k)):
        if o[k]['procs'] == n[k]['procs']:
            continue
        entry = {
            'protocol': k[0],
            'port':     k[1],
            'was':      sorted(o[k]['procs']),
            'now':      sorted(n[k]['procs']),
        }
        # A name that is known on one side and UNKNOWN on the other is a
        # missing psexe annotation, not a port that changed hands.
        was, now = _named(o[k]['procs']), _named(n[k]['procs'])
        if not was or not now:
            unattributed.append(entry)
        elif 'systemd' in was or 'systemd' in now:
            # Socket activation: systemd holds the port until the unit's
            # daemon takes it (Ubuntu's ssh.socket, then sshd). Same service.
            pass
        elif was != now:
            changed.append(entry)
    out = {'added': added, 'removed': removed, 'rebound': rebound,
           'changed': changed, 'unattributed': unattributed}
    if loopback_only is not None:
        out['widened'] = [_entry(k, n[k]) for k in sorted(widened_keys, key=lambda k: (k[1], k))]
    return out


def parse_assign(specs):
    """--assign GLOB=BASELINE pairs, in the order given (first match wins)."""
    out = []
    for spec in specs or ():
        glob, sep, name = spec.partition('=')
        if not sep or not glob or not name:
            raise ValueError(f"--assign wants GLOB=BASELINE, got {spec!r}")
        out.append((glob, name))
    return out


def pick_baseline(host, baselines, assign):
    """The baseline for host: the first --assign glob that matches, else the
    only baseline there is, else None."""
    for glob, name in assign:
        if fnmatch.fnmatchcase(host, glob):
            return name
    if len(baselines) == 1:
        return next(iter(baselines))
    return None


def _split_dynamic(idx, rng):
    """
    Split an index into its static part and {(protocol, process): [keys]} for
    the attributed listeners inside the ephemeral range.
    """
    lo, hi = rng
    static, dynamic = {}, {}
    for k, ctx in idx.items():
        named = _named(ctx['procs'])
        if lo <= k[1] <= hi and named:
            for proc in named:
                dynamic.setdefault((k[0], proc), []).append(k)
        else:
            static[k] = ctx
    return static, dynamic


def diff_baseline(baselines, new, key='port', assign=(), ephemeral=None):
    """
    Compare every host in new with its baseline ({name: doc}).

    Per host: added (not stock), removed (stock, not on the host), rebound
    (dynamic ports the baseline's process also holds), dynamic_missing (stock
    processes holding no dynamic port here), changed (stock port, other
    process), unattributed, widened (stock binds it to loopback only), and the
    count of stock listeners that matched. Loopback records are left
    out on both sides.
    """
    for _, name in assign:
        if name not in baselines:
            raise ValueError(f"--assign names an unknown baseline {name!r} "
                             f"(have: {', '.join(sorted(baselines))})")
    keyfn = KEY_MODES[key]
    ref = {b: index_listeners(d, keyfn, loopback=False) for b, d in baselines.items()}
    ref_lo = {b: {k for k in index_listeners(d, keyfn) if k not in ref[b]}
              for b, d in baselines.items()}

    assigned, unassigned, changes = {}, [], {}
    for host in sorted(new):
        b = pick_baseline(host, baselines, assign)
        if b is None:
            unassigned.append(host)
            continue
        assigned[host] = b
        n = index_listeners(new[host], keyfn, loopback=False)
        rng = ephemeral_for(new[host], ephemeral)
        # Dynamic ports compare by process, not by number or count: a DNS
        # server holds thousands, and how many is configuration, not surface.
        # Each side by its own range: the baseline's may differ from the host's.
        bs, bd = _split_dynamic(ref[b], ephemeral_for(baselines[b], ephemeral))
        ns, nd = _split_dynamic(n, rng)
        c = _compare(bs, ns, rng, ref_lo[b])
        c['stock'] = len(set(bs) & set(ns))
        added, dynamic, impostors = set(), [], []
        for group, keys in sorted(nd.items()):
            # The same name from another executable is not the stock process:
            # a name is free to choose, and a dynamic port under avahi-daemon,
            # svchost or lsass is exactly where something would hide.
            if group in bd:
                now_exe = _group_exes(n, keys, group[1])
                was_exe = _group_exes(ref[b], bd[group], group[1])
                if now_exe and was_exe and not now_exe <= was_exe:
                    impostors.append({'protocol': group[0], 'process': group[1],
                                      'exe': sorted(now_exe - was_exe),
                                      'stock_exe': sorted(was_exe),
                                      'ports': sorted(k[1] for k in keys)})
                    added.update(keys)
                    continue
            if group in bd:
                dynamic.append({'protocol': group[0], 'processes': [group[1]],
                                'was': sorted(k[1] for k in bd[group]),
                                'now': sorted(k[1] for k in keys)})
            else:
                added.update(keys)
        # A stock process with no dynamic ports here at all: one entry per
        # process, not one per port it would have held.
        c['dynamic_missing'] = [{'protocol': g[0], 'processes': [g[1]], 'stock_ports': len(keys)}
                                for g, keys in sorted(bd.items()) if g not in nd]
        stock_dynamic = {k for g in dynamic for k in nd[(g['protocol'], g['processes'][0])]}
        added -= stock_dynamic
        c['added'] = sorted(c['added'] + [_entry(k, n[k]) for k in added],
                            key=lambda e: (e['port'], e['protocol']))
        c['rebound'] = dynamic
        c['ephemeral'] = list(rng)
        # Host findings loot-listeners attached, then any process holding
        # dynamic ports under a stock name from another executable.
        c['findings'] = list(new[host].get('findings') or []) + [
            {'kind': 'impostor', 'message':
             f"{i['protocol']} {_ports(i['ports'])} held by {i['process']} from "
             f"{', '.join(i['exe'])}; the stock {i['process']} runs "
             f"{', '.join(i['stock_exe'])}"} for i in impostors]
        changes[host] = c

    return {
        'key': key,
        'mode': 'baseline',
        'baselines': sorted(baselines),
        'assigned': assigned,
        'hosts': {'common': sorted(assigned), 'only_old': [], 'only_new': unassigned},
        'changes': changes,
    }


def residual_docs(result, new):
    """
    {host: document}: each host's loot cut to the listeners its baseline does
    not explain (added, widened beyond loopback, or held by another process),
    for synthesis to give terms; what the baseline explains is the role's. A
    stock process on other dynamic ports is the baseline's too. A host with no
    baseline keeps its whole loot, unmarked.
    """
    out = {}
    for host, doc in new.items():
        c = result['changes'].get(host)
        if c is None:
            out[host] = doc
            continue
        keep = {(e['protocol'], e['port'])
                for kind in ('added', 'widened', 'changed') for e in c.get(kind) or []}
        ports = [r for r in doc.get('listen_ports', [])
                 if (r.get('protocol', ''), r.get('port')) in keep]
        out[host] = dict(doc, listen_ports=ports, residual={
            'baseline': result['assigned'][host],
            'listeners': len(ports),
            'of': len(doc.get('listen_ports', [])),
        })
    return out


def write_residual(result, new, outdir):
    os.makedirs(outdir, exist_ok=True)
    docs = residual_docs(result, new)
    for host, doc in sorted(docs.items()):
        with open(os.path.join(outdir, f"{host}.json"), 'w') as f:
            json.dump(doc, f, indent=2)
            f.write('\n')
    unassigned = sorted(h for h in docs if 'residual' not in docs[h])
    print(f"  residual → {outdir} ({len(docs) - len(unassigned)} host(s) over a baseline"
          + (f", {len(unassigned)} whole: {', '.join(unassigned)}" if unassigned else "")
          + ")", file=sys.stderr)


def diff_snapshots(old, new, key='port', new_hosts=False, ephemeral=None):
    """
    Compare two {hostname: doc} snapshots.

    Returns a result dict with the host-set delta and, per host present in both,
    the listeners added, removed, rebound, changed (same key, different
    process), and unattributed.
    """
    keyfn = KEY_MODES[key]
    # Resolved per host rather than once: a fleet is not one operating system,
    # and the range is a property of the kernel that allocated the port.
    override = ephemeral
    old_idx = {h: index_listeners(d, keyfn) for h, d in old.items()}
    new_idx = {h: index_listeners(d, keyfn) for h, d in new.items()}

    common   = sorted(set(old_idx) & set(new_idx))
    only_old = sorted(set(old_idx) - set(new_idx))
    only_new = sorted(set(new_idx) - set(old_idx))

    changes = {}
    for host in common:
        c = _compare(old_idx[host], new_idx[host], ephemeral_for(new.get(host), override))
        if any(c.values()):
            changes[host] = c

    if new_hosts:
        for host in only_new:
            n = new_idx[host]
            entries = [_entry(k, n[k]) for k in sorted(n, key=lambda k: (k[1], k))]
            if entries:
                changes.setdefault(host, {'added': [], 'removed': [], 'rebound': [],
                                          'changed': [], 'unattributed': []})
                changes[host]['added'] = entries

    return {
        'key': key,
        'hosts': {
            'common':   common,
            'only_old': only_old,
            'only_new': only_new,
        },
        'changes': changes,
    }


def delta_surface(result, defs):
    """
    The added listeners as an estate-wide service surface, in the shape
    `firru synth --all` emits for a whole snapshot: (known, unknown) keyed by
    token / (proto, port), each carrying the processes and hosts behind it.

    Same rendering, narrower input — so the delta reads as "the part of the
    inventory that is new", next to the inventory itself.
    """
    known, unknown = {}, {}
    for host, change in result['changes'].items():
        host_token = normalize_token(host)
        for e in change['added']:
            proto, port = e['protocol'], e['port']
            token = None
            if defs is not None:
                try:
                    parents = defs.GetPortParents(port, proto)
                    # The narrowest, as synth names it: tcp/5985 is WinRM, not
                    # the failover-cluster suite that also lists it.
                    from firru.service_naming import best_token
                    token = best_token(defs, parents) if parents else None
                except Exception:
                    token = None
            if token is not None:
                rec = known.setdefault(token, {'ports': set(), 'procs': Counter(),
                                               'hosts': set()})
                rec['ports'].add((proto, port))
            else:
                rec = unknown.setdefault((proto, port), {'procs': Counter(), 'hosts': set()})
            for name in e['processes']:
                if name and name != 'UNKNOWN':
                    rec['procs'][name] += 1
            rec['hosts'].add(host_token)
    return known, unknown


def emit_sh(result, old_path, new_path, defs_dir):
    """
    Emit the commands that fold this observation delta into policy: regenerate
    the affected host's proposal, then diff it against the authoritative file.
    One host per pair of lines, so `| grep <host> | sh` scopes the work.

    A rebound process alone does not earn a regenerate: the service surface is
    unchanged, only the number the kernel handed out.
    """
    for host in sorted(result['changes']):
        if not result['changes'][host]['added'] and not result['changes'][host]['removed']:
            continue
        _emit_regenerate(host, new_path, defs_dir)


def _emit_regenerate(host, new_path, defs_dir):
    # NEW may be one host's file rather than a directory of them.
    src = new_path if os.path.isfile(new_path) else f"{new_path}/{host}.json"
    print(f"firru synth --input {src} --output policies/staged "
          f"--defs {defs_dir} --overwrite")
    print(f"firru diff policies/pol/{host}.yml policies/staged/{host}.yml "
          f"--defs {defs_dir}")


def emit_sh_baseline(result, new_path, defs_dir, defs):
    """
    The sh form of a baseline diff. Against a baseline the delta is what the
    estate runs beyond stock: things to name, not a change to fold in. An
    unnamed port is funny until someone says what it is, so each one is the
    command that would file it in funny.yml -- as a comment, as `firru diff -o
    sh` prints undefined ports: naming is a judgment, not a mechanical edit.
    Named additions follow as comments, then each host's regenerate-and-diff.
    """
    # A process the baseline does not have, on dynamic ports: the finding is
    # the process -- the numbers change every restart, and the range's token
    # (WINDOWS-RPC-DYNAMIC) would file it under stock.
    newproc, static = {}, dict(result, changes={})
    for host, c in result['changes'].items():
        rng = tuple(c.get('ephemeral') or DEFAULT_EPHEMERAL)
        keep = []
        for e in c['added']:
            if is_ephemeral(e['port'], rng):
                for name in e['processes'] or ['?']:
                    rec = newproc.setdefault((e['protocol'], name), {'ports': 0, 'hosts': set()})
                    rec['ports'] += 1
                    rec['hosts'].add(host)
            else:
                keep.append(e)
        static['changes'][host] = dict(c, added=keep)
    for (proto, name), info in sorted(newproc.items(), key=lambda x: (-len(x[1]['hosts']), x[0])):
        print(f"# ! {name} holds {info['ports']} dynamic {proto} port(s) on "
              f"{len(info['hosts'])} host(s): a process the baseline does not have")
    known, unknown = delta_surface(static, defs)
    for (proto, port), info in sorted(unknown.items()):
        procs = ", ".join(f"{n}x{c}" for n, c in info['procs'].most_common(3)) or "?"
        print(f"# firru edit-services add {defs_dir}/funny.yml {proto.upper()}_{port} "
              f"{port}/{proto}  # unnamed: {procs}; {len(info['hosts'])} host(s)")
    for token, info in sorted(known.items()):
        ports = ",".join(f"{p}/{pr}" for pr, p in sorted(info['ports']))
        procs = ", ".join(n for n, _ in info['procs'].most_common(3)) or "?"
        print(f"# + {token} {ports}  ({procs}; {len(info['hosts'])} host(s)) beyond the baseline")
    hosts = [h for h in sorted(result['changes']) if result['changes'][h]['added']]
    if os.path.isfile(new_path):
        for host in hosts:
            _emit_regenerate(host, new_path, defs_dir)
        return
    # A fleet: one synth for all of it, then each host's diff to review.
    if hosts:
        print(f"firru synth --input {new_path} --output policies/staged "
              f"--defs {defs_dir} --overwrite")
    for host in hosts:
        print(f"firru diff policies/pol/{host}.yml policies/staged/{host}.yml "
              f"--defs {defs_dir}")


def _fmt(entry):
    procs = ','.join(entry['processes'])
    line  = f"{entry['protocol']}/{entry['port']}  {procs}"
    if 'world-listen' in entry['flags']:
        line += '  [world-listen]'
    return line


def _ports(ports, show=6):
    """A port list, or its count and span when it is long: a DNS server holds
    thousands of dynamic UDP sockets, and listing them buries the report."""
    if len(ports) <= show:
        return ",".join(str(p) for p in ports)
    return f"{min(ports)}..{max(ports)} ({len(ports)} ports)"


def format_baseline_text(result, baseline_name, new_name, limit=None):
    """Human-readable report for --baseline. Returns a list of lines."""
    h = result['hosts']
    out = [
        f"baseline: {baseline_name}  ({', '.join(result['baselines'])})",
        f"hosts: {new_name}  ({len(h['common'])} compared, "
        f"{len(h['only_new'])} without a baseline)",
        f"identity: {result['key']}; loopback listeners left out on both sides",
    ]
    if h['only_new']:
        shown = h['only_new'] if limit is None else h['only_new'][:limit]
        out.append("")
        out.append(f"no baseline assigned ({len(h['only_new'])}; add --assign GLOB=BASELINE):")
        out.extend(f"  {x}" for x in shown)
        if len(shown) < len(h['only_new']):
            out.append(f"  … {len(h['only_new']) - len(shown)} more")

    def total(kind):
        return sum(len(c[kind]) for c in result['changes'].values())

    for host in sorted(result['changes']):
        c = result['changes'][host]
        out.append("")
        out.append(f"  {host}  (baseline {result['assigned'][host]}, "
                   f"{c['stock']} stock listeners matched)")
        for f in c.get('findings', []):
            out.append(f"    ! {f['message']}")
        for e in c['added']:
            out.append(f"    + {_fmt(e)}")
        for e in c['widened']:
            out.append(f"    ^ {_fmt(e)}  (stock binds loopback only)")
        for e in c['changed']:
            out.append(f"    ~ {e['protocol']}/{e['port']}  "
                       f"stock {','.join(e['was'])}, here {','.join(e['now'])}")
        for e in c['removed']:
            out.append(f"    - {_fmt(e)}")
        for e in c['dynamic_missing']:
            out.append(f"    - {e['protocol']} dynamic  {','.join(e['processes'])}  "
                       f"(stock holds {e['stock_ports']})")
        for e in c['unattributed']:
            out.append(f"    ? {e['protocol']}/{e['port']}  "
                       f"stock {','.join(e['was'])}, here {','.join(e['now'])}")
        if c['rebound']:
            procs = sorted({f"{e['processes'][0]}/{e['protocol']}" for e in c['rebound']})
            out.append(f"    = dynamic ports of {len(procs)} stock processes: "
                       f"{', '.join(procs)}")

    out.append("")
    out.append("+ not in the baseline   ^ scope widened   ~ stock port, other process")
    out.append("- in the baseline, not here (hardened, or the role is not running)")
    out.append("= dynamic ports of a stock process   ? process name missing on one side")
    out.append("! host finding (not fixable by a firewall term)")
    out.append("")
    out.append(f"{total('added')} added, {total('widened')} widened, "
               f"{total('changed')} other process, "
               f"{total('removed') + total('dynamic_missing')} missing, "
               f"across {len(result['changes'])} hosts")
    return out


def format_text(result, old_name, new_name, limit=None):
    """Human-readable report. Returns a list of lines."""
    if result.get('mode') == 'baseline':
        return format_baseline_text(result, old_name, new_name, limit=limit)
    h = result['hosts']
    out = [
        f"old: {old_name}  ({len(h['common']) + len(h['only_old'])} hosts)",
        f"new: {new_name}  ({len(h['common']) + len(h['only_new'])} hosts)",
        f"identity: {result['key']}",
        "",
        f"hosts in both: {len(h['common'])}   "
        f"only in old: {len(h['only_old'])}   only in new: {len(h['only_new'])}",
    ]

    for label, hosts in (('only in old', h['only_old']), ('only in new', h['only_new'])):
        if not hosts:
            continue
        shown = hosts if limit is None else hosts[:limit]
        out.append("")
        out.append(f"hosts {label} ({len(hosts)}):")
        out.extend(f"  {x}" for x in shown)
        if len(shown) < len(hosts):
            out.append(f"  … {len(hosts) - len(shown)} more")

    def total(kind):
        return sum(len(c[kind]) for c in result['changes'].values())

    if result['changes']:
        out.append("")
        out.append("per-host listener changes:")
        for host in sorted(result['changes']):
            c = result['changes'][host]
            out.append(f"  {host}")
            for e in c['added']:
                out.append(f"    + {_fmt(e)}")
            for e in c['removed']:
                out.append(f"    - {_fmt(e)}")
            for e in c['rebound']:
                out.append(f"    = {e['protocol']}/{_ports(e['was'])} → "
                           f"{e['protocol']}/{_ports(e['now'])}  "
                           f"{','.join(e['processes'])}  (rebound)")
            for e in c['changed']:
                out.append(f"    ~ {e['protocol']}/{e['port']}  "
                           f"{','.join(e['was'])} → {','.join(e['now'])}")
            for e in c['unattributed']:
                out.append(f"    ? {e['protocol']}/{e['port']}  "
                           f"{','.join(e['was'])} → {','.join(e['now'])}")

    out.append("")
    out.append(f"{total('added')} added, {total('removed')} removed, "
               f"{total('changed')} changed process, across {len(result['changes'])} hosts")
    if total('rebound'):
        out.append(f"{total('rebound')} process(es) rebound to a different ephemeral "
                   f"port (same service, new port — not new surface)")
    if total('unattributed'):
        out.append(f"{total('unattributed')} ports lost or gained a process name "
                   f"(annotation gap, not a change of service)")
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Compare two loot-listeners snapshots: what opened, what closed, "
                    "and where a port changed hands.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  loot-diff fam/ exec/
  loot-diff fam/ exec/ --key bind
  loot-diff fam/ exec/ --new-hosts --json delta.json
  loot-diff --baseline dc-baseline.json exec/
  loot-diff --baseline win2022-dc hosts/dc01/        # a named stock install, raw loot
  loot-diff --baseline list
  loot-diff --baseline baselines/ exec/ --assign 'dc*=win2022-dc' --assign '*=win2022'
        """
    )
    parser.add_argument('paths', nargs='*', metavar='OLD NEW',
                        help='Earlier and later snapshot (loot-listeners JSON, a directory of '
                             'them, or raw loot); with --baseline REF only NEW')
    parser.add_argument(
        '--key', choices=sorted(KEY_MODES), default='port',
        help="Listener identity: port (protocol+port, default), bind (adds the bind "
             "address), proc (adds the process name)"
    )
    parser.add_argument(
        '--closest', nargs='?', const='*', default=None, metavar='GLOB',
        help="against baselines: for each host, the available run (and layers) "
             "that explain most of its listeners; GLOB limits the runs ('*-g2')")
    parser.add_argument(
        '--baseline', nargs='?', const=True, default=None, metavar='REF',
        help='Compare every host in NEW with a stock install instead of an earlier run. '
             'REF is a baseline name (win2022-dc, win11, almalinux-9.8-minimal; '
             '"list" shows them) found in $FIRRU_BASELINES or ~/firru-os-baselines, '
             'or a path. Without REF, OLD holds the baseline(s)'
    )
    parser.add_argument(
        '--assign', action='append', metavar='GLOB=BASELINE',
        help='With --baseline: hosts matching GLOB use BASELINE (its hostname in the '
             'document). Repeatable, first match wins; one baseline needs none'
    )
    parser.add_argument(
        '--new-hosts', action='store_true',
        help='Count listeners on hosts present only in NEW as additions'
    )
    parser.add_argument(
        '--ephemeral', default=None, metavar='LO-HI',
        help=f"Ephemeral port range used to pair a rebound process, as LO-HI "
             f"(default: per-host from the loot's OS — Linux "
             f"net.ipv4.ip_local_port_range). Use 0-0 to disable pairing."
    )
    parser.add_argument(
        '-o', '--output', choices=['human', 'json', 'sh', 'yaml'], default='human',
        help="Rendering of the same delta: human report (default); json data; sh "
             "commands that fold it into policy; yaml service surface of what was added"
    )
    parser.add_argument(
        '--defs', '-d', default='def', metavar='DIR',
        help='Aerleon definitions directory, for reusing known service tokens in '
             '-o yaml (default: def)'
    )
    parser.add_argument(
        '--json', metavar='PATH', dest='json_out',
        help="Also write the delta as JSON to PATH ('-' for stdout)"
    )
    parser.add_argument(
        '--residual', metavar='DIR',
        help="With --baseline: also write each host's loot cut to what its baseline "
             "does not explain, one <host>.json per host, for `firru synth`")
    parser.add_argument(
        '--max-hosts', type=int, default=0, metavar='N',
        help='In -o yaml, truncate each token\'s host list to N names plus a count '
             '(default: 0, list them all)'
    )
    parser.add_argument(
        '--limit', type=int, default=20, metavar='N',
        help='Truncate the host-set listings to N names (default: 20, 0 for all)'
    )
    parser.add_argument(
        '--quiet', '-q', action='store_true',
        help='Suppress the text report (use with --json)'
    )
    args = parser.parse_args()

    ephemeral = None  # per host, from the loot's recorded OS
    if args.ephemeral:
        try:
            lo, hi = (int(x) for x in args.ephemeral.split('-', 1))
        except ValueError:
            print(f"loot-diff: --ephemeral wants LO-HI, got {args.ephemeral!r}",
                  file=sys.stderr)
            return 1
        ephemeral = (lo, hi)

    if args.baseline == 'list':
        for run, path in available_baselines().items():
            print(f"{run}\t{path}")
        return 0
    if args.closest and not args.paths and os.path.exists(args.closest):
        # `--closest LOOT`: the optional GLOB took the loot path.
        args.paths, args.closest = [args.closest], '*'
    if args.closest:
        if args.baseline or args.assign or len(args.paths) != 1:
            parser.error('--closest takes NEW only (no --baseline, no --assign)')
        new = load_any(args.paths[0])
        found = closest_available(new, args.closest, key=args.key, ephemeral=ephemeral)
        if not found:
            print(f"loot-diff: no baselines match {args.closest!r}", file=sys.stderr)
            return 1
        host_to, old = found
        args.assign = [f"{h}={b}" for h, b in host_to.items()]
        args.baseline, args.old, args.new = 'closest', 'closest', args.paths[0]
        result = diff_baseline(old, new, key=args.key, assign=parse_assign(args.assign),
                               ephemeral=ephemeral)
        if args.residual:
            write_residual(result, new, args.residual)
        return _output(args, result)
    want = 1 if isinstance(args.baseline, str) else 2
    if len(args.paths) != want:
        parser.error('expected ' + ('NEW after --baseline REF' if want == 1 else 'OLD and NEW'))
    try:
        if isinstance(args.baseline, str):
            old = load_baseline(args.baseline)
        else:
            old = load_any(args.paths[0])
        new = load_any(args.paths[-1])
    except (FileNotFoundError, ValueError) as e:
        print(f"loot-diff: {e}", file=sys.stderr)
        return 1
    args.old = args.baseline if isinstance(args.baseline, str) else args.paths[0]
    args.new = args.paths[-1]

    if args.baseline:
        try:
            result = diff_baseline(old, new, key=args.key, assign=parse_assign(args.assign),
                                   ephemeral=ephemeral)
        except ValueError as e:
            print(f"loot-diff: {e}", file=sys.stderr)
            return 1
        if args.residual:
            write_residual(result, new, args.residual)
    elif args.assign or args.residual:
        print("loot-diff: --assign and --residual need --baseline", file=sys.stderr)
        return 1
    else:
        result = diff_snapshots(old, new, key=args.key, new_hosts=args.new_hosts,
                                ephemeral=ephemeral)

    return _output(args, result)


def _output(args, result):
    """Print the result in the chosen form."""
    if args.json_out:
        doc = dict(result, old=os.fspath(args.old), new=os.fspath(args.new))
        if args.json_out == '-':
            json.dump(doc, sys.stdout, indent=2)
            sys.stdout.write('\n')
        else:
            with open(args.json_out, 'w') as f:
                json.dump(doc, f, indent=2)
            print(f"  delta → {args.json_out}", file=sys.stderr)

    if args.quiet:
        return 0

    if args.output == 'json':
        json.dump(dict(result, old=os.fspath(args.old), new=os.fspath(args.new)),
                  sys.stdout, indent=2)
        sys.stdout.write('\n')
    elif args.output == 'sh' and args.baseline:
        from aerleon.lib import naming
        from firru.defs_dir import resolve
        emit_sh_baseline(result, args.new, args.defs, naming.Naming(resolve(args.defs)))
    elif args.output == 'sh':
        emit_sh(result, args.old, args.new, args.defs)
    elif args.output == 'yaml':
        from aerleon.lib import naming
        from firru.cli.listeners_to_aerleon import emit_surface
        try:
            defs = naming.Naming(args.defs)
        except Exception as e:
            print(f"Warning: no definitions from {args.defs} ({e}); "
                  f"every added port will read as new", file=sys.stderr)
            defs = None
        known, unknown = delta_surface(result, defs)
        emit_surface(known, unknown, unknown_only=False, max_hosts=args.max_hosts,
                     title=f"# --- Listeners added between {args.old} and {args.new} "
                           f"({sum(len(c['added']) for c in result['changes'].values())} "
                           f"on {len(result['changes'])} hosts) ---")
    else:
        limit = None if args.limit == 0 else args.limit
        print('\n'.join(format_text(result, args.old, args.new, limit=limit)))

    return 0


if __name__ == '__main__':
    sys.exit(main())
