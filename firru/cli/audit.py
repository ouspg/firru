#!/usr/bin/env python3
"""
firru audit — one host, every cell of the matrix the loot can reach: what
listens, what the running firewall admits, what stock would have, and what the
reviewed policy says.

    firru audit loot/dc01/                                   # exposure
    firru audit loot/dc01/ --baseline win2022-dc             # + added to stock
    firru audit loot/ --policy policies/pol/ --defs def/     # + policy, drift
    firru audit loot/dc01/ --policy pol/dc01.yml -o sh       # the fixes

Sections, by cell (docs/design.md):

- exposure (observed x enforced): each listener against the firewall the host
  is running (firewall.json on Windows, nft.json on Linux): open from any
  address, scoped, blocked, or local. Then the
  allow rules nothing listens behind (stale: a hole any process that binds the
  port inherits, unless the rule names a program) and allow-everything rules
  (broad).
- baseline (observed x stock): listeners added to, or missing from, the stock
  install, as `loot-diff --baseline`.
- policy (observed x intended): `firru diff POL LOOT`, the loot synthesized
  with today's code against the reviewed policy.
- drift (intended x enforced): `firru diff POL RULESET`, read only.

`-o sh` emits only the policy cell's commands: what to apply to or remove from
POL. The running firewall never writes policy (that is documenting the world
instead of intending it), so exposure and drift travel as comments. The normalized
loot is written to --loot-dir so the emitted commands can name it.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

from firru import winfw
from firru.ephemeral import ephemeral_for, is_ephemeral


# ---------------------------------------------------------------------------
# Linux: listeners against the nft input path (firru.nfteval)
# ---------------------------------------------------------------------------

def _nft_exposure(data, listeners):
    from firru import nfteval
    out = []
    for lst in listeners:
        rec = {'protocol': lst.get('protocol'), 'port': lst.get('port'),
               'bind': lst.get('bind_address'),
               'process': (lst.get('process') or {}).get('name') or 'UNKNOWN'}
        if winfw._loopback(lst.get('bind_address') or ''):
            out.append(dict(rec, cls='local', why='loopback only'))
            continue
        cls, why = nfteval.evaluate(data, rec['protocol'], rec['port'],
                                    v6=':' in (rec['bind'] or ''))
        if cls == 'unknown':
            cls, why = 'open', ['no input-hook chain: nothing filters inbound']
        out.append(dict(rec, cls=cls, why='; '.join(why)))
    stale, broad = nfteval.stale_and_broad(data, listeners)
    return {'listeners': out, 'stale': stale, 'broad': broad, 'off': []}


# ---------------------------------------------------------------------------
# Per host
# ---------------------------------------------------------------------------

def _host_dir(doc):
    lf = (doc.get('metadata') or {}).get('listenfile')
    return Path(lf).parent if lf else None


def exposure_for(doc, defs_dir):
    """(exposure dict, ruleset path) or (None, None) when no ruleset was collected."""
    d = _host_dir(doc)
    if d is None:
        return None, None
    fw_path, nft_path = d / 'firewall.json', d / 'nft.json'
    listeners = doc.get('listen_ports') or []
    if fw_path.is_file():
        with open(fw_path, encoding='utf-8-sig') as f:
            fw = json.load(f)
        ipsec = (fw.get('ipsec') or {})
        n = (ipsec.get('connection_security_rules') or 0) + (ipsec.get('main_mode_rules') or 0)
        urls = None
        if (d / 'http-urls.csv').is_file():
            import csv
            with open(d / 'http-urls.csv', encoding='utf-8-sig', newline='') as f:
                urls = list(csv.DictReader(f))
        e = winfw.exposure(fw, listeners, n, urls)
        return e, fw_path
    if nft_path.is_file():
        with open(nft_path) as f:
            data = json.load(f)
        return _nft_exposure(data, listeners), nft_path
    return None, None


def _collapse(rows, rng):
    """Merge IPv4/IPv6 twins; fold a process's dynamic-range sockets into one row."""
    seen, fixed, dyn = set(), [], defaultdict(list)
    for r in rows:
        key = (r['cls'], r['protocol'], r['port'], r['process'])
        if key in seen:
            continue
        seen.add(key)
        if rng and is_ephemeral(r['port'], rng):
            dyn[(r['cls'], r['protocol'], r['process'])].append(r)
        else:
            fixed.append(r)
    return fixed, dyn


ORDER = ('open', 'scoped',
         'blocked', 'local')


def format_exposure(host, doc, e, ruleset, limit=12):
    os_name = (doc.get('metadata') or {}).get('os') or '?'
    head = f"== {host}  ({os_name}"
    if e.get('profiles'):
        head += f", profile {'/'.join(e['profiles'])}"
    if e['off']:
        head += f", FIREWALL OFF on {'/'.join(e['off'])}"
    lines = [head + ")", f"exposure: listeners against the running firewall ({ruleset})"]
    fixed, dyn = _collapse(e['listeners'], ephemeral_for(doc))
    if e['off']:
        # Everything is open for one reason; the list is the surface, not the finding.
        opened = [r for r in fixed if r['cls'] == 'open']
        names = [f"{r['protocol']}/{r['port']} {r['process']}" for r in opened]
        dn = sum(len(v) for k, v in dyn.items() if k[0] == 'open')
        lines.append(f"  open     all {len(opened)} listener(s), firewall off: " + ', '.join(names)
                     + (f"; plus {dn} dynamic-range socket(s)" if dn else ''))
        fixed = [r for r in fixed if r['cls'] != 'open']
        dyn = {k: v for k, v in dyn.items() if k[0] != 'open'}
    for cls in ORDER:
        rows = [r for r in fixed if r['cls'] == cls]
        drows = {k: v for k, v in dyn.items() if k[0] == cls}
        if not rows and not drows:
            continue
        if cls in ('blocked', 'local'):
            names = [f"{r['protocol']}/{r['port']} {r['process']}" for r in rows]
            more = f" ... +{len(names) - limit}" if len(names) > limit else ''
            dn = sum(len(v) for v in drows.values())
            lines.append(f"  {cls:8} {len(rows)}: " + ', '.join(names[:limit]) + more
                         + (f"; plus {dn} dynamic-range socket(s)" if dn else ''))
            continue
        for r in rows:
            lines.append(f"  {cls:8} {r['protocol']}/{r['port']:<6} {r['process']:<18} {r['why']}")
        for (_, proto, proc), v in sorted(drows.items()):
            ports = sorted({x['port'] for x in v})
            shown = ','.join(map(str, ports[:5])) + (',...' if len(ports) > 5 else '')
            lines.append(f"  {cls:8} {proto}/dyn    {proc:<18} {len(ports)} dynamic port(s) {shown}: {v[0]['why']}")
    squat = [s for s in e['stale'] if s['squattable'] is True]
    httpsys = [s for s in e['stale'] if s['squattable'] == 'httpsys']
    if e['stale']:
        rest = len(e['stale']) - len(squat) - len(httpsys)
        lines.append(f"  stale    {len(e['stale'])} allow rule(s) with nothing listening"
                     + (f": {len(squat)} open to any program that binds the port" if squat else '')
                     + (f"{',' if squat else ':'} {len(httpsys)} open to an admin through HTTP.sys (System)"
                        if httpsys else '')
                     + (f"{',' if squat or httpsys else ':'} {rest} for one program or service" if rest else ''))
        for s in (squat + httpsys)[:limit]:
            how = 'any program' if s['squattable'] is True else 'HTTP.sys'
            lines.append(f"           {s['protocol']}/{','.join(s['ports'])} {s['rule']} from {s['peers']} ({how})")
    for b in e['broad']:
        lines.append(f"  broad    {b['rule']} {b['display']}: every {b['protocol']} port from {b['peers']}")
    for f in doc.get('findings') or []:
        lines.append(f"  ! {f['message']}")
    return lines


def _load_fw(doc):
    d = _host_dir(doc)
    p = d / 'firewall.json' if d else None
    if not p or not p.is_file():
        return None
    with open(p, encoding='utf-8-sig') as f:
        return json.load(f)


def format_rule_diff(base_name, rd, match, limit=10):
    """The Windows rule set against stock: weakening first."""
    lines = [f"firewall rules vs stock ({base_name}):"]
    for name, d in rd['profiles']:
        tag = ''
        if tuple(str(x) for x in d.get('Enabled', ())) == ('True', 'False'):
            tag = '  <- firewall turned OFF'
        lines.append(f"  profile {name}: " + ', '.join(f"{k} {o} -> {n}" for k, (o, n) in d.items()) + tag)

    def block(title, rules, show_state=False):
        if not rules:
            return
        lines.append(f"  {title} ({len(rules)}):")
        for r in rules[:limit]:
            layer = ','.join(match(r))
            state = ('on  ' if r.get('Enabled') else 'off ') if show_state else ''
            lines.append(f"    {state}{'[' + layer + '] ' if layer else ''}{winfw.show_rule(r)}")
        if len(rules) > limit:
            lines.append(f"    ... +{len(rules) - limit}")
    block('added', rd['added'], show_state=True)
    block('stock rules enabled', rd['enabled'])
    if rd['changed']:
        lines.append(f"  stock rules changed ({len(rd['changed'])}):")
        for r, ks in rd['changed'][:limit]:
            lines.append(f"    {r.get('DisplayName')!r}: " + '; '.join(f"{k} {o} -> {n}" for k, o, n in ks))
    block('stock rules disabled', rd['disabled'])
    block('stock rules removed', rd['removed'])
    if len(lines) == 1:
        lines.append("  same as stock")
    return lines


def _policy_for(policy, host):
    if not policy:
        return None
    p = Path(policy)
    if p.is_dir():
        cand = p / f"{host}.yml"
        return cand if cand.is_file() else None
    return p


def main():
    ap = argparse.ArgumentParser(
        description="One host's loot against its running firewall, a stock baseline and "
                    "its reviewed policy.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split('\n\n', 1)[1])
    ap.add_argument('loot', help='Raw loot (a host directory, a tree of hosts) or loot-listeners JSON '
                                 'next to its ruleset')
    ap.add_argument('--baseline', metavar='REF', help='Stock install to compare with '
                                                      '(name or path, as loot-diff --baseline); '
                                                      'default: the closest available run per '
                                                      'host, as loot-diff --closest')
    ap.add_argument('--no-baseline', action='store_true',
                    help='Skip the baseline comparison. Without it nothing says whether a '
                         'listener in the dynamic range belongs there.')
    ap.add_argument('--layers', metavar='YML', help='Layer signatures (firru-os-baselines '
                                                     'analysis/layers.yml): tag added firewall '
                                                     'rules with the layer that adds them')
    ap.add_argument('--policy', metavar='POL', help='Reviewed policy: a YAML file, or a directory '
                                                    'of <host>.yml')
    ap.add_argument('--defs', '-d', default='def')
    ap.add_argument('--loot-dir', default='loot', help='Where the normalized loot is written for '
                                                       'the policy diff (default: loot/)')
    ap.add_argument('-o', '--output', choices=['human', 'json', 'sh'], default='human')
    a = ap.parse_args()

    from firru.cli.loot_diff import (closest_available, load_any, load_baseline,
                                     diff_baseline, format_baseline_text)
    try:
        hosts = load_any(a.loot)
        baselines = load_baseline(a.baseline) if a.baseline else None
    except (FileNotFoundError, ValueError) as e:
        print(f"firru audit: {e}", file=sys.stderr)
        return 1
    # Which baseline each host is compared with: the one named, or the closest
    # run there is. The comparison is what tells a stock process's dynamic
    # ports from a listener nothing explains, so it is on unless declined.
    assign, label = (), a.baseline
    if not a.baseline and not a.no_baseline:
        found = closest_available(hosts)
        if found:
            host_to, baselines = found
            assign, label = tuple(host_to.items()), 'closest'

    match = winfw.layer_matcher(None)
    if a.layers:
        from ruyaml import YAML
        with open(a.layers) as f:
            match = winfw.layer_matcher((YAML(typ='safe').load(f) or {}).get('layers'))
    from firru.cli.loot_diff import pick_baseline

    def rules_vs_stock(host, doc):
        if not baselines:
            return None, None
        name = pick_baseline(host, baselines, assign)
        hfw, bfw = _load_fw(doc), _load_fw(baselines[name]) if name else None
        if not (hfw and bfw):
            return name, None
        return name, winfw.rule_diff(bfw, hfw)

    report, rc = {}, 0
    for host, doc in sorted(hosts.items()):
        e, ruleset = exposure_for(doc, a.defs)
        entry = {'exposure': e, 'ruleset': str(ruleset) if ruleset else None,
                 'findings': doc.get('findings') or []}
        pol = _policy_for(a.policy, host)
        loot_json = None
        if pol or a.output == 'sh':
            os.makedirs(a.loot_dir, exist_ok=True)
            loot_json = Path(a.loot_dir) / f"{host}.json"
            with open(loot_json, 'w') as f:
                json.dump(doc, f, indent=2)
        report[host] = entry

        bname, rd = rules_vs_stock(host, doc)
        if a.output == 'json':
            if baselines:
                entry['baseline'] = diff_baseline(baselines, {host: doc}, assign=assign)
                if rd:
                    entry['rules_vs_stock'] = rd
            continue
        if a.output == 'human':
            if e:
                print('\n'.join(format_exposure(host, doc, e, ruleset)))
            else:
                print(f"== {host}\nexposure: no ruleset in the loot (firewall.json / nft.json)")
            if baselines:
                print(f"baseline: against {bname or label}")
                res = diff_baseline(baselines, {host: doc}, assign=assign)
                body = format_baseline_text(res, label, a.loot)
                print('\n'.join('  ' + l for l in body[3:] if l.strip() and not l.startswith(('+ not', '- in', '= dyn', '? pro', '! host'))))
                if rd:
                    print('\n'.join(format_rule_diff(bname, rd, match)))
            if pol:
                from firru.cli.dispatch import dispatch_argv
                print(f"policy: firru diff {pol} {loot_json}")
                rc |= dispatch_argv(['diff', str(pol), str(loot_json), '--defs', a.defs])
                if ruleset:
                    print(f"drift: firru diff {pol} {ruleset}")
                    rc |= dispatch_argv(['diff', str(pol), str(ruleset), '--defs', a.defs])
            elif a.policy:
                print(f"policy: no {host}.yml under {a.policy}")
            if not baselines and not a.no_baseline:
                print("baseline: none found ($FIRRU_BASELINES, ~/firru-os-baselines, "
                      "~/baselines, the records firru ships): listeners in the dynamic "
                      "range are not checked")
            print()
        else:  # sh
            print(f"# == {host}")
            if e:
                for line in format_exposure(host, doc, e, ruleset)[1:]:
                    print('# ' + line)
                if e['off']:
                    print(f"# firewall off on {'/'.join(e['off'])}: no policy edit fixes that; "
                          f"deploy the compiled policy and turn the profile on")
            if pol:
                from firru.cli.dispatch import dispatch_argv
                dispatch_argv(['diff', str(pol), str(loot_json), '--defs', a.defs, '-o', 'sh'])
                if ruleset:
                    print(f"# drift (read only): firru diff {pol} {ruleset} --defs {a.defs}")
            else:
                print(f"# no reviewed policy for {host}: start one with")
                print(f"# firru synth --input {a.loot_dir}/{host}.json --output policies/staged "
                      f"--defs {a.defs}")
    if a.output == 'json':
        json.dump(report, sys.stdout, indent=2, default=str)
        print()
    return 0


if __name__ == '__main__':
    sys.exit(main())
