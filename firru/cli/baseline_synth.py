"""
firru baseline-synth CHECKOUT [--out DIR] -- the stock-install records firru
ships (baseline/, beside def/), made from a firru-os-baselines checkout.

One record per install: the newest run of a pinned set (Windows -g2 and
later, which replace set 1; Linux -gN; delta runs -dN, one package on a saved
stock guest), as the loot-listeners documents `loot-diff --baseline` compares
against, the Windows firewall as collected, and where it all came from: the
checkout's commit and the run's PROVENANCE. A record is evidence-pointing,
not evidence: `evidence` names the run in the checkout, which holds the raw
loot, the scan and the recipe.

Left out: earlier and narrower runs (-rN), tests (-tN), egress runs and proof
runs (they measure egress, which these records do not describe), delta bases.
Runs without a finished PROVENANCE are skipped.

    firru baseline-synth ~/firru-os-baselines             # into baseline/
"""
import argparse
import gzip
import json
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = 1
# -g2, -g2b (a rerun), -g3k (kept for others to join), -d3: set letter, number, rerun letter.
SET = re.compile(r'-([gd])(\d+)([a-z]?)$')
SKIP = re.compile(r'(-egress-|\+trigger-|-e?base\d+$|-t\d+$|-r\d+$)')


def provenance(run):
    p = run / 'recipe' / 'PROVENANCE'
    try:
        lines = p.read_text().splitlines()
    except OSError:
        return None
    if not any(line.startswith('run_finished=') for line in lines):
        return None
    return lines


def pick(checkout):
    """{install: run dir}: per install, the newest pinned run."""
    best = {}
    top = Path(checkout) / 'runs'          # the runs, since 2026-10-23; the checkout itself before
    top = top if top.is_dir() else Path(checkout)
    for run in sorted(p for p in top.iterdir() if (p / 'loot-host').is_dir()):
        m = SET.search(run.name)
        if not m or SKIP.search(run.name):
            continue
        kind, num, rerun = m.group(1), int(m.group(2)), m.group(3)
        if run.name.startswith('win') and kind == 'g' and num < 2:
            continue                    # Windows set 2 replaces set 1
        if provenance(run) is None:
            continue
        install = run.name[:m.start()]
        key = (num, rerun != 'k', rerun)    # a later set, then a rerun, over a kept run
        if install not in best or key > best[install][0]:
            best[install] = (key, run)
    return {k: v[1] for k, v in sorted(best.items())}


def documents(run):
    """The run's loot-listeners documents as a record ships them: loopback
    binds kept (a host's 5432 on any, stock on 127.0.0.1, is widened, not
    added), file paths relative to the run (not the machine that made the
    record), and no findings (checks on the stock install itself; a comparison does not use
    them, and they are recomputed for the host being compared)."""
    from firru.cli.loot_diff import normalize_raw
    docs = normalize_raw(run, loopback=True)
    prefix = str(run.resolve()) + '/'
    for doc in docs.values():
        doc.pop('findings', None)
        meta = doc.get('metadata') or {}
        for k, v in list(meta.items()):
            if isinstance(v, str) and v.startswith(prefix):
                meta[k] = v[len(prefix):]
    return docs


def record(run, commit):
    fw = run / 'loot-host' / 'firewall.json'
    return {
        'schema': SCHEMA,
        'run': run.name,
        'evidence': f'firru-os-baselines@{commit}:{run.parent.name + "/" if run.parent.name == "runs" else ""}{run.name}/',
        'provenance': provenance(run),
        'documents': documents(run),
        'firewall': json.loads(fw.read_text(encoding='utf-8-sig')) if fw.exists() else None,
    }


def write(path, obj):
    """gzip with no timestamp or name in the header: the same record, the same bytes."""
    data = json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()
    with open(path, 'wb') as f:
        with gzip.GzipFile(filename='', mode='wb', fileobj=f, mtime=0) as g:
            g.write(data)


def main(argv=None):
    ap = argparse.ArgumentParser(prog='firru baseline-synth',
                                 description=__doc__.split('\n\n')[0].strip(),
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('checkout', help='firru-os-baselines checkout')
    from firru.defs_dir import STOCK_BASELINE
    ap.add_argument('--out', default=str(STOCK_BASELINE),
                    help=f'directory for the records (default: {STOCK_BASELINE})')
    a = ap.parse_args(argv)
    checkout = Path(a.checkout).expanduser()
    commit = subprocess.run(['git', '-C', str(checkout), 'rev-parse', '--short=12', 'HEAD'],
                            capture_output=True, text=True).stdout.strip() or 'unknown'
    dirty = subprocess.run(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'],
                           capture_output=True, text=True).stdout.strip()
    if dirty:
        print(f"warning: {checkout} has uncommitted changes; records name {commit} anyway",
              file=sys.stderr)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    runs = pick(checkout)
    for old in out.glob('*.json.gz'):
        if old.name[:-len('.json.gz')] not in {r.name for r in runs.values()}:
            old.unlink()
    for run in runs.values():
        write(out / f'{run.name}.json.gz', record(run, commit))
    index = {'schema': SCHEMA, 'source': f'firru-os-baselines@{commit}',
             'runs': sorted(r.name for r in runs.values())}
    (out / 'index.json').write_text(json.dumps(index, indent=1) + '\n')
    size = sum(p.stat().st_size for p in out.glob('*.json.gz'))
    print(f"{len(runs)} records from firru-os-baselines@{commit} -> {out} ({size // 1024} KiB)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
