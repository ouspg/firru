"""firru baseline-synth: the shipped stock-install records, and --baseline reading them."""
import hashlib
import json

from firru.cli import baseline_synth, dispatch
from firru.cli.loot_diff import load_baseline, resolve_baseline_name

WIN_CONN = ('"LocalAddress","LocalPort","RemoteAddress","RemotePort","State","OwningProcess","Protocol"\n'
            '"0.0.0.0","{port}","0.0.0.0","0","Listen","4","TCP"\n')


def _run(root, name, port, finished=True):
    lh = root / name / 'loot-host'
    lh.mkdir(parents=True)
    (lh / 'connections.csv').write_text(WIN_CONN.format(port=port))
    (lh / 'hostname').write_text('WIN-RANDOM123\r\n')
    (root / name / 'recipe').mkdir()
    (root / name / 'recipe' / 'PROVENANCE').write_text(
        'run_started=2026-10-20T00:00:00Z\n' + ('run_finished=2026-10-20T01:00:00Z\n' if finished else ''))
    return root / name


def _checkout(tmp_path):
    co = tmp_path / 'firru-os-baselines'
    _run(co, 'win2022-std-desktop-dc-g1', 1)          # Windows set 1: replaced by set 2
    _run(co, 'win2022-std-desktop-dc-g2', 88)
    _run(co, 'win2022-std-desktop-dc-r1', 2)          # earlier, narrower run
    _run(co, 'win2025-std-desktop-dhcp-g2', 3)
    _run(co, 'win2025-std-desktop-dhcp-g2b', 67)      # the rerun wins
    _run(co, 'win2022-std-desktop-public-g3', 4, finished=False)   # never finished
    _run(co, 'ubuntu-24.04.5-server+squid-d3', 3128)
    _run(co, 'ubuntu-24.04.5-server-egress-g1', 5)    # egress run: not a listening baseline
    _run(co, 'ubuntu-24.04.5-server-t9', 6)           # a test
    return co


def test_synth_picks_the_newest_pinned_run_per_install(tmp_path):
    out = tmp_path / 'baseline'
    assert baseline_synth.main([str(_checkout(tmp_path)), '--out', str(out)]) == 0
    runs = json.loads((out / 'index.json').read_text())['runs']
    assert runs == ['ubuntu-24.04.5-server+squid-d3', 'win2022-std-desktop-dc-g2',
                    'win2025-std-desktop-dhcp-g2b']


def test_a_record_carries_documents_provenance_and_where_it_came_from(tmp_path):
    out = tmp_path / 'baseline'
    baseline_synth.main([str(_checkout(tmp_path)), '--out', str(out)])
    import gzip
    rec = json.loads(gzip.open(out / 'win2022-std-desktop-dc-g2.json.gz').read())
    assert rec['schema'] == 1 and rec['run'] == 'win2022-std-desktop-dc-g2'
    assert rec['evidence'].startswith('firru-os-baselines@') and rec['evidence'].endswith(':win2022-std-desktop-dc-g2/')
    assert 'run_finished=2026-10-20T01:00:00Z' in rec['provenance']
    assert '88' in json.dumps(rec['documents'])


def test_records_are_byte_for_byte_reproducible(tmp_path):
    co = _checkout(tmp_path)
    digests = []
    for n in (1, 2):
        out = tmp_path / f'out{n}'
        baseline_synth.main([str(co), '--out', str(out)])
        digests.append(hashlib.sha256((out / 'win2022-std-desktop-dc-g2.json.gz').read_bytes()).hexdigest())
    assert digests[0] == digests[1]


def test_baseline_by_name_from_records_and_by_path(tmp_path, monkeypatch, capsys):
    out = tmp_path / 'baseline'
    baseline_synth.main([str(_checkout(tmp_path)), '--out', str(out)])
    monkeypatch.setenv('FIRRU_BASELINES', str(out))
    docs = load_baseline('windows-2022-dc')
    assert '88' in json.dumps(docs)
    assert load_baseline(str(out / 'ubuntu-24.04.5-server+squid-d3.json.gz'))
    host = _run(tmp_path / 'loot', 'dc01', 88)
    (host / 'loot-host' / 'connections.csv').write_text(
        WIN_CONN.format(port=88) + '"0.0.0.0","8080","0.0.0.0","0","Listen","4","TCP"\n')
    delta = tmp_path / 'delta.json'
    assert dispatch.dispatch_argv(['diff', '--baseline', 'windows-2022-dc', str(host),
                                   '--json', str(delta), '-q']) == 0
    assert '8080' in delta.read_text()
    assert 'win2022-std-desktop-dc-g2.json.gz' in capsys.readouterr().err


def test_resolver_knows_delta_runs_reruns_and_kept_runs(tmp_path):
    runs = {n: tmp_path / n for n in ('win2025-std-desktop-dhcp-g2', 'win2025-std-desktop-dhcp-g2b',
                                      'win2022-std-desktop-dc-g2', 'win2022-std-desktop-dc-g3k',
                                      'ubuntu-24.04.5-server+squid-d3', 'ubuntu-24.04.5-server+squid-d4')}
    assert resolve_baseline_name('win2025-dhcp', runs) == 'win2025-std-desktop-dhcp-g2b'
    assert resolve_baseline_name('win2022-dc', runs) == 'win2022-std-desktop-dc-g3k'
    assert resolve_baseline_name('ubuntu-squid', runs) == 'ubuntu-24.04.5-server+squid-d4'


def test_closest_reads_shipped_records(tmp_path, monkeypatch):
    out = tmp_path / 'baseline'
    baseline_synth.main([str(_checkout(tmp_path)), '--out', str(out)])
    monkeypatch.setenv('FIRRU_BASELINES', str(out))
    host = _run(tmp_path / 'loot', 'dc01', 88)
    delta = tmp_path / 'delta.json'
    assert dispatch.dispatch_argv(['diff', '--closest', str(host), '--json', str(delta), '-q']) == 0
    assert 'win2022-std-desktop-dc-g2' in delta.read_text()


def test_closest_layer_bound_to_loopback_reports_widened(tmp_path, monkeypatch):
    co = _checkout(tmp_path)
    pg = _run(co, 'ubuntu-24.04.5-server+postgresql-server-g1', 0)
    (pg / 'loot-host' / 'connections.csv').write_text(
        WIN_CONN.format(port=88).replace('"0.0.0.0","88"', '"127.0.0.1","5432"').replace('"4"', '"9"'))
    out = tmp_path / 'baseline'
    baseline_synth.main([str(co), '--out', str(out)])
    monkeypatch.setenv('FIRRU_BASELINES', str(out))
    host = _run(tmp_path / 'loot', 'db01', 88)
    (host / 'loot-host' / 'connections.csv').write_text(
        WIN_CONN.format(port=88) + '"0.0.0.0","5432","0.0.0.0","0","Listen","9","TCP"\n')
    delta = tmp_path / 'delta.json'
    assert dispatch.dispatch_argv(['diff', '--closest', str(host), '--json', str(delta), '-q']) == 0
    r = json.loads(delta.read_text())
    c = next(iter(r['changes'].values()))
    assert '+postgresql-server-g1' in next(iter(r['assigned'].values()))
    assert [w['port'] for w in c['widened']] == [5432] and not c['added']
