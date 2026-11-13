"""--baseline REF: named stock installs, raw loot on either side, and the firru diff route."""
import json
from pathlib import Path

import pytest

from firru.cli import dispatch, loot_diff
from firru.cli.loot_diff import resolve_baseline_name
from firru.discovery import get_discovery_list

RUNS = {n: Path('/b') / n for n in (
    'smoke-win2022', 'win2022-std-desktop-public-r1', 'win2022-std-desktop-public-r2',
    'win2022-std-desktop-private-r1', 'win2022-std-desktop-dc-r1', 'win2022-std-desktop-dc-egress-r1',
    'win2022-std-desktop-asa-r1', 'win11-pro-26300-public-r1', 'win11-pro-26300-fwtest-r1',
    'almalinux-9.8-minimal', 'almalinux-9.8-server', 'almalinux-9.8-dns-server')}


@pytest.mark.parametrize('name, run', [
    ('windows-2022-dc', 'win2022-std-desktop-dc-r1'),
    ('windows-server-2022-dc', 'win2022-std-desktop-dc-r1'),
    ('win2022', 'win2022-std-desktop-public-r1'),       # not smoke-, not a collection variant
    ('win2022-r2', 'win2022-std-desktop-public-r2'),
    ('win2022-private', 'win2022-std-desktop-private-r1'),
    ('win11', 'win11-pro-26300-public-r1'),
    ('almalinux-9.8', 'almalinux-9.8-minimal'),
    ('almalinux-9.8-server', 'almalinux-9.8-server'),
    ('win2022-std-desktop-asa-r1', 'win2022-std-desktop-asa-r1'),   # exact names pass through
])
def test_loose_names_pick_the_plain_install(name, run):
    assert resolve_baseline_name(name, RUNS) == run


def test_golden_set_is_preferred_over_earlier_runs():
    runs = dict(RUNS, **{n: Path('/b') / n for n in ('win2022-std-desktop-public-g1',
                                                     'win2022-std-desktop-dc-g1',
                                                     'win2022-std-desktop-web-g1')})
    assert resolve_baseline_name('win2022', runs) == 'win2022-std-desktop-public-g1'
    assert resolve_baseline_name('win2022-dc', runs) == 'win2022-std-desktop-dc-g1'
    assert resolve_baseline_name('win2022-web', runs) == 'win2022-std-desktop-web-g1'
    assert resolve_baseline_name('win2022-r2', runs) == 'win2022-std-desktop-public-r2'


def test_unknown_and_ambiguous_names_say_what_exists():
    with pytest.raises(ValueError, match='available'):
        resolve_baseline_name('win2025', RUNS)
    with pytest.raises(ValueError, match='ambiguous'):
        resolve_baseline_name('almalinux', {n: Path('/b') / n for n in
                                           ('almalinux-9.8-mariadb', 'almalinux-9.8-mysql')})


WIN_CONN = ('"LocalAddress","LocalPort","RemoteAddress","RemotePort","State","OwningProcess","Protocol"\n'
            '"0.0.0.0","{port}","0.0.0.0","0","Listen","4","TCP"\n')


def _run(root, name, port):
    lh = root / name / 'loot-host'
    lh.mkdir(parents=True)
    (lh / 'connections.csv').write_text(WIN_CONN.format(port=port))
    (lh / 'hostname').write_text('WIN-RANDOM123\r\n')
    return root / name


def test_a_run_directory_is_one_host_named_after_the_run(tmp_path):
    run = _run(tmp_path, 'win2022-std-desktop-dc-r1', 88)
    assert [e['hostname'] for e in get_discovery_list(str(run))] == ['win2022-std-desktop-dc-r1']
    assert [e['hostname'] for e in get_discovery_list(str(run / 'loot-host'))] == \
        ['win2022-std-desktop-dc-r1']
    assert [e['hostname'] for e in get_discovery_list(str(tmp_path))] == \
        ['win2022-std-desktop-dc-r1']


def test_firru_diff_baseline_name_against_raw_loot(tmp_path, monkeypatch, capsys):
    base = tmp_path / 'baselines'
    _run(base, 'win2022-std-desktop-dc-r1', 88)
    host = _run(tmp_path / 'loot', 'dc01', 88)
    (host / 'loot-host' / 'connections.csv').write_text(
        WIN_CONN.format(port=88) + '"0.0.0.0","8080","0.0.0.0","0","Listen","4","TCP"\n')
    monkeypatch.setenv('FIRRU_BASELINES', str(base))
    out_json = tmp_path / 'delta.json'
    rc = dispatch.dispatch_argv(['diff', '--baseline', 'windows-2022-dc', str(host),
                                 '--json', str(out_json), '-q'])
    assert rc == 0
    delta = json.loads(out_json.read_text())
    assert 'dc01' in json.dumps(delta) and '8080' in json.dumps(delta)
    assert "-> win2022-std-desktop-dc-r1" in capsys.readouterr().err


def test_old_forms_still_work(tmp_path, monkeypatch):
    base = _run(tmp_path / 'b', 'stock', 88)
    host = _run(tmp_path / 'l', 'dc01', 88)
    for argv in (['loot-diff', '--baseline', str(base), str(host), '-q'],
                 ['loot-diff', str(base), str(host), '--baseline', '-q'],
                 ['loot-diff', str(base), str(host), '-q']):
        monkeypatch.setattr('sys.argv', argv)
        assert (loot_diff.main() or 0) == 0
