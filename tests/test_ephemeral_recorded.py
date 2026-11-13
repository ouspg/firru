"""The host's own ephemeral range, recorded by loot-host, wins over the OS default."""
from firru.cli.loot_listeners import _ephemeral_ranges
from firru.ephemeral import ephemeral_for

NETSH = """
Protocol tcp Dynamic Port Range
---------------------------------
Start Port      : 6005
Number of Ports : 59530


Protocol udp Dynamic Port Range
---------------------------------
Start Port      : 49152
Number of Ports : 16384
"""


def test_windows_netsh(tmp_path):
    (tmp_path / 'dynamicport.txt').write_text(NETSH)
    assert _ephemeral_ranges(str(tmp_path)) == {'tcp': [6005, 65534], 'udp': [49152, 65535]}


def test_linux_port_range(tmp_path):
    (tmp_path / 'ip_local_port_range').write_text('32768\t60999\n')
    assert _ephemeral_ranges(str(tmp_path)) == {'tcp': [32768, 60999], 'udp': [32768, 60999]}


def test_absent(tmp_path):
    assert _ephemeral_ranges(str(tmp_path)) is None


def test_recorded_wins_over_os_default():
    doc = {'metadata': {'os': 'windows', 'ephemeral': {'tcp': [6005, 65534]}}}
    assert ephemeral_for(doc) == (6005, 65534)
    assert ephemeral_for(doc, (1, 2)) == (1, 2)


def test_release(tmp_path):
    from firru.cli.loot_listeners import _release
    (tmp_path / 'os-release').write_text('NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n')
    assert _release(str(tmp_path)) == ('ubuntu-24.04', 'os-release')
    (tmp_path / 'os-release').write_text('NAME=Microsoft Windows Server 2022 Standard\nBUILD=20348\n')
    assert _release(str(tmp_path)) == ('win2022', 'os-release')
    (tmp_path / 'os-release').write_text('NAME=Microsoft Windows 11 Pro\n')
    assert _release(str(tmp_path)) == ('win11', 'os-release')


def test_a_release_added_afterwards_is_used_and_says_so(tmp_path):
    from firru.cli.loot_listeners import _release
    assert _release(str(tmp_path)) == (None, None)
    (tmp_path / 'release.added').write_text('# from the install media, not collected\nwin2022\n')
    assert _release(str(tmp_path)) == ('win2022', 'release.added')
    (tmp_path / 'os-release').write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    assert _release(str(tmp_path)) == ('ubuntu-24.04', 'os-release')  # collected wins


def test_collected_at_is_the_recorded_time_and_an_mtime_says_it_is_one(tmp_path):
    from firru.cli.loot_listeners import _collected_at
    ss = tmp_path / 'ss'
    ss.write_text('')
    at, source = _collected_at(str(tmp_path), str(ss))
    assert source == 'mtime' and at
    (tmp_path / 'collected-at').write_text('2026-10-30T07:00:00Z\n')
    assert _collected_at(str(tmp_path), str(ss)) == ('2026-10-30T07:00:00Z', 'collected-at')
