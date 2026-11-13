"""
One entry point per host directory, and content deciding what each file is.

The test that motivated the module is `test_a_bsd_host_is_reachable_at_all`.
Before this, `firru.discovery` could only label a host `linux` or `windows`, and
`process_host` dispatched on that label, so the BSD `netstat` reader -- with its
own 26 tests, all passing -- could not be reached by any real collection. Its
tests built the entry dict by hand. That is the shape of a test suite agreeing
with itself while the program cannot do the thing.

The rest pin the two properties that make adding a source cheap: a file is
identified by what is in it rather than by what it is called, and a file nothing
claims is reported rather than skipped.
"""

import json
import pathlib
import shutil

import pytest

from firru.readers import (REGISTRY, HostInventory, identify, read_host,
                           sniff_bsd_netstat, sniff_linux_netstat, sniff_ss)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SS = FIXTURES / "ss" / "debian-12-tulnpe.out"
LINUX_NETSTAT = FIXTURES / "netstat_linux_tulnp.txt"
BSD_NETSTAT = FIXTURES / "netstat_freebsd12_an.txt"
MACOS_NETSTAT = FIXTURES / "netstat_macos26_an.txt"


def _host(tmp_path, **files):
    """Build a host directory: keyword is the filename, value a source path."""
    d = tmp_path / "somehost"
    d.mkdir(parents=True)
    for name, src in files.items():
        name = name.replace("__", ".")
        shutil.copy(src, d / name)
    return d


class TestTheBsdBranchIsReachable:
    def test_a_bsd_host_is_reachable_at_all(self, tmp_path):
        """The bug this module exists for. A directory holding a BSD netstat
        dump now inventories; before, nothing in the program could produce the
        `os` label that reached the reader."""
        inv = read_host(_host(tmp_path, netstat=BSD_NETSTAT))
        assert inv.os == "bsd"
        assert inv.sources == ["bsd-netstat"]
        assert {(l["proto"], l["local_port"]) for l in inv.listeners} == {
            ("tcp", 25), ("tcp", 22), ("udp", 514)}

    def test_it_carries_the_attribution_gap_rather_than_inventing_one(self, tmp_path):
        inv = read_host(_host(tmp_path, netstat=BSD_NETSTAT))
        assert {l["process_info"]["name"] for l in inv.listeners} == {"UNKNOWN"}
        assert all(l["pid"] is None for l in inv.listeners)

    def test_a_macos_dump_reaches_the_same_reader(self, tmp_path):
        inv = read_host(_host(tmp_path, netstat=MACOS_NETSTAT))
        assert inv.os == "bsd"
        assert {l["local_port"] for l in inv.listeners if l["proto"] == "tcp"} == {22}


class TestContentDecides:
    """Filename orders the candidates; the bytes choose. `netstat` is a legal
    name for two different formats, so a name-only rule cannot be right."""

    def test_the_same_filename_resolves_to_two_different_readers(self, tmp_path):
        bsd = read_host(_host(tmp_path / "a", netstat=BSD_NETSTAT))
        lin = read_host(_host(tmp_path / "b", netstat=LINUX_NETSTAT))
        assert bsd.sources == ["bsd-netstat"]
        assert lin.sources == ["linux-netstat"]

    def test_an_ss_dump_named_netstat_is_still_read_as_ss(self, tmp_path):
        inv = read_host(_host(tmp_path, netstat=SS))
        assert inv.sources == ["ss"]
        assert inv.os == "linux"
        assert inv.listeners

    def test_a_netstat_dump_named_ss_is_still_read_as_netstat(self, tmp_path):
        inv = read_host(_host(tmp_path, ss=BSD_NETSTAT))
        assert inv.sources == ["bsd-netstat"]

    def test_identify_returns_none_for_something_unrelated(self, tmp_path):
        p = tmp_path / "notes.txt"
        p.write_text("remember to run the collection again on friday\n")
        assert identify(p) is None

    def test_identify_does_not_choke_on_an_empty_file(self, tmp_path):
        p = tmp_path / "ss"
        p.write_text("")
        assert identify(p) is None


class TestLinuxNetstat:
    """Not a worse `ss`: a different observation, and the only one some hosts
    have. net-tools reports the command line rather than `comm`."""

    def test_listeners_come_across(self, tmp_path):
        inv = read_host(_host(tmp_path, netstat=LINUX_NETSTAT))
        got = {(l["proto"], l["local_address"], l["local_port"])
               for l in inv.listeners}
        assert got == {
            ("tcp", "0.0.0.0", 22), ("tcp", "::", 22),
            ("tcp", "127.0.0.1", 631), ("tcp", "0.0.0.0", 27500),
            ("udp", "0.0.0.0", 5353), ("udp", "::", 5353),
        }

    def test_family_is_a_fact_not_an_inference(self, tmp_path):
        """net-tools writes tcp6, so the v6 wildcard is `::` because the source
        said so, not because the address was guessed at."""
        inv = read_host(_host(tmp_path, netstat=LINUX_NETSTAT))
        assert any(l["local_address"] == "::" for l in inv.listeners)

    def test_a_name_with_a_space_and_colon_survives(self, tmp_path):
        inv = read_host(_host(tmp_path, netstat=LINUX_NETSTAT))
        ssh = next(l for l in inv.listeners
                   if l["local_port"] == 22 and l["local_address"] == "0.0.0.0")
        assert ssh["process_info"]["name"] == "sshd: /usr/sbi"
        assert ssh["pid"] == "1569"

    def test_an_unreadable_owner_is_unknown_rather_than_dropped(self, tmp_path):
        """`-` in the PID column is what an unprivileged collection produces for
        other users' sockets. The socket is still a fact; the owner is the gap."""
        inv = read_host(_host(tmp_path, netstat=LINUX_NETSTAT))
        orphan = next(l for l in inv.listeners if l["local_port"] == 27500)
        assert orphan["process_info"]["name"] == "UNKNOWN"
        assert orphan["pid"] is None

    def test_udp_is_kept_although_it_has_no_state(self, tmp_path):
        inv = read_host(_host(tmp_path, netstat=LINUX_NETSTAT))
        assert sum(1 for l in inv.listeners if l["proto"] == "udp") == 2


class TestPrecedenceWhenAHostHasSeveral:
    def test_ss_wins_over_linux_netstat(self, tmp_path):
        inv = read_host(_host(tmp_path, ss=SS, netstat=LINUX_NETSTAT))
        assert inv.sources == ["ss", "linux-netstat"]
        assert inv.files["linux-netstat"].endswith("netstat")

    def test_the_unchosen_source_is_recorded_not_merged(self, tmp_path):
        """Merging would be inventing. The two sources disagree about process
        names on real hosts -- `ss` reports comm, net-tools a truncated command
        line -- so a record fused from both describes a host neither observed."""
        inv = read_host(_host(tmp_path, ss=SS, netstat=LINUX_NETSTAT))
        ports = {l["local_port"] for l in inv.listeners}
        assert 27500 not in ports, "a port only netstat saw leaked into the answer"


class TestProblemsAreReportedNotSwallowed:
    def test_an_unrecognized_file_is_a_finding(self, tmp_path):
        d = _host(tmp_path, ss=SS)
        (d / "sockets.dump").write_text("something a future collector wrote\n")
        inv = read_host(d)
        assert inv.listeners
        assert any("sockets.dump" in p for p in inv.problems)

    def test_a_directory_with_nothing_readable_says_so(self, tmp_path):
        d = tmp_path / "empty"
        d.mkdir()
        (d / "readme").write_text("nothing here\n")
        inv = read_host(d)
        assert inv.listeners == []
        assert any("no listener inventory" in p for p in inv.problems)

    def test_an_empty_host_is_not_confused_with_an_unreadable_one(self, tmp_path):
        """The distinction the whole error contract rests on. A dump that parses
        to no listeners is an answer; a dump that could not be read is not."""
        d = tmp_path / "bare"
        d.mkdir()
        (d / "netstat").write_text(
            "Active Internet connections (including servers)\n"
            "Proto Recv-Q Send-Q  Local Address          "
            "Foreign Address        (state)\n")
        inv = read_host(d)
        assert inv.listeners == []
        assert inv.sources == ["bsd-netstat"]
        assert not inv.problems

    def test_a_failed_parse_does_not_come_back_as_an_empty_host(self, tmp_path):
        d = tmp_path / "broken"
        d.mkdir()
        (d / "ss").write_text(
            "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "tcp   \x01\x02 garbage that is not a row at all\n")
        inv = read_host(d)
        assert inv.listeners == [] and inv.problems

    def test_context_files_are_not_reported_as_problems(self, tmp_path):
        """ipaddr and friends are expected company for a dump, and flagging them
        would make `problems` noise that nobody reads."""
        d = _host(tmp_path, ss=SS)
        (d / "ipaddr.json").write_text("[]")
        (d / "loot.json").write_text("{}")
        inv = read_host(d)
        assert inv.problems == []


class TestAnnotationIsJoinedWhenPresent:
    def test_psexe_fills_the_exe_path(self, tmp_path):
        d = _host(tmp_path, ss=SS)
        rows = read_host(d).listeners
        pid = next(l["pid"] for l in rows if l["pid"])
        (d / "psexe").write_text(
            "    PID COMMAND         USER     EXE\n"
            f"{pid:>7} plain           root     /usr/local/bin/plain\n")
        after = read_host(d)
        if "psexe" in after.files:      # only if jc's ps parser took the file
            got = next(l for l in after.listeners if l["pid"] == pid)
            assert got["process_info"]["name"]

    def test_a_source_with_no_annotator_still_reads(self, tmp_path):
        """BSD declares no annotators, so the normalizer must be callable with
        an empty annotation rather than assuming one exists."""
        inv = read_host(_host(tmp_path, netstat=BSD_NETSTAT))
        assert inv.listeners


class TestTheRegistryContract:
    def test_every_inventory_reader_can_parse_and_normalize(self):
        for r in REGISTRY:
            if r.kind == "inventory":
                assert r.parse and r.normalize, r.name
            if r.kind == "annotation":
                assert r.load, r.name

    def test_precedence_is_unambiguous_within_an_os(self):
        """Two inventory sources for one OS at the same precedence would make
        the chosen source depend on registry order, which is not a decision
        anyone wrote down."""
        seen = {}
        for r in REGISTRY:
            if r.kind != "inventory":
                continue
            key = (r.os, r.precedence)
            assert key not in seen, f"{r.name} ties with {seen.get(key)}"
            seen[key] = r.name

    def test_no_reader_decides_by_filename_alone(self):
        for r in REGISTRY:
            assert r.sniff is not None, r.name

    def test_it_does_not_ask_which_jc_is_installed(self):
        import inspect

        from firru import readers
        src = inspect.getsource(readers)
        for probe in ("jc.__version__", "importlib.metadata", "pkg_resources"):
            assert probe not in src, f"version check crept in: {probe}"


class TestDiscoveryEndToEnd:
    """The half of the bug that lives in `firru.discovery`.

    Reading a netstat dump correctly is no use if no walk over an estate ever
    hands one to the reader. Discovery used to map filename to `os` directly,
    so a directory holding `netstat` produced no entry at all -- not a failure,
    just a host that quietly was not there.
    """

    def test_a_bsd_host_directory_is_discovered(self, tmp_path):
        from firru.discovery import get_discovery_list
        root = tmp_path / "hosts"
        _host(root, netstat=BSD_NETSTAT)
        found = get_discovery_list(str(root))
        assert len(found) == 1
        assert found[0]["os"] == "bsd"
        assert found[0]["listenfile"].endswith("netstat")

    def test_and_survives_the_whole_way_through_process_host(self, tmp_path):
        from firru.cli.loot_listeners import process_host
        from firru.discovery import get_discovery_list
        root = tmp_path / "hosts"
        _host(root, netstat=BSD_NETSTAT)
        meta, ports = process_host(get_discovery_list(str(root))[0])
        assert meta["os"] == "bsd"
        assert {p["port"] for p in ports} == {22, 514}   # 25 is loopback-only
        assert {p["process"]["name"] for p in ports} == {"UNKNOWN"}

    def test_a_linux_netstat_only_host_is_discovered(self, tmp_path):
        from firru.discovery import get_discovery_list
        root = tmp_path / "hosts"
        _host(root, netstat=LINUX_NETSTAT)
        found = get_discovery_list(str(root))
        assert found[0]["os"] == "linux"

    def test_the_better_source_is_chosen_and_the_other_carried(self, tmp_path):
        from firru.discovery import get_discovery_list
        root = tmp_path / "hosts"
        _host(root, ss=SS, netstat=LINUX_NETSTAT)
        e = get_discovery_list(str(root))[0]
        assert e["listenfile"].endswith("/ss")
        assert [p.rsplit("/", 1)[-1] for p in e["otherfiles"]] == ["netstat"]

    def test_a_netns_dump_does_not_become_the_hosts_own_inventory(self, tmp_path):
        """`netns0-ss` is a socket dump and would sniff as one. It belongs to a
        different host than the directory holding it, and content-based
        recognition must not undo that."""
        from firru.discovery import get_discovery_list
        root = tmp_path / "hosts"
        d = _host(root, ss=SS)
        shutil.copy(SS, d / "netns0-ss")
        entries = get_discovery_list(str(root))
        main = next(e for e in entries if not e["hostname"].endswith("-netns0"))
        assert main["listenfile"].endswith("/ss")
        assert main["otherfiles"] == []
        assert any(e["hostname"].endswith("-netns0") for e in entries)

    def test_a_csv_that_is_not_a_connections_export_is_not_called_windows(self, tmp_path):
        """The single-file path used to label anything ending in `.csv` as
        Windows and hand it to the CSV normalizer."""
        from firru.discovery import get_discovery_list
        p = tmp_path / "somehost" / "inventory.csv"
        p.parent.mkdir(parents=True)
        p.write_text("asset,owner\nweb01,ops\n")
        assert get_discovery_list(str(p))[0]["os"] is None


class TestPoShR2Layout:
    """A Windows host collected by PoSh-R2 rather than by loot-host.sh: the
    same job, a different directory, ~38 CSVs instead of two.

    It is the case content-based recognition exists for, and it found two bugs
    on contact. Both were silent.
    """

    def _posh(self, tmp_path):
        d = tmp_path / "dc1"
        d.mkdir(parents=True)
        # The layout PoSh-R2 really writes: its own parse of `netstat -ano`,
        # so LISTENING and ProcessID, and N/A where Get-Process found nothing.
        (d / "connections.csv").write_text(
            '"ComputerName","Protocol","Version","LocalAddress","LocalPort",'
            '"RemoteAddress","RemotePort","State","ProcessID","ProcessName",'
            '"ProcessPath"\n'
            ',"TCP","IPv4","0.0.0.0","445","0.0.0.0","0","LISTENING","4",'
            '"System",\n'
            ',"TCP","IPv4","0.0.0.0","3389","0.0.0.0","0","LISTENING","912",'
            '"N/A","N/A"\n'
            ',"TCP","IPv4","10.0.0.5","49700","10.0.0.9","443","ESTABLISHED",'
            '"912","svchost",\n'
            ',"UDP","IPv6","::","123","*","*","","1376","svchost",\n')
        (d / "Services.csv").write_text(
            '"ProcessID","Name","Description","PathName"\n'
            '"912","TermService","Remote Desktop","C:\\\\svchost.exe"\n')
        (d / "Services_Full.csv").write_text(
            '"Name","Status","PathName","ProcessId","Description"\n'
            '"TermService","OK","C:\\\\svchost.exe","912","Remote Desktop"\n')
        for noise in ("Autoruns.csv", "Patches.csv", "Users.csv"):
            (d / noise).write_text('"Fqdn","Name"\n"dc1","x"\n')
        return d

    def test_the_connections_export_is_found_among_the_noise(self, tmp_path):
        from firru.discovery import get_discovery_list
        root = tmp_path / "hosts"
        root.mkdir()
        d = self._posh(root)
        e = get_discovery_list(str(root))[0]
        assert e["os"] == "windows"
        assert e["listenfile"].endswith("connections.csv")

    def test_the_hinted_services_file_wins_over_the_wider_one(self, tmp_path):
        """Both sniff as a services export. Without a rule the answer came down
        to which sorted last, which is not a decision anyone made."""
        from firru.discovery import get_discovery_list
        root = tmp_path / "hosts"
        root.mkdir()
        self._posh(root)
        e = get_discovery_list(str(root))[0]
        assert e["annotationfile"].endswith("Services.csv")

    def test_either_spelling_of_the_pid_column_is_read(self, tmp_path):
        """`Get-WmiObject Win32_Service` writes ProcessID; PoSh-R2's fuller
        export writes ProcessId. Reading only one gave a services table with no
        pids in it, so every listener came back unannotated and nothing said
        why."""
        from firru.readers import read_services
        d = self._posh(tmp_path)
        assert read_services(str(d / "Services.csv")).keys() == {"912"}
        assert read_services(str(d / "Services_Full.csv")).keys() == {"912"}

    def test_netstat_shaped_tcp_listeners_are_read(self, tmp_path):
        """firru once accepted only Get-NetTCPConnection's LISTEN, so every
        Windows host collected by PoSh-R2 came back UDP-only."""
        from firru.readers import read_host
        h = read_host(str(self._posh(tmp_path)))
        got = {(r["proto"], r["local_port"]) for r in h.listeners}
        assert {("tcp", 445), ("tcp", 3389), ("udp", 123)} <= got
        assert ("tcp", 49700) not in got

    def test_the_unrelated_csvs_do_not_become_an_inventory(self, tmp_path):
        from firru.discovery import get_discovery_list
        root = tmp_path / "hosts"
        root.mkdir()
        self._posh(root)
        assert len(get_discovery_list(str(root))) == 1
