"""
BSD and macOS netstat as a listener source.

Fixtures are jc's own corpus (MIT, kellyjonbrazil/jc, tests/fixtures), which
already carries real FreeBSD 12 and macOS 10.14 captures. Borrowing them is the
point: a parser does not need the host, it needs one representative dump, and
the platforms hardest to stand up are the ones someone else already captured.

What is pinned here is mostly the two ways this source lies. It has no process
attribution at all, so a listener that arrives fully named would be a bug. And
macOS `netstat -An` parses perfectly while containing no listening sockets,
which is the silent-empty failure arriving through a *correct* parse rather
than a broken one.
"""

import pathlib

import pytest

from firru.netstat import (
    NetstatParseError,
    _is_listener,
    iter_listeners,
    looks_like_netstat,
    parse_netstat_safe,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
FREEBSD = FIXTURES / "netstat_freebsd12_an.txt"
OSX_NO_LISTENERS = FIXTURES / "netstat_osx1014_An_no_listeners.txt"


class TestSniffing:
    def test_bsd_netstat_is_recognized(self):
        assert looks_like_netstat(FREEBSD.read_text())

    def test_linux_ss_is_not(self):
        assert not looks_like_netstat((FIXTURES / "ss_sample.txt").read_text())


class TestFreeBSD:
    def test_listeners_come_across_with_their_family(self):
        """BSD writes tcp4/tcp6, so family is a fact here rather than an
        inference from the bind address. That is the dimension design.md says
        everything drops, and this source gives it away free."""
        got = set(iter_listeners(parse_netstat_safe(str(FREEBSD))))
        assert got == {
            ("tcp", 4, "127.0.0.1", 25),
            ("tcp", 4, "*", 22),
            ("tcp", 6, "*", 22),
            ("udp", 4, "*", 514),
            ("udp", 6, "*", 514),
        }

    def test_an_established_connection_is_not_a_listener(self):
        """The fixture's first row is an inbound ssh session. Counting it would
        invent a service on the client's ephemeral port."""
        ports = {p for _, _, _, p in iter_listeners(parse_netstat_safe(str(FREEBSD)))}
        assert 56321 not in ports

    def test_unix_domain_sockets_are_dropped(self):
        rows = parse_netstat_safe(str(FREEBSD))
        assert all(r.get("kind") == "network" for r in rows)

    def test_udp_is_kept_despite_having_no_state(self):
        """No handshake means no LISTEN, so a state-only test would silently
        lose every UDP service."""
        udp = [l for l in iter_listeners(parse_netstat_safe(str(FREEBSD)))
               if l[0] == "udp"]
        assert len(udp) == 2


class TestTheMacOsFlagTrap:
    def test_a_connections_only_dump_is_refused(self):
        """`netstat -An` (capital A, no lowercase a) prints connections only.
        It parses cleanly and inventories nothing, which is exactly the empty
        result that must never be mistaken for a host with no services."""
        with pytest.raises(NetstatParseError) as e:
            parse_netstat_safe(str(OSX_NO_LISTENERS))
        assert "-An" in str(e.value) and "netstat -an" in str(e.value)

    def test_the_check_is_on_tcp_not_on_listeners_overall(self):
        """Why the guard cannot be "no listeners at all": this dump has 88
        unconnected UDP sockets that pass the listener test. They are a Mac's
        DNS and mDNS clients on ephemeral ports. TCP always carries a state
        column, so TCP-with-no-LISTEN is the signature that actually fires."""
        import jc
        rows = [r for r in jc.parse("netstat", OSX_NO_LISTENERS.read_text())
                if r.get("kind") == "network"]
        assert sum(1 for r in rows if _is_listener(r)) > 50
        assert not any(str(r.get("state") or "").upper() == "LISTEN" for r in rows)

    def test_ephemeral_udp_clients_are_not_filtered_by_the_reader(self):
        """A reader does not decide what a socket is for. Port number is not
        evidence; firru.ephemeral and audit-services answer that question, the
        same way they do for Linux."""
        import jc
        rows = [r for r in jc.parse("netstat", OSX_NO_LISTENERS.read_text())
                if r.get("kind") == "network"]
        high = [r for r in rows if _is_listener(r)
                and int(r.get("local_port_num") or 0) > 49152]
        assert high, "fixture no longer contains ephemeral UDP client sockets"


class TestFailureContract:
    def test_missing_file_raises(self):
        with pytest.raises(NetstatParseError):
            parse_netstat_safe(str(FIXTURES / "nope.txt"))

    def test_empty_file_raises(self, tmp_path):
        p = tmp_path / "e.txt"
        p.write_text("")
        with pytest.raises(NetstatParseError):
            parse_netstat_safe(str(p))

    def test_linux_ss_output_is_refused_rather_than_misparsed(self, tmp_path):
        with pytest.raises(NetstatParseError) as e:
            parse_netstat_safe(str(FIXTURES / "ss_sample.txt"))
        assert "does not look like" in str(e.value)

    def test_a_host_with_no_listeners_is_an_answer_not_an_error(self, tmp_path):
        """The other side of the line: a banner and no sockets is a real host
        that serves nothing, and must not raise."""
        p = tmp_path / "bare.txt"
        p.write_text("Active Internet connections (including servers)\n"
                     "Proto Recv-Q Send-Q Local Address          "
                     "Foreign Address        (state)\n")
        assert parse_netstat_safe(str(p)) == []


class TestAsALootListenersSource:
    """The reader plugged into process_host, so a BSD host produces the same
    record shape as a Linux one and everything downstream is unchanged."""

    def test_a_row_normalizes_to_the_unified_schema(self):
        from firru.cli.loot_listeners import normalize_bsd_entry
        rows = parse_netstat_safe(str(FREEBSD))
        out = [r for r in (normalize_bsd_entry(x) for x in rows) if r]
        assert len(out) == 5
        ssh = next(r for r in out if r["local_port"] == 22
                   and r["local_address"] == "0.0.0.0")
        assert ssh["proto"] == "tcp"
        assert ssh["pid"] is None

    def test_every_listener_is_unknown_and_says_so(self):
        """BSD netstat has no PID or command name. A named process arriving
        from this source would be invented, and a false attribution is worse
        than the gap it hides."""
        from firru.cli.loot_listeners import normalize_bsd_entry
        rows = parse_netstat_safe(str(FREEBSD))
        out = [r for r in (normalize_bsd_entry(x) for x in rows) if r]
        assert {r["process_info"]["name"] for r in out} == {"UNKNOWN"}

    def test_the_wildcard_is_spelled_the_way_the_linux_source_spells_it(self):
        """Downstream tests the bind address for world-listen. BSD's `*` left
        alone would read as a specific address and lose the flag."""
        from firru.cli.loot_listeners import normalize_bsd_entry
        rows = parse_netstat_safe(str(FREEBSD))
        addrs = {r["local_address"]
                 for r in (normalize_bsd_entry(x) for x in rows) if r}
        assert "*" not in addrs
        assert {"0.0.0.0", "::", "127.0.0.1"} == addrs

    def test_a_loopback_bind_keeps_its_real_address(self):
        from firru.cli.loot_listeners import normalize_bsd_entry
        rows = parse_netstat_safe(str(FREEBSD))
        smtp = next(r for r in (normalize_bsd_entry(x) for x in rows)
                    if r and r["local_port"] == 25)
        assert smtp["local_address"] == "127.0.0.1"


MACOS26 = FIXTURES / "netstat_macos26_an.txt"
MACOS26_AN = FIXTURES / "netstat_macos26_An_no_listeners.txt"


class TestMacOs26:
    """A real `netstat -an` from macOS 26.6.2, captured on a hosted runner
    (.github/workflows/capture-bsd-fixtures.yml) because no public dump with a
    listening socket in it exists.

    It broke the parser twice on arrival, both times through jc reading an
    unknown section's *column header* as a data row, which has no dotted
    address in it. Newer netstat grew sections older ones did not have.
    """

    def test_it_parses_at_all(self):
        assert parse_netstat_safe(str(MACOS26))

    def test_the_multipath_section_does_not_break_it(self):
        """macOS 26 emits `Active Multipath Internet connections`. Dropping it
        also matches what the Linux reader does with mptcp rows: a multipath
        listener is the tcp listener seen a second way."""
        assert "Active Multipath Internet connections" in MACOS26.read_text()
        assert parse_netstat_safe(str(MACOS26))

    def test_the_vsock_section_does_not_break_it(self):
        """Every hosted runner is a guest, so `Active VSock sockets` shows up
        with `3:1024`-style addresses: colon-separated, no dot."""
        assert "Active VSock sockets" in MACOS26.read_text()
        assert parse_netstat_safe(str(MACOS26))

    def test_the_real_listeners_come_across(self):
        got = {l for l in iter_listeners(parse_netstat_safe(str(MACOS26)))
               if l[0] == "tcp"}
        assert got == {("tcp", 4, "*", 22), ("tcp", 6, "*", 22)}

    def test_a_dead_process_leaves_closed_sockets_that_are_not_listeners(self):
        """The first capture planted three listeners in one Actions step and
        dumped in the next. The processes were reaped at the step boundary and
        left CLOSED sockets on 19001-19003 — bound-looking, and not listening.
        Counting those would invent three services on a host that has none."""
        rows = parse_netstat_safe(str(MACOS26))
        closed = [r for r in rows if str(r.get("state") or "").upper() == "CLOSED"]
        assert len(closed) == 3
        assert not any(_is_listener(r) for r in closed)
        ports = {p for _, _, _, p in iter_listeners(rows)}
        assert not ({19001, 19002, 19003} & ports)

    def test_the_An_trap_on_a_real_modern_dump(self):
        """Same flag mistake, now pinned against macOS 26 rather than only the
        borrowed 10.14 capture."""
        with pytest.raises(NetstatParseError) as e:
            parse_netstat_safe(str(MACOS26_AN))
        assert "netstat -an" in str(e.value)


class TestForwardCompatibilityWithJc:
    """The section-dropping has to survive jc being fixed.

    firru carries a workaround for a jc bug (an unrecognized netstat section's
    header gets claimed by the previous section, and VSock's `cid:port`
    addresses then raise IndexError). The fix is submitted upstream, but
    distro-packaged jc runs years behind, so the workaround has to keep working
    on old jc *and* become a no-op on new jc without being told which is which.
    """

    def test_dropping_is_a_no_op_on_output_without_those_sections(self):
        """FreeBSD has neither section. If the function touched that dump, it
        would be doing something beyond compatibility."""
        from firru.netstat import _drop_unparsable_sections
        text = FREEBSD.read_text()
        assert _drop_unparsable_sections(text) == text

    def test_dropping_removes_no_network_rows(self):
        """The safety property that makes it unconditional: whatever it cuts,
        the listener inventory is identical."""
        from firru.netstat import _drop_unparsable_sections
        import jc
        text = MACOS26.read_text()
        kept = jc.parse("netstat", _drop_unparsable_sections(text))
        assert [r for r in kept if r.get("kind") == "network"]
        # Every dropped line belongs to one of the named sections, never to
        # `Active Internet connections`.
        dropped = set(text.splitlines()) - set(
            _drop_unparsable_sections(text).splitlines())
        assert dropped
        assert not any(" LISTEN" in d for d in dropped)

    def test_it_does_not_ask_which_jc_is_installed(self):
        """Version sniffing is the thing that breaks in three years."""
        import inspect
        from firru import netstat
        src = inspect.getsource(netstat)
        for probe in ("jc.__version__", "version(", "importlib.metadata",
                      "pkg_resources"):
            assert probe not in src, f"version check crept in: {probe}"
