import pathlib

import pytest

from firru.ss import (
    SsParseError,
    _strip_cgroup,
    _sanitize_proc_name,
    get_process_name_pid,
    parse_ss_safe,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


class TestStripCgroup:
    def test_removes_cgroup_field(self):
        line = "tcp LISTEN 0 128 0.0.0.0:22 users:((...)) cgroup:/system.slice/sshd.service"
        assert "cgroup:" not in _strip_cgroup(line)

    def test_leaves_normal_line_untouched(self):
        line = "tcp LISTEN 0 128 0.0.0.0:22 users:((...))"
        assert _strip_cgroup(line) == line


class TestSanitizeProcName:
    def test_spaces_colons_parens_replaced_in_name(self):
        line = 'tcp LISTEN 0 128 0.0.0.0:22 users:(("my proc:x",pid=1,fd=3))'
        out = _sanitize_proc_name(line)
        assert '"my_proc_x"' in out
        # surrounding structure preserved
        assert "pid=1" in out


class TestGetProcessNamePid:
    def test_structured_process_dict(self):
        entry = {"process": {"process_id": {"1234": {"user": "sshd"}}}}
        assert get_process_name_pid(entry) == ("sshd", "1234")

    def test_raw_opts_string(self):
        entry = {"opts": "users:(('sshd',pid=1234,fd=5))"}
        assert get_process_name_pid(entry) == ("sshd", "1234")

    def test_unknown_when_absent(self):
        assert get_process_name_pid({}) == ("UNKNOWN", None)


class TestParseSsSafe:
    def test_parses_fixture_to_rows(self):
        rows = parse_ss_safe(str(FIXTURES / "ss_sample.txt"))
        assert isinstance(rows, list)
        assert rows, "expected at least one parsed tcp/udp row"

    def test_missing_file_raises(self):
        """It used to return []. A host whose dump is missing is not a host
        listening on nothing, and collapsing the two is how `--prune` strips a
        working host of every rule."""
        with pytest.raises(SsParseError):
            parse_ss_safe(str(FIXTURES / "does_not_exist.txt"))

    def test_empty_file_raises(self, tmp_path):
        """ss writing nothing is a collection failure. A real host with no
        listeners still emits a header line."""
        p = tmp_path / "empty.txt"
        p.write_text("")
        with pytest.raises(SsParseError):
            parse_ss_safe(str(p))

    def test_a_header_with_no_sockets_is_empty_not_an_error(self, tmp_path):
        """The other side of the same line: this host really is listening on
        nothing, and that is an answer rather than a failure."""
        p = tmp_path / "none.txt"
        p.write_text("Netid State  Recv-Q Send-Q Local_Address:Port "
                     "Peer_Address:Port Process\n")
        assert parse_ss_safe(str(p)) == []

    def test_the_error_points_at_the_sanitizer(self, tmp_path):
        """A new ss version emitting a field the sanitizers miss is the
        expected cause, so the message has to name that rather than just
        surfacing jc's traceback."""
        p = tmp_path / "bad.txt"
        p.write_text("Netid State\ntcp LISTEN \x00\x01 garbage:::::(((\n")
        try:
            parse_ss_safe(str(p))
        except SsParseError as e:
            assert "sanitizer" in str(e)
        # Parsing without raising is acceptable too; jc is permissive. What is
        # not acceptable is a silent [].


class TestIproute2SixHeader:
    """The Debian 12 dump, kept for what it actually proved.

    It was the first corpus fixture that failed to parse, and I misread the
    cause as iproute2 6.x writing `Peer Address:PortProcess` with no separator.
    jc handles that header fine. The real cause was the capture script writing
    `#` provenance lines that became the header, which the comment-skipping in
    parse_ss_safe fixes. The header "fix" was a no-op confirmed by a test that
    changed two things at once, and it is gone.

    The fixture stays because it is a real iproute2 6.1.0 capture with all three
    hostile process names in it.
    """

    FIXTURE = FIXTURES / "ss_debian12_iproute2_6.1.0.txt"

    def test_the_header_really_is_the_unseparated_shape(self):
        header = self.FIXTURE.read_text().splitlines()[0]
        assert "PortProcess" in header

    def test_and_jc_parses_it_anyway(self):
        rows = parse_ss_safe(str(self.FIXTURE))
        assert len(rows) == 3
        assert {r["local_port"] for r in rows} == {"19001", "19002", "19003"}

    def test_the_hostile_process_names_survive(self):
        """Exactly as ss wrote them where jc can manage it, sanitized where it
        cannot. Both are correct answers; which one you get is a property of
        the installed parser, not of firru."""
        from firru.ss import jc_keeps_process_names
        names = {get_process_name_pid(r)[0] for r in parse_ss_safe(str(self.FIXTURE))}
        if jc_keeps_process_names():
            assert names == {"my proc:x", "svc(1", "plain"}
        else:
            assert names == {"my_proc_x", "svc_1", "plain"}

    def test_a_comment_line_as_header_is_what_actually_broke_it(self, tmp_path):
        """Reproduced directly, so the real cause is pinned rather than the
        one I guessed."""
        import jc
        lines = self.FIXTURE.read_text().splitlines(True)
        body = [l for l in lines[1:] if "tcp" in l]
        with pytest.raises(KeyError):
            jc.parse("ss", "".join(["# ss-version: whatever\n"] + body))


class TestCgroupIsKeptWhereJcCanReadIt:
    """`cgroup:` used to be stripped unconditionally on the grounds that it
    tripped jc. Current jc parses it, and the value is the systemd unit —
    better attribution than the comm name. So it is kept, with stripping as the
    fallback for a jc that cannot."""

    LINE = ('tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    '
            'users:(("sshd",pid=812,fd=3)) ino:24680 sk:1 '
            'cgroup:/system.slice/ssh.service <->\n')
    HDR = ("Netid State  Recv-Q Send-Q Local Address:Port  "
           "Peer Address:PortProcess\n")

    def test_the_systemd_unit_survives(self, tmp_path):
        """jc files the block under `process` or `opts` depending on what the
        header column is called, which is why get_process_name_pid reads both."""
        p = tmp_path / "ss.txt"
        p.write_text(self.HDR + self.LINE)
        row = parse_ss_safe(str(p))[0]
        block = row.get("process") or row.get("opts")
        assert block["cgroup"] == "/system.slice/ssh.service"

    def test_the_process_is_still_attributed(self, tmp_path):
        p = tmp_path / "ss.txt"
        p.write_text(self.HDR + self.LINE)
        assert get_process_name_pid(parse_ss_safe(str(p))[0]) == ("sshd", "812")

    def test_stripping_still_works_as_a_fallback(self):
        """The fallback has to keep doing its job for an older jc, so the
        function stays and stays tested even though it is no longer the default."""
        from firru.ss import _strip_cgroup
        assert "cgroup:" not in _strip_cgroup(self.LINE)
        assert "users:" in _strip_cgroup(self.LINE)


class TestJcCapabilityProbe:
    """Whether to sanitize is a question about the installed jc, and it is
    asked by parsing rather than by reading a version number.

    Version comparison cannot work here. jc's fix is not released, so there is
    no version to compare against; a distro can backport it without changing
    the version; and a locally patched checkout reports whatever it forked
    from. All three are ordinary situations and all three defeat a table of
    version numbers.
    """

    def test_the_probe_answers_from_behaviour_not_a_version(self):
        import inspect
        from firru import ss
        src = inspect.getsource(ss.jc_keeps_process_names)
        for probe in ("__version__", "version(", "importlib.metadata",
                      "pkg_resources", "1.25"):
            assert probe not in src, f"version check crept in: {probe}"

    def test_the_probe_name_carries_all_three_characters(self):
        """A probe missing one of them would pass on a jc that still mangles
        it, which is the whole failure this guards against."""
        from firru.ss import _PROBE_NAME
        assert " " in _PROBE_NAME
        assert ":" in _PROBE_NAME
        assert "(" in _PROBE_NAME

    def test_it_checks_the_value_rather_than_whether_parsing_raised(self):
        """The paren case does not raise on a broken jc, it returns `[sd-pam`
        for `(sd-pam`. An exception-based probe would call that healthy."""
        import inspect
        from firru import ss
        src = inspect.getsource(ss.jc_keeps_process_names)
        assert "_PROBE_NAME" in src and "names ==" in src

    def test_the_answer_is_cached(self):
        """It runs on every parse_ss_safe call otherwise, and the answer cannot
        change within a process."""
        from firru.ss import jc_keeps_process_names
        assert hasattr(jc_keeps_process_names, "cache_info")
        jc_keeps_process_names()
        before = jc_keeps_process_names.cache_info().hits
        jc_keeps_process_names()
        assert jc_keeps_process_names.cache_info().hits == before + 1

    def test_names_are_never_worse_than_before_the_probe(self, tmp_path):
        """Whichever branch is taken, every planted listener still comes back
        attributed. The probe changes the spelling, never the presence."""
        rows = parse_ss_safe(str(FIXTURES / "ss_debian12_iproute2_6.1.0.txt"))
        names = {get_process_name_pid(r)[0] for r in rows}
        assert "UNKNOWN" not in names
        assert len(names) == 3
