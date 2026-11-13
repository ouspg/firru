"""
loot-conntrack: conntrack text in, flow records out.

The tool had no tests and a parser that took the first occurrence of each key,
which quietly kept the original direction's counters and dropped the reply's.
The parsing is jc's now, and these stay as the contract it has to keep: the
shapes that actually come off a Linux box, including the two that
only appear once the accounting and timestamp sysctls are on -- the ones a
capture taken on a default box will never contain.

The fixtures are written by hand from the format strings in
libnetfilter_conntrack's snprintf_default.c rather than captured, so no real
estate's addresses end up in the repository.
"""

import json
import subprocess

import pytest

from firru.cli.conntrack_flows import parse, snapshot, to_flow


def flow(line):
    entries = parse(line)
    return to_flow(entries[0]) if entries else None


class TestTheTupleAndItsDirections:
    LINE = ('tcp      6 431982 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 '
            'sport=34846 dport=993 src=10.0.0.2 dst=10.0.0.1 sport=993 '
            'dport=34846 [ASSURED] mark=0 use=1')

    def test_the_originator_is_the_original_direction(self):
        f = flow(self.LINE)
        assert (f['src_ip'], f['dst_ip']) == ('10.0.0.1', '10.0.0.2')
        assert (f['src_port'], f['dst_port']) == (34846, 993)
        assert f['originator'] == '10.0.0.1'

    def test_a_summary_line_is_not_a_flow(self):
        """conntrack ends a dump with a sentence, and it is not evidence of a
        connection to anywhere."""
        assert flow('conntrack v1.4.8 (conntrack-tools): 469 flow entries '
                    'have been shown.') is None

    def test_icmp_keeps_the_type_code_mapping(self):
        f = flow('icmp     1 28 src=10.0.0.1 dst=10.0.0.2 type=8 code=0 id=7 '
                 'src=10.0.0.2 dst=10.0.0.1 type=0 code=0 id=7 mark=0 use=1')
        assert (f['src_port'], f['dst_port']) == (8, 0)

    def test_a_protocol_without_ports_still_yields_a_flow(self):
        """GRE has keys where TCP has ports. The tuple is still a fact about
        who talked to whom, so it is kept with null ports rather than dropped."""
        f = flow('gre      47 30 src=10.0.0.1 dst=10.0.0.2 srckey=0x1a2b '
                 'dstkey=0x3c4d src=10.0.0.2 dst=10.0.0.1 srckey=0x3c4d '
                 'dstkey=0x1a2b mark=0 use=1')
        assert f['protocol'] == 'gre'
        assert f['src_port'] is None and f['dst_port'] is None


class TestCountersComeFromBothDirections:
    """`packets=`/`bytes=` is printed once after each tuple, with the same
    field names. Reading the first occurrence of each name -- which this tool
    used to do -- keeps the original direction and silently loses the reply,
    which is exactly the half that says whether anything answered."""

    LINE = ('udp      17 25 src=10.0.0.1 dst=10.0.0.53 sport=50798 dport=53 '
            'packets=1 bytes=74 src=10.0.0.53 dst=10.0.0.1 sport=53 '
            'dport=50798 packets=2 bytes=141 mark=0 use=1')

    def test_each_direction_keeps_its_own_counters(self):
        f = flow(self.LINE)
        assert (f['orig_pkts'], f['orig_bytes']) == (1, 74)
        assert (f['resp_pkts'], f['resp_bytes']) == (2, 141)

    def test_without_the_acct_sysctl_the_counters_are_absent_not_zero(self):
        """A flow with no accounting extension has no counter, which is not
        the same statement as a flow that carried no packets."""
        f = flow('udp      17 25 src=10.0.0.1 dst=10.0.0.53 sport=50798 '
                 'dport=53 src=10.0.0.53 dst=10.0.0.1 sport=53 dport=50798 '
                 'mark=0 use=1')
        assert f['orig_pkts'] is None and f['resp_pkts'] is None


class TestTheKtimestampBracketsSurvive:
    """`-o ktimestamp` prints `[start=...]` as a ctime() string, so a bracketed
    token contains spaces. Splitting the line on whitespace tears it into
    `[start=Sun`, `Sep`, `20`, ... and a parser that rejects a token it cannot
    read loses the whole line -- 44 of 469 on the dump this was written from,
    and they are the informative ones, since a flow only carries a kernel
    timestamp if it also carries counters."""

    LINE = ('udp      17 4 src=10.0.0.1 dst=10.0.0.53 sport=52641 dport=53 '
            'packets=1 bytes=68 src=10.0.0.53 dst=10.0.0.1 sport=53 '
            'dport=52641 packets=1 bytes=155 mark=0 delta-time=26 '
            '[start=Sun Sep 20 15:32:30 2026] use=1')

    def test_the_line_parses_at_all(self):
        assert flow(self.LINE) is not None

    def test_the_start_time_becomes_an_epoch(self):
        import time
        f = flow(self.LINE)
        assert time.ctime(f['timestamp']) == 'Sun Sep 20 15:32:30 2026'

    def test_the_fields_after_it_are_not_swallowed(self):
        """`use=1` comes after the bracketed timestamp; a tokenizer that loses
        its place would drop it or fold it into the tuple."""
        assert flow(self.LINE)['resp_bytes'] == 155

    def test_a_stop_time_becomes_the_end_time(self):
        f = flow('[DESTROY] tcp      6 src=10.0.0.1 dst=10.0.0.2 sport=1234 '
                 'dport=8080 packets=10 bytes=1000 src=10.0.0.2 dst=10.0.0.1 '
                 'sport=8080 dport=1234 packets=8 bytes=800 '
                 '[start=Sun Sep 20 15:30:00 2026] '
                 '[stop=Sun Sep 20 15:30:04 2026]')
        assert f['end_time'] - f['timestamp'] == 4


class TestRespondedSaysWhatWasObserved:
    """`responded` is the admitted/blocked axis the other flow sources emit,
    and the three cases here are genuinely different statements."""

    def test_a_new_event_does_not_know_yet(self):
        """A flow created a moment ago has not been answered *yet*. Reporting
        that as not-answered turns every connection attempt into evidence of a
        block."""
        f = flow(' [NEW] tcp      6 120 SYN_SENT src=10.0.0.1 dst=10.0.0.2 '
                 'sport=1234 dport=8080 [UNREPLIED] src=10.0.0.2 dst=10.0.0.1 '
                 'sport=8080 dport=1234')
        assert f['responded'] is None
        assert f['conntrack_event'] == 'NEW'

    def test_unreplied_on_a_table_row_is_a_no(self):
        f = flow('tcp      6 118 SYN_SENT src=10.0.0.1 dst=10.0.0.2 '
                 'sport=1234 dport=8080 [UNREPLIED] src=10.0.0.2 '
                 'dst=10.0.0.1 sport=8080 dport=1234 mark=0 use=1')
        assert f['responded'] is False
        assert f['incomplete'] is True

    def test_the_absence_of_unreplied_is_a_yes(self):
        """The kernel prints [UNREPLIED] only while it has seen no reply, so a
        row without it has seen one. That is a better signal than the packet
        heuristics the capture-based sources have to use."""
        f = flow('tcp      6 431982 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 '
                 'sport=34846 dport=993 src=10.0.0.2 dst=10.0.0.1 sport=993 '
                 'dport=34846 [ASSURED] mark=0 use=1')
        assert f['responded'] is True


class TestTheEventStreamForms:
    def test_the_o_timestamp_prefix_becomes_the_flow_time(self):
        """`-o timestamp` is conntrack's own clock and needs no sysctl, which
        makes it the only timing a default box gives at all."""
        f = flow('[1758369296.123456]\t[NEW] udp      17 30 src=10.0.0.1 '
                 'dst=10.0.0.53 sport=5353 dport=53 [UNREPLIED] '
                 'src=10.0.0.53 dst=10.0.0.1 sport=53 dport=5353')
        assert f['timestamp'] == pytest.approx(1758369296.123456)

    def test_the_extended_family_prefix_is_not_mistaken_for_the_protocol(self):
        """`-o extended` writes `ipv4 2 tcp 6 ...`, and reading the first word
        as the protocol would file every flow under ipv4."""
        f = flow('ipv4     2 tcp      6 431982 ESTABLISHED src=10.0.0.1 '
                 'dst=10.0.0.2 sport=34846 dport=993 src=10.0.0.2 '
                 'dst=10.0.0.1 sport=993 dport=34846 [ASSURED] mark=0 use=1')
        assert f['protocol'] == 'tcp'


class TestTheSnapshotAsksForOptionsItMayNotGet:
    """`-o ktimestamp` is not in every conntrack build, and a build that does
    not know an option fails the whole command rather than ignoring it. Trying
    and falling back keeps the version question from ever being asked."""

    LINE = ('tcp      6 431982 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 '
            'sport=34846 dport=993 src=10.0.0.2 dst=10.0.0.1 sport=993 '
            'dport=34846 [ASSURED] mark=0 use=1\n')

    def test_it_retries_without_the_option(self, monkeypatch, capsys):
        calls = []

        class FakePopen:
            def __init__(self, cmd, **kw):
                calls.append(cmd)
                self.returncode = 1

            def communicate(self):
                return '', 'conntrack v1.4.4: unknown option'

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout=TestTheSnapshotAsksForOptionsItMayNotGet.LINE, stderr='')

        monkeypatch.setattr(subprocess, 'Popen', FakePopen)
        monkeypatch.setattr(subprocess, 'run', fake_run)

        count = snapshot()
        out = capsys.readouterr()

        assert count == 1, "the flow has to survive the fallback"
        assert json.loads(out.out)['dst_port'] == 993
        assert '-o' in calls[0] and '-o' not in calls[1]

    def test_a_table_that_cannot_be_read_is_not_an_empty_table(self, monkeypatch):
        """Without root, conntrack -L fails. Returning 0 there would report a
        collection failure as a host with no flows, and `loot-conntrack >>
        flows.jsonl` would append nothing and exit successfully."""
        class FakePopen:
            def __init__(self, cmd, **kw):
                self.returncode = 1

            def communicate(self):
                return '', 'you must be root or get CAP_NET_ADMIN'

        monkeypatch.setattr(subprocess, 'Popen', FakePopen)
        monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw:
                            subprocess.CompletedProcess(cmd, 1, stdout='',
                                                        stderr='you must be root'))
        assert snapshot() is None

    def test_an_empty_table_is_an_answer(self):
        """The other side of the same line: conntrack ran and found nothing."""
        class FakePopen:
            def __init__(self, cmd, **kw):
                self.returncode = 0

            def communicate(self):
                return '', ''

        import firru.cli.conntrack_flows as m
        original = subprocess.Popen
        subprocess.Popen = FakePopen
        try:
            assert snapshot() == 0
        finally:
            subprocess.Popen = original


class TestStdoutIsNothingButFlows:
    """`loot-conntrack >> flows.jsonl` is the documented way to run it, so one
    progress line on the wrong stream corrupts the file it is appending to.
    Counts, warnings and the Ctrl-C banner all belong on stderr."""

    LINE = ('tcp      6 431982 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 '
            'sport=34846 dport=993 src=10.0.0.2 dst=10.0.0.1 sport=993 '
            'dport=34846 [ASSURED] mark=0 use=1\n')

    def test_every_stdout_line_is_a_flow_record(self, monkeypatch, capsys):
        from firru.cli import conntrack_flows

        class FakePopen:
            def __init__(self, cmd, **kw):
                self.returncode = 0

            def communicate(self):
                return TestStdoutIsNothingButFlows.LINE * 3, ''

        monkeypatch.setattr(subprocess, 'Popen', FakePopen)
        monkeypatch.setattr('sys.argv', ['loot-conntrack', '--snapshot-only'])

        assert conntrack_flows.main() == 0
        out = capsys.readouterr()

        lines = [l for l in out.out.splitlines() if l.strip()]
        assert len(lines) == 3
        for line in lines:
            json.loads(line)          # raises if a message leaked into stdout

        assert '3 flows from the conntrack table' in out.err
        assert '3 flows emitted total' in out.err


class TestSavedTextReadsLikeTheLiveTable:
    """loot-host.sh saves `conntrack -L` on hosts that do not carry firru, and
    the file has to give the same flows the live snapshot would."""

    TEXT = (TestStdoutIsNothingButFlows.LINE * 2
            + 'conntrack v1.4.8 (conntrack-tools): 2 flow entries have been '
              'shown.\n')

    def test_a_saved_table_becomes_flows(self, tmp_path, monkeypatch, capsys):
        from firru.cli import conntrack_flows

        saved = tmp_path / 'conntrack'
        saved.write_text(self.TEXT)

        def no_conntrack(*a, **kw):
            raise AssertionError('a saved file must not run conntrack')

        monkeypatch.setattr(subprocess, 'Popen', no_conntrack)
        monkeypatch.setattr('sys.argv', ['loot-conntrack', str(saved)])

        assert conntrack_flows.main() == 0
        lines = capsys.readouterr().out.splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])['dst_port'] == 993
