"""firru mass runs a stream of firru commands in one process — the fast backend
for the emitted edit scripts. Same input as `| sh`, comments and tags skipped."""

import textwrap

import pytest
from ruyaml import YAML

from firru.cli.mass import iter_commands, main as mass_main


class TestParse:
    def test_comments_and_blanks_are_skipped(self):
        cmds = list(iter_commands(["# a comment", "", "  ", "firru rm p t"]))
        assert cmds == [["rm", "p", "t"]]

    def test_a_trailing_tag_is_stripped(self):
        cmds = list(iter_commands(["firru set-source p t X --defs d  # narrowed observed (5)"]))
        assert cmds == [["set-source", "p", "t", "X", "--defs", "d"]]

    def test_a_leading_firru_is_optional(self):
        assert list(iter_commands(["rm p t"])) == [["rm", "p", "t"]]

    def test_a_commented_command_line_is_not_run(self):
        # the terminal swap and zero-evidence-scored lines start with '#'
        assert list(iter_commands(["# firru rm p allow-ANY  # terminal"])) == []


def _pol(tmp_path):
    p = tmp_path / "pol.yml"
    p.write_text(textwrap.dedent("""\
        metadata: {host: H1}
        filters:
          - header: {targets: {nftables: mixed input DROP}}
            terms:
              - name: allow-tcp-SSH
                protocol: tcp
                destination-port: SSH
                source-address: ANY
                action: accept
              - name: allow-tcp-OLD
                protocol: tcp
                destination-port: OLD
                action: accept
              - {name: drop-ANY, action: deny}
        """))
    return str(p)


class TestRun:
    def test_a_stream_mutates_the_file_in_one_process(self, tmp_path, capsys, monkeypatch):
        pol = _pol(tmp_path)
        script = f"firru set-source {pol} allow-tcp-SSH NET_MGMT\nfirru rm {pol} allow-tcp-OLD\n"
        monkeypatch.setattr("sys.stdin", __import__("io").StringIO(script))
        monkeypatch.setattr("sys.argv", ["firru mass"])
        rc = mass_main()
        assert rc == 0
        doc = YAML().load(open(pol))
        names = [t["name"] for t in doc["filters"][0]["terms"]]
        assert "allow-tcp-OLD" not in names
        assert doc["filters"][0]["terms"][0]["source-address"] == "NET_MGMT"

    def test_a_failing_line_does_not_stop_the_batch(self, tmp_path, capsys, monkeypatch):
        pol = _pol(tmp_path)
        # first line targets a nonexistent term (fails), second must still run
        script = f"firru rm {pol} no-such-term\nfirru rm {pol} allow-tcp-OLD\n"
        monkeypatch.setattr("sys.stdin", __import__("io").StringIO(script))
        monkeypatch.setattr("sys.argv", ["firru mass"])
        rc = mass_main()
        assert rc == 1  # a line failed
        assert "allow-tcp-OLD" not in open(pol).read()  # but the good line ran

    def test_dry_run_executes_nothing(self, tmp_path, capsys, monkeypatch):
        pol = _pol(tmp_path)
        before = open(pol).read()
        script = f"firru rm {pol} allow-tcp-OLD\n"
        monkeypatch.setattr("sys.stdin", __import__("io").StringIO(script))
        monkeypatch.setattr("sys.argv", ["firru mass", "-n"])
        mass_main()
        assert open(pol).read() == before
