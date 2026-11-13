import textwrap

import pytest
import yaml as pyyaml

from firru.cli.edit_services import cmd_add, cmd_rm, parse_entry, token_references


class Args:
    def __init__(self, **kw):
        self.force = False
        self.dry_run = False
        self.policies = None
        self.defs = None
        self.__dict__.update(kw)


def _def(tmp_path, name="funny.yml", body=None):
    d = tmp_path / "def"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_text(body if body is not None else textwrap.dedent("""\
        services:
          TCP_9191:
            - port: 9191
              protocol: tcp
          SYSLOG:
            - port: 514
              protocol: udp
    """))
    return p


class TestParseEntry:
    def test_single_port(self):
        assert parse_entry("9191/tcp") == {"port": 9191, "protocol": "tcp"}

    def test_range(self):
        assert parse_entry("49152-65535/tcp") == {"port": "49152-65535", "protocol": "tcp"}

    @pytest.mark.parametrize("bad", ["9191", "9191/ftp", "abc/tcp", "1-x/tcp"])
    def test_rejects_junk(self, bad):
        with pytest.raises(ValueError):
            parse_entry(bad)


class TestAdd:
    def test_adds_a_token(self, tmp_path, capsys):
        p = _def(tmp_path)
        assert cmd_add(Args(file=str(p), token="VENDOR_P2P",
                            entries=["40000/tcp", "40000/udp"])) == 0
        doc = pyyaml.safe_load(p.read_text())
        assert doc["services"]["VENDOR_P2P"] == [
            {"port": 40000, "protocol": "tcp"}, {"port": 40000, "protocol": "udp"}]

    def test_a_file_not_there_yet_is_created(self, tmp_path, capsys):
        # The review script suggests def/funny.yml before anyone has made it.
        p = tmp_path / "def" / "funny.yml"
        p.parent.mkdir()
        assert cmd_add(Args(file=str(p), token="TCP_4242", entries=["4242/tcp"])) == 0
        assert pyyaml.safe_load(p.read_text()) == {
            "services": {"TCP_4242": [{"port": 4242, "protocol": "tcp"}]}}
        assert "created" in capsys.readouterr().out

    def test_existing_token_is_refused(self, tmp_path):
        p = _def(tmp_path)
        assert cmd_add(Args(file=str(p), token="TCP_9191", entries=["9191/tcp"])) == 1

    def test_force_replaces(self, tmp_path):
        p = _def(tmp_path)
        assert cmd_add(Args(file=str(p), token="TCP_9191", entries=["9292/tcp"],
                            force=True)) == 0
        assert pyyaml.safe_load(p.read_text())["services"]["TCP_9191"] == [
            {"port": 9292, "protocol": "tcp"}]

    def test_dry_run_writes_nothing(self, tmp_path):
        p = _def(tmp_path)
        before = p.read_text()
        assert cmd_add(Args(file=str(p), token="NEW", entries=["1/tcp"], dry_run=True)) == 0
        assert p.read_text() == before

    def test_comments_survive(self, tmp_path):
        p = _def(tmp_path, body=textwrap.dedent("""\
            services:
              TCP_9191: # [auto] Procs: {'x': 1} | Hosts(1): ['h']
                - port: 9191
                  protocol: tcp
        """))
        cmd_add(Args(file=str(p), token="NEW", entries=["1/tcp"]))
        assert "[auto] Procs:" in p.read_text()


class TestReferences:
    def test_a_policy_reference_is_found(self, tmp_path):
        p = _def(tmp_path)
        pol = tmp_path / "pol"
        pol.mkdir()
        (pol / "h1.yml").write_text("filters:\n  - terms:\n    - destination-port: SYSLOG\n")
        pol_hits, def_hits = token_references("SYSLOG", str(p.parent), str(pol))
        assert len(pol_hits) == 1 and def_hits == []

    def test_a_group_member_reference_is_found(self, tmp_path):
        _def(tmp_path)
        (tmp_path / "def" / "groups.yml").write_text(
            "services:\n  LOGGING:\n    - name: SYSLOG\n")
        _, def_hits = token_references("SYSLOG", str(tmp_path / "def"), None)
        assert len(def_hits) == 1

    def test_its_own_definition_is_not_a_reference(self, tmp_path):
        _def(tmp_path)
        pol_hits, def_hits = token_references("SYSLOG", str(tmp_path / "def"), None)
        assert pol_hits == [] and def_hits == []


class TestRm:
    def test_removes_an_unreferenced_token(self, tmp_path):
        p = _def(tmp_path)
        assert cmd_rm(Args(file=str(p), token="TCP_9191")) == 0
        assert "TCP_9191" not in pyyaml.safe_load(p.read_text())["services"]

    def test_refuses_when_a_policy_still_uses_it(self, tmp_path, capsys):
        p = _def(tmp_path)
        pol = tmp_path / "pol"
        pol.mkdir()
        (pol / "h1.yml").write_text("filters:\n  - terms:\n    - destination-port: SYSLOG\n")
        assert cmd_rm(Args(file=str(p), token="SYSLOG", policies=str(pol))) == 1
        assert "SYSLOG" in pyyaml.safe_load(p.read_text())["services"]
        assert "still referenced" in capsys.readouterr().err

    def test_refuses_when_a_group_still_uses_it(self, tmp_path):
        p = _def(tmp_path)
        (tmp_path / "def" / "groups.yml").write_text(
            "services:\n  LOGGING:\n    - name: SYSLOG\n")
        assert cmd_rm(Args(file=str(p), token="SYSLOG")) == 1

    def test_force_overrides_the_refusal(self, tmp_path):
        p = _def(tmp_path)
        (tmp_path / "def" / "groups.yml").write_text(
            "services:\n  LOGGING:\n    - name: SYSLOG\n")
        assert cmd_rm(Args(file=str(p), token="SYSLOG", force=True)) == 0

    def test_checks_run_at_removal_not_at_report_time(self, tmp_path):
        # The generated line said TCP_9191 was unused; by the time it runs, a
        # policy references it. The verb must re-check, not trust the caller.
        p = _def(tmp_path)
        pol = tmp_path / "pol"
        pol.mkdir()
        (pol / "h1.yml").write_text("terms:\n  - destination-port: TCP_9191\n")
        assert cmd_rm(Args(file=str(p), token="TCP_9191", policies=str(pol))) == 1

    def test_missing_token_is_an_error(self, tmp_path):
        p = _def(tmp_path)
        assert cmd_rm(Args(file=str(p), token="NOPE")) == 1

    def test_dry_run_writes_nothing(self, tmp_path):
        p = _def(tmp_path)
        before = p.read_text()
        assert cmd_rm(Args(file=str(p), token="TCP_9191", dry_run=True)) == 0
        assert p.read_text() == before
