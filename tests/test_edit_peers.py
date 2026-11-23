"""add-source / remove-source / set-action: the verb is the class of change,
and a line edits only what it names."""

import argparse

from ruyaml import YAML

from firru.cli.edit import (cmd_add_destination, cmd_add_source, cmd_remove_destination,
                            cmd_remove_source, cmd_set_action)
from tests.test_edit_more import DROP, _et, _merged_pol, _pol, _t, _write


def _ns(pol, term, *peers, **kw):
    return argparse.Namespace(pol=pol, term=term, peers=list(peers), defs="def", **kw)


def _term(pol, name):
    doc = YAML().load(open(pol))
    for f in doc["filters"]:
        for t in f["terms"]:
            if t.get("name") == name:
                return t


def _ssh(tmp_path, src="[NET_A, NET_B, NET_C]", note=""):
    body = _t("allow-tcp-SSH", "SSH", src=src) + note
    return _write(tmp_path, "pol.yml", _pol([body, DROP]))


class TestRemoveSource:
    def test_removes_only_the_named(self, tmp_path):
        pol = _ssh(tmp_path)
        assert cmd_remove_source(_ns(pol, "allow-tcp-SSH", "NET_B")) == 0
        assert list(_term(pol, "allow-tcp-SSH")["source-address"]) == ["NET_A", "NET_C"]

    def test_holds_on_a_policy_edited_since(self, tmp_path):
        """A source added by hand after the line was written survives it."""
        pol = _ssh(tmp_path, src="[NET_A, NET_B, NET_HAND]")
        cmd_remove_source(_ns(pol, "allow-tcp-SSH", "NET_B"))
        assert list(_term(pol, "allow-tcp-SSH")["source-address"]) == ["NET_A", "NET_HAND"]

    def test_a_peer_already_gone_is_a_note(self, tmp_path, capsys):
        pol = _ssh(tmp_path)
        before = open(pol).read()
        assert cmd_remove_source(_ns(pol, "allow-tcp-SSH", "NET_X")) == 0
        assert "already removed" in capsys.readouterr().err
        assert open(pol).read() == before

    def test_the_last_one_makes_a_logged_deny_not_any(self, tmp_path):
        pol = _ssh(tmp_path, src="NET_A")
        cmd_remove_source(_ns(pol, "allow-tcp-SSH", "NET_A"))
        t = _term(pol, "allow-tcp-SSH")
        assert t["action"] == "deny" and t["logging"] is True
        assert "source-address" not in t

    def test_the_trailing_comment_stays_last(self, tmp_path):
        pol = _ssh(tmp_path, src="NET_A", note="\n# [auto] IPv4 0.0.0.0/0 (sshd)")
        cmd_remove_source(_ns(pol, "allow-tcp-SSH", "NET_A"))
        lines = open(pol).read().splitlines()
        assert lines.index("# [auto] IPv4 0.0.0.0/0 (sshd)") > lines.index("        logging: true")

    def test_nothing_to_remove_from_any(self, tmp_path, capsys):
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-SSH", "SSH"), DROP]))
        assert cmd_remove_source(_ns(pol, "allow-tcp-SSH", "NET_A")) == 1
        assert "set-source" in capsys.readouterr().err

    def test_comments_survive(self, tmp_path):
        pol = _ssh(tmp_path, note="\n        # scoring: keep for the check")
        cmd_remove_source(_ns(pol, "allow-tcp-SSH", "NET_C"))
        assert "# scoring: keep for the check" in open(pol).read()

    def test_refuses_an_egress_term(self, tmp_path, capsys):
        pol = _write(tmp_path, "pol.yml", _merged_pol(
            [_t("allow-tcp-SSH", "SSH", src="NET_A"), DROP],
            [_et("allow-egress-HTTP", "HTTP", dst="[WEB_A, WEB_B]"), DROP]))
        assert cmd_remove_source(_ns(pol, "allow-egress-HTTP", "WEB_A")) == 1
        assert "remove-destination" in capsys.readouterr().err
        assert cmd_remove_destination(_ns(pol, "allow-egress-HTTP", "WEB_A")) == 0
        assert _term(pol, "allow-egress-HTTP")["destination-address"] == "WEB_B"


class TestAddSource:
    def test_appends_the_new(self, tmp_path):
        pol = _ssh(tmp_path, src="[NET_A, NET_B]")
        cmd_add_source(_ns(pol, "allow-tcp-SSH", "NET_B", "NET_D"))
        assert list(_term(pol, "allow-tcp-SSH")["source-address"]) == ["NET_A", "NET_B", "NET_D"]

    def test_any_stays_any(self, tmp_path):
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-SSH", "SSH"), DROP]))
        assert cmd_add_source(_ns(pol, "allow-tcp-SSH", "NET_A")) == 0
        assert "source-address" not in _term(pol, "allow-tcp-SSH")

    def test_destination_side(self, tmp_path):
        pol = _write(tmp_path, "pol.yml", _merged_pol(
            [DROP], [_et("allow-egress-HTTP", "HTTP", dst="WEB_A"), DROP]))
        cmd_add_destination(_ns(pol, "allow-egress-HTTP", "WEB_B"))
        assert list(_term(pol, "allow-egress-HTTP")["destination-address"]) == ["WEB_A", "WEB_B"]


class TestSetAction:
    def _act(self, pol, action, log=None, force=False):
        return cmd_set_action(argparse.Namespace(pol=pol, term="allow-tcp-SSH", action=action,
                                                 log=log, force=force, defs="def"))

    def test_deny_logged_keeps_the_term(self, tmp_path):
        pol = _ssh(tmp_path)
        assert self._act(pol, "deny", log=True) == 0
        t = _term(pol, "allow-tcp-SSH")
        assert t["action"] == "deny" and t["logging"] is True
        assert list(t["source-address"]) == ["NET_A", "NET_B", "NET_C"]
        assert list(t.keys()).index("logging") == list(t.keys()).index("action") + 1

    def test_no_log_clears(self, tmp_path):
        pol = _ssh(tmp_path)
        self._act(pol, "deny", log=True)
        self._act(pol, "accept", log=False)
        assert "logging" not in _term(pol, "allow-tcp-SSH")

    def test_a_scored_term_is_not_denied(self, tmp_path, capsys):
        pol = _ssh(tmp_path, note="\n        # [score] the availability check reaches this")
        self._act(pol, "deny", log=True)
        assert _term(pol, "allow-tcp-SSH")["action"] == "accept"
        assert "scored" in capsys.readouterr().out
        self._act(pol, "deny", log=True, force=True)
        assert _term(pol, "allow-tcp-SSH")["action"] == "deny"
