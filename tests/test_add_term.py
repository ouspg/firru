"""add-term: copy a term by name from a proposal or loot, before the
terminal, with its comments; never twice, never a different term's place."""

import argparse
import textwrap

from ruyaml import YAML

from firru.cli.edit import cmd_add_term
from tests.test_edit_more import DROP, _defs, _pol, _t, _write


def _add(tmp_path, pol, new, *terms, replace=None):
    defs = tmp_path / "def"
    return cmd_add_term(argparse.Namespace(
        pol=pol, from_=new, terms=list(terms), replace=replace,
        defs=str(defs) if defs.exists() else _defs(tmp_path), direction="both"))


def _names(pol):
    return [t["name"] for t in YAML().load(open(pol))["filters"][0]["terms"]]


POL = [_t("allow-tcp-SSH", "SSH"),
       "      # keep HTTP open for vendor\n" + _t("allow-tcp-HTTP", "HTTP"), DROP]
NEW = [_t("allow-tcp-SSH", "SSH", src="NET_MGMT"),
       "      # [auto] IPv4 10.0.0.5 (mysqld)\n" + _t("allow-tcp-MYSQL", "MYSQL")]


def _pair(tmp_path):
    return _write(tmp_path, "pol.yml", _pol(POL)), _write(tmp_path, "new.yml", _pol(NEW))


def test_goes_in_before_the_terminal_with_its_evidence(tmp_path):
    pol, new = _pair(tmp_path)
    assert _add(tmp_path, pol, new, "allow-tcp-MYSQL") == 0
    assert _names(pol) == ["allow-tcp-SSH", "allow-tcp-HTTP", "allow-tcp-MYSQL", "drop-ANY"]
    assert "[auto] IPv4 10.0.0.5 (mysqld)" in open(pol).read()


def test_only_the_named_term_changes(tmp_path):
    """NEW narrows SSH too; add-term does not carry that across."""
    pol, new = _pair(tmp_path)
    _add(tmp_path, pol, new, "allow-tcp-MYSQL")
    ssh = YAML().load(open(pol))["filters"][0]["terms"][0]
    assert "source-address" not in ssh
    assert "keep HTTP open for vendor" in open(pol).read()


def test_twice_is_once(tmp_path, capsys):
    pol, new = _pair(tmp_path)
    _add(tmp_path, pol, new, "allow-tcp-MYSQL")
    _add(tmp_path, pol, new, "allow-tcp-MYSQL")
    assert _names(pol).count("allow-tcp-MYSQL") == 1
    assert "already has" in capsys.readouterr().err


def test_a_term_new_lacks_is_an_error(tmp_path):
    pol, new = _pair(tmp_path)
    before = open(pol).read()
    assert _add(tmp_path, pol, new, "allow-tcp-NOPE") == 1
    assert open(pol).read() == before


def test_replace_needs_one_term(tmp_path):
    pol, new = _pair(tmp_path)
    assert _add(tmp_path, pol, new, "allow-tcp-SSH", "allow-tcp-MYSQL",
                replace="allow-tcp-HTTP") == 1
