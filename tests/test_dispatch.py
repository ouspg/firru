"""The `firru` umbrella dispatches verbs to the right module main()."""

import sys

import pytest

from firru.cli import dispatch


def _run(argv, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["firru", *argv])
    try:
        dispatch.main()
    except SystemExit as e:
        return e.code
    return 0


def test_help_lists_verbs(monkeypatch, capsys):
    rc = _run([], monkeypatch)
    out = capsys.readouterr().out
    assert rc == 0
    for verb in ("synth", "score", "tighten", "merge-zones", "diff", "apply", "set-source", "rm"):
        assert verb in out


def test_unknown_verb_errors(monkeypatch, capsys):
    rc = _run(["bogus"], monkeypatch)
    assert rc == 2
    assert "unknown command" in capsys.readouterr().err


def test_edit_verb_delegates_to_edit(monkeypatch):
    """`firru diff …` reaches edit.main with the verb restored as argv[1]."""
    seen = {}

    def fake_edit_main():
        seen["argv"] = list(sys.argv)
        raise SystemExit(0)

    monkeypatch.setattr("firru.cli.edit.main", fake_edit_main)
    rc = _run(["diff", "a.yml", "b.yml", "--defs", "def"], monkeypatch)
    assert rc == 0
    assert seen["argv"] == ["firru", "diff", "a.yml", "b.yml", "--defs", "def"]


def test_module_verb_delegates(monkeypatch):
    """`firru score …` reaches score_policy.main with argv rewritten."""
    seen = {}

    def fake_main():
        seen["argv"] = list(sys.argv)
        return 0

    monkeypatch.setattr("firru.cli.score_policy.main", fake_main)
    rc = _run(["score", "--scoring", "s.yml", "pol/"], monkeypatch)
    assert rc == 0
    assert seen["argv"] == ["firru score", "--scoring", "s.yml", "pol/"]
