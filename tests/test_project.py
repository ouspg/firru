"""firru.toml: finding the project, its windows, and reading flows for one."""

import argparse
import json
from datetime import datetime, timezone

import pytest

from firru import project
from firru.flows import iter_flow_groups

TOML = """\
[flows]
store = "flows"
timezone = "+02:00"

[windows]
night = ["2030-01-21 19:00", "2030-01-22 08:00"]
"""


def args(**kw):
    a = argparse.Namespace(window=None, since=None, until=None)
    for k, v in kw.items():
        setattr(a, k, v)
    return a


def utc(text):
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp()


@pytest.fixture
def proj(tmp_path, monkeypatch):
    monkeypatch.delenv("FIRRU_PROJECT", raising=False)
    (tmp_path / "firru.toml").write_text(TOML)
    (tmp_path / "sub" / "deeper").mkdir(parents=True)
    return tmp_path


def test_the_project_is_found_from_below_it(proj, monkeypatch):
    monkeypatch.chdir(proj / "sub" / "deeper")
    p = project.find()
    assert p.root == proj and p.store == proj / "flows" and p.zone == "+02:00"


def test_firru_project_overrides_the_search(proj, tmp_path_factory, monkeypatch):
    other = tmp_path_factory.mktemp("elsewhere")
    monkeypatch.chdir(other)
    assert project.find() is None
    monkeypatch.setenv("FIRRU_PROJECT", str(proj))
    assert project.find().root == proj


def test_a_window_must_be_two_times(tmp_path):
    (tmp_path / "firru.toml").write_text('[windows]\nnight = "19:00"\n')
    with pytest.raises(ValueError, match="night"):
        project.load(tmp_path)


def test_a_named_window_is_read_in_the_projects_zone(proj):
    p = project.load(proj)
    assert project.window_from_args(args(window="night"), p) == (
        utc("2030-01-21 17:00"), utc("2030-01-22 06:00"))


def test_since_and_until_override_the_windows_ends(proj):
    p = project.load(proj)
    lo, hi = project.window_from_args(args(window="night", since="night 23:00"), p)
    assert lo == utc("2030-01-21 21:00") and hi == utc("2030-01-22 06:00")


def test_since_alone_is_open_ended(proj):
    p = project.load(proj)
    assert project.window_from_args(args(since="2030-01-21 12:00 UTC"), p) == (
        utc("2030-01-21 12:00"), None)


def test_an_unknown_window_names_the_known_ones(proj):
    with pytest.raises(ValueError, match="known: night"):
        project.window_from_args(args(window="nite"), project.load(proj))


def test_without_a_project_times_are_utc_and_there_are_no_names():
    assert project.window_from_args(args(since="2030-01-21 12:00", until="2030-01-21 13:00")) == (
        utc("2030-01-21 12:00"), utc("2030-01-21 13:00"))
    with pytest.raises(ValueError, match="no firru.toml"):
        project.window_from_args(args(window="night"))


def test_a_window_without_flows_takes_the_projects_store(proj, monkeypatch):
    monkeypatch.chdir(proj)
    flows, span, label = project.flows_for(args(window="night"))
    assert flows == "flows" and span[0] == utc("2030-01-21 17:00")
    assert label.startswith("--window night: 2030-01-21 17:00Z")
    assert project.flows_for(args()) == (None, None, None)


FLOWS = [  # (timestamp, src, responded)
    (utc("2030-01-21 16:59"), "10.0.0.1", True),     # before night
    (utc("2030-01-21 17:00"), "10.0.0.2", True),     # its first second
    (utc("2030-01-21 23:30"), "10.0.0.3", False),
    (utc("2030-01-22 05:59"), "10.0.0.4", True),
    (utc("2030-01-22 06:00"), "10.0.0.5", True),     # its end: excluded
]


def write_both(tmp_path):
    rows = [{"protocol": "tcp", "src_ip": s, "dst_ip": "10.0.0.9", "dst_port": 22,
             "timestamp": t, "responded": r} for t, s, r in FLOWS]
    jsonl = tmp_path / "flows.jsonl"
    jsonl.write_text("".join(json.dumps(r) + "\n" for r in rows))
    import duckdb
    store = tmp_path / "store"
    duckdb.sql(f"""COPY (SELECT *, strftime(to_timestamp(timestamp), '%Y-%m-%dT%H') AS hour
                   FROM read_json({str(jsonl)!r})) TO {str(store)!r}
                   (FORMAT parquet, PARTITION_BY (hour))""")
    return jsonl, store


def test_jsonl_and_a_partitioned_store_read_the_same_window(tmp_path):
    jsonl, store = write_both(tmp_path)
    span = (utc("2030-01-21 17:00"), utc("2030-01-22 06:00"))
    for path in (jsonl, store):
        got = sorted((g["src_ip"], g["n"], g["unanswered"])
                     for g in iter_flow_groups(str(path), span=span))
        assert got == [("10.0.0.2", 1, 0), ("10.0.0.3", 1, 1), ("10.0.0.4", 1, 0)], path


def test_diff_counts_unanswered_flows_from_a_store(tmp_path):
    # It read one dict per flow with only the four core columns, so a parquet
    # store's `responded` never reached it.
    from firru.cli.edit import _flow_evidence
    _, store = write_both(tmp_path)
    ev = _flow_evidence(str(store), ["10.0.0.9"])
    hits = ev[("in", "tcp", 22)]
    assert sum(hits.values()) == 5 and hits.unanswered == {"10.0.0.3": 1}
