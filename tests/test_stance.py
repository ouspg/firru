"""The enforcement stance: what each stage writes is what `firru stance` reads."""

import json

import pytest

from firru import stance as st
from firru.cli import dispatch
from firru.cli.merge_zones import build_terminal_rule
from firru.cli.stance import main as stance_main


@pytest.mark.parametrize("stage", st.STAGES)
def test_every_stage_reads_back_as_itself(stage):
    assert st.stance_of_term(st.terminal_term(stage)) == stage


@pytest.mark.parametrize("stage", st.STAGES)
def test_merge_zones_terminal_is_the_stance_terminal(stage):
    assert build_terminal_rule(stage) == st.terminal_term(stage)


def test_terminal_term_is_a_fresh_dict():
    st.terminal_term(st.DROP)["name"] = "mutated"
    assert st.terminal_term(st.DROP)["name"] == "drop-ANY"


def test_unknown_stage_fails_where_it_is_made():
    with pytest.raises(ValueError):
        st.terminal_term("log_drop")


def test_progression_and_fallback():
    assert [st.next_stage(s) for s in st.STAGES] == [st.LOG_DROP, st.DROP, None]
    assert [st.previous_stage(s) for s in st.STAGES] == [None, st.LOG_ACCEPT, st.LOG_DROP]
    assert st.next_stage(st.OPEN) is None and st.next_stage(st.NONE) is None


def test_the_name_is_a_label_not_the_stage():
    # Behavior decides: a renamed term, and the egress variants, read the same.
    for name in ("log-drop-ANY-egress", "renamed-by-hand", "whatever"):
        assert st.stance_of_term({"name": name, "action": "deny", "logging": True}) == st.LOG_DROP


def test_open_end_is_not_a_stage_of_the_progression():
    assert st.stance_of_term({"name": "allow-ANY", "action": "accept"}) == st.OPEN
    assert st.OPEN not in st.STAGES


def test_last_catch_all_decides_and_scoped_terms_are_ignored():
    terms = [{"name": "ssh", "protocol": "tcp", "destination-port": "SSH", "action": "accept"},
             st.terminal_term(st.LOG_DROP),
             {"name": "late", "protocol": "tcp", "action": "accept"}]
    assert st.stance_of_terms(terms) == st.LOG_DROP
    assert st.stance_of_terms(terms[:1]) == st.NONE


def _doc(header, terms):
    return {"metadata": {"host": "h"}, "filters": [{"header": header, "terms": terms}]}


def test_policy_stances_per_side_and_silent_when_direction_unstated():
    both = {"filters": [
        {"header": {"targets": {"nftables": "inet input"}}, "terms": [st.terminal_term(st.DROP)]},
        {"header": {"targets": {"nftables": "inet output"}}, "terms": [st.terminal_term(st.LOG_ACCEPT)]},
    ]}
    assert st.policy_stances(both) == {"in": st.DROP, "out": st.LOG_ACCEPT}
    zone_pair = _doc({"targets": {"paloaltofw": "from-zone a to-zone b"}}, [st.terminal_term(st.DROP)])
    assert st.policy_stances(zone_pair) == {}


def test_cli_reports_and_filters(tmp_path, capsys):
    p = tmp_path / "h.yml"
    p.write_text(json.dumps(_doc({"targets": {"nftables": "inet input"}},
                                 [st.terminal_term(st.LOG_ACCEPT)])))   # JSON is YAML
    bad = tmp_path / "bad.yml"
    bad.write_text("just: a mapping\n")
    assert stance_main([str(p), "-o", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["policies"][0]["stance"] == {"in": "log-accept"}
    assert out["policies"][0]["next"] == {"in": "log-drop"}
    assert stance_main([str(p), "--at", "drop"]) == 0
    assert capsys.readouterr().out == ""
    assert stance_main([str(p), str(bad)]) == 2        # unreadable is loud, not silent


def test_dispatch_routes_and_lists_the_verb(capsys):
    assert dispatch.dispatch_argv([]) == 0
    assert "stance" in capsys.readouterr().out
    assert dispatch.dispatch_argv(["stance", "/nonexistent.yml"]) == 2
