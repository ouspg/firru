"""Tighten counts a peer whose flows all went unanswered, and says so.

The window need not have run under the policy being tightened, so a refused
attempt is still evidence that someone tried. But a peer that was never
answered did not use the service, and a reviewer reading `[ADMIN, web1, win1]`
should see which of the three that was.
"""
import json
from collections import Counter, defaultdict

import pytest

from firru import flows
from firru.cli.tighten import Hits, _bucket_flow, collect_flows_from_file, summarise_annotations


class _Defs:
    def GetPortParents(self, port, proto):
        return {(389, "tcp"): ["LDAP"]}.get((port, proto), [])


class _Ann:
    def annotate_ip(self, ip):
        return {"type": "HOST", "host": {"10.0.0.2": "win1", "10.0.0.3": "web1"}[ip], "parents": []}


def _flow(src, responded=None):
    f = {"protocol": "tcp", "src_ip": src, "dst_ip": "10.0.0.1", "dst_port": 389}
    if responded is not None:
        f["responded"] = responded
    return f


def _write(tmp_path, rows):
    p = tmp_path / "flows.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return str(p)


class TestGrouping:
    def test_only_an_explicit_false_counts(self, tmp_path):
        """Absent is not zero: a flow without `responded` says nothing."""
        path = _write(tmp_path, [_flow("10.0.0.3", False), _flow("10.0.0.3", True),
                                 _flow("10.0.0.3")])
        (g,) = flows.iter_flow_groups(path)
        assert (g["n"], g["unanswered"]) == (3, 1)

    # parquet: tests/test_zeek_flow_source.py


class TestBucketing:
    def test_collect_keeps_the_unanswered_count(self, tmp_path):
        path = _write(tmp_path, [_flow("10.0.0.2", True)] * 3 + [_flow("10.0.0.3", False)] * 2)
        ingress, _, _, _ = collect_flows_from_file(path, ["10.0.0.1"], _Defs())
        hits = ingress[("tcp", "LDAP")]
        assert hits == Counter({"10.0.0.2": 3, "10.0.0.3": 2})
        assert hits.unanswered == Counter({"10.0.0.3": 2})

    def test_a_plain_counter_still_takes_the_hits(self):
        """Callers that pass Counters of their own get hits, not a crash."""
        b = (defaultdict(Counter), defaultdict(Counter), defaultdict(Counter), defaultdict(Counter))
        _bucket_flow(_flow("10.0.0.3", False), {"10.0.0.1"}, _Defs(), *b)
        assert b[0][("tcp", "LDAP")] == Counter({"10.0.0.3": 1})

    def test_merging_carries_the_count(self):
        a, b = Hits({"10.0.0.3": 2}), Hits({"10.0.0.3": 1})
        a.unanswered["10.0.0.3"] = 2
        merged = Hits()
        merged.merge(a)
        merged.merge(b)
        assert (merged["10.0.0.3"], merged.unanswered["10.0.0.3"]) == (3, 2)


class TestComment:
    def _comment(self, hits, unanswered):
        h = Hits(hits)
        h.unanswered.update(unanswered)
        return summarise_annotations(h, _Ann())[0]

    def test_a_peer_never_answered_is_tagged(self):
        assert self._comment({"10.0.0.2": 30, "10.0.0.3": 6}, {"10.0.0.3": 6}) == \
            "30 hits: win1 (10.0.0.2) | 6 hits: web1 (10.0.0.3) [never answered]"

    def test_a_peer_answered_sometimes_says_how_often_not(self):
        assert self._comment({"10.0.0.3": 6}, {"10.0.0.3": 2}) == \
            "6 hits: web1 (10.0.0.3) [2 unanswered]"

    @pytest.mark.parametrize("counter", [Counter({"10.0.0.2": 3}), Hits({"10.0.0.2": 3})])
    def test_answered_or_unknown_is_untagged(self, counter):
        assert summarise_annotations(counter, _Ann())[0] == "3 hits: win1 (10.0.0.2)"
