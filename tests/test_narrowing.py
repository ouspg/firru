import textwrap

from aerleon.lib import naming

from firru.policy import (
    ANY_PEERS,
    compare_peers,
    diff_surface,
    peer_families,
    source_peers,
)


def _defs(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH:
            - {port: 22, protocol: tcp}
          HTTP:
            - {port: 80, protocol: tcp}
    """))
    # MGMT is a strict subset of APP; APP_ALIAS is the same addresses under
    # another name; APP6 adds the v6 half of the same estate.
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          APP:
            values:
              - address: 10.0.0.0/24
              - address: 10.0.1.0/24
          APP_ALIAS:
            values:
              - address: 10.0.0.0/24
              - address: 10.0.1.0/24
          MGMT:
            values:
              - address: 10.0.0.0/24
          OTHER:
            values:
              - address: 10.9.9.0/24
          APP6:
            values:
              - address: '2001:db8::/32'
    """))
    return naming.Naming(str(d))


def _pol(terms):
    return {"metadata": {"host": "H1"},
            "filters": [{"header": {"targets": {"nftables": "mixed input DROP"}},
                         "terms": terms}]}


def _term(name, port, src="ANY", proto="tcp"):
    t = {"name": name, "protocol": proto, "destination-port": port, "action": "accept"}
    if src is not None:
        t["source-address"] = src
    return t


class TestSourcePeers:
    def test_any_is_the_universe(self, tmp_path):
        defs = _defs(tmp_path)
        assert source_peers(defs, "ANY") is ANY_PEERS
        assert source_peers(defs, None) is ANY_PEERS
        assert source_peers(defs, ["APP", "ANY_V6"]) is ANY_PEERS

    def test_tokens_resolve_to_addresses(self, tmp_path):
        defs = _defs(tmp_path)
        assert source_peers(defs, "MGMT") < source_peers(defs, "APP")

    def test_rename_resolves_equal(self, tmp_path):
        # The point of resolving: a token renamed is not an enforcement change.
        defs = _defs(tmp_path)
        assert source_peers(defs, "APP") == source_peers(defs, "APP_ALIAS")

    def test_unresolvable_token_falls_back_to_its_name(self, tmp_path):
        defs = _defs(tmp_path)
        assert source_peers(defs, "NO_SUCH_TOKEN") == frozenset({"NO_SUCH_TOKEN"})


class TestComparePeers:
    def test_any_to_tokens_is_narrowing(self, tmp_path):
        defs = _defs(tmp_path)
        assert compare_peers(ANY_PEERS, source_peers(defs, "APP")) == "narrowed"

    def test_tokens_to_any_is_widening(self, tmp_path):
        defs = _defs(tmp_path)
        assert compare_peers(source_peers(defs, "APP"), ANY_PEERS) == "widened"

    def test_subset_is_narrowing(self, tmp_path):
        defs = _defs(tmp_path)
        assert compare_peers(source_peers(defs, "APP"), source_peers(defs, "MGMT")) == "narrowed"

    def test_superset_is_widening(self, tmp_path):
        defs = _defs(tmp_path)
        assert compare_peers(source_peers(defs, "MGMT"), source_peers(defs, "APP")) == "widened"

    def test_an_exchange_of_peers_is_widening(self, tmp_path):
        # Swapping MGMT for OTHER drops one and admits another. It admits
        # somebody new, so it is never mechanical, whatever the net count says.
        defs = _defs(tmp_path)
        assert compare_peers(source_peers(defs, "MGMT"), source_peers(defs, "OTHER")) == "widened"

    def test_equal_is_no_change(self, tmp_path):
        defs = _defs(tmp_path)
        assert compare_peers(source_peers(defs, "APP"), source_peers(defs, "APP_ALIAS")) is None


class TestFamilies:
    def test_any_spans_both(self):
        assert peer_families(ANY_PEERS) == {4, 6}

    def test_v4_only_token(self, tmp_path):
        defs = _defs(tmp_path)
        assert peer_families(source_peers(defs, "APP")) == {4}

    def test_mixed_token_list(self, tmp_path):
        defs = _defs(tmp_path)
        assert peer_families(source_peers(defs, ["APP", "APP6"])) == {4, 6}

    def test_diff_reports_a_dropped_family(self, tmp_path):
        # Tightening ANY to a v4-only token silently stops covering v6.
        defs = _defs(tmp_path)
        old = _pol([_term("allow-tcp-SSH", "SSH")])
        new = _pol([_term("allow-tcp-SSH", "SSH", "APP")])
        result = diff_surface(old, new, defs)
        assert [(ports, o, n) for _, ports, o, n in result["families"]] == \
               [([("in", "tcp", 22)], {4, 6}, {4})]


class TestDiffClassification:
    def test_tightening_is_narrowed_not_modified_only(self, tmp_path):
        defs = _defs(tmp_path)
        old = _pol([_term("allow-tcp-SSH", "SSH")])
        new = _pol([_term("allow-tcp-SSH", "SSH", "APP")])
        r = diff_surface(old, new, defs)
        assert [t.get("name") for t, _ in r["narrowed"]] == ["allow-tcp-SSH"]
        assert r["widened"] == []
        # modified stays as the union, for callers that do not care which
        assert [t.get("name") for t, _ in r["modified"]] == ["allow-tcp-SSH"]

    def test_loosening_is_widened(self, tmp_path):
        defs = _defs(tmp_path)
        old = _pol([_term("allow-tcp-SSH", "SSH", "MGMT")])
        new = _pol([_term("allow-tcp-SSH", "SSH")])
        r = diff_surface(old, new, defs)
        assert [t.get("name") for t, _ in r["widened"]] == ["allow-tcp-SSH"]
        assert r["narrowed"] == []

    def test_rename_of_an_equal_source_is_cosmetic(self, tmp_path):
        defs = _defs(tmp_path)
        old = _pol([_term("allow-tcp-HTTP", "HTTP", "APP")])
        new = _pol([_term("allow-tcp-WEB", "HTTP", "APP_ALIAS")])
        r = diff_surface(old, new, defs)
        assert [t.get("name") for t, _ in r["cosmetic"]] == ["allow-tcp-WEB"]
        assert r["narrowed"] == [] and r["widened"] == []
