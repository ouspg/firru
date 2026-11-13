"""merge-zones against the policy shapes the egress work now produces:
destination-address group tokens, log-accept terms with `logging`, and hosts
whose egress carries real terms but still ends open."""

import textwrap

import pytest
from aerleon.lib import naming

from firru.cli.merge_zones import (collect_terms, emit_zone_yaml,
                                   is_placeholder_egress, zone_networks)


@pytest.fixture
def defs(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH:
            - {port: 22, protocol: tcp}
          HTTPS:
            - {port: 443, protocol: tcp}
    """))
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          NET_DMZ:
            values:
              - address: 10.1.0.0/24
          H1:
            values:
              - address: 10.1.0.5/32
          H2:
            values:
              - address: 10.1.0.6/32
          h1:
            values:
              - address: 10.1.0.5/32
          EXTERN:
            values:
              - address: 172.16.0.0/16
          DNS_CDN:
            values:
              - address: 142.250.0.1/32
    """))
    return naming.Naming(str(d))


def _filters(in_terms, out_terms):
    return [
        {"header": {"targets": {"nftables": "mixed input DROP"}}, "terms": in_terms},
        {"header": {"targets": {"nftables": "mixed output"}}, "terms": out_terms},
    ]


ALLOW_ANY = {"name": "allow-ANY", "action": "accept"}
EG_GROUP = {"name": "allow-egress-https-dns", "protocol": "tcp",
            "destination-port": "HTTPS", "destination-address": "DNS_CDN",
            "action": "accept"}
EG_LOGACCEPT = {"name": "log-accept-egress-https", "protocol": "tcp",
                "destination-port": "HTTPS", "action": "accept", "logging": True}


class TestPlaceholder:
    def test_bare_allow_any_is_a_placeholder(self):
        assert is_placeholder_egress([ALLOW_ANY, {"name": "d", "action": "deny"}])

    def test_real_terms_are_not(self):
        assert not is_placeholder_egress([EG_GROUP, ALLOW_ANY])


class TestCollect:
    def _collect(self, defs, out_terms, host="h1"):
        z = zone_networks("NET_DMZ", defs)
        return collect_terms(host, "NET_DMZ", z, _filters(
            [{"name": "allow-tcp-SSH", "protocol": "tcp", "destination-port": "SSH",
              "source-address": "EXTERN", "action": "accept"}], out_terms), defs)

    def test_group_token_egress_is_collected(self, defs):
        _, _, egress = self._collect(defs, [EG_GROUP, ALLOW_ANY])
        assert [t.get("name") for t, _ in egress] == ["allow-egress-https-dns"]

    def test_log_accept_egress_is_collected_with_logging(self, defs):
        _, _, egress = self._collect(defs, [EG_LOGACCEPT, ALLOW_ANY])
        assert egress and egress[0][0].get("logging") is True

    def test_an_open_end_with_real_terms_is_noted(self, defs, capsys):
        self._collect(defs, [EG_GROUP, ALLOW_ANY])
        assert "still ends open" in capsys.readouterr().err

    def test_a_closed_egress_is_not_noted(self, defs, capsys):
        self._collect(defs, [EG_GROUP, {"name": "log-drop-egress-ANY",
                                        "action": "deny", "logging": True}])
        assert "still ends open" not in capsys.readouterr().err


class TestZoneEgress:
    def _zone(self, defs, terminal):
        z = zone_networks("NET_DMZ", defs)
        data = {"hosts": set(), "ingress": [], "intrazone": [], "egress": []}
        for host in ("h1", "h2"):
            _, _, eg = collect_terms(host, "NET_DMZ", z,
                                     _filters([], [EG_GROUP, EG_LOGACCEPT, ALLOW_ANY]),
                                     defs)
            data["hosts"].add(host)
            data["egress"].extend(eg)
        return emit_zone_yaml("NET_DMZ", data, terminal=terminal, defs=defs)

    def _out_filter(self, doc):
        return [f for f in doc["filters"] if "output" in str(f["header"])][0]

    def test_the_egress_terminal_follows_the_mode(self, defs):
        terms = self._out_filter(self._zone(defs, "log-drop"))["terms"]
        last = terms[-1]
        assert last["name"] == "log-drop-ANY-egress"
        assert last["action"] == "deny" and last.get("logging") is True

    def test_log_accept_mode_keeps_egress_open_but_logged(self, defs):
        # The regression: this used to be a hardcoded deny-ANY, silently
        # dropping at the zone edge what the host's log-accept stage allows.
        last = self._out_filter(self._zone(defs, "log-accept"))["terms"][-1]
        assert last["action"] == "accept" and last.get("logging") is True

    def test_group_destination_survives_the_merge(self, defs):
        terms = self._out_filter(self._zone(defs, "drop"))["terms"]
        dns = [t for t in terms if t.get("destination-address") == "DNS_CDN"]
        assert dns, [t.get("name") for t in terms]

    def test_logging_survives_the_merge(self, defs):
        terms = self._out_filter(self._zone(defs, "drop"))["terms"]
        assert any(t.get("logging") is True and t.get("destination-port") == "HTTPS"
                   and t.get("destination-address") is None for t in terms)

    def test_terminal_names_do_not_collide_with_ingress(self, defs):
        doc = self._zone(defs, "log-drop")
        names = [t["name"] for f in doc["filters"] for t in f["terms"]]
        assert len(names) == len(set(names))


class TestMultiSourceMerge:
    """A port carrying more than one source across the zone (mgmt-restricted on
    most hosts, wider on a few) must still merge each distinct source into one
    term — not explode every host — while warning about the inconsistency."""

    def _defs(self, tmp_path):
        d = tmp_path / "def"
        d.mkdir()
        (d / "services.yml").write_text(textwrap.dedent("""\
            services:
              WRM:
                - {port: 5985, protocol: tcp}
        """))
        (d / "networks.yml").write_text(textwrap.dedent("""\
            networks:
              ZONE:
                values: [{address: 10.0.0.0/24}]
              MGMT:
                values: [{address: 10.9.0.0/16}]
              WIDE:
                values: [{address: 0.0.0.0/0}]
        """) + "".join(
            f"  h{i}:\n    values: [{{address: 10.0.0.{i}/32}}]\n" for i in range(1, 8)))
        from aerleon.lib import naming
        return naming.Naming(str(d))

    def _term(self, src):
        return {"name": "allow-tcp-WRM", "protocol": "tcp",
                "destination-port": "WRM", "source-address": src, "action": "accept"}

    def test_identical_source_hosts_collapse_despite_an_outlier(self, tmp_path):
        from firru.cli.merge_zones import merge_terms
        # h1..h5 share MGMT; h6, h7 are wider. Five must become one term.
        hosts = [(self._term("MGMT"), f"h{i}") for i in range(1, 6)]
        hosts += [(self._term("WIDE"), "h6"), (self._term("WIDE"), "h7")]
        merged, warnings = merge_terms(hosts, "ZONE", [f"h{i}" for i in range(1, 8)],
                                       defs=self._defs(tmp_path))
        by_src = {}
        for t in merged:
            by_src.setdefault(str(t.get("source-address")), []).append(t)
        assert len(by_src["MGMT"]) == 1        # collapsed, not five
        assert len(by_src["WIDE"]) == 1        # collapsed, not two
        assert warnings                        # still flagged as inconsistent

    def test_the_merged_names_do_not_collide(self, tmp_path):
        from firru.cli.merge_zones import merge_terms
        hosts = [(self._term("MGMT"), f"h{i}") for i in range(1, 4)]
        hosts += [(self._term("WIDE"), f"h{i}") for i in range(4, 7)]
        merged, _ = merge_terms(hosts, "ZONE", [f"h{i}" for i in range(1, 7)],
                                defs=self._defs(tmp_path))
        names = [t["name"] for t in merged]
        assert len(names) == len(set(names))
        assert any("MGMT" in n for n in names) and any("WIDE" in n for n in names)

    def test_a_single_source_zone_keeps_the_plain_shared_name(self, tmp_path):
        # backward compatibility: no disambiguation when the port is consistent
        from firru.cli.merge_zones import merge_terms
        hosts = [(self._term("MGMT"), f"h{i}") for i in range(1, 4)]
        merged, warnings = merge_terms(hosts, "ZONE", ["h1", "h2", "h3"],
                                       defs=self._defs(tmp_path))
        assert len(merged) == 1
        assert merged[0]["name"] == "allow-tcp-WRM-shared"
        assert not warnings

    def test_a_source_only_one_host_uses_stays_that_host(self, tmp_path):
        from firru.cli.merge_zones import merge_terms
        hosts = [(self._term("MGMT"), f"h{i}") for i in range(1, 4)]
        hosts += [(self._term("WIDE"), "h4")]  # lone outlier
        merged, _ = merge_terms(hosts, "ZONE", [f"h{i}" for i in range(1, 5)],
                                defs=self._defs(tmp_path))
        lone = [t for t in merged if t.get("source-address") == "WIDE"]
        assert len(lone) == 1 and lone[0]["destination-address"] == "h4"
        assert lone[0]["name"].startswith("h4-")


class TestTerminalCompiles:
    """The terminal rule must use aerleon's action keyword (`deny`), not the
    nftables output word (`drop`): a log-drop zone that emitted `action: drop`
    was rejected by the compiler, so no such zone ever deployed."""

    def test_build_terminal_rule_uses_a_valid_action(self):
        from firru.cli.merge_zones import build_terminal_rule
        for mode in ("log-accept", "log-drop", "drop"):
            assert build_terminal_rule(mode)["action"] in ("accept", "deny")

    def test_log_drop_keeps_logging(self):
        from firru.cli.merge_zones import build_terminal_rule
        t = build_terminal_rule("log-drop")
        assert t["action"] == "deny" and t["logging"] is True

    def test_a_log_drop_zone_compiles(self, defs, tmp_path):
        # end to end: emit a zone with a log-drop terminal and run aerleon.
        from aerleon import api
        from firru.cli.merge_zones import (collect_terms, emit_zone_yaml,
                                          zone_networks)
        z = zone_networks("NET_DMZ", defs)
        data = {"hosts": set(), "ingress": [], "intrazone": [], "egress": []}
        ingress, intra, egress = collect_terms("H1", "NET_DMZ", z, _filters(
            [{"name": "allow-tcp-SSH", "protocol": "tcp", "destination-port": "SSH",
              "source-address": "EXTERN", "action": "accept"}], [ALLOW_ANY]), defs)
        data["hosts"].add("H1")
        data["ingress"].extend(ingress)
        doc = emit_zone_yaml("NET_DMZ", data, terminal="log-drop", defs=defs)
        out = api.Generate([doc], defs)  # raises on an invalid action
        assert out


class TestHostIdentity:
    """The file name is the inventory token; metadata.host is the collector's
    label, which two zones can share. A host the definitions cannot address
    stays out of its zone rather than becoming an undefined token."""

    def _policy(self, path, host):
        import yaml
        path.write_text(yaml.safe_dump({
            "metadata": {"host": host, "zone": "NET_DMZ"},
            "filters": _filters([{"name": "allow-tcp-SSH", "protocol": "tcp",
                                  "destination-port": "SSH", "action": "accept"}],
                                [ALLOW_ANY])}))
        return str(path)

    def test_the_file_token_wins_over_a_shared_label(self, defs, tmp_path):
        from firru.cli.merge_zones import build_zones
        zones = build_zones([self._policy(tmp_path / "H2.yml", "www")], defs)
        assert zones["NET_DMZ"]["hosts"] == {"H2"}

    def test_a_host_with_no_addresses_is_left_out(self, defs, tmp_path, capsys):
        from firru.cli.merge_zones import build_zones
        zones = build_zones([self._policy(tmp_path / "siem.yml", "siem-server"),
                             self._policy(tmp_path / "H1.yml", "h1")], defs)
        assert zones["NET_DMZ"]["hosts"] == {"H1"}
        assert "no addresses for 'siem-server'" in capsys.readouterr().err
