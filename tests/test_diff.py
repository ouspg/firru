import textwrap

from aerleon.lib import naming

from firru.policy import diff_surface, normalize_source


def _defs(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH:
            - {port: 22, protocol: tcp}
          HTTP:
            - {port: 80, protocol: tcp}
          HXXP:
            - {port: 80, protocol: tcp}
          POSTGRES:
            - {port: 5432, protocol: tcp}
          DNS:
            - {port: 53, protocol: tcp}
            - {port: 53, protocol: udp}
          RPC_HIGH:
            - {port: 49152-65535, protocol: tcp}
    """))
    (d / "networks.yml").write_text("networks:\n  LOOPBACK:\n    - {address: 127.0.0.1/32}\n")
    return naming.Naming(str(d))


def _pol(terms):
    return {"metadata": {"host": "H1"},
            "filters": [{"header": {"targets": {"nftables": "mixed input DROP"}},
                         "terms": terms}]}


def _term(name, port, src="ANY", proto="tcp"):
    return {"name": name, "protocol": proto, "destination-port": port,
            "source-address": src, "action": "accept"}


class TestNormalizeSource:
    def test_any_variants(self):
        assert normalize_source(None) == "ANY"
        assert normalize_source("ANY_V4") == "ANY"
        assert normalize_source(["NET_A", "ANY_V6"]) == "ANY"

    def test_token_and_list(self):
        assert normalize_source("NET_APP") == "NET_APP"
        assert normalize_source(["NET_B", "NET_A"]) == ("NET_A", "NET_B")


class TestDiffSurface:
    def _run(self, tmp_path):
        defs = _defs(tmp_path)
        old = _pol([
            _term("allow-tcp-SSH", "SSH"),
            _term("allow-tcp-HTTP", "HTTP"),
            _term("allow-tcp-POSTGRES", "POSTGRES", src="NET_APP"),
            _term("allow-tcp-rpc", "RPC_HIGH"),          # unchanged group
        ])
        new = _pol([
            _term("allow-tcp-SSH", "SSH", src="NET_MGMT"),   # modified (enforcement)
            _term("allow-tcp-HXXP", "HXXP"),                 # cosmetic rename of HTTP
            _term("allow-tcp-DNS", "DNS"),                   # added (tcp+udp)
            _term("allow-tcp-rpc", "RPC_HIGH"),              # unchanged group
        ])
        return diff_surface(old, new, defs)

    def test_added(self, tmp_path):
        res = self._run(tmp_path)
        assert len(res["added"]) == 1
        term, ports = res["added"][0]
        assert term["name"] == "allow-tcp-DNS"
        assert set(ports) == {("in", "tcp", 53), ("in", "udp", 53)}

    def test_removed(self, tmp_path):
        res = self._run(tmp_path)
        assert [t["name"] for t, _ in res["removed"]] == ["allow-tcp-POSTGRES"]
        assert res["removed"][0][1] == [("in", "tcp", 5432)]

    def test_modified_enforcement(self, tmp_path):
        res = self._run(tmp_path)
        assert len(res["modified"]) == 1
        term, ports = res["modified"][0]
        assert term["name"] == "allow-tcp-SSH"
        assert ports == [("in", "tcp", 22)]

    def test_cosmetic_rename(self, tmp_path):
        res = self._run(tmp_path)
        assert len(res["cosmetic"]) == 1
        term, ports = res["cosmetic"][0]
        assert term["name"] == "allow-tcp-HXXP"
        assert ports == [("in", "tcp", 80)]

    def test_unchanged_group_absent(self, tmp_path):
        res = self._run(tmp_path)
        allnames = [t["name"] for cls in ("added", "removed", "modified", "cosmetic")
                    for t, _ in res[cls]]
        assert "allow-tcp-rpc" not in allnames  # RPC_HIGH unchanged → no noise

    def test_identical_is_empty(self, tmp_path):
        defs = _defs(tmp_path)
        pol = _pol([_term("allow-tcp-SSH", "SSH")])
        res = diff_surface(pol, pol, defs)
        assert not any(res[k] for k in ("added", "removed", "modified", "cosmetic"))


# ---------------------------------------------------------------------------
# Merged ingress+egress policies
#
# The same (proto, port) means two unrelated things on the two sides, so the
# surface is keyed by direction. Without that, an egress term overwrites the
# ingress term at the same port and the diff compares each against the other's
# peer field: a bounded egress rule read as an unrestricted ingress one.
# ---------------------------------------------------------------------------

def _merged(in_terms, out_terms):
    return {"metadata": {"host": "H1"},
            "filters": [
                {"header": {"targets": {"nftables": "inet filter input"}},
                 "terms": in_terms},
                {"header": {"targets": {"nftables": "inet filter output"}},
                 "terms": out_terms}]}


def _etarget(name, port, dst=None, proto="tcp"):
    t = {"name": name, "protocol": proto, "destination-port": port, "action": "accept"}
    if dst:
        t["destination-address"] = dst
    return t


def _edefs(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          HTTPS:
            - {port: 443, protocol: tcp}
    """))
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          WORKSTATIONS:
            values:
              - address: 10.1.0.0/16
          CDN:
            values:
              - address: 142.250.0.0/16
    """))
    return naming.Naming(str(d))


class TestMergedDirections:
    def _both(self, tmp_path, old_dst, new_dst):
        defs = _edefs(tmp_path)
        ingress = [{"name": "allow-tcp-HTTPS", "protocol": "tcp",
                    "destination-port": "HTTPS", "source-address": "WORKSTATIONS",
                    "action": "accept"}]
        old = _merged(ingress, [_etarget("allow-egress-https", "HTTPS", old_dst)])
        new = _merged(ingress, [_etarget("allow-egress-https", "HTTPS", new_dst)])
        return diff_surface(old, new, defs)

    def test_an_egress_narrowing_is_not_read_as_an_ingress_widening(self, tmp_path):
        # The regression: egress ANY -> CDN was classified as the ingress term
        # widening from WORKSTATIONS to ANY, inverting the sign of the change.
        res = self._both(tmp_path, None, "CDN")
        assert not res["widened"]
        assert [t.get("name") for t, _ in res["narrowed"]] == ["allow-egress-https"]

    def test_an_unchanged_ingress_term_stays_unchanged(self, tmp_path):
        res = self._both(tmp_path, None, "CDN")
        for cls in ("added", "removed", "widened", "cosmetic"):
            assert not any(t.get("name") == "allow-tcp-HTTPS" for t, _ in res[cls])

    def test_the_two_sides_keep_separate_entries_at_one_port(self, tmp_path):
        res = self._both(tmp_path, None, "CDN")
        assert set(res["_new"]) == {("in", "tcp", 443), ("out", "tcp", 443)}

    def test_the_change_carries_its_direction(self, tmp_path):
        _, ports = self._both(tmp_path, None, "CDN")["narrowed"][0]
        assert ports == [("out", "tcp", 443)]

    def test_an_egress_widening_is_still_caught(self, tmp_path):
        res = self._both(tmp_path, "CDN", None)
        assert [t.get("name") for t, _ in res["widened"]] == ["allow-egress-https"]
