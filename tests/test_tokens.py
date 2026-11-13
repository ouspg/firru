import socket

import pytest

from firru.tokens import normalize_token, is_ip_land, proto_name


class TestNormalizeToken:
    def test_fqdn_dots_become_underscores(self):
        assert normalize_token("host.example.com") == "host_example_com"

    def test_hyphens_preserved_and_lowercased(self):
        assert normalize_token("Web-01") == "web-01"

    def test_ipv4_becomes_v4_token(self):
        assert normalize_token("1.2.3.4") == "v4_1_2_3_4_32"

    def test_ipv4_cidr(self):
        assert normalize_token("10.0.0.0/24") == "v4_10_0_0_0_24"

    def test_ipv6(self):
        assert normalize_token("2001:db8::1") == "v6_2001_db8__1_128"

    def test_other_punctuation_replaced(self):
        assert normalize_token("a b/c") == "a_b_c"

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            normalize_token("")


class TestIsIpLand:
    @pytest.mark.parametrize("addr", ["1.2.3.4", "10.0.0.0/24", "2001:db8::/32", "::1"])
    def test_valid(self, addr):
        assert is_ip_land(addr) is True

    @pytest.mark.parametrize("addr", ["host.example.com", "web-01", "notanip", ""])
    def test_invalid(self, addr):
        assert is_ip_land(addr) is False


class TestProtoName:
    def test_tcp(self):
        assert proto_name(socket.IPPROTO_TCP) == "tcp"

    def test_udp(self):
        assert proto_name(socket.IPPROTO_UDP) == "udp"

    def test_unknown_number(self):
        assert proto_name(200) == "other(200)"


class TestAliasTokens:
    """A token that only names another token must not shadow the one that
    actually defines the address (firru/annotator.py:_is_alias)."""

    def _defs(self, tmp_path):
        import textwrap
        d = tmp_path / "def"
        d.mkdir(exist_ok=True)
        (d / "networks.yml").write_text(textwrap.dedent("""\
            networks:
              real_host_example_org:
                values:
                  - address: 10.0.0.5
              FW_PLACEHOLDER:
                values:
                  - address: real_host_example_org
              SUBNET:
                values:
                  - address: 10.0.0.0/24
        """))
        (d / "services.yml").write_text("services:\n  SSH:\n    - {port: 22, protocol: tcp}\n")
        return str(d)

    def test_the_defining_token_wins_over_the_alias(self, tmp_path):
        from firru.annotator import PolicyAnnotator
        ann = PolicyAnnotator(self._defs(tmp_path))
        assert ann.annotate_ip("10.0.0.5")["host"] == "real_host_example_org"

    def test_the_alias_is_recognised_as_one(self, tmp_path):
        from firru.annotator import PolicyAnnotator
        ann = PolicyAnnotator(self._defs(tmp_path))
        assert ann._is_alias("FW_PLACEHOLDER") is True
        assert ann._is_alias("real_host_example_org") is False
        assert ann._is_alias("SUBNET") is False

    def test_an_address_only_the_alias_covers_still_resolves(self, tmp_path):
        # Deprioritising an alias must not mean dropping it.
        from firru.annotator import PolicyAnnotator
        ann = PolicyAnnotator(self._defs(tmp_path))
        assert ann.annotate_ip("10.0.0.5")["type"] == "HOST"
