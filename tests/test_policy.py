import textwrap

from aerleon.lib import naming

from firru.policy import port_ranges, term_covers


def _defs(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH:
            - port: 22
              protocol: tcp
          DNS:
            - port: 53
              protocol: tcp
            - port: 53
              protocol: udp
          RPC_HIGH:
            - port: 49152-65535
              protocol: tcp
    """))
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          LOOPBACK:
            - address: 127.0.0.1/32
    """))
    return naming.Naming(str(d))


class TestPortRanges:
    def test_single_token(self, tmp_path):
        assert port_ranges(_defs(tmp_path), "SSH", "tcp") == {("tcp", 22, 22)}

    def test_multi_proto_token(self, tmp_path):
        assert port_ranges(_defs(tmp_path), "DNS") == {("tcp", 53, 53), ("udp", 53, 53)}

    def test_group_range_token(self, tmp_path):
        assert port_ranges(_defs(tmp_path), "RPC_HIGH", "tcp") == {("tcp", 49152, 65535)}

    def test_bare_numeric_needs_proto(self, tmp_path):
        d = _defs(tmp_path)
        assert port_ranges(d, 80, "tcp") == {("tcp", 80, 80)}
        assert port_ranges(d, 80, None) == set()

    def test_range_string(self, tmp_path):
        assert port_ranges(_defs(tmp_path), "1000-1002", "udp") == {("udp", 1000, 1002)}

    def test_list(self, tmp_path):
        d = _defs(tmp_path)
        assert port_ranges(d, ["SSH", 80], "tcp") == {("tcp", 22, 22), ("tcp", 80, 80)}

    def test_unknown_and_portless(self, tmp_path):
        d = _defs(tmp_path)
        assert port_ranges(d, "NOPE", "tcp") == set()
        assert port_ranges(d, None, None) == set()


class TestTermCovers:
    def test_direct(self, tmp_path):
        d = _defs(tmp_path)
        t = {"destination-port": "SSH", "protocol": "tcp"}
        assert term_covers(d, t, "tcp", 22)
        assert not term_covers(d, t, "tcp", 23)
        assert not term_covers(d, t, "udp", 22)

    def test_inside_group(self, tmp_path):
        d = _defs(tmp_path)
        t = {"destination-port": "RPC_HIGH", "protocol": "tcp"}
        assert term_covers(d, t, "tcp", 50000)
        assert not term_covers(d, t, "tcp", 22)

    def test_portless_term(self, tmp_path):
        d = _defs(tmp_path)
        assert not term_covers(d, {"source-address": "LOOPBACK", "action": "accept"}, "tcp", 22)
