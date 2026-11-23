"""propose -o sh: each change as a firru command whose verb is its class and
whose trailing comment is its reason; nothing that widens runs by accident."""

import textwrap

from aerleon.lib import naming
from ruyaml import YAML

from firru.cli.propose_sh import egress_lines, ingress_lines

P = "h1.yml"


def _defs(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH: [{port: 22, protocol: tcp}]
          HTTP: [{port: 80, protocol: tcp}]
          GOSSIP: [{port: 7946, protocol: tcp}, {port: 7946, protocol: udp}]
          GOSSIP-TCP: [{port: 7946, protocol: tcp}]
    """))
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          A: {values: [{address: 10.0.0.1/32}]}
          B: {values: [{address: 10.0.0.2/32}]}
          C: {values: [{address: 10.0.0.3/32}]}
          GRP: {values: [{address: 10.0.0.0/29}]}
          ANY_V4: {values: [{address: 0.0.0.0/0}]}
          V6HOST: {values: [{address: "2001:db8::1/128"}]}
          WEB: {values: [{address: 192.0.2.10/32}]}
    """))
    return naming.Naming(str(d))


def _doc(*terms, egress=()):
    y = YAML()
    body = "\n".join(terms)
    eg = "\n".join(egress) or "      - {name: allow-ANY, action: accept}"
    return y.load(textwrap.dedent("""\
        metadata: {host: h1}
        filters:
          - header: {targets: {nftables: mixed input DROP}}
            terms:
        """) + body + "\n      - {name: drop-ANY, action: deny}\n"
        + "  - header: {targets: {nftables: mixed output}}\n    terms:\n" + eg + "\n")


def _t(name, svc, src=None, proto="tcp", extra=""):
    s = f"      - {{name: {name}, protocol: {proto}, destination-port: {svc}, action: accept"
    s += f", source-address: {src}" if src else ""
    return s + extra + "}"


def _lines(tmp_path, old, new, unused=(), declared=lambda svc: []):
    return ingress_lines(P, old, new, _defs(tmp_path), list(unused), declared)


class TestNarrowing:
    def test_from_any_is_set_source_and_runs(self, tmp_path):
        (line,) = _lines(tmp_path, _doc(_t("allow-tcp-SSH", "SSH")),
                         _doc(_t("allow-tcp-SSH", "SSH", "A")))
        assert line == f"firru set-source {P} allow-tcp-SSH A  # narrowed observed: ANY -> [A]"

    def test_a_subset_is_remove_source(self, tmp_path):
        (line,) = _lines(tmp_path, _doc(_t("allow-tcp-SSH", "SSH", "[A, B, C]")),
                         _doc(_t("allow-tcp-SSH", "SSH", "[A, C]")))
        assert line.startswith(f"firru remove-source {P} allow-tcp-SSH B  # narrowed observed")

    def test_a_group_replaced_by_a_member_is_set_source(self, tmp_path):
        """Removing GRP would leave nothing: the term would become a deny."""
        (line,) = _lines(tmp_path, _doc(_t("allow-tcp-SSH", "SSH", "GRP")),
                         _doc(_t("allow-tcp-SSH", "SSH", "A")))
        assert line.startswith(f"firru set-source {P} allow-tcp-SSH A  # narrowed observed")

    def test_two_terms_on_one_port_are_both_seen(self, tmp_path):
        """A tcp+udp service beside a tcp-only term: both cover tcp/7946."""
        old = _doc(_t("allow-udp-GOSSIP", "GOSSIP", proto="udp"),
                   _t("allow-tcp-GOSSIP", "GOSSIP-TCP", "ANY_V4"))
        new = _doc(_t("allow-udp-GOSSIP", "GOSSIP", "B", proto="udp"),
                   _t("allow-tcp-GOSSIP", "GOSSIP-TCP", "A"))
        names = sorted(l.split()[3] for l in _lines(tmp_path, old, new))
        assert names == ["allow-tcp-GOSSIP", "allow-udp-GOSSIP"]


class TestWidening:
    def test_only_adding_is_a_commented_add_source(self, tmp_path):
        (line,) = _lines(tmp_path, _doc(_t("allow-tcp-SSH", "SSH", "A")),
                         _doc(_t("allow-tcp-SSH", "SSH", "[A, B]")))
        assert line == f"# firru add-source {P} allow-tcp-SSH B  # widened REVIEW: [A] -> [A, B]"

    def test_an_exchange_is_one_commented_set_source(self, tmp_path):
        """Removing A on its own could cut what the proposal kept."""
        (line,) = _lines(tmp_path, _doc(_t("allow-tcp-SSH", "SSH", "[A, B]")),
                         _doc(_t("allow-tcp-SSH", "SSH", "[B, C]")))
        assert line.startswith(f"# firru set-source {P} allow-tcp-SSH B C  # widened REVIEW")

    def test_gaining_a_family_is_a_widening(self, tmp_path):
        (line,) = _lines(tmp_path, _doc(_t("allow-tcp-SSH", "SSH", "ANY_V4")),
                         _doc(_t("allow-tcp-SSH", "SSH", "[A, V6HOST]")))
        assert line.startswith("# firru set-source") and "widened REVIEW: ANY_V4 -> [A, V6HOST]" in line


class TestUnexercised:
    U = [{"name": "allow-tcp-HTTP", "svc": "HTTP", "proto": "tcp", "source": "ANY"}]

    def test_denied_and_logged(self, tmp_path):
        doc = _doc(_t("allow-tcp-HTTP", "HTTP"))
        (line,) = _lines(tmp_path, doc, doc, self.U)
        assert line == (f"firru set-action {P} allow-tcp-HTTP deny --log  "
                        f"# denied unexercised: no flows in the window")

    def test_declared_is_pinned(self, tmp_path):
        doc = _doc(_t("allow-tcp-HTTP", "HTTP", "A"))
        (line,) = _lines(tmp_path, doc, doc, self.U, declared=lambda svc: ["A"])
        assert line.startswith("# allow-tcp-HTTP") and line.endswith("# pinned")

    def test_scored_is_pinned(self, tmp_path):
        y = YAML()
        doc = y.load(textwrap.dedent("""\
            metadata: {host: h1}
            filters:
              - header: {targets: {nftables: mixed input DROP}}
                terms:
                  - name: allow-tcp-HTTP
                    protocol: tcp
                    destination-port: HTTP
                    action: accept
            # [score] the availability check reaches this
                  - {name: drop-ANY, action: deny}
            """))
        (line,) = _lines(tmp_path, doc, doc, self.U)
        assert "scored" in line and line.endswith("# pinned")


def test_egress_is_always_a_comment(tmp_path):
    old = _doc(_t("allow-tcp-SSH", "SSH"))
    new = _doc(_t("allow-tcp-SSH", "SSH"),
               egress=["      - {name: allow-egress-HTTP, protocol: tcp, destination-port: HTTP, "
                       "destination-address: WEB, action: accept}"])
    lines = egress_lines(P, "proposals/h1.yml", "def", old, new, _defs(tmp_path))
    assert lines and all(l.startswith("# firru ") and "egress proposed" in l for l in lines)
