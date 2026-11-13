"""Comment-contract behaviour for aerleon-tighten: rebuilding ingress terms
must refresh only [auto] lines and preserve human + [score] lines."""

import io
import textwrap

from ruyaml import YAML

from firru.cli.tighten import tighten_ingress


class StubDefs:
    def GetService(self, svc):
        raise Exception("not a group")

    def GetPortParents(self, *a):
        return []


class StubAnnotator:
    group_members = {}

    def annotate_ip(self, ip):
        return {"type": "EXTERNAL"}


POL = textwrap.dedent("""\
    terms:
      # [auto] IPv4 10.0.0.5 (postgres) | 900 flows
      # [score] DO NOT BLOCK - partner integration
      # keep ANY until Q3, vendor still migrating
      - name: allow-tcp-POSTGRES
        protocol: tcp
        destination-port: POSTGRES
        source-address: NET_APP
        action: accept
      - name: drop-ANY
        action: deny
""")


def _yaml():
    y = YAML()
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def test_tighten_preserves_human_and_score_lines():
    y = _yaml()
    in_terms = y.load(POL)["terms"]

    # No flows observed → the "source unchanged" [auto] path.
    tightened, _, _, _ = tighten_ingress(
        in_terms, ingress_flows={}, annotator=StubAnnotator(), defs=StubDefs()
    )

    buf = io.StringIO()
    y.dump({"terms": tightened}, buf)
    out = buf.getvalue()

    # Human + [score] lines survived the rebuild
    assert "keep ANY until Q3, vendor still migrating" in out
    assert "[score] DO NOT BLOCK - partner integration" in out
    # Stale [auto] evidence replaced by the fresh [auto] line
    assert "900 flows" not in out
    assert "[auto] no flows observed in window" in out


def test_the_next_terms_auto_line_does_not_travel_with_this_term():
    # ruyaml hangs the comment above term B on term A's source list.
    import ruyaml
    from firru.comments import detached
    doc = ruyaml.YAML().load("terms:\n  - name: a\n    source-address:\n      - X\n"
                             "# [auto] for b\n  - name: b\n    source-address: ANY\n")
    import io
    out = io.StringIO()
    ruyaml.YAML().dump({"terms": [detached(doc["terms"][0])]}, out)
    assert "for b" not in out.getvalue()


def test_a_term_with_no_source_tightens_like_an_any_term():
    # No source-address is any source in aerleon; "was:" says so.
    class Host(StubAnnotator):
        def annotate_ip(self, ip):
            return {"type": "HOST", "host": "app1", "ip": ip}
    y = _yaml()
    terms = y.load("terms:\n  - name: t\n    protocol: tcp\n    destination-port: POSTGRES\n"
                   "    action: accept\n")["terms"]
    flows = {("tcp", "POSTGRES"): {"10.0.0.7": 3}}
    tightened, _, _, _ = tighten_ingress(terms, ingress_flows=flows,
                                         annotator=Host(), defs=StubDefs())
    buf = io.StringIO()
    y.dump({"terms": tightened}, buf)
    assert "source-address: app1  # was: ANY" in buf.getvalue()
