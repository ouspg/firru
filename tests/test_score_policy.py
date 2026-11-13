import io
import textwrap

from aerleon.lib import naming
from ruyaml import YAML

from firru.cli.score_policy import annotate_policy


def _defs(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH:
            - port: 22
              protocol: tcp
          HTTP:
            - port: 80
              protocol: tcp
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


POL = textwrap.dedent("""\
    metadata:
      host: H1
    filters:
      - header:
          targets:
            nftables: mixed input DROP
        terms:
          - name: allow-tcp-SSH
            protocol: tcp
            destination-port: SSH
            action: accept
          - name: allow-tcp-rpc-high
            protocol: tcp
            destination-port: RPC_HIGH
            action: accept
          # [auto] IPv4 10.0.0.9 (nginx)
          # keep ANY until Q3
          - name: allow-tcp-HTTP
            protocol: tcp
            destination-port: HTTP
            action: accept
""")

SCORING = textwrap.dedent("""\
    H1:
      - {proto: tcp, port: 22, note: ssh mgmt}
      - {proto: tcp, port: 50000, note: rpc must stay}
""")


def _yaml():
    y = YAML()
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def _run(tmp_path):
    from firru.scoring import load_scoring
    sp = tmp_path / "scoring.yml"
    sp.write_text(SCORING)
    scoring_index = load_scoring(str(sp))
    defs = _defs(tmp_path)
    y = _yaml()
    doc = y.load(POL)
    host, host_scoring, n = annotate_policy(doc, scoring_index, defs)
    buf = io.StringIO()
    y.dump(doc, buf)
    return buf.getvalue(), n


def test_annotates_direct_and_group(tmp_path):
    out, n = _run(tmp_path)
    assert n == 2  # SSH + RPC_HIGH group
    assert "[score] ssh mgmt" in out
    # The group-collapse fix: a port inside RPC_HIGH gets annotated
    assert "[score] rpc must stay" in out


def test_preserves_auto_and_human(tmp_path):
    out, _ = _run(tmp_path)
    assert "[auto] IPv4 10.0.0.9 (nginx)" in out
    assert "keep ANY until Q3" in out


def test_unscored_term_untouched(tmp_path):
    out, _ = _run(tmp_path)
    # HTTP is not scored — no [score] line near it
    assert "[score]" not in out.split("allow-tcp-HTTP")[0].rsplit("allow-tcp-rpc-high", 1)[-1]


def test_idempotent(tmp_path):
    """Re-running replaces [score] lines rather than duplicating them."""
    from firru.scoring import load_scoring
    sp = tmp_path / "scoring.yml"
    sp.write_text(SCORING)
    scoring_index = load_scoring(str(sp))
    defs = _defs(tmp_path)
    y = _yaml()

    doc = y.load(POL)
    annotate_policy(doc, scoring_index, defs)
    buf1 = io.StringIO(); y.dump(doc, buf1)

    doc2 = y.load(buf1.getvalue())
    _, _, n2 = annotate_policy(doc2, scoring_index, defs)
    buf2 = io.StringIO(); y.dump(doc2, buf2)

    assert n2 == 2
    assert buf2.getvalue().count("[score] ssh mgmt") == 1
    assert buf2.getvalue().count("[score] rpc must stay") == 1
