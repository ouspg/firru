"""Zero-evidence: block-early drops accept terms that saw no flows in the
window; review-then-deploy keeps them. Scored terms are never dropped. The two
posture greps (observed vs runnable) divide the one emitted script."""

import argparse
import json
import textwrap

import pytest
from ruyaml import YAML

from firru.cli.edit import cmd_diff, cmd_rm


def _defs(tmp_path):
    d = tmp_path / "def"
    d.mkdir(exist_ok=True)
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH:  [{port: 22, protocol: tcp}]
          HTTP: [{port: 80, protocol: tcp}]
          ISAKMP: [{port: 500, protocol: udp}]
    """))
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          H1:
            values: [{address: 10.0.0.5/32}]
          NET_MGMT:
            values: [{address: 10.9.0.0/16}]
    """))
    return str(d)


def _pol(tmp_path, fname, terms):
    p = tmp_path / fname
    p.write_text(textwrap.dedent("""\
        metadata: {host: H1}
        filters:
          - header: {targets: {nftables: mixed input DROP}}
            terms:
        """) + "\n".join(terms) + "\n      - {name: drop-ANY, action: deny}\n")
    return str(p)


SSH = "\n".join([
    "      - name: allow-tcp-SSH",
    "        protocol: tcp",
    "        destination-port: SSH",
    "        action: accept"])
HTTP = "      - {name: allow-tcp-HTTP, protocol: tcp, destination-port: HTTP, action: accept}"
ISAKMP = "\n".join([
    "      - name: allow-udp-ISAKMP",
    "        protocol: udp",
    "        destination-port: ISAKMP",
    "        action: accept"])


def _flows(tmp_path, *items):
    p = tmp_path / "flows.jsonl"
    lines = []
    for proto, port, src, hits in items:
        for _ in range(hits):
            lines.append(json.dumps({"protocol": proto, "dst_port": port,
                                     "src_ip": src, "dst_ip": "10.0.0.5"}))
    p.write_text("\n".join(lines) + "\n")
    return str(p)


def _emit(tmp_path, terms, flows, capsys, zero=True):
    defs = _defs(tmp_path)
    pol = _pol(tmp_path, "pol.yml", terms)
    # NEW == pol (no tightening change), so only zero-evidence differs
    new = _pol(tmp_path, "new.yml", terms)
    cmd_diff(argparse.Namespace(old=pol, new=new, defs=defs, output="sh",
                                direction="in", flows=flows, zero_evidence=zero))
    return capsys.readouterr().out, pol


class TestEmission:
    def test_an_unexercised_term_gets_a_zero_evidence_rm(self, tmp_path, capsys):
        flows = _flows(tmp_path, ("tcp", 22, "10.9.1.1", 3))  # SSH only
        out, pol = _emit(tmp_path, [SSH, ISAKMP], flows, capsys)
        line = [l for l in out.splitlines() if "ISAKMP" in l][0]
        assert line == f"firru rm {pol} allow-udp-ISAKMP  # zero-evidence (0 flows)"

    def test_an_exercised_term_gets_no_zero_evidence_line(self, tmp_path, capsys):
        flows = _flows(tmp_path, ("udp", 500, "10.9.1.1", 2))  # ISAKMP has traffic
        out, _ = _emit(tmp_path, [SSH, ISAKMP], flows, capsys)
        assert not any("ISAKMP" in l and "zero-evidence" in l for l in out.splitlines())

    def test_review_grep_skips_it_block_early_takes_it(self, tmp_path, capsys):
        flows = _flows(tmp_path, ("tcp", 22, "10.9.1.1", 3))
        out, _ = _emit(tmp_path, [SSH, ISAKMP], flows, capsys)
        line = [l for l in out.splitlines() if "ISAKMP" in l][0]
        # review: grep 'observed ('  → no match
        assert "observed (" not in line
        # block-early: grep -v '^#' | grep -v '# widened' → runnable
        assert not line.startswith("#") and "# widened" not in line

    def test_a_scored_term_is_emitted_commented(self, tmp_path, capsys):
        scored_isakmp = ISAKMP + "\n# !!! SCORING - DO NOT BLOCK: scored VPN"
        flows = _flows(tmp_path, ("tcp", 22, "10.9.1.1", 3))
        out, _ = _emit(tmp_path, [SSH, scored_isakmp], flows, capsys)
        line = [l for l in out.splitlines() if "ISAKMP" in l][0]
        assert line.startswith("#") and "SCORED" in line

    def test_no_zero_evidence_without_the_flag(self, tmp_path, capsys):
        flows = _flows(tmp_path, ("tcp", 22, "10.9.1.1", 3))
        out, _ = _emit(tmp_path, [SSH, ISAKMP], flows, capsys, zero=False)
        assert "zero-evidence" not in out

    def test_the_terminal_is_not_a_zero_evidence_target(self, tmp_path, capsys):
        # drop-ANY has no port surface; it must never be emitted as zero-evidence
        flows = _flows(tmp_path, ("tcp", 22, "10.9.1.1", 3))
        out, _ = _emit(tmp_path, [SSH], flows, capsys)
        assert "drop-ANY" not in out


class TestRmVeto:
    # rm vetoes a scored term by default; --force overrides
    def test_default_removes_an_unscored_term(self, tmp_path):
        pol = _pol(tmp_path, "pol.yml", [SSH, ISAKMP])
        rc = cmd_rm(argparse.Namespace(pol=pol, term="allow-udp-ISAKMP", force=False))
        assert rc == 0
        assert "allow-udp-ISAKMP" not in open(pol).read()

    def test_default_keeps_a_scored_term(self, tmp_path, capsys):
        scored = ISAKMP + "\n# !!! SCORING - DO NOT BLOCK: scored VPN"
        pol = _pol(tmp_path, "pol.yml", [SSH, scored])
        rc = cmd_rm(argparse.Namespace(pol=pol, term="allow-udp-ISAKMP", force=False))
        assert rc == 0  # not an error — a deliberate skip
        assert "allow-udp-ISAKMP" in open(pol).read()
        assert "scored" in capsys.readouterr().out.lower()

    def test_force_removes_a_scored_term(self, tmp_path):
        # the veto is opt-in; bare rm is unconditional
        scored = SSH + "\n# !!! SCORING - DO NOT BLOCK"
        pol = _pol(tmp_path, "pol.yml", [scored, ISAKMP])
        cmd_rm(argparse.Namespace(pol=pol, term="allow-tcp-SSH", force=True))
        assert "allow-tcp-SSH" not in open(pol).read()
