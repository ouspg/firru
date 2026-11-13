"""--flows evidence on firru diff: the paper's two deployment counterfactuals
made greppable. `observed` backs review-then-deploy; `unexercised` is what
block-early accepts on faith; `contradicted` (the change would cut observed
flows) is never emitted runnable."""

import argparse
import json
import textwrap

import pytest
from ruyaml import YAML

from firru.cli.edit import cmd_diff


def _defs(tmp_path):
    d = tmp_path / "def"
    d.mkdir(exist_ok=True)
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH:
            - {port: 22, protocol: tcp}
          HTTP:
            - {port: 80, protocol: tcp}
          MYSQL:
            - {port: 3306, protocol: tcp}
    """))
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          H1:
            values:
              - address: 10.0.0.5/32
          NET_MGMT:
            values:
              - address: 10.9.0.0/16
          NET_APP:
            values:
              - address: 10.7.0.0/16
    """))
    return str(d)


def _pol(tmp_path, fname, terms):
    body = "\n".join(terms)
    p = tmp_path / fname
    p.write_text(textwrap.dedent("""\
        metadata: {host: H1}
        filters:
          - header: {targets: {nftables: mixed input DROP}}
            terms:
        """) + body + "\n      - {name: drop-ANY, action: deny}\n")
    return str(p)


def _t(name, svc, src=None):
    lines = [f"      - name: {name}", "        protocol: tcp",
             f"        destination-port: {svc}", "        action: accept"]
    if src:
        lines.insert(3, f"        source-address: {src}")
    return "\n".join(lines)


def _flows(tmp_path, *items):
    """items: (proto, port, src_ip, hits) — all ingress to H1 (10.0.0.5)."""
    p = tmp_path / "flows.jsonl"
    lines = []
    for proto, port, src, hits in items:
        for _ in range(hits):
            lines.append(json.dumps({"protocol": proto, "dst_port": port,
                                     "src_ip": src, "dst_ip": "10.0.0.5"}))
    p.write_text("\n".join(lines) + "\n")
    return str(p)


def _run(tmp_path, old_terms, new_terms, flows, output="sh", capsys=None):
    defs = _defs(tmp_path)
    old = _pol(tmp_path, "old.yml", old_terms)
    new = _pol(tmp_path, "new.yml", new_terms)
    cmd_diff(argparse.Namespace(old=old, new=new, defs=defs, output=output,
                                direction="in", flows=flows))
    return capsys.readouterr().out


class TestEvidenceTags:
    def test_a_supported_narrowing_is_tagged_observed(self, tmp_path, capsys):
        flows = _flows(tmp_path, ("tcp", 22, "10.9.1.1", 4))
        out = _run(tmp_path, [_t("allow-tcp-SSH", "SSH")],
                   [_t("allow-tcp-SSH", "SSH", src="NET_MGMT")], flows, capsys=capsys)
        line = [l for l in out.splitlines() if "set-source" in l][0]
        assert "# narrowed observed (4 flows)" in line
        assert not line.startswith("#")

    def test_an_untouched_term_is_tagged_unexercised(self, tmp_path, capsys):
        flows = _flows(tmp_path, ("tcp", 80, "10.9.1.1", 2))  # HTTP only
        out = _run(tmp_path, [_t("allow-tcp-SSH", "SSH")],
                   [_t("allow-tcp-SSH", "SSH", src="NET_MGMT")], flows, capsys=capsys)
        line = [l for l in out.splitlines() if "set-source" in l][0]
        assert "# narrowed unexercised" in line

    def test_a_contradicted_narrowing_is_commented(self, tmp_path, capsys):
        # 10.7.1.1 was admitted (ANY) and NET_MGMT would drop it.
        flows = _flows(tmp_path, ("tcp", 22, "10.7.1.1", 5))
        out = _run(tmp_path, [_t("allow-tcp-SSH", "SSH")],
                   [_t("allow-tcp-SSH", "SSH", src="NET_MGMT")], flows, capsys=capsys)
        line = [l for l in out.splitlines() if "set-source" in l][0]
        assert line.startswith("#")
        assert "CONTRADICTED" in line and "10.7.1.1" in line and "5 observed" in line

    def test_a_narrowing_that_keeps_all_observed_peers_is_runnable(self, tmp_path, capsys):
        # Observed source inside the surviving set: narrowing cuts nothing.
        flows = _flows(tmp_path, ("tcp", 22, "10.9.2.2", 3))
        out = _run(tmp_path, [_t("allow-tcp-SSH", "SSH", src="[NET_MGMT, NET_APP]")],
                   [_t("allow-tcp-SSH", "SSH", src="NET_MGMT")], flows, capsys=capsys)
        line = [l for l in out.splitlines() if "set-source" in l][0]
        assert not line.startswith("#") and "observed" in line

    def test_an_exercised_removal_is_commented(self, tmp_path, capsys):
        flows = _flows(tmp_path, ("tcp", 3306, "10.9.1.1", 7))
        out = _run(tmp_path,
                   [_t("allow-tcp-SSH", "SSH"), _t("allow-tcp-MYSQL", "MYSQL")],
                   [_t("allow-tcp-SSH", "SSH")], flows, capsys=capsys)
        line = [l for l in out.splitlines() if "firru rm" in l][0]
        assert line.startswith("#") and "CONTRADICTED" in line

    def test_an_unexercised_removal_is_the_block_early_grep(self, tmp_path, capsys):
        flows = _flows(tmp_path, ("tcp", 22, "10.9.1.1", 1))  # MYSQL silent
        out = _run(tmp_path,
                   [_t("allow-tcp-SSH", "SSH"), _t("allow-tcp-MYSQL", "MYSQL")],
                   [_t("allow-tcp-SSH", "SSH")], flows, capsys=capsys)
        line = [l for l in out.splitlines() if "firru rm" in l][0]
        assert not line.startswith("#")
        assert "# removed unexercised" in line

    def test_without_flows_no_tags_appear(self, tmp_path, capsys):
        out = _run(tmp_path, [_t("allow-tcp-SSH", "SSH")],
                   [_t("allow-tcp-SSH", "SSH", src="NET_MGMT")], None, capsys=capsys)
        assert "observed" not in out and "unexercised" not in out

    def test_the_human_report_names_the_postures(self, tmp_path, capsys):
        flows = _flows(tmp_path, ("tcp", 22, "10.9.1.1", 4))
        out = _run(tmp_path, [_t("allow-tcp-SSH", "SSH")],
                   [_t("allow-tcp-SSH", "SSH", src="NET_MGMT")], flows,
                   output="human", capsys=capsys)
        assert "review-then-deploy" in out and "block-early" in out


class TestPostureGreps:
    """The two postures as actual pipelines over the emitted script."""

    def _script(self, tmp_path, capsys):
        flows = _flows(tmp_path,
                       ("tcp", 22, "10.9.1.1", 4),    # SSH narrowing supported
                       ("tcp", 3306, "10.7.1.1", 2))  # MYSQL removal contradicted
        return _run(tmp_path,
                    [_t("allow-tcp-SSH", "SSH"),
                     _t("allow-tcp-HTTP", "HTTP"),     # removal, silent
                     _t("allow-tcp-MYSQL", "MYSQL")],  # removal, exercised
                    [_t("allow-tcp-SSH", "SSH", src="NET_MGMT")],
                    flows, capsys=capsys)

    def test_review_then_deploy_takes_only_observed(self, tmp_path, capsys):
        lines = [l for l in self._script(tmp_path, capsys).splitlines()
                 if not l.startswith("#") and "observed" in l]
        assert len(lines) == 1 and "set-source" in lines[0]

    def test_block_early_also_takes_unexercised_but_never_contradicted(self, tmp_path, capsys):
        runnable = [l for l in self._script(tmp_path, capsys).splitlines()
                    if not l.startswith("#") and ("observed" in l or "unexercised" in l)]
        assert len(runnable) == 2
        assert not any("MYSQL" in l for l in runnable)


class TestFmtCutDeterministic:
    """The CONTRADICTED example list must not depend on flow-read order."""

    def test_ties_sort_by_count_then_peer(self):
        from collections import Counter
        from firru.cli.edit import _fmt_cut
        # insertion order deliberately not the display order
        cut = Counter()
        cut["10.0.0.9"] = 4
        cut["10.0.0.1"] = 4
        cut["10.0.0.5"] = 6
        s = _fmt_cut(cut, limit=3)
        # count desc, then peer string asc for the ×4 tie
        assert "10.0.0.5×6, 10.0.0.1×4, 10.0.0.9×4" in s
        assert s.startswith("14 observed flow(s) from ")

    def test_same_output_regardless_of_insertion_order(self):
        from collections import Counter
        from firru.cli.edit import _fmt_cut
        a = Counter({"b": 2, "a": 2, "c": 3})
        b = Counter()
        for k in ("a", "c", "b"):
            b[k] = {"a": 2, "b": 2, "c": 3}[k]
        assert _fmt_cut(a) == _fmt_cut(b)


class TestNeverAnswered:
    """A change that would admit a peer whose every flow went unanswered grants
    more than the window's policy enforced: it is written commented out, as
    widened, so `grep narrowed | sh` cannot take it."""

    def _flows(self, tmp_path, *items):
        """items: (src_ip, hits, responded) on tcp/22 to H1."""
        p = tmp_path / "flows.jsonl"
        p.write_text("".join(
            json.dumps({"protocol": "tcp", "dst_port": 22, "src_ip": src,
                        "dst_ip": "10.0.0.5", "responded": responded}) + "\n"
            for src, hits, responded in items for _ in range(hits)))
        return str(p)

    def _line(self, tmp_path, capsys, flows):
        out = _run(tmp_path, [_t("allow-tcp-SSH", "SSH")],
                   [_t("allow-tcp-SSH", "SSH", src="NET_MGMT")], flows, capsys=capsys)
        return [l for l in out.splitlines() if "set-source" in l][0]

    def _sh(self, tmp_path, capsys, flows, src):
        out = _run(tmp_path, [_t("allow-tcp-SSH", "SSH")],
                   [_t("allow-tcp-SSH", "SSH", src=src)], flows, capsys=capsys)
        return [l for l in out.splitlines() if "set-source" in l]

    def test_a_token_only_never_answered_is_left_out_of_a_runnable_line(self, tmp_path, capsys):
        flows = self._flows(tmp_path, ("10.9.1.1", 4, True), ("10.7.1.1", 2, False))
        runnable, proposed = self._sh(tmp_path, capsys, flows, "[NET_MGMT, NET_APP]")
        assert runnable.startswith("firru set-source ") and " NET_MGMT --defs" in runnable
        assert runnable.endswith("# narrowed observed (4 flows), left out never answered: NET_APP")
        assert proposed.startswith("# firru set-source ") and "NET_APP NET_MGMT" in proposed

    def test_nothing_runnable_when_every_token_was_never_answered(self, tmp_path, capsys):
        flows = self._flows(tmp_path, ("10.7.1.1", 2, False))
        (line,) = self._sh(tmp_path, capsys, flows, "NET_APP")
        assert line.startswith("# ") and "# widened:" in line

    def test_an_admitted_peer_never_answered_is_named(self, tmp_path, capsys):
        """10.9.2.2 sits in NET_MGMT beside an answered peer: the group stays,
        so it still admits 10.9.2.2, and no line is runnable."""
        flows = self._flows(tmp_path, ("10.9.1.1", 4, True), ("10.9.2.2", 3, False))
        (line,) = self._sh(tmp_path, capsys, flows, "NET_MGMT")
        assert line.startswith("# firru set-source ")
        assert line.endswith("# widened: would admit "
                             "3 never-answered flow(s) from 10.9.2.2×3")

    def test_a_peer_answered_once_is_not(self, tmp_path, capsys):
        flows = self._flows(tmp_path, ("10.9.2.2", 3, False), ("10.9.2.2", 1, True))
        line = self._line(tmp_path, capsys, flows)
        assert not line.startswith("#") and line.endswith("# narrowed observed (4 flows)")

    def test_a_peer_the_new_side_refuses_is_not_its_concern(self, tmp_path, capsys):
        """10.7.x is outside NET_MGMT: the narrowing cuts it, which is a
        contradiction, not an admission."""
        flows = self._flows(tmp_path, ("10.9.1.1", 4, True), ("10.7.1.1", 2, False))
        assert "widened" not in self._line(tmp_path, capsys, flows)

    def test_the_terminal_says_it_too(self, tmp_path, capsys):
        flows = self._flows(tmp_path, ("10.9.1.1", 4, True), ("10.9.2.2", 3, False))
        out = _run(tmp_path, [_t("allow-tcp-SSH", "SSH")],
                   [_t("allow-tcp-SSH", "SSH", src="NET_MGMT")], flows,
                   output="human", capsys=capsys)
        assert "!! WIDENED: admits 3 never-answered flow(s) from 10.9.2.2×3" in out
