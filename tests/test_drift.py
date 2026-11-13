"""
Deployment drift: the committed policy against what the host is running.

`firru diff POL nft.json` reads the enforced ruleset back through
nft-to-aerleon and compares it in the ordinary six classes, so the cell that
mattered in the exercise -- policy correct, enforcement stale -- is reachable
without a bespoke comparison (docs/design.md, compiled x enforced).

What is pinned here is mostly the boundary rather than the arithmetic: which
JSON shape means which comparison, that the parse's own limits are reported
rather than folded into the findings, and that the ruleset is refused as an
`apply` source. The last one is not a convenience check. Folding the running
firewall back into pol/ documents the world instead of intending it, which is
the failure the pipeline exists to reverse.
"""

import json
import textwrap

import pytest
from aerleon.lib import naming

from firru.cli.edit import _load_side, _ruleset_caveats


# --------------------------------------------------------------------------
# fixtures: a two-token def/ and hand-built `nft -j list ruleset` output
# --------------------------------------------------------------------------

def _defs_dir(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH:
            - {port: 22, protocol: tcp}
    """))
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          NET_MGMT:
            values:
              - address: 10.1.0.0/24
          NET_ANY:
            values:
              - address: 0.0.0.0/0
    """))
    return d


def _saddr(addr, length):
    return {"match": {"op": "==",
                      "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                      "right": {"prefix": {"addr": addr, "len": length}}}}


def _dport(port):
    return {"match": {"op": "==",
                      "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                      "right": port}}


def _ruleset(exprs, chain="web1_ssh", policy="drop", packets=7):
    """An `nft -j list ruleset` document: one hooked base chain that jumps to
    one generated per-term chain, which is the shape aerleon-to-nftables emits.
    """
    return {"nftables": [
        {"chain": {"family": "inet", "table": "filter", "name": "input",
                   "handle": 1, "type": "filter", "hook": "input", "prio": 0,
                   "policy": policy}},
        {"chain": {"family": "inet", "table": "filter", "name": chain,
                   "handle": 2}},
        {"rule": {"family": "inet", "table": "filter", "chain": "input",
                  "handle": 3, "expr": [{"jump": {"target": chain}}]}},
        {"rule": {"family": "inet", "table": "filter", "chain": chain,
                  "handle": 4,
                  "expr": [*exprs,
                           {"counter": {"packets": packets, "bytes": 400}},
                           {"accept": None}]}},
    ]}


def _write(tmp_path, name, doc):
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return str(p)


def _committed(tmp_path, src):
    """The policy as reviewed and committed: SSH from one source."""
    p = tmp_path / "web1.yml"
    p.write_text(textwrap.dedent(f"""\
        metadata:
          host: web1
        filters:
          - header:
              targets:
                nftables: mixed input DROP
            terms:
              - name: ssh
                protocol: tcp
                destination-port: SSH
                source-address: {src}
                action: accept
              - name: drop-ANY
                action: deny
    """))
    return str(p)


# --------------------------------------------------------------------------
# which JSON shape means which comparison
# --------------------------------------------------------------------------

def test_an_nft_dump_loads_as_a_policy_side(tmp_path):
    defs = _defs_dir(tmp_path)
    path = _write(tmp_path, "nft.json",
                  _ruleset([_saddr("10.1.0.0", 24), _dport(22)]))
    doc, unknown = _load_side(path, str(defs), allow_ruleset=True)
    terms = doc["filters"][0]["terms"]
    # The port arrives as the number the rule carried; naming it back is not
    # this parser's job, and port_surface resolves both forms to the same key.
    assert any(str(t.get("destination-port")) == "22" for t in terms), terms
    # The address, by contrast, IS named: NET_MGMT expands to exactly this set.
    assert any(t.get("source-address") == "NET_MGMT" for t in terms), terms
    # The base chain's policy has to arrive as a term, or a host imported this
    # way merges into a zone as accepts with nothing behind them.
    assert any(t["name"] == "drop-ANY" and t["action"] == "deny" for t in terms)
    assert unknown is None


def test_a_json_that_is_neither_shape_says_so(tmp_path):
    defs = _defs_dir(tmp_path)
    path = _write(tmp_path, "other.json", {"something": "else"})
    with pytest.raises(SystemExit) as e:
        _load_side(path, str(defs), allow_ruleset=True)
    assert "listen_ports" in str(e.value) and "nftables" in str(e.value)


def test_a_ruleset_of_only_nat_is_not_a_silent_empty_diff(tmp_path):
    """Docker and libvirt rulesets are mostly NAT. Converting one to an empty
    policy would report the whole committed surface as removed, which reads as
    a catastrophic drift and is really an unreadable file."""
    defs = _defs_dir(tmp_path)
    doc = {"nftables": [
        {"chain": {"family": "ip", "table": "nat", "name": "POSTROUTING",
                   "handle": 1, "type": "nat", "hook": "postrouting",
                   "prio": 100, "policy": "accept"}},
        {"rule": {"family": "ip", "table": "nat", "chain": "POSTROUTING",
                  "handle": 2, "expr": [{"masquerade": None}]}},
    ]}
    path = _write(tmp_path, "nat.json", doc)
    with pytest.raises(SystemExit) as e:
        _load_side(path, str(defs), allow_ruleset=True)
    assert "nothing to diff" in str(e.value)


# --------------------------------------------------------------------------
# the drift itself, in the ordinary classes
# --------------------------------------------------------------------------

def test_a_host_running_wider_than_committed_reads_as_widened(tmp_path):
    """The case the exercise turned on: the policy restricts SSH to management,
    the box is actually answering it from anywhere."""
    from firru.policy import diff_surface
    defs_dir = _defs_dir(tmp_path)
    defs = naming.Naming(str(defs_dir))
    pol = _committed(tmp_path, "NET_MGMT")
    running = _write(tmp_path, "nft.json",
                     _ruleset([_saddr("0.0.0.0", 0), _dport(22)]))

    old_doc, _ = _load_side(pol, str(defs_dir))
    new_doc, _ = _load_side(running, str(defs_dir), allow_ruleset=True)
    result = diff_surface(old_doc, new_doc, defs, "in")

    assert result["widened"], result
    assert not result["narrowed"]


def test_a_host_running_what_was_committed_reads_clean(tmp_path):
    from firru.policy import diff_surface
    defs_dir = _defs_dir(tmp_path)
    defs = naming.Naming(str(defs_dir))
    pol = _committed(tmp_path, "NET_MGMT")
    running = _write(tmp_path, "nft.json",
                     _ruleset([_saddr("10.1.0.0", 24), _dport(22)]))

    old_doc, _ = _load_side(pol, str(defs_dir))
    new_doc, _ = _load_side(running, str(defs_dir), allow_ruleset=True)
    result = diff_surface(old_doc, new_doc, defs, "in")

    assert not result["widened"], result
    assert not result["narrowed"], result
    assert not result["added"] and not result["removed"], result


def test_a_term_never_reloaded_reads_as_removed(tmp_path):
    """Policy grants SSH; the running ruleset has no such rule. That is the
    stale-deployment case, and it must not be quietly clean."""
    from firru.policy import diff_surface
    defs_dir = _defs_dir(tmp_path)
    defs = naming.Naming(str(defs_dir))
    pol = _committed(tmp_path, "NET_MGMT")
    running = _write(tmp_path, "nft.json",
                     _ruleset([_saddr("10.1.0.0", 24), _dport(9999)]))

    old_doc, _ = _load_side(pol, str(defs_dir))
    new_doc, _ = _load_side(running, str(defs_dir), allow_ruleset=True)
    result = diff_surface(old_doc, new_doc, defs, "in")

    removed_ports = [p for _, ports in result["removed"] for p in ports]
    assert ("in", "tcp", 22) in removed_ports, result


# --------------------------------------------------------------------------
# the bounds travel with the finding
# --------------------------------------------------------------------------

def test_a_partial_parse_warns_that_its_error_runs_wide():
    """An ignored match narrows the rule, so the term read back is wider than
    what is enforced. Unflagged, that is a widening the host never granted."""
    notes = _ruleset_caveats({"partial": 2, "ignored_kinds": {"meta mark": 2},
                              "skipped": 0, "unnamed_terms": 0, "idle": 0,
                              "default": "drop", "terms": 5, "nat": 0})
    assert len(notes) == 1
    assert "WIDER" in notes[0] and "meta mark" in notes[0]


def test_a_missing_base_policy_makes_removed_unreliable():
    notes = _ruleset_caveats({"partial": 0, "ignored_kinds": {}, "skipped": 0,
                              "unnamed_terms": 0, "idle": 0, "default": None,
                              "terms": 5, "nat": 0})
    assert any("default-deny" in n and "removed" in n for n in notes)


def test_a_clean_parse_carries_no_caveats():
    assert _ruleset_caveats({"partial": 0, "ignored_kinds": {}, "skipped": 0,
                             "unnamed_terms": 0, "idle": 0, "default": "drop",
                             "terms": 5, "nat": 0}) == []


def test_the_caveats_go_to_stderr_not_into_the_findings(tmp_path, capsys):
    defs = _defs_dir(tmp_path)
    # 0.0.0.0/0 is named by NET_ANY here, but 10.9.9.0/24 is named by nothing,
    # so the term comes back carrying a literal.
    path = _write(tmp_path, "nft.json",
                  _ruleset([_saddr("10.9.9.0", 24), _dport(22)]))
    _load_side(path, str(defs), allow_ruleset=True)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "literal addresses" in captured.err


# --------------------------------------------------------------------------
# the boundary: drift is a finding, never a patch
# --------------------------------------------------------------------------

def test_apply_refuses_a_ruleset_as_a_source(tmp_path):
    defs = _defs_dir(tmp_path)
    path = _write(tmp_path, "nft.json",
                  _ruleset([_saddr("0.0.0.0", 0), _dport(22)]))
    with pytest.raises(SystemExit) as e:
        _load_side(path, str(defs))          # allow_ruleset defaults to False
    msg = str(e.value)
    assert "enforced state" in msg
    assert "firru diff" in msg


def test_loot_json_still_loads_the_way_it_did(tmp_path):
    """The new branch must not have moved the observed x intended path."""
    defs = _defs_dir(tmp_path)
    path = _write(tmp_path, "loot.json",
                  {"hostname": "web1",
                   "listen_ports": [{"protocol": "tcp", "port": 22,
                                     "address": "0.0.0.0"}]})
    doc, unknown = _load_side(path, str(defs))
    assert doc["filters"][0]["terms"]
    assert unknown is not None


def test_the_report_says_how_to_read_the_classes(tmp_path, capsys):
    """`removed` means "committed but not running" here, the opposite of its
    synthesis reading. A reader who carries the usual reading across gets the
    finding backwards, so the report has to say which one is in force."""
    from firru.cli.edit import cmd_diff
    import argparse
    defs_dir = _defs_dir(tmp_path)
    args = argparse.Namespace(
        old=_committed(tmp_path, "NET_MGMT"),
        new=_write(tmp_path, "nft.json", _ruleset([_saddr("0.0.0.0", 0), _dport(22)])),
        defs=str(defs_dir), direction="in", flows=None, zero_evidence=False,
        out=None, output="human", zone_prefix="web1")
    cmd_diff(args)
    out = capsys.readouterr().out
    assert "reading enforced state" in out
    assert "widened" in out


def test_a_drift_never_emits_edits(tmp_path):
    """`-o sh` would rewrite pol/ to agree with the host: a hand-patched SSH
    widened to ANY applied as though it were intent."""
    from firru.cli.edit import cmd_diff
    import argparse
    defs_dir = _defs_dir(tmp_path)
    args = argparse.Namespace(
        old=_committed(tmp_path, "NET_MGMT"),
        new=_write(tmp_path, "nft.json", _ruleset([_saddr("0.0.0.0", 0), _dport(22)])),
        defs=str(defs_dir), direction="in", flows=None, zero_evidence=False,
        out=None, output="sh", zone_prefix="web1")
    with pytest.raises(SystemExit) as e:
        cmd_diff(args)
    assert "refusing to emit edits" in str(e.value)


def test_a_ruleset_does_not_invent_a_host_from_the_filename(tmp_path):
    defs = _defs_dir(tmp_path)
    path = _write(tmp_path, "nft.json", _ruleset([_saddr("10.1.0.0", 24), _dport(22)]))
    doc, _ = _load_side(path, str(defs), allow_ruleset=True)
    assert "host" not in (doc.get("metadata") or {})
    assert doc["metadata"]["source"] == "enforced"
