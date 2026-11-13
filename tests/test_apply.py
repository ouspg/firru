import argparse
import textwrap

from aerleon.lib import naming
from ruyaml import YAML

from firru.cli.edit import cmd_apply


def _defs(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH:
            - {port: 22, protocol: tcp}
          HTTP:
            - {port: 80, protocol: tcp}
          MYSQL:
            - {port: 3306, protocol: tcp}
    """))
    (d / "networks.yml").write_text("networks:\n  LOOPBACK:\n    - {address: 127.0.0.1/32}\n")
    return str(d)


def _accept(name, port, src=None):
    lines = [f"      - name: {name}",
             "        protocol: tcp",
             f"        destination-port: {port}",
             "        action: accept"]
    if src:
        lines.insert(3, f"        source-address: {src}")
    return "\n".join(lines)


def _pol_doc(terms_block):
    return textwrap.dedent("""\
        metadata: {host: H1}
        filters:
          - header: {targets: {nftables: mixed input DROP}}
            terms:
        """) + terms_block + "\n"


POL = _pol_doc("\n".join([
    "      - name: allow-loopback\n        source-address: LOOPBACK\n        action: accept",
    "      # [auto] IPv4 10.0.0.9 (nginx)\n      # keep HTTP open for vendor",
    _accept("allow-tcp-HTTP", "HTTP"),
    _accept("allow-tcp-SSH", "SSH"),
    "      - name: drop-ANY\n        action: deny",
]))

BASE = _pol_doc("\n".join([
    _accept("allow-tcp-HTTP", "HTTP"),
    _accept("allow-tcp-SSH", "SSH"),
]))

NEW = _pol_doc("\n".join([
    _accept("allow-tcp-HTTP", "HTTP"),
    _accept("allow-tcp-SSH", "SSH", src="NET_MGMT"),   # enforcement change → advisory
    "      # [auto] IPv4 10.0.0.5 (mysqld)",
    _accept("allow-tcp-MYSQL", "MYSQL"),               # addition
]))


def _args(tmp_path, dry_run=False):
    d = tmp_path
    (d / "pol.yml").write_text(POL)
    (d / "base.yml").write_text(BASE)
    (d / "new.yml").write_text(NEW)
    return argparse.Namespace(
        pol=str(d / "pol.yml"), from_=str(d / "new.yml"),
        base=str(d / "base.yml"), defs=_defs(d), dry_run=dry_run,
        only=None, prune=False, scoring=None)


def _read(path):
    with open(path) as f:
        return f.read()


def test_apply_inserts_addition_before_terminal(tmp_path):
    args = _args(tmp_path)
    rc = cmd_apply(args)
    assert rc == 0
    out = _read(args.pol)
    # MYSQL term added, before the terminal drop
    assert "allow-tcp-MYSQL" in out
    assert out.index("allow-tcp-MYSQL") < out.index("drop-ANY")
    # its [auto] evidence carried over
    assert "[auto] IPv4 10.0.0.5 (mysqld)" in out


def test_apply_preserves_human_comment(tmp_path):
    args = _args(tmp_path)
    cmd_apply(args)
    out = _read(args.pol)
    assert "keep HTTP open for vendor" in out
    assert "[auto] IPv4 10.0.0.9 (nginx)" in out


def test_enforcement_change_is_advisory_not_written(tmp_path):
    args = _args(tmp_path)
    cmd_apply(args)
    doc = YAML().load(_read(args.pol))
    terms = doc["filters"][0]["terms"]
    ssh = next(t for t in terms if t["name"] == "allow-tcp-SSH")
    # SSH source stays as POL had it (unset/ANY) — the NET_MGMT change is advisory
    assert "source-address" not in ssh


def test_dry_run_writes_nothing(tmp_path):
    args = _args(tmp_path, dry_run=True)
    before = _read(args.pol)
    cmd_apply(args)
    assert _read(args.pol) == before


def test_addition_only_when_pol_lacks_it(tmp_path):
    """Re-applying is a no-op: POL already has MYSQL after the first apply."""
    args = _args(tmp_path)
    cmd_apply(args)
    cmd_apply(args)
    out = _read(args.pol)
    assert out.count("name: allow-tcp-MYSQL") == 1


# ---------------------------------------------------------------------------
# The floor under --prune.
#
# A host whose ss dump could not be parsed used to synthesize to an empty
# policy, and every committed term then arrived here as `removed`. Applying
# that strips a working host of its whole ruleset because a parser met an ss
# version it did not know. Absence of evidence reaches this function as an
# empty NEW side, and it must not be read as evidence of absence.
# ---------------------------------------------------------------------------

EMPTY_NEW = _pol_doc("      - name: drop-ANY\n        action: deny")

ONE_ACCEPT_POL = _pol_doc("\n".join([
    _accept("allow-tcp-SSH", "SSH"),
    "      - name: drop-ANY\n        action: deny",
]))


def _prune_args(tmp_path, pol_text, new_text, only=None):
    d = tmp_path
    (d / "pol.yml").write_text(pol_text)
    (d / "new.yml").write_text(new_text)
    return argparse.Namespace(
        pol=str(d / "pol.yml"), from_=str(d / "new.yml"), base=None,
        defs=_defs(d), dry_run=False, only=only, prune=True, scoring=None,
        narrow=False, direction="both")


def test_an_empty_generated_side_refuses_to_prune(tmp_path):
    args = _prune_args(tmp_path, POL, EMPTY_NEW)
    before = _read(args.pol)
    assert cmd_apply(args) == 2
    assert _read(args.pol) == before, "policy must be untouched"


def test_pruning_everything_refuses_even_when_the_side_parsed(tmp_path):
    """Not only the empty case: any prune that would leave the policy with no
    accept terms is the same outcome by a different route."""
    args = _prune_args(tmp_path, ONE_ACCEPT_POL, EMPTY_NEW)
    assert cmd_apply(args) == 2
    assert "allow-tcp-SSH" in _read(args.pol)


def test_a_partial_prune_still_works(tmp_path):
    """The floor must not turn --prune off. HTTP goes, SSH stays."""
    new = _pol_doc("\n".join([
        _accept("allow-tcp-SSH", "SSH"),
        "      - name: drop-ANY\n        action: deny",
    ]))
    args = _prune_args(tmp_path, POL, new)
    assert cmd_apply(args) == 0
    out = _read(args.pol)
    assert "allow-tcp-HTTP" not in out
    assert "allow-tcp-SSH" in out


def test_only_is_exempt_so_a_host_can_still_be_decommissioned(tmp_path):
    """Naming the term is the deliberate act the floor exists to require, and
    the refusal message tells the operator to do exactly this."""
    args = _prune_args(tmp_path, ONE_ACCEPT_POL, EMPTY_NEW,
                       only=["allow-tcp-SSH"])
    assert cmd_apply(args) == 0
    assert "allow-tcp-SSH" not in _read(args.pol)
