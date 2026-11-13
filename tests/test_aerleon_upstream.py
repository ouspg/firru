"""
What firru needs from aerleon that a stock release does not yet do.

firru depends on a fork of aerleon (pyproject.toml). Each test here compiles
firru's own output through the installed aerleon and checks one behavior the
fork has and the latest stock release lacks, so the file is the list of
reasons for the fork. When it passes on a stock release, depend on that
release instead and delete this file. Run it against one with:

    pip install --force-reinstall --no-deps aerleon==X.Y.Z
    pytest tests/test_aerleon_upstream.py

What firru does on its own side to get correct output is tested in
test_synth_compiles.py, which stays.
"""

import io
import re
import textwrap

import pytest
from aerleon import api
from aerleon.lib import naming
from ruyaml import YAML

from firru.cli.listeners_to_aerleon import synth_host


@pytest.fixture(scope="module")
def defs(tmp_path_factory):
    d = tmp_path_factory.mktemp("defs")
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH: [{port: 22, protocol: tcp}]
          DNS: [{port: 53, protocol: udp}]
    """))
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          ANY:      {values: [{address: 0.0.0.0/0}, {address: '::/0'}]}
          ANY_V4:   {values: [{address: 0.0.0.0/0}]}
          ANY_V6:   {values: [{address: '::/0'}]}
          LOOPBACK: {values: [{address: 127.0.0.0/8}, {address: '::1/128'}]}
    """))
    return naming.Naming(str(d))


def _listen(proto, port, bind):
    return {"protocol": proto, "port": port, "bind_address": bind,
            "process": {"name": "p"}, "flags": []}


#: A dual-stack host: SSH on both families, DNS on IPv4 only.
LISTEN = [_listen("tcp", 22, "0.0.0.0/0"), _listen("tcp", 22, "::/0"),
          _listen("udp", 53, "0.0.0.0/0")]


def compile_doc(doc, defs):
    doc = dict(doc, filename="h")
    return "\n".join(api.Generate([doc], defs).values())


def compile_host(os_type, defs):
    _, pol, _ = synth_host({"metadata": {"hostname": "h", "os": os_type},
                            "listen_ports": LISTEN}, defs)
    buf = io.StringIO()
    YAML().dump(pol, buf)                 # what lands in the policy file
    return compile_doc(YAML(typ="safe").load(buf.getvalue()), defs)


def chain(nft, name):
    """The rule lines of the first nftables chain called `name`."""
    m = re.search(rf"chain {re.escape(name)} {{\n(.*?)\n\s*}}", nft, re.S)
    assert m, f"no chain {name}"
    return [line.strip() for line in m.group(1).splitlines() if line.strip()]


# --- needs the fork -----------------------------------------------------------

def test_icmpv6_is_not_gated_on_a_new_connection(defs):
    """Neighbor discovery is ICMPv6, and conntrack does not track it, so a
    `ct state new` match never fires for it. The input policy is drop, so a
    gated term leaves IPv6 unable to resolve neighbors: the host stops
    answering on IPv6 at all. (fork: upstream-nftables-icmpv6-ndp)"""
    rules = chain(compile_host("linux", defs), "allow-icmpv6")
    assert rules and not any("ct state new" in r for r in rules), rules


def test_a_dual_family_term_renders_each_rule_once(defs):
    """A term whose sources name both families comes out with every rule
    twice. Harmless to the packet, but the rule set is what an operator reads
    and diffs against the running firewall. (fork: dedup for mixed terms)"""
    nft = compile_host("linux", defs)
    for name in ("allow-tcp-SSH", "allow-udp-DNS"):
        rules = chain(nft, name)
        assert len(rules) == len(set(rules)), rules


def test_windows_default_deny_renders_as_the_profile_policy(defs):
    """The only way to say default deny on Windows: a deny-all term is a block
    rule, which beats every allow. Stock validates `block` in the header and
    then refuses to render it. (fork: upstream-windows-mixed-default)"""
    out = compile_host("windows", defs)
    assert ("netsh advfirewall set allprofiles firewallpolicy "
            "blockinbound,notconfigured") in out


def test_windows_mixed_renders_both_icmp_families(defs):
    """`mixed` keeps one filter per direction with both families in it; stock
    rejects `mixed` on windows_advfirewall, and under its `inet` default an
    icmpv6 term is dropped with only a warning. (fork: same branch)"""
    out = compile_host("windows", defs)
    for direction in ("dir=in", "dir=out"):
        for proto in ("protocol=icmpv4", "protocol=icmpv6"):
            assert any(proto in line and direction in line
                       for line in out.splitlines()), (direction, proto)
