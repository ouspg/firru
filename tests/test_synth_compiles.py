"""
Synthesized policy has to compile into what the policy says. Where a generator
gets a shape wrong, synthesis avoids the shape; these pin that it keeps
avoiding it. They run against the aerleon firru depends on.
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


def test_windows_renders_no_block_rule(defs):
    """Windows Firewall has no rule order and block beats allow, so a rendered
    drop-ANY would block every allowed service too. Synthesis platform-excludes
    it; the header's default action does the dropping."""
    out = compile_host("windows", defs)
    assert "action=allow" in out
    assert "action=block" not in out


def test_linux_counts_what_falls_through(defs):
    """The chain policy drops the same packets, but a policy has no counter.
    The terminal term is kept so the drops can be counted."""
    nft = compile_host("linux", defs)
    m = re.search(r"chain drop-ANY \{\n(.*?)\n\s*\}", nft, re.S)
    assert m and "counter" in m.group(1), nft
