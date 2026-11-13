"""`firru synth --unknown` reports exactly the listeners synthesis would have to
name: not ephemeral client binds, not platform exclusions, and with the OS taken
from host metadata when the loot has none (synth_entries, shared)."""
import json
import textwrap

import pytest
from aerleon.lib import naming

from firru.cli.listeners_to_aerleon import build_service_surface, synth_host


@pytest.fixture(scope="module")
def defs(tmp_path_factory):
    d = tmp_path_factory.mktemp("defs")
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH: [{port: 22, protocol: tcp}]
    """))
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          ANY: {values: [{address: 0.0.0.0/0}, {address: '::/0'}]}
    """))
    return naming.Naming(str(d))


def _listen(proto, port, name="p", services=()):
    return {"protocol": proto, "port": port, "bind_address": "0.0.0.0/0",
            "process": {"name": name, "services": list(services)}, "flags": []}


def _write(tmp_path, name, doc):
    p = tmp_path / f"{name}.json"
    p.write_text(json.dumps(doc))
    return p


def test_unknown_leaves_out_what_synthesis_drops(tmp_path, defs):
    linux = _write(tmp_path, "lin", {
        "metadata": {"hostname": "lin", "os": "linux"},
        "listen_ports": [_listen("tcp", 22), _listen("tcp", 8443),
                         _listen("tcp", 41234)]})             # ephemeral client bind
    win = _write(tmp_path, "win", {
        "metadata": {"hostname": "win"},                          # os from host metadata
        "listen_ports": [
                         _listen("tcp", 50123, "lsass")]})     # Windows dynamic range
    meta = {"win": {"os": "windows"}}
    known, unknown = build_service_surface([linux, win], defs, meta)
    assert set(known) == {"SSH"}
    assert set(unknown) == {("tcp", 8443)}


def test_report_and_synthesis_agree_on_unknown(tmp_path, defs):
    doc = {"metadata": {"hostname": "lin", "os": "linux"},
           "listen_ports": [_listen("tcp", 22), _listen("tcp", 8443), _listen("tcp", 41234)]}
    _, _, synth_unknown = synth_host(doc, defs)
    _, report_unknown = build_service_surface([_write(tmp_path, "lin", doc)], defs)
    assert set(report_unknown) == set(synth_unknown)


def test_keep_ephemeral_reports_them(tmp_path, defs):
    p = _write(tmp_path, "lin", {"metadata": {"hostname": "lin", "os": "linux"},
                                 "listen_ports": [_listen("tcp", 41234)]})
    _, unknown = build_service_surface([p], defs, keep_ephemeral=True)
    assert ("tcp", 41234) in unknown
