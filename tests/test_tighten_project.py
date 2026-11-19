"""tighten run inside a project: its def/, its store and its proposals/, from
any directory of it, and a note when no window narrows the store."""

import json
import subprocess
import sys
import textwrap


def project(tmp_path):
    (tmp_path / "firru.toml").write_text('[flows]\nstore = "data/flows.jsonl"\n')
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text("services:\n  SSH: [{port: 22, protocol: tcp}]\n")
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          H1: {values: [{address: 10.0.0.5/32}]}
          ADMIN: {values: [{address: 10.9.1.1/32}]}
    """))
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "flows.jsonl").write_text(json.dumps(
        {"protocol": "tcp", "src_ip": "10.9.1.1", "dst_ip": "10.0.0.5", "dst_port": 22,
         "timestamp": 1900000000, "responded": True}) + "\n")
    pol = tmp_path / "policies"
    pol.mkdir()
    (pol / "H1.yml").write_text(textwrap.dedent("""\
        metadata: {host: H1}
        filters:
          - header: {targets: {nftables: mixed input DROP}}
            terms:
              - {name: allow-tcp-SSH, protocol: tcp, destination-port: SSH, action: accept}
              - {name: drop-ANY, action: deny}
    """))
    (tmp_path / "somewhere").mkdir()
    return tmp_path


def run(cwd, *argv, env_extra=None):
    import os
    env = {k: v for k, v in os.environ.items() if k != "FIRRU_PROJECT"}
    return subprocess.run([sys.executable, "-m", "firru.cli.tighten", *argv],
                          cwd=cwd, capture_output=True, text=True, env=env)


def test_from_any_directory_it_reads_the_projects_def_store_and_writes_proposals(tmp_path):
    root = project(tmp_path)
    r = run(root / "somewhere", "--policy", "../policies/H1.yml")
    assert r.returncode == 0, r.stderr
    out = (root / "proposals" / "H1.yml").read_text()
    assert "source-address: ADMIN" in out            # the project's def/ named the peer
    assert "No window given: reading all of ../data/flows.jsonl" in r.stderr


def test_outside_a_project_the_defaults_are_the_working_directorys(tmp_path):
    root = project(tmp_path)
    (root / "firru.toml").unlink()
    r = run(root / "somewhere", "--policy", "../policies/H1.yml")
    assert r.returncode != 0 and "--flows-file is required" in r.stderr
