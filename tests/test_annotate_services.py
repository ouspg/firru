import json
import textwrap

import pytest
from aerleon.lib import naming
from ruyaml import YAML

from firru.cli.annotate_services import (
    annotate_file,
    evidence_for,
    format_evidence,
    observed_index,
    split_eol,
)

yaml_handler = YAML()


def _defs_dir(tmp_path, services):
    d = tmp_path / "def"
    d.mkdir(exist_ok=True)
    (d / "services.yml").write_text(services)
    (d / "networks.yml").write_text(
        "networks:\n  LOOPBACK:\n    values:\n      - address: 127.0.0.1/32\n")
    return d


def _loot(tmp_path, host, ports):
    d = tmp_path / "loot"
    d.mkdir(exist_ok=True)
    (d / f"{host}.json").write_text(json.dumps({
        "metadata": {"hostname": host, "os": "linux"},
        "listen_ports": [
            {"protocol": p.get("proto", "tcp"), "port": p["port"],
             "bind_address": "0.0.0.0/0",
             "process": {"name": p.get("proc", "sshd")}, "flags": []}
            for p in ports
        ],
    }))
    return d


class TestObservedIndex:
    def test_counts_processes_and_hosts(self, tmp_path):
        _loot(tmp_path, "a.example.org", [{"port": 22}])
        _loot(tmp_path, "b.example.org", [{"port": 22}])
        idx = observed_index([tmp_path / "loot"])
        assert idx[("tcp", 22)]["hosts"] == {"a_example_org", "b_example_org"}
        assert idx[("tcp", 22)]["procs"]["sshd"] == 2

    def test_unknown_process_is_not_counted_as_a_name(self, tmp_path):
        _loot(tmp_path, "a.example.org", [{"port": 22, "proc": "UNKNOWN"}])
        idx = observed_index([tmp_path / "loot"])
        assert idx[("tcp", 22)]["procs"] == {}
        assert idx[("tcp", 22)]["hosts"] == {"a_example_org"}


class TestEvidence:
    def test_a_range_token_collects_every_port_in_it(self, tmp_path):
        d = _defs_dir(tmp_path, textwrap.dedent("""\
            services:
              RPC_HIGH:
                - {port: 49152-49155, protocol: tcp}
        """))
        _loot(tmp_path, "a.example.org", [{"port": 49153, "proc": "svchost"},
                                          {"port": 49154, "proc": "svchost"}])
        defs = naming.Naming(str(d))
        idx = observed_index([tmp_path / "loot"])
        procs, hosts = evidence_for(defs, "RPC_HIGH", idx)
        assert procs["svchost"] == 2 and hosts == {"a_example_org"}

    def test_unobserved_token_is_none(self, tmp_path):
        d = _defs_dir(tmp_path, "services:\n  SSH:\n    - {port: 22, protocol: tcp}\n")
        _loot(tmp_path, "a.example.org", [{"port": 80}])
        defs = naming.Naming(str(d))
        assert evidence_for(defs, "SSH", observed_index([tmp_path / "loot"])) is None

    def test_host_list_truncates_but_keeps_the_count(self):
        from collections import Counter
        line = format_evidence(Counter({"nginx": 3}), {f"h{i}" for i in range(9)},
                               max_hosts=2)
        assert "Hosts(9):" in line and "+7 more" in line
        assert line.startswith("[auto] ")


class TestCommentOwnership:
    def test_tagged_line_is_replaceable(self):
        assert split_eol("# [auto] Procs: {} | Hosts(0): []")[0].startswith("[auto]")

    def test_an_untagged_line_is_kept_whatever_it_looks_like(self):
        # Untagged is human, full stop — even where it resembles generator output.
        raw = "# Procs: {'sshd': 2} | Hosts: ['a', 'b']"
        replaceable, kept, tail = split_eol(raw)
        assert not replaceable and kept == raw.lstrip("# ") and tail == ""

    def test_a_human_note_is_kept(self):
        replaceable, kept, _ = split_eol("# keep this open until Q3, vendor migrating")
        assert not replaceable
        assert kept == "keep this open until Q3, vendor migrating"

    def test_another_tools_tag_is_kept(self):
        replaceable, kept, _ = split_eol("# [score] DO NOT BLOCK")
        assert not replaceable and kept == "[score] DO NOT BLOCK"

    def test_following_lines_are_a_verbatim_tail(self):
        # ruyaml keeps commented-out data in the same slot as the EOL comment.
        raw = "# [auto] Procs: {}\n#    - HTTPS\n#    - HTTP\n"
        replaceable, kept, tail = split_eol(raw)
        assert replaceable.startswith("[auto]") and kept == ""
        assert tail == "\n#    - HTTPS\n#    - HTTP"


class TestAnnotateFile:
    def _setup(self, tmp_path, services):
        d = _defs_dir(tmp_path, services)
        _loot(tmp_path, "a.example.org", [{"port": 22, "proc": "sshd"}])
        return d, naming.Naming(str(d)), observed_index([tmp_path / "loot"])

    def test_annotation_is_written_and_data_untouched(self, tmp_path):
        import yaml as pyyaml
        src = "services:\n  SSH:\n    - {port: 22, protocol: tcp}\n"
        d, defs, idx = self._setup(tmp_path, src)
        before = pyyaml.safe_load((d / "services.yml").read_text())
        doc, changed, unobserved, kept = annotate_file(d / "services.yml", defs, idx)
        assert changed == 1 and unobserved == 0
        out = tmp_path / "out.yml"
        with open(out, "w") as f:
            yaml_handler.dump(doc, f)
        text = out.read_text()
        assert "[auto] Procs: {'sshd': 1}" in text
        assert pyyaml.safe_load(text) == before

    def test_human_note_survives_the_refresh(self, tmp_path):
        src = ("services:\n"
               "  SSH: # vendor insists on this one\n"
               "    - {port: 22, protocol: tcp}\n")
        d, defs, idx = self._setup(tmp_path, src)
        doc, changed, _, kept = annotate_file(d / "services.yml", defs, idx)
        assert kept == 1
        out = tmp_path / "out.yml"
        with open(out, "w") as f:
            yaml_handler.dump(doc, f)
        text = out.read_text()
        assert "vendor insists on this one" in text
        assert "[auto] Procs:" in text

    def test_stale_annotation_is_replaced_not_appended(self, tmp_path):
        src = ("services:\n"
               "  SSH: # [auto] Procs: {'dropbear': 9} | Hosts(1): ['old_host']\n"
               "    - {port: 22, protocol: tcp}\n")
        d, defs, idx = self._setup(tmp_path, src)
        doc, changed, _, kept = annotate_file(d / "services.yml", defs, idx)
        assert changed == 1 and kept == 0
        out = tmp_path / "out.yml"
        with open(out, "w") as f:
            yaml_handler.dump(doc, f)
        text = out.read_text()
        assert "dropbear" not in text and "old_host" not in text

    def test_rerunning_changes_nothing(self, tmp_path):
        src = "services:\n  SSH:\n    - {port: 22, protocol: tcp}\n"
        d, defs, idx = self._setup(tmp_path, src)
        doc, _, _, _ = annotate_file(d / "services.yml", defs, idx)
        with open(d / "services.yml", "w") as f:
            yaml_handler.dump(doc, f)
        _, changed, _, _ = annotate_file(d / "services.yml", defs, idx)
        assert changed == 0

    def test_unobserved_tokens_are_counted_not_annotated(self, tmp_path):
        src = ("services:\n"
               "  SSH:\n    - {port: 22, protocol: tcp}\n"
               "  GOPHER:\n    - {port: 70, protocol: tcp}\n")
        d, defs, idx = self._setup(tmp_path, src)
        doc, changed, unobserved, _ = annotate_file(d / "services.yml", defs, idx)
        assert changed == 1 and unobserved == 1
        out = tmp_path / "out.yml"
        with open(out, "w") as f:
            yaml_handler.dump(doc, f)
        gopher = [ln for ln in out.read_text().splitlines() if ln.startswith("  GOPHER")]
        assert gopher == ["  GOPHER:"]

    def test_a_file_with_no_services_is_skipped(self, tmp_path):
        p = tmp_path / "networks.yml"
        p.write_text("networks:\n  NET:\n    values:\n      - address: 10.0.0.0/8\n")
        d = _defs_dir(tmp_path, "services:\n  SSH:\n    - {port: 22, protocol: tcp}\n")
        doc, changed, _, _ = annotate_file(p, naming.Naming(str(d)), {})
        assert doc is None and changed == 0

    def test_commented_out_data_after_the_key_survives_and_stays_idempotent(self, tmp_path):
        # A disabled service entry lives in the key's comment slot, after the
        # annotation. Re-running must not duplicate the annotation or eat it.
        src = ("services:\n"
               "  SSH:\n"
               "#    - {port: 2222, protocol: tcp}\n"
               "    - {port: 22, protocol: tcp}\n")
        d, defs, idx = self._setup(tmp_path, src)
        doc, changed, _, _ = annotate_file(d / "services.yml", defs, idx)
        assert changed == 1
        with open(d / "services.yml", "w") as f:
            yaml_handler.dump(doc, f)
        text = (d / "services.yml").read_text()
        assert "#    - {port: 2222, protocol: tcp}" in text
        assert text.count("[auto]") == 1
        _, changed_again, _, _ = annotate_file(d / "services.yml", defs, idx)
        assert changed_again == 0

    def test_a_banner_before_the_key_survives(self, tmp_path):
        # ruyaml's own yaml_add_eol_comment raises on exactly this shape.
        src = ("services:\n"
               "  # ----------------------------\n"
               "  # Remote access\n"
               "  # ----------------------------\n"
               "  SSH:\n    - {port: 22, protocol: tcp}\n")
        d, defs, idx = self._setup(tmp_path, src)
        doc, changed, _, _ = annotate_file(d / "services.yml", defs, idx)
        assert changed == 1
        out = tmp_path / "out.yml"
        with open(out, "w") as f:
            yaml_handler.dump(doc, f)
        text = out.read_text()
        assert "# Remote access" in text
        assert "SSH: # [auto]" in text
