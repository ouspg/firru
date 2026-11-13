import json
from collections import Counter

from firru.cli.unknown_services import (
    CLIENT_TARGET_PORTS,
    audit_against_flows,
    emit_edit_sh,
    export_audit_yaml,
    generated_token,
    peer_ports_from_flows,
)


def write_flows(tmp_path, flows):
    p = tmp_path / "flows.jsonl"
    p.write_text("".join(json.dumps(f) + "\n" for f in flows))
    return str(p)


def flow(proto="udp", src_port=41234, dst_port=53):
    return {"protocol": proto, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": src_port, "dst_port": dst_port, "responded": True}


def reg(*keys):
    return {k: {"procs": Counter({"someproc": 1}), "hosts": {"h1"}, "anomaly": False}
            for k in keys}


class TestPeerPorts:
    def test_counts_the_other_end_from_either_direction(self, tmp_path):
        f = write_flows(tmp_path, [flow(src_port=41234, dst_port=53),
                                   flow(src_port=53, dst_port=41234)])
        peers = peer_ports_from_flows([f], {("udp", 41234)})
        assert peers[("udp", 41234)] == Counter({53: 2})

    def test_ignores_ports_not_asked_about(self, tmp_path):
        f = write_flows(tmp_path, [flow(src_port=9999, dst_port=53)])
        assert peer_ports_from_flows([f], {("udp", 41234)}) == {}

    def test_protocol_must_match(self, tmp_path):
        f = write_flows(tmp_path, [flow(proto="tcp", src_port=41234, dst_port=53)])
        assert peer_ports_from_flows([f], {("udp", 41234)}) == {}

    def test_survives_a_corrupt_line(self, tmp_path):
        p = tmp_path / "flows.jsonl"
        p.write_text(json.dumps(flow()) + "\nnot json\n" + json.dumps(flow()) + "\n")
        peers = peer_ports_from_flows([str(p)], {("udp", 41234)})
        assert peers[("udp", 41234)][53] == 2


class TestRenderings:
    def _reg(self, procs=("docker-proxy",)):
        return {("tcp", 1100): {"procs": Counter(dict.fromkeys(procs, 2)),
                                "hosts": {"h1", "h2"}, "anomaly": False}}

    def test_both_renderings_name_the_port_identically(self, capsys):
        reg = self._reg()
        export_audit_yaml(reg)
        yaml_out = capsys.readouterr().out
        emit_edit_sh(reg, "def/funny.yml")
        sh_out = capsys.readouterr().out
        token = generated_token("tcp", 1100, reg[("tcp", 1100)]["procs"])
        assert f"  {token}:" in yaml_out
        assert f"add def/funny.yml {token} 1100/tcp" in sh_out

    def test_yaml_rendering_still_runs_with_flags(self, capsys):
        # The docker/anomaly flags read the top process; a token-naming refactor
        # once broke exactly this path while every other test still passed.
        reg = {("tcp", 1100): {"procs": Counter({"dockerd": 1}),
                               "hosts": {"h1"}, "anomaly": True}}
        export_audit_yaml(reg)
        assert "1100" in capsys.readouterr().out

    def test_an_unattributed_port_still_gets_a_name(self):
        assert generated_token("udp", 4444, Counter()) == "UNKNOWN_UDP_4444"

    def test_dots_and_dashes_are_token_safe(self):
        assert generated_token("tcp", 80, Counter({"next-server.v1": 1})) \
            == "next_server_v1_TCP_80"


class TestAuditAgainstFlows:
    def _peers(self, key, counter):
        return {key: Counter(counter)}

    def test_a_dns_client_socket_is_resolved(self):
        registry = reg(("udp", 41234))
        kept, resolved = audit_against_flows(
            registry, self._peers(("udp", 41234), {53: 40}), set(CLIENT_TARGET_PORTS))
        assert kept == {} and list(resolved) == [("udp", 41234)]

    def test_ntp_too(self):
        kept, resolved = audit_against_flows(
            reg(("udp", 50001)), self._peers(("udp", 50001), {123: 9}),
            set(CLIENT_TARGET_PORTS))
        assert list(resolved) == [("udp", 50001)]

    def test_one_odd_peer_keeps_it_on_the_list(self):
        # Funny on both ends: exactly the case a human has to look at.
        kept, resolved = audit_against_flows(
            reg(("udp", 41234)), self._peers(("udp", 41234), {53: 100, 4444: 1}),
            set(CLIENT_TARGET_PORTS))
        assert list(kept) == [("udp", 41234)] and resolved == {}

    def test_no_flow_evidence_keeps_it(self):
        # Silence is not evidence. An unobserved port stays for review.
        kept, resolved = audit_against_flows(reg(("udp", 41234)), {},
                                             set(CLIENT_TARGET_PORTS))
        assert list(kept) == [("udp", 41234)] and resolved == {}

    def test_tcp_is_left_alone_by_default(self):
        # A TCP listener announces itself with LISTEN; no inference needed, and
        # inferring could drop a real one that also queried a resolver.
        kept, resolved = audit_against_flows(
            reg(("tcp", 41234)), self._peers(("tcp", 41234), {53: 5}),
            set(CLIENT_TARGET_PORTS))
        assert list(kept) == [("tcp", 41234)] and resolved == {}

    def test_the_client_target_set_is_configurable(self):
        kept, resolved = audit_against_flows(
            reg(("udp", 41234)), self._peers(("udp", 41234), {53: 5}), {123})
        assert list(kept) == [("udp", 41234)]

    def test_a_beacon_to_a_high_port_is_never_resolved(self):
        # All-outbound to one odd port is what an implant looks like; it must
        # stay on the list rather than pass as a client socket.
        kept, resolved = audit_against_flows(
            reg(("udp", 51000)), self._peers(("udp", 51000), {31337: 2000}),
            set(CLIENT_TARGET_PORTS))
        assert list(kept) == [("udp", 51000)] and resolved == {}
