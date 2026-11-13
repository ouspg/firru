"""
A host as a curated role plus synthesis over its residual: loot-diff
--residual cuts the loot to what the baseline does not explain, synth --role
puts the role's terms before the synthesized ones.
"""

import textwrap

import pytest
from aerleon.lib import naming, policy_builder

from firru import aerleon_caps
from firru.cli.listeners_to_aerleon import load_role, pick_role, synth_host
from firru.cli.loot_diff import diff_baseline, residual_docs


def _listen(proto, port, proc, bind="0.0.0.0"):
    return {"protocol": proto, "port": port, "bind_address": bind,
            "process": {"name": proc}, "flags": []}


def _doc(host, *listeners):
    return {"metadata": {"hostname": host, "os": "windows"},
            "listen_ports": list(listeners)}


@pytest.fixture(scope="module")
def defs(tmp_path_factory):
    d = tmp_path_factory.mktemp("defs")
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          LDAP: [{port: 389, protocol: tcp}]
          RDP: [{port: 3389, protocol: tcp}]
          HTTP-ALT: [{port: 8080, protocol: tcp}]
    """))
    (d / "networks.yml").write_text(textwrap.dedent("""\
        networks:
          ANY:      {values: [{address: 0.0.0.0/0}, {address: '::/0'}]}
    """))
    return naming.Naming(str(d))


STOCK = _doc("stock", _listen("tcp", 389, "lsass"), _listen("tcp", 3389, "svchost"),
             _listen("tcp", 5432, "postgres", bind="127.0.0.1"))
HOST = _doc("dc1", _listen("tcp", 389, "lsass"), _listen("tcp", 3389, "rdpproxy"),
            _listen("tcp", 8080, "java"), _listen("tcp", 5432, "postgres"))


def test_the_residual_is_what_the_baseline_does_not_explain():
    result = diff_baseline({"stock": STOCK}, {"dc1": HOST})
    doc = residual_docs(result, {"dc1": HOST})["dc1"]
    # 8080 added, 3389 held by another program, 5432 widened beyond loopback
    assert sorted(r["port"] for r in doc["listen_ports"]) == [3389, 5432, 8080]
    assert doc["residual"] == {"baseline": "stock", "listeners": 3, "of": 4}


def test_a_host_with_no_baseline_keeps_its_whole_loot():
    result = diff_baseline({"stock": STOCK, "other": STOCK}, {"dc1": HOST},
                           assign=[("x*", "stock"), ("y*", "other")])
    doc = residual_docs(result, {"dc1": HOST})["dc1"]
    assert doc is HOST and "residual" not in doc


@pytest.fixture
def role(tmp_path):
    p = tmp_path / "windows-dc.yaml"
    p.write_text(textwrap.dedent("""\
        terms:
          - name: adds-ldap
            # curated: clients by class
            protocol: tcp
            destination-port: LDAP
            source-address: ADFW_CLIENTS
            action: accept
    """))
    return load_role(p)


def test_role_terms_come_first_and_say_where_they_came_from(defs, role):
    result = diff_baseline({"stock": STOCK}, {"dc1": HOST})
    doc = residual_docs(result, {"dc1": HOST})["dc1"]
    _, policy, _ = synth_host(doc, defs, role=role)
    names = [t["name"] for t in policy["filters"][0]["terms"]]
    assert names.index("adds-ldap") < names.index("allow-tcp-HTTP-ALT")
    assert not any("LDAP" in n for n in names if n != "adds-ldap")
    term = policy["filters"][0]["terms"][names.index("adds-ldap")]
    assert "[auto] role: windows-dc.yaml" in str(term.ca.comment)


def test_a_role_term_may_not_share_a_synthesized_name(defs, tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text("terms:\n  - {name: allow-tcp-HTTP-ALT, action: accept}\n")
    with pytest.raises(ValueError, match="also synthesized"):
        synth_host(_doc("h", _listen("tcp", 8080, "java")), defs, role=load_role(p))


def test_roles_are_picked_by_hostname_first_match(role):
    roles = [("dc*", role), ("*", None)]
    assert pick_role("dc1", roles) is role and pick_role("web1", roles) is None


def test_an_aerleon_without_the_scoping_keys_is_reported(monkeypatch):
    policy = {"filters": [{"header": {"targets": {"windows_advfirewall": "in"}},
                           "terms": [{"name": "t", "windows-program": "x.exe"}]}]}
    monkeypatch.setattr(policy_builder, "BUILTIN_SPEC", {})
    assert any("unscoped" in m for m in aerleon_caps.check_policy(policy))
    monkeypatch.setattr(policy_builder, "BUILTIN_SPEC", {"windows-program": None})
    assert not any("unscoped" in m for m in aerleon_caps.check_policy(policy))


def test_a_port_the_role_covers_gets_no_synthesized_term(defs, role):
    # LDAP is the role's, from clients; a second ANY term would widen it
    _, policy, _ = synth_host(_doc("dc1", _listen("tcp", 389, "lsass")), defs, role=role)
    names = [t["name"] for t in policy["filters"][0]["terms"]]
    assert "adds-ldap" in names and "allow-tcp-LDAP" not in names


def test_a_program_scoped_role_term_covers_only_its_program(defs, tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text(textwrap.dedent("""\
        terms:
          - name: dc-http
            protocol: tcp
            destination-port: HTTP-ALT
            windows-program: '%systemroot%\\System32\\lsass.exe'
            action: accept
    """))
    role = load_role(p)
    lsass = dict(_listen("tcp", 8080, "lsass"),
                 process={"name": "lsass", "exe": r"C:\Windows\System32\lsass.exe"})
    java = dict(_listen("tcp", 8080, "java"), process={"name": "java", "exe": r"C:\jdk\java.exe"})
    for entry, synthesized in ((lsass, False), (java, True)):
        _, policy, _ = synth_host(_doc("h", entry), defs, role=role)
        names = [t["name"] for t in policy["filters"][0]["terms"]]
        assert ("allow-tcp-HTTP-ALT" in names) is synthesized


def test_a_system_scoped_role_term_covers_a_kernel_listener(defs, tmp_path):
    # http.sys (WinRM, WSUS, IIS) listens as System, with no program path
    p = tmp_path / "r.yaml"
    p.write_text("terms:\n  - {name: r, protocol: tcp, destination-port: HTTP-ALT,"
                 " windows-program: System, action: accept}\n")
    _, policy, _ = synth_host(_doc("h", _listen("tcp", 8080, "System")), defs,
                              role=load_role(p))
    assert "allow-tcp-HTTP-ALT" not in [t["name"] for t in policy["filters"][0]["terms"]]
