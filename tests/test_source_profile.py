"""
Source policy is a profile beside the definitions; the engine alone knows only
what holds on any network.
"""

import textwrap

from firru import src_heuristics as sh
from firru.cli.listeners_to_aerleon import listen_to_term


def entry(cidr="0.0.0.0/0"):
    return {"protocol": "tcp", "port": 22, "bind_address": cidr,
            "process": {"name": "sshd", "exe": "/usr/sbin/sshd",
                        "services": [], "user": "root", "pid": 1},
            "flags": []}


def test_without_a_profile_management_is_any():
    assert sh.get_suggested_source("h", "SSH", True, True, {"zone": "corp"}) == "ANY"


def test_without_a_profile_link_local_and_ssdp_still_hold():
    assert "MDNS_SOURCES_V4" in sh.get_suggested_source("h", "MDNS", True, False, {})
    assert sh.get_suggested_rule("h", "SSDP", True, False, {})["action"] == "deny"


def test_a_directory_without_a_profile_gets_the_defaults(tmp_path):
    assert sh.load_profile(str(tmp_path)) is sh.DEFAULT


def write_profile(tmp_path, body):
    (tmp_path / sh.PROFILE_FILE).write_text(textwrap.dedent(body))
    return sh.load_profile(str(tmp_path))


def test_a_profile_names_management_sources(tmp_path):
    p = write_profile(tmp_path, """
        MGMT_SERVICES = ["SSH"]
        def management_sources(md):
            return [md["zone"].upper() + "_ADMINS"] if md.get("zone") else None
        """)
    assert sh.get_suggested_source("h", "SSH", True, True, {"zone": "corp"}, p) == ["CORP_ADMINS"]
    # None falls through to the rest of the rules: here, ANY
    assert sh.get_suggested_source("h", "SSH", True, True, {}, p) == "ANY"


def test_the_rule_hook_can_add_a_logged_accept_for_the_rest(tmp_path):
    """A best guess, and while it is being proven, everyone else accepted and
    logged rather than refused."""
    p = write_profile(tmp_path, """
        def rule(host, service, v4, v6, md, suggested, context):
            if service != "SSH":
                return suggested
            return [{"action": "accept", "source": ["CORP_ADMINS"]},
                    {"action": "accept", "source": None, "logging": True, "suffix": "rest"}]
        """)
    terms = listen_to_term("h", "tcp", 22, ["SSH"], [entry()], {"zone": "corp"}, profile=p)
    assert [t["name"] for t in terms] == ["allow-tcp-SSH", "allow-tcp-SSH-rest"]
    assert terms[0]["source-address"] == ["CORP_ADMINS"]
    assert "source-address" not in terms[1] and terms[1]["logging"] == "true"
    assert sh.get_suggested_source("h", "SSH", True, True, {}, p) == ["CORP_ADMINS"]


def test_the_rule_hook_can_drop_a_term(tmp_path):
    p = write_profile(tmp_path, """
        def rule(host, service, v4, v6, md, suggested, context):
            return None if service == "TELNET" else suggested
        """)
    assert listen_to_term("h", "tcp", 23, ["TELNET"], [entry()], {}, profile=p) is None


def test_the_stock_template_changes_nothing():
    from firru.defs_dir import STOCK
    p = sh.load_profile(str(STOCK))
    assert p.origin  # it is there to copy
    assert not p.mgmt_services and not p.definitional_sources
    assert p.management_sources is None and p.rule_hook is None


def test_the_stock_template_examples_work_uncommented(tmp_path):
    from firru.defs_dir import STOCK
    lines = (STOCK / sh.PROFILE_FILE).read_text().splitlines()
    # only the code lines: assignments, defs and their bodies
    code = "\n".join(l[2:] for l in lines
                     if l.startswith("# ") and (l[2:].startswith(("MGMT_", "DEFINITIONAL", "_ZONE",
                         "def ")) or l.startswith("#     ")))
    (tmp_path / sh.PROFILE_FILE).write_text(code + "\n")
    p = sh.load_profile(str(tmp_path))
    md = {"zone": "corp"}
    assert sh.get_suggested_source("h", "SSH", True, True, md, p) == ["CORP_ADMINS"]
    assert sh.get_suggested_source("h", "NETBIOS-SSN", True, True, md, p) == ["CORP_HOSTS"]
    rules = sh.get_suggested_rule("h", "POSTGRES", True, True, md, p)
    assert rules[0]["source"] == ["CORP_APP_SERVERS"] and rules[1]["logging"]


def test_a_rule_can_carry_term_options(tmp_path):
    p = write_profile(tmp_path, """
        def rule(host, service, v4, v6, md, suggested, context):
            return dict(suggested, options={"windows-service": "sshd"})
        """)
    (term,) = listen_to_term("h", "tcp", 22, ["SSH"], [entry()], {}, profile=p)
    assert term["windows-service"] == "sshd"


DC_LOOT = {"metadata": {"hostname": "dc", "os": "windows"}, "listen_ports": [
    {"protocol": "tcp", "port": 49668, "bind_address": "0.0.0.0/0",
     "process": {"name": "lsass", "exe": "C:\\Windows\\System32\\lsass.exe",
                 "services": ["Netlogon", "NTDS"]}, "flags": []},
    {"protocol": "tcp", "port": 49670, "bind_address": "0.0.0.0/0",
     "process": {"name": "lsass", "exe": "C:\\Windows\\System32\\lsass.exe",
                 "services": ["Netlogon", "NTDS"]}, "flags": []},
    {"protocol": "tcp", "port": 49701, "bind_address": "0.0.0.0/0",
     "process": {"name": "spoolsv", "exe": "C:\\Windows\\System32\\spoolsv.exe",
                 "services": ["Spooler"]}, "flags": []},
]}


def synth(profile):
    from aerleon.lib import naming
    from firru.cli.listeners_to_aerleon import synth_host
    from firru.defs_dir import STOCK
    _, pol, _ = synth_host(dict(DC_LOOT), naming.Naming(str(STOCK)), profile=profile)
    return pol


def test_dynamic_listeners_get_no_term_without_a_hook():
    terms = synth(sh.DEFAULT)["filters"][0]["terms"]
    assert not any("dynamic" in t["name"] for t in terms)
    assert "windows_advfirewall" in synth(sh.DEFAULT)["filters"][0]["header"]["targets"]


def test_a_profile_scopes_dynamic_listeners_by_owner(tmp_path):
    p = write_profile(tmp_path, """
        TARGETS = {"windows": "windows_powershell"}
        def dynamic_rules(host, protocol, owner, listeners, md):
            if "NTDS" not in owner["services"]:
                return None
            return {"action": "accept", "source": ["DCS"],
                    "options": {"windows-rpc": "dynamic", "windows-program": owner["program"]}}
        """)
    pol = synth(p)
    (term,) = [t for t in pol["filters"][0]["terms"] if "dynamic" in t["name"]]
    assert term["name"] == "allow-tcp-dynamic-lsass"  # hosts two services: named by process
    assert term["windows-rpc"] == "dynamic" and "destination-port" not in term
    assert term["source-address"] == ["DCS"]
    # one term for both of lsass's ports; Spooler, given no rule, none
    assert pol["filters"][0]["header"]["targets"] == {"windows_powershell": "in mixed block"}
