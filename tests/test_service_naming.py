"""Naming a port from its process: the proposals, and what must never be one."""
import pytest

from firru.service_naming import _common_suite, derive_token, name_port


def h(**kw):
    """process -> hosts, the shape name_port takes."""
    return {p: {f"host{i}" for i in range(n)} for p, n in kw.items()}


def test_a_curated_triple_wins_over_everything():
    tok, basis, _ = name_port("udp", 5050, h(svchost=31))
    assert (tok, basis) == ("WINDOWS-CDP", "curated")


def test_an_opaque_process_alone_names_nothing():
    tok, basis, why = name_port("tcp", 9999, h(svchost=4))
    assert tok is None and basis == "opaque"
    assert "identifies none" in why


def test_a_self_naming_process_derives_its_token():
    tok, basis, _ = name_port("tcp", 3000, h(gitea=3))
    assert (tok, basis) == ("GITEA", "derived")


def test_the_daemon_d_is_not_stripped_because_httpd_is_not_http():
    # Stripping it turned `httpd` into HTTP, an existing token for another
    # port. A proposal that collides with a real name is worse than an ugly one.
    assert derive_token("httpd") == "HTTPD"
    assert derive_token("rigctld") == "RIGCTLD"


def test_a_collision_with_an_existing_token_is_refused_not_renamed():
    tok, basis, why = name_port("tcp", 9099, h(prometheus=1, UNKNOWN=2),
                                taken={"PROMETHEUS"})
    assert tok is None and basis == "collides"
    assert "already use" in why


def test_naming_from_a_minority_process_says_so():
    tok, basis, why = name_port("tcp", 8444, h(nginx=1, java=2))
    assert tok == "NGINX" and basis == "minority"
    assert "1 of 3 hosts" in why


def test_two_real_processes_are_ambiguous_not_guessed():
    tok, basis, _ = name_port("tcp", 8888, h(nginx=2, **{"otelcol-contrib": 1}))
    assert tok is None and basis == "ambiguous"


def test_components_of_one_suite_name_the_suite():
    tok, basis, _ = name_port("udp", 2152,
                              h(**{"open5gs-smfd": 1, "open5gs-upfd": 1}))
    assert (tok, basis) == ("OPEN5GS", "suite")


@pytest.mark.parametrize("names", [
    ["nginx", "nginy"],            # a shared prefix is not a suite
    ["ab-one", "ab-two"],          # too short to mean anything
    ["gitea", "gitea-runner"],     # no separator after the prefix on one side
])
def test_a_shared_prefix_alone_is_not_a_suite(names):
    assert _common_suite(names) is None


# --- the ephemeral range is the host's, not the fleet's ---------------------

def test_each_host_gets_its_own_ephemeral_range(tmp_path):
    """
    Linux hands out 32768-60999 and Windows 49152-65535. One cutoff for the
    fleet is wrong twice: it keeps a Linux client socket on 40000 and discards a
    Linux service on 61000. There is no RPC dynamic range on Linux to justify
    borrowing the Windows one.
    """
    import json
    from firru.cli.suggest_services import load_loot

    def host(name, os_name, ports):
        (tmp_path / f"{name}.json").write_text(json.dumps({
            "metadata": {"hostname": name, "os": os_name},
            "listen_ports": [{"protocol": "tcp", "port": p,
                              "process": {"name": "someproc"}} for p in ports],
        }))

    host("lin", "linux", [40000, 61000, 443])
    host("win", "windows", [40000, 61000, 443])

    seen, dropped = load_loot([str(tmp_path)])
    kept = {(proto, port) for (proto, port) in seen}

    # 40000: ephemeral on Linux, a service on Windows -> kept, from the Windows host
    assert ("tcp", 40000) in kept
    assert "lin" not in set().union(*seen[("tcp", 40000)].values())
    # 61000: a service on Linux, ephemeral on Windows -> kept, from the Linux host
    assert ("tcp", 61000) in kept
    assert "win" not in set().union(*seen[("tcp", 61000)].values())
    # 443 is a service on both
    assert len(set().union(*seen[("tcp", 443)].values())) == 2
    assert dropped == 2


def test_keeping_ephemeral_is_available_but_not_the_default(tmp_path):
    import json
    from firru.cli.suggest_services import load_loot
    (tmp_path / "h.json").write_text(json.dumps({
        "metadata": {"hostname": "h", "os": "linux"},
        "listen_ports": [{"protocol": "udp", "port": 45123,
                          "process": {"name": "avahi-daemon"}}],
    }))
    assert load_loot([str(tmp_path)])[0] == {}
    assert ("udp", 45123) in load_loot([str(tmp_path)], drop_ephemeral=False)[0]


# --- the OS lookup must not answer confidently when it does not know --------

def test_os_family_reads_the_detailed_spellings_a_collector_records():
    from firru.ephemeral import EPHEMERAL_BY_OS, range_for_os
    # An exact-match table answered "linux" for every one of these, which is
    # right by accident for Ubuntu and wrong for 74 Windows hosts.
    assert range_for_os("windows_server_2022") == EPHEMERAL_BY_OS["windows"]
    assert range_for_os("windows_11_25h2") == EPHEMERAL_BY_OS["windows"]
    assert range_for_os("ubuntu_24_04_desktop") == EPHEMERAL_BY_OS["linux"]
    assert range_for_os("debian_13") == EPHEMERAL_BY_OS["linux"]


def test_an_unknown_os_still_falls_back_to_linux():
    """
    The fallback is unchanged, and the test says so explicitly so that changing
    it later is a decision rather than a side effect. UNKNOWN_EPHEMERAL is the
    alternative and the docstring on range_for_os carries the argument.
    """
    from firru.ephemeral import DEFAULT_EPHEMERAL, UNKNOWN_EPHEMERAL, range_for_os
    for unknown in (None, "", "?", "plan9"):
        assert range_for_os(unknown) == DEFAULT_EPHEMERAL
    assert UNKNOWN_EPHEMERAL == (49152, 60999)


# --- a narrowed range is data, not a new code path -------------------------

def test_a_host_declares_its_own_range_in_the_os_field():
    """
    Restricting the Windows dynamic port range is the control the evidence
    points at, and the tool cannot know a host did it. Recording it where the
    OS already is keeps a three-configuration fleet at three metadata values
    and no new code, which a table of named variants would not: someone has to
    add `windows_hardened`, then `windows_hardened_2`, and the table drifts
    from what the hosts are set to.
    """
    from firru.ephemeral import ephemeral_for, os_family, range_for_os
    assert range_for_os("windows_server_2022 49152-49651") == (49152, 49651)
    assert range_for_os("linux 32768-40000") == (32768, 40000)
    assert range_for_os("windows/49152-49251") == (49152, 49251)
    # the declaration is not part of the name
    assert os_family("windows_server_2022 49152-49651") == "windows"
    assert ephemeral_for({"metadata": {"os": "windows 49152-49651"}}) == (49152, 49651)


def test_an_undeclared_host_keeps_the_platform_default():
    from firru.ephemeral import EPHEMERAL_BY_OS, range_for_os
    assert range_for_os("windows_server_2022") == EPHEMERAL_BY_OS["windows"]
    assert range_for_os("ubuntu_24_04") == EPHEMERAL_BY_OS["linux"]


def test_a_malformed_declaration_falls_back_rather_than_inventing_a_range():
    from firru.ephemeral import EPHEMERAL_BY_OS, range_for_os
    for bad in ("windows 1-70000", "windows 50000-40000", "windows abc-def"):
        assert range_for_os(bad) == EPHEMERAL_BY_OS["windows"], bad


# --- when the registry name and the process disagree ------------------------

def test_a_resolver_on_443_is_flagged_not_renamed():
    """
    `unbound` on 443 is DNS-over-HTTPS. The port resolves to HTTPS and the term
    reads `allow-tcp-HTTPS`, which on a nameserver is a web server as far as a
    reviewer can tell. The name is right for the wire protocol and wrong for the
    service, which is a thing to raise rather than settle.
    """
    from firru.service_naming import contradicted
    proc, note = contradicted("tcp", 443, ["unbound", "UNKNOWN"])
    assert proc == "unbound" and "dns daemon" in note


def test_a_resolver_on_a_dns_port_is_not_flagged():
    from firru.service_naming import contradicted
    for port in (53, 853, 5353):
        assert contradicted("udp", port, ["unbound"]) is None, port


def test_an_ordinary_web_server_on_443_is_not_a_contradiction():
    """The general 'process does not match the token' test fires on nginx
    behind HTTPS and is useless. Only daemons that do one thing qualify."""
    from firru.service_naming import contradicted
    assert contradicted("tcp", 443, ["nginx", "caddy", "docker-proxy"]) is None


# --- synthesis drops ephemeral binds, with one carve-out -------------------

def _synth(tmp_path, defs_dir, os_name, ports):
    import json
    from aerleon.lib import naming
    from firru.cli.listeners_to_aerleon import synth_host
    data = {"metadata": {"hostname": "h1.example.org", "os": os_name},
            "listen_ports": [{"protocol": "tcp", "port": p,
                              "bind_address": "0.0.0.0/0",
                              "process": {"name": "someproc"}} for p in ports]}
    _, policy, _ = synth_host(data, naming.Naming(str(defs_dir)))
    return {t.get("destination-port") for f in policy["filters"]
            for t in f["terms"] if t.get("destination-port")}


@pytest.fixture
def defs_dir(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text(
        "services:\n"
        "  MYSQL_X:\n    - port: 33060\n      protocol: tcp\n"
        "  WIDE_RANGE:\n    - port: 49152-65535\n      protocol: tcp\n"
        "  HTTPS:\n    - port: 443\n      protocol: tcp\n")
    (d / "networks.yml").write_text("networks:\n  ANY:\n    values:\n      - address: 0.0.0.0/0\n")
    return d


def test_a_port_registered_inside_the_ephemeral_range_survives(tmp_path, defs_dir):
    """MySQL X on 33060 is inside the Linux range and is still a service."""
    assert "MYSQL_X" in _synth(tmp_path, defs_dir, "linux", [33060, 443])


def test_a_range_token_does_not_rescue_the_whole_range(tmp_path, defs_dir):
    """
    WIDE_RANGE spans 49152-65535, so "has a token" would rescue every dynamic
    port there is. The token must be narrower than the range it rescues from.
    """
    emitted = _synth(tmp_path, defs_dir, "windows", [50000, 443])
    assert "WIDE_RANGE" not in emitted and "HTTPS" in emitted


def test_the_range_is_the_hosts_own(tmp_path, defs_dir):
    # 40000 is ephemeral on Linux and a service on Windows.
    assert _synth(tmp_path, defs_dir, "linux", [40000, 443]) == {"HTTPS"}
    assert "HTTPS" in _synth(tmp_path, defs_dir, "windows", [40000, 443])


def test_the_diff_path_keeps_what_synthesis_drops(tmp_path, defs_dir):
    """
    The two callers want opposite things and both are right. Synthesis drops an
    ephemeral bind because a client socket is not a policy subject. `firru diff`
    keeps it, because a listener appearing in the dynamic range is a change, and
    a diff that silently drops it is the alert the diff exists to raise.
    """
    import json
    from aerleon.lib import naming
    from firru.cli.listeners_to_aerleon import synth_host
    data = {"metadata": {"hostname": "h1.example.org", "os": "linux"},
            "listen_ports": [{"protocol": "tcp", "port": 42424,
                              "bind_address": "0.0.0.0/0",
                              "process": {"name": "someproc"}}]}
    defs = naming.Naming(str(defs_dir))
    _, dropped, _ = synth_host(dict(data), defs)
    _, kept, unknown = synth_host(dict(data), defs, keep_ephemeral=True)
    ports = lambda d: {t.get("destination-port") for f in d["filters"]
                       for t in f["terms"] if t.get("destination-port")}
    assert not ports(dropped)
    assert ports(kept) or unknown        # it survives, named or as unknown
