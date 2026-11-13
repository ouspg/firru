import json

import pytest

from firru.cli.loot_diff import (diff_baseline, diff_snapshots, format_text, load_snapshot,
                                 parse_assign)


def doc(hostname, ports, os_type="linux"):
    return {
        "metadata": {"hostname": hostname, "os": os_type},
        "listen_ports": [
            {
                "protocol": p.get("proto", "tcp"),
                "port": p["port"],
                "bind_address": p.get("bind", "0.0.0.0/0"),
                "process": {"name": p.get("proc", "sshd"), "cmdline": "", "exe": "",
                            "services": [], "user": "root", "pid": 1},
                "flags": p.get("flags", ["world-listen", "root-owned"]),
            }
            for p in ports
        ],
    }


def snap(**hosts):
    return {h: doc(h, ports) for h, ports in hosts.items()}


class TestListenerDelta:
    def test_added_and_removed_ports(self):
        old = snap(a=[{"port": 22}, {"port": 80, "proc": "nginx"}])
        new = snap(a=[{"port": 22}, {"port": 8080, "proc": "java"}])
        r = diff_snapshots(old, new)
        assert [e["port"] for e in r["changes"]["a"]["added"]] == [8080]
        assert [e["port"] for e in r["changes"]["a"]["removed"]] == [80]

    def test_unchanged_host_is_absent_from_changes(self):
        old = snap(a=[{"port": 22}])
        r = diff_snapshots(old, snap(a=[{"port": 22}]))
        assert r["changes"] == {}

    def test_same_port_new_binary_is_a_change_not_an_add(self):
        # The interesting case: 443 was nginx at FAM, is something else now.
        old = snap(a=[{"port": 443, "proc": "nginx"}])
        new = snap(a=[{"port": 443, "proc": "python3"}])
        r = diff_snapshots(old, new)
        c = r["changes"]["a"]
        assert c["added"] == [] and c["removed"] == []
        assert c["changed"] == [{"protocol": "tcp", "port": 443,
                                 "was": ["nginx"], "now": ["python3"]}]
        assert c["unattributed"] == []

    def test_losing_the_process_name_is_an_annotation_gap(self):
        # No psexe for the second run: the service did not change hands.
        old = snap(a=[{"port": 443, "proc": "nginx"}])
        new = snap(a=[{"port": 443, "proc": "UNKNOWN"}])
        c = diff_snapshots(old, new)["changes"]["a"]
        assert c["changed"] == []
        assert [e["port"] for e in c["unattributed"]] == [443]

    def test_gaining_a_second_process_still_counts_as_changed(self):
        old = snap(a=[{"port": 8080, "proc": "nginx"}])
        new = snap(a=[{"port": 8080, "proc": "nginx", "bind": "10.0.0.1/32"},
                      {"port": 8080, "proc": "java", "bind": "::/0"}])
        c = diff_snapshots(old, new)["changes"]["a"]
        assert c["changed"] == [{"protocol": "tcp", "port": 8080,
                                 "was": ["nginx"], "now": ["java", "nginx"]}]

    def test_protocol_is_part_of_identity(self):
        old = snap(a=[{"port": 53, "proto": "udp", "proc": "dns"}])
        new = snap(a=[{"port": 53, "proto": "tcp", "proc": "dns"}])
        r = diff_snapshots(old, new)
        assert [e["protocol"] for e in r["changes"]["a"]["added"]] == ["tcp"]
        assert [e["protocol"] for e in r["changes"]["a"]["removed"]] == ["udp"]


class TestBindAddressHandling:
    def test_new_address_on_the_same_port_is_not_an_addition(self):
        # A host that picked up an IPv6 address between runs opened nothing.
        old = snap(a=[{"port": 22, "bind": "10.0.0.1/32"}])
        new = snap(a=[{"port": 22, "bind": "10.0.0.1/32"},
                      {"port": 22, "bind": "2001:db8::1/128"}])
        assert diff_snapshots(old, new)["changes"] == {}

    def test_key_bind_makes_it_visible(self):
        old = snap(a=[{"port": 22, "bind": "10.0.0.1/32"}])
        new = snap(a=[{"port": 22, "bind": "10.0.0.1/32"},
                      {"port": 22, "bind": "2001:db8::1/128"}])
        r = diff_snapshots(old, new, key="bind")
        assert [e["binds"] for e in r["changes"]["a"]["added"]] == [["2001:db8::1/128"]]

    def test_context_merges_across_addresses(self):
        new = snap(a=[{"port": 80, "bind": "10.0.0.1/32", "proc": "nginx"},
                      {"port": 80, "bind": "::/0", "proc": "nginx"}])
        r = diff_snapshots(snap(a=[]), new, key="port")
        added = r["changes"]["a"]["added"][0]
        assert added["binds"] == ["10.0.0.1/32", "::/0"]
        assert added["processes"] == ["nginx"]


class TestRebound:
    def test_same_process_on_a_new_ephemeral_port_is_rebound(self):
        old = snap(a=[{"port": 41234, "proto": "udp", "proc": "avahi-daemon"}])
        new = snap(a=[{"port": 52001, "proto": "udp", "proc": "avahi-daemon"}])
        c = diff_snapshots(old, new)["changes"]["a"]
        assert c["added"] == [] and c["removed"] == []
        assert c["rebound"] == [{"protocol": "udp", "processes": ["avahi-daemon"],
                                 "was": [41234], "now": [52001]}]

    def test_a_real_service_moving_stays_an_add_and_a_remove(self):
        # postgres 5432 -> 5433 is a surface change, not a rebind.
        old = snap(a=[{"port": 5432, "proc": "postgres"}])
        new = snap(a=[{"port": 5433, "proc": "postgres"}])
        c = diff_snapshots(old, new)["changes"]["a"]
        assert [e["port"] for e in c["added"]] == [5433]
        assert [e["port"] for e in c["removed"]] == [5432]
        assert c["rebound"] == []

    def test_only_one_side_ephemeral_does_not_pair(self):
        old = snap(a=[{"port": 8080, "proc": "java"}])
        new = snap(a=[{"port": 41234, "proc": "java"}])
        c = diff_snapshots(old, new)["changes"]["a"]
        assert c["rebound"] == [] and c["added"] and c["removed"]

    def test_a_different_process_does_not_pair(self):
        old = snap(a=[{"port": 41234, "proc": "avahi-daemon"}])
        new = snap(a=[{"port": 52001, "proc": "nc"}])
        c = diff_snapshots(old, new)["changes"]["a"]
        assert c["rebound"] == [] and c["added"] and c["removed"]

    def test_unattributed_ports_never_pair(self):
        # A missing process name is not evidence that a socket was rebound.
        old = snap(a=[{"port": 41234, "proc": "UNKNOWN"}])
        new = snap(a=[{"port": 52001, "proc": "UNKNOWN"}])
        c = diff_snapshots(old, new)["changes"]["a"]
        assert c["rebound"] == [] and c["added"] and c["removed"]

    def test_an_implant_rebinding_pairs_the_same_way(self):
        # The class describes how the port was chosen, not who chose it: this
        # must NOT be silently dropped, only reported as rebound.
        old = snap(a=[{"port": 40001, "proc": "kworkerd"}])
        new = snap(a=[{"port": 55123, "proc": "kworkerd"}])
        c = diff_snapshots(old, new)["changes"]["a"]
        assert c["rebound"][0]["processes"] == ["kworkerd"]

    def test_pairing_can_be_disabled(self):
        old = snap(a=[{"port": 41234, "proto": "udp", "proc": "avahi-daemon"}])
        new = snap(a=[{"port": 52001, "proto": "udp", "proc": "avahi-daemon"}])
        c = diff_snapshots(old, new, ephemeral=(0, 0))["changes"]["a"]
        assert c["rebound"] == [] and c["added"] and c["removed"]

    def test_rebound_ports_stay_out_of_the_added_surface(self):
        from firru.cli.loot_diff import delta_surface
        old = snap(a=[{"port": 41234, "proto": "udp", "proc": "avahi-daemon"}])
        new = snap(a=[{"port": 52001, "proto": "udp", "proc": "avahi-daemon"},
                      {"port": 8888, "proc": "evil"}])
        known, unknown = delta_surface(diff_snapshots(old, new), defs=None)
        assert sorted(unknown) == [("tcp", 8888)]


class TestHostSet:
    def test_hosts_seen_once_are_a_host_delta_not_a_listener_delta(self):
        old = snap(a=[{"port": 22}], gone=[{"port": 22}, {"port": 80}])
        new = snap(a=[{"port": 22}], fresh=[{"port": 22}, {"port": 80}])
        r = diff_snapshots(old, new)
        assert r["hosts"] == {"common": ["a"], "only_old": ["gone"], "only_new": ["fresh"]}
        assert r["changes"] == {}

    def test_new_hosts_opts_their_listeners_in(self):
        r = diff_snapshots(snap(a=[{"port": 22}]),
                           snap(a=[{"port": 22}], fresh=[{"port": 22}, {"port": 80}]),
                           new_hosts=True)
        assert [e["port"] for e in r["changes"]["fresh"]["added"]] == [22, 80]


class TestLoading:
    def test_hostname_comes_from_metadata_not_filename(self, tmp_path):
        (tmp_path / "renamed.json").write_text(json.dumps(doc("real.example.org", [])))
        assert list(load_snapshot(tmp_path)) == ["real.example.org"]

    def test_non_loot_json_is_skipped_with_a_warning(self, tmp_path, capsys):
        (tmp_path / "good.json").write_text(json.dumps(doc("a", [{"port": 22}])))
        (tmp_path / "other.json").write_text(json.dumps({"something": "else"}))
        hosts = load_snapshot(tmp_path)
        assert list(hosts) == ["a"]
        assert "not a loot-listeners document" in capsys.readouterr().err

    def test_empty_directory_is_an_error(self, tmp_path):
        with pytest.raises(ValueError):
            load_snapshot(tmp_path)

    def test_single_file_side(self, tmp_path):
        p = tmp_path / "a.json"
        p.write_text(json.dumps(doc("a", [{"port": 22}])))
        assert list(load_snapshot(p)) == ["a"]


class TestReport:
    def test_summary_counts_every_kind_of_change(self):
        old = snap(a=[{"port": 22}, {"port": 80, "proc": "nginx"}])
        new = snap(a=[{"port": 22, "proc": "dropbear"}, {"port": 8080, "proc": "java"}])
        lines = format_text(diff_snapshots(old, new), "fam", "exec")
        assert lines[-1] == "1 added, 1 removed, 1 changed process, across 1 hosts"
        assert any("+ tcp/8080  java" in ln for ln in lines)
        assert any("~ tcp/22  sshd → dropbear" in ln for ln in lines)

    def test_annotation_gaps_get_their_own_line(self):
        old = snap(a=[{"port": 22, "proc": "sshd"}])
        new = snap(a=[{"port": 22, "proc": "UNKNOWN"}])
        lines = format_text(diff_snapshots(old, new), "fam", "exec")
        assert lines[-2] == "0 added, 0 removed, 0 changed process, across 1 hosts"
        assert lines[-1].startswith("1 ports lost or gained a process name")
        assert any("? tcp/22  sshd → UNKNOWN" in ln for ln in lines)

    def test_host_listing_is_truncated(self):
        old = snap(**{f"h{i}": [] for i in range(5)})
        lines = format_text(diff_snapshots(old, snap(a=[])), "fam", "exec", limit=2)
        assert any("… 3 more" in ln for ln in lines)


class TestBaseline:
    """--baseline: every host against a stock install, not its own past."""

    def base(self):
        return {"stock-dc": doc("stock-dc", [
            {"port": 88, "proc": "lsass"},
            {"port": 389, "proc": "lsass"},
            {"port": 593, "proc": "svchost"},
            {"port": 3306, "proc": "mysqld", "bind": "127.0.0.1/32"},
            {"port": 50001, "proto": "udp", "proc": "dns"},
            {"port": 50002, "proto": "udp", "proc": "dns"},
        ], os_type="windows")}

    def test_every_host_is_compared_whatever_its_name(self):
        new = {h: doc(h, [{"port": 88, "proc": "lsass"}, {"port": 22, "proc": "sshd"}],
                      os_type="windows") for h in ("dc1", "dc2")}
        r = diff_baseline(self.base(), new)
        assert r["assigned"] == {"dc1": "stock-dc", "dc2": "stock-dc"}
        for h in ("dc1", "dc2"):
            c = r["changes"][h]
            assert [e["port"] for e in c["added"]] == [22]
            assert sorted(e["port"] for e in c["removed"]) == [389, 593]
            assert c["dynamic_missing"] == [{"protocol": "udp", "processes": ["dns"],
                                             "stock_ports": 2}]
            assert c["stock"] == 1

    def test_dynamic_ports_of_a_stock_process_are_stock_whatever_the_count(self):
        # A DNS server's socket pool: other numbers, more of them. Not surface.
        new = {"dc1": doc("dc1", [{"port": p, "proto": "udp", "proc": "dns"}
                                  for p in range(60000, 60010)], os_type="windows")}
        c = diff_baseline(self.base(), new)["changes"]["dc1"]
        assert not [e for e in c["added"] if e["protocol"] == "udp"]
        assert c["rebound"][0]["processes"] == ["dns"]

    def test_dynamic_port_of_a_process_the_baseline_lacks_is_added(self):
        new = {"dc1": doc("dc1", [{"port": 61000, "proc": "python"}], os_type="windows")}
        c = diff_baseline(self.base(), new)["changes"]["dc1"]
        assert [(e["port"], e["processes"]) for e in c["added"]] == [(61000, ["python"])]

    def test_loopback_only_in_stock_but_reachable_here_is_widened(self):
        new = {"db1": doc("db1", [{"port": 3306, "proc": "mysqld"}], os_type="windows")}
        c = diff_baseline(self.base(), new)["changes"]["db1"]
        assert [e["port"] for e in c["widened"]] == [3306]
        assert c["added"] == []

    def test_loopback_listeners_are_ignored_on_the_host_side(self):
        # Many collections drop loopback; its absence must not read as hardening
        # and its presence must not read as an addition.
        new = {"dc1": doc("dc1", [{"port": 8000, "proc": "agent", "bind": "127.0.0.1/32"}],
                          os_type="windows")}
        c = diff_baseline(self.base(), new)["changes"]["dc1"]
        assert c["added"] == [] and c["widened"] == []

    def test_stock_port_served_by_another_process_is_changed(self):
        new = {"dc1": doc("dc1", [{"port": 593, "proc": "python"}], os_type="windows")}
        c = diff_baseline(self.base(), new)["changes"]["dc1"]
        assert c["changed"] == [{"protocol": "tcp", "port": 593,
                                 "was": ["svchost"], "now": ["python"]}]

    def test_assign_picks_the_baseline_by_hostname_first_match_wins(self):
        bases = dict(self.base(), **{"stock-ws": doc("stock-ws", [{"port": 5357, "proc": "System"}],
                                                     os_type="windows")})
        new = {h: doc(h, [], os_type="windows") for h in ("dc1", "ws1", "srv1")}
        r = diff_baseline(bases, new, assign=parse_assign(["dc*=stock-dc", "ws*=stock-ws"]))
        assert r["assigned"] == {"dc1": "stock-dc", "ws1": "stock-ws"}
        assert r["hosts"]["only_new"] == ["srv1"]

    def test_assign_to_an_unknown_baseline_is_an_error(self):
        with pytest.raises(ValueError):
            diff_baseline(self.base(), {}, assign=parse_assign(["*=nope"]))
        with pytest.raises(ValueError):
            parse_assign(["no-equals-sign"])

    def test_report_names_the_baseline_and_counts(self):
        new = {"dc1": doc("dc1", [{"port": 22, "proc": "sshd"}], os_type="windows")}
        lines = format_text(diff_baseline(self.base(), new), "stock-dc.json", "exec")
        text = "\n".join(lines)
        assert "baseline stock-dc" in text and "+ tcp/22  sshd" in text
        assert "1 added, 0 widened, 0 other process, 4 missing" in text


def test_a_stock_name_from_another_executable_is_not_stock():
    # avahi-daemon holds a dynamic UDP port on a stock install. A process
    # that calls itself avahi-daemon but runs from elsewhere is not it.
    from firru.cli.loot_diff import diff_baseline

    def doc(exe, port):
        return {"metadata": {"hostname": "h", "os": "linux"}, "listen_ports": [
            {"protocol": "udp", "port": port, "bind_address": "0.0.0.0/0",
             "process": {"name": "avahi-daemon", "exe": exe}, "flags": []}]}
    stock = doc("/usr/sbin/avahi-daemon", 41234)
    same = diff_baseline({"stock": stock}, {"h": doc("/usr/sbin/avahi-daemon", 52000)})
    fake = diff_baseline({"stock": stock}, {"h": doc("/tmp/.x/avahi-daemon", 52000)})
    assert not same["changes"]["h"]["added"] and not same["changes"]["h"]["findings"]
    assert [e["port"] for e in fake["changes"]["h"]["added"]] == [52000]
    assert "/tmp/.x/avahi-daemon" in fake["changes"]["h"]["findings"][0]["message"]
