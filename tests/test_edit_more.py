import argparse
import textwrap

from aerleon.lib import naming
from ruyaml import YAML

from firru.cli.edit import cmd_apply, cmd_set_source, cmd_rm, cmd_diff


def _defs(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text(textwrap.dedent("""\
        services:
          SSH:
            - {port: 22, protocol: tcp}
          HTTP:
            - {port: 80, protocol: tcp}
          HXXP:
            - {port: 80, protocol: tcp}
          MYSQL:
            - {port: 3306, protocol: tcp}
    """))
    (d / "networks.yml").write_text("networks:\n  LOOPBACK:\n    - {address: 127.0.0.1/32}\n")
    return str(d)


def _pol(terms):
    body = "\n".join(terms)
    return textwrap.dedent("""\
        metadata: {host: H1}
        filters:
          - header: {targets: {nftables: mixed input DROP}}
            terms:
        """) + body + "\n"


def _t(name, port, src=None):
    lines = [f"      - name: {name}", "        protocol: tcp",
             f"        destination-port: {port}", "        action: accept"]
    if src:
        lines.insert(3, f"        source-address: {src}")
    return "\n".join(lines)


DROP = "      - {name: drop-ANY, action: deny}"


def _write(tmp_path, fname, content):
    p = tmp_path / fname
    p.write_text(content)
    return str(p)


def _read(path):
    with open(path) as f:
        return f.read()


def _apply_args(tmp_path, pol, new, base=None, **kw):
    kw.setdefault("only", None)
    kw.setdefault("prune", False)
    kw.setdefault("scoring", None)
    kw.setdefault("dry_run", False)
    return argparse.Namespace(pol=pol, from_=new, base=base, defs=_defs(tmp_path), **kw)


class TestPrune:
    def _setup(self, tmp_path):
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-SSH", "SSH"), _t("allow-tcp-HTTP", "HTTP"), DROP]))
        base = _write(tmp_path, "base.yml", _pol([_t("allow-tcp-SSH", "SSH"), _t("allow-tcp-HTTP", "HTTP")]))
        new = _write(tmp_path, "new.yml", _pol([_t("allow-tcp-SSH", "SSH")]))
        return pol, base, new

    def test_prune_removes(self, tmp_path):
        pol, base, new = self._setup(tmp_path)
        cmd_apply(_apply_args(tmp_path, pol, new, base, prune=True))
        assert "allow-tcp-HTTP" not in _read(pol)

    def test_no_prune_keeps(self, tmp_path):
        pol, base, new = self._setup(tmp_path)
        cmd_apply(_apply_args(tmp_path, pol, new, base, prune=False))
        assert "allow-tcp-HTTP" in _read(pol)

    def test_scoring_vetoes_prune(self, tmp_path):
        pol, base, new = self._setup(tmp_path)
        scoring = _write(tmp_path, "s.yml", "H1:\n  - {proto: tcp, port: 80, note: keep}\n")
        cmd_apply(_apply_args(tmp_path, pol, new, base, prune=True, scoring=scoring))
        assert "allow-tcp-HTTP" in _read(pol)  # vetoed → kept


class TestCosmetic:
    def test_rename_propagates(self, tmp_path):
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-HTTP", "HTTP"), DROP]))
        base = _write(tmp_path, "base.yml", _pol([_t("allow-tcp-HTTP", "HTTP")]))
        new = _write(tmp_path, "new.yml", _pol([_t("allow-tcp-HXXP", "HXXP")]))
        cmd_apply(_apply_args(tmp_path, pol, new, base))
        doc = YAML().load(_read(pol))
        names = [t.get("name") for t in doc["filters"][0]["terms"]]
        assert "allow-tcp-HXXP" in names and "allow-tcp-HTTP" not in names
        hxxp = next(t for t in doc["filters"][0]["terms"] if t.get("name") == "allow-tcp-HXXP")
        assert hxxp["destination-port"] == "HXXP"


class TestSetSource:
    def _pol(self, tmp_path):
        return _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-SSH", "SSH"), DROP]))

    def test_single(self, tmp_path):
        pol = self._pol(tmp_path)
        cmd_set_source(argparse.Namespace(pol=pol, term="allow-tcp-SSH", peers=["NET_MGMT"], defs="def"))
        doc = YAML().load(_read(pol))
        assert doc["filters"][0]["terms"][0]["source-address"] == "NET_MGMT"

    def test_list(self, tmp_path):
        pol = self._pol(tmp_path)
        cmd_set_source(argparse.Namespace(pol=pol, term="allow-tcp-SSH", peers=["NET_A", "NET_B"], defs="def"))
        doc = YAML().load(_read(pol))
        assert list(doc["filters"][0]["terms"][0]["source-address"]) == ["NET_A", "NET_B"]

    def test_any_clears(self, tmp_path):
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-SSH", "SSH", src="NET_MGMT"), DROP]))
        cmd_set_source(argparse.Namespace(pol=pol, term="allow-tcp-SSH", peers=["ANY"], defs="def"))
        doc = YAML().load(_read(pol))
        assert "source-address" not in doc["filters"][0]["terms"][0]


class TestRm:
    def test_removes(self, tmp_path):
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-SSH", "SSH"), _t("allow-tcp-HTTP", "HTTP"), DROP]))
        cmd_rm(argparse.Namespace(pol=pol, term="allow-tcp-HTTP"))
        assert "allow-tcp-HTTP" not in _read(pol)
        assert "allow-tcp-SSH" in _read(pol)


class TestEmitSh:
    def test_emits_runnable_commands(self, tmp_path, capsys):
        old = _write(tmp_path, "old.yml", _pol([_t("allow-tcp-SSH", "SSH"), _t("allow-tcp-HTTP", "HTTP")]))
        new = _write(tmp_path, "new.yml", _pol([_t("allow-tcp-SSH", "SSH", src="NET_MGMT"), _t("allow-tcp-MYSQL", "MYSQL")]))
        rc = cmd_diff(argparse.Namespace(old=old, new=new, defs=_defs(tmp_path), output="sh"))
        assert rc == 1
        out = capsys.readouterr().out
        assert f"firru set-source {old} allow-tcp-SSH NET_MGMT" in out        # enforcement
        assert f"firru apply {old} --from {new} --only allow-tcp-MYSQL" in out  # addition
        assert f"firru rm {old} allow-tcp-HTTP" in out                       # removal
        # every uncommented line is a runnable firru command, greppable by
        # service; commented lines are the terminal swap, deliberate-only
        assert all(line.startswith(("firru ", "#")) for line in out.strip().splitlines())


# ---------------------------------------------------------------------------
# Egress terms edit the destination field, and only via the matching verb
# ---------------------------------------------------------------------------

def _merged_pol(in_terms, out_terms):
    return (textwrap.dedent("""\
        metadata: {host: H1}
        filters:
          - header: {targets: {nftables: inet filter input}}
            terms:
        """) + "\n".join(in_terms) + "\n"
        + "  - header: {targets: {nftables: inet filter output}}\n"
        + "    terms:\n"
        + "\n".join(out_terms) + "\n")


def _et(name, port, dst=None):
    lines = [f"      - name: {name}", "        protocol: tcp",
             f"        destination-port: {port}", "        action: accept"]
    if dst:
        lines.insert(3, f"        destination-address: {dst}")
    return "\n".join(lines)


class TestSetDestination:
    def _pol(self, tmp_path):
        return _write(tmp_path, "pol.yml", _merged_pol(
            [_t("allow-tcp-SSH", "SSH", src="NET_MGMT"), DROP],
            [_et("allow-egress-HTTP", "HTTP"), DROP]))

    def test_sets_the_destination_field(self, tmp_path):
        from firru.cli.edit import cmd_set_destination
        pol = self._pol(tmp_path)
        cmd_set_destination(argparse.Namespace(
            pol=pol, term="allow-egress-HTTP", peers=["CDN"], defs="def"))
        doc = YAML().load(_read(pol))
        assert doc["filters"][1]["terms"][0]["destination-address"] == "CDN"

    def test_it_leaves_the_ingress_term_alone(self, tmp_path):
        from firru.cli.edit import cmd_set_destination
        pol = self._pol(tmp_path)
        cmd_set_destination(argparse.Namespace(
            pol=pol, term="allow-egress-HTTP", peers=["CDN"], defs="def"))
        doc = YAML().load(_read(pol))
        assert doc["filters"][0]["terms"][0]["source-address"] == "NET_MGMT"
        assert "destination-address" not in doc["filters"][0]["terms"][0]

    def test_any_clears_the_destination(self, tmp_path):
        from firru.cli.edit import cmd_set_destination
        pol = _write(tmp_path, "pol.yml", _merged_pol(
            [_t("allow-tcp-SSH", "SSH"), DROP],
            [_et("allow-egress-HTTP", "HTTP", dst="CDN"), DROP]))
        cmd_set_destination(argparse.Namespace(
            pol=pol, term="allow-egress-HTTP", peers=["ANY"], defs="def"))
        doc = YAML().load(_read(pol))
        assert "destination-address" not in doc["filters"][1]["terms"][0]


class TestDirectionGuard:
    """Writing source-address on an egress term is a silent no-op at the
    firewall: the term stays as permissive as it was, and the command says it
    succeeded. It is refused instead."""

    def _pol(self, tmp_path):
        return _write(tmp_path, "pol.yml", _merged_pol(
            [_t("allow-tcp-SSH", "SSH", src="NET_MGMT"), DROP],
            [_et("allow-egress-HTTP", "HTTP"), DROP]))

    def test_set_source_refuses_an_egress_term(self, tmp_path, capsys):
        pol = self._pol(tmp_path)
        rc = cmd_set_source(argparse.Namespace(
            pol=pol, term="allow-egress-HTTP", peers=["CDN"], defs="def"))
        assert rc == 1
        assert "set-destination" in capsys.readouterr().err

    def test_set_destination_refuses_an_ingress_term(self, tmp_path, capsys):
        from firru.cli.edit import cmd_set_destination
        pol = self._pol(tmp_path)
        rc = cmd_set_destination(argparse.Namespace(
            pol=pol, term="allow-tcp-SSH", peers=["CDN"], defs="def"))
        assert rc == 1
        assert "set-source" in capsys.readouterr().err

    def test_a_refused_edit_writes_nothing(self, tmp_path):
        pol = self._pol(tmp_path)
        before = _read(pol)
        cmd_set_source(argparse.Namespace(
            pol=pol, term="allow-egress-HTTP", peers=["CDN"], defs="def"))
        assert _read(pol) == before


class TestEmitShDirections:
    def _pair(self, tmp_path, old_dst, new_dst):
        ingress = [_t("allow-tcp-SSH", "SSH", src="NET_MGMT"), DROP]
        old = _write(tmp_path, "old.yml", _merged_pol(
            ingress, [_et("allow-egress-HTTP", "HTTP", dst=old_dst), DROP]))
        new = _write(tmp_path, "new.yml", _merged_pol(
            ingress, [_et("allow-egress-HTTP", "HTTP", dst=new_dst), DROP]))
        return old, new

    def test_an_egress_change_emits_set_destination(self, tmp_path, capsys):
        old, new = self._pair(tmp_path, None, "CDN")
        cmd_diff(argparse.Namespace(old=old, new=new, defs=_defs(tmp_path), output="sh"))
        out = capsys.readouterr().out
        assert f"firru set-destination {old} allow-egress-HTTP CDN" in out
        assert "set-source" not in out

    def test_the_emitted_command_is_the_one_that_runs(self, tmp_path, capsys):
        # The emitted line must not be refused by its own verb guard.
        old, new = self._pair(tmp_path, None, "CDN")
        cmd_diff(argparse.Namespace(old=old, new=new, defs=_defs(tmp_path), output="sh"))
        line = [l for l in capsys.readouterr().out.splitlines() if "set-" in l][0]
        parts = line.split("#")[0].split()
        from firru.cli.edit import cmd_set_destination
        assert parts[1] == "set-destination"
        rc = cmd_set_destination(argparse.Namespace(
            pol=parts[2], term=parts[3], peers=[parts[4]], defs="def"))
        assert rc == 0


class TestApplyDirections:
    def test_a_narrowing_lands_in_the_egress_filter(self, tmp_path, capsys):
        ingress = [_t("allow-tcp-HTTP", "HTTP", src="NET_MGMT"), DROP]
        pol = _write(tmp_path, "pol.yml", _merged_pol(
            ingress, [_et("allow-egress-HTTP", "HTTP"), DROP]))
        new = _write(tmp_path, "new.yml", _merged_pol(
            ingress, [_et("allow-egress-HTTP", "HTTP", dst="LOOPBACK"), DROP]))
        cmd_apply(argparse.Namespace(pol=pol, from_=new, base=None, only=None,
                                    narrow=True, prune=False, scoring=None,
                                    defs=_defs(tmp_path), dry_run=False))
        doc = YAML().load(_read(pol))
        assert doc["filters"][1]["terms"][0]["destination-address"] == "LOOPBACK"
        # the ingress term at the same port keeps its own peers untouched
        assert doc["filters"][0]["terms"][0]["source-address"] == "NET_MGMT"
        assert "destination-address" not in doc["filters"][0]["terms"][0]


class TestDirectionScope:
    """A generator that proposes only egress emits a document with only that
    filter. Unscoped, the diff reads the absent ingress filter as wholly
    removed, and --prune then deletes the ingress policy."""

    def _pair(self, tmp_path):
        pol = _write(tmp_path, "pol.yml", _merged_pol(
            [_t("allow-tcp-SSH", "SSH", src="NET_MGMT"), DROP],
            [_et("allow-egress-HTTP", "HTTP"), DROP]))
        egress_only = _write(tmp_path, "new.yml",
            "metadata: {host: H1}\nfilters:\n"
            "  - header: {targets: {nftables: inet filter output}}\n"
            "    terms:\n" + _et("allow-egress-HTTP", "HTTP", dst="LOOPBACK") + "\n" + DROP + "\n")
        return pol, egress_only

    def test_unscoped_reads_the_absent_side_as_removed(self, tmp_path):
        from firru.policy import diff_surface
        pol, new = self._pair(tmp_path)
        res = diff_surface(YAML().load(_read(pol)), YAML().load(_read(new)),
                           naming.Naming(_defs(tmp_path)))
        assert [t.get("name") for t, _ in res["removed"]] == ["allow-tcp-SSH"]

    def test_scoping_to_out_leaves_the_ingress_side_alone(self, tmp_path):
        from firru.policy import diff_surface
        pol, new = self._pair(tmp_path)
        res = diff_surface(YAML().load(_read(pol)), YAML().load(_read(new)),
                           naming.Naming(_defs(tmp_path)), direction="out")
        assert not res["removed"]
        assert [t.get("name") for t, _ in res["narrowed"]] == ["allow-egress-HTTP"]

    def test_prune_scoped_out_does_not_delete_the_ingress_policy(self, tmp_path):
        pol, new = self._pair(tmp_path)
        cmd_apply(argparse.Namespace(pol=pol, from_=new, base=None, only=None,
                                     narrow=False, prune=True, scoring=None,
                                     defs=_defs(tmp_path), dry_run=False,
                                     direction="out"))
        assert "allow-tcp-SSH" in _read(pol)

    def test_the_emitted_command_carries_the_scope(self, tmp_path, capsys):
        pol, new = self._pair(tmp_path)
        cmd_diff(argparse.Namespace(old=pol, new=new, defs=_defs(tmp_path),
                                    output="sh", direction="out"))
        for line in capsys.readouterr().out.strip().splitlines():
            if " apply " in line:
                assert "--direction out" in line


class TestTerminalInsertion:
    """An unrestricted accept is as terminal as an unrestricted drop: the egress
    stub `allow-ANY` ends the filter, and a term placed after it never runs."""

    ANY_ACCEPT = "      - {name: allow-ANY, action: accept}"

    def test_a_new_term_goes_before_an_unrestricted_accept(self, tmp_path):
        pol = _write(tmp_path, "pol.yml", _merged_pol(
            [_t("allow-tcp-SSH", "SSH", src="NET_MGMT"), DROP],
            [self.ANY_ACCEPT]))
        new = _write(tmp_path, "new.yml", _merged_pol(
            [_t("allow-tcp-SSH", "SSH", src="NET_MGMT"), DROP],
            [_et("allow-egress-HTTP", "HTTP", dst="LOOPBACK"), self.ANY_ACCEPT]))
        cmd_apply(argparse.Namespace(pol=pol, from_=new, base=None, only=None,
                                     narrow=False, prune=False, scoring=None,
                                     defs=_defs(tmp_path), dry_run=False,
                                     direction="out"))
        names = [t["name"] for t in YAML().load(_read(pol))["filters"][1]["terms"]]
        assert names == ["allow-egress-HTTP", "allow-ANY"]

    def test_a_restricted_accept_is_not_terminal(self, tmp_path):
        # allow-icmp accepts, but only icmp; a new term still goes after it.
        pol = _write(tmp_path, "pol.yml", _merged_pol(
            [_t("allow-tcp-SSH", "SSH", src="NET_MGMT"), DROP],
            ["      - {name: allow-icmp, protocol: icmp, action: accept}",
             self.ANY_ACCEPT]))
        new = _write(tmp_path, "new.yml", _merged_pol(
            [_t("allow-tcp-SSH", "SSH", src="NET_MGMT"), DROP],
            [_et("allow-egress-HTTP", "HTTP", dst="LOOPBACK"), self.ANY_ACCEPT]))
        cmd_apply(argparse.Namespace(pol=pol, from_=new, base=None, only=None,
                                     narrow=False, prune=False, scoring=None,
                                     defs=_defs(tmp_path), dry_run=False,
                                     direction="out"))
        names = [t["name"] for t in YAML().load(_read(pol))["filters"][1]["terms"]]
        assert names == ["allow-icmp", "allow-egress-HTTP", "allow-ANY"]


class TestTerminalSwap:
    """The swap from an open end (allow-ANY) to a logged drop is the
    enforcement decision. It is emitted only as a comment, and adopted only by
    name."""

    LOG_DROP = "      - {name: log-drop-egress-ANY, action: deny, logging: true}"
    ANY_ACCEPT = "      - {name: allow-ANY, action: accept}"

    def _pair(self, tmp_path):
        pol = _write(tmp_path, "pol.yml", _merged_pol(
            [_t("allow-tcp-SSH", "SSH", src="NET_MGMT"), DROP],
            [self.ANY_ACCEPT]))
        new = _write(tmp_path, "new.yml", _merged_pol(
            [_t("allow-tcp-SSH", "SSH", src="NET_MGMT"), DROP],
            [_et("allow-egress-HTTP", "HTTP", dst="LOOPBACK"), self.LOG_DROP]))
        return pol, new

    def test_the_swap_is_emitted_as_a_comment(self, tmp_path, capsys):
        pol, new = self._pair(tmp_path)
        cmd_diff(argparse.Namespace(old=pol, new=new, defs=_defs(tmp_path),
                                    output="sh", direction="out"))
        out = capsys.readouterr().out
        swap = [l for l in out.splitlines() if "log-drop-egress-ANY" in l and "firru" in l]
        assert swap and all(l.startswith("#") for l in swap)
        assert f"firru rm {pol} allow-ANY" in swap[-1]
        assert "--only log-drop-egress-ANY" in swap[-1]

    def test_no_uncommented_line_touches_the_terminal(self, tmp_path, capsys):
        # `| sh` and every grep subset must pass over the swap.
        pol, new = self._pair(tmp_path)
        cmd_diff(argparse.Namespace(old=pol, new=new, defs=_defs(tmp_path),
                                    output="sh", direction="out"))
        for line in capsys.readouterr().out.splitlines():
            if not line.startswith("#"):
                assert "allow-ANY" not in line and "log-drop" not in line

    def test_the_human_report_names_the_decision(self, tmp_path, capsys):
        pol, new = self._pair(tmp_path)
        cmd_diff(argparse.Namespace(old=pol, new=new, defs=_defs(tmp_path),
                                    output="human", direction="out"))
        out = capsys.readouterr().out
        assert "terminal (out)" in out and "enforcement decision" in out

    def test_matching_closed_ends_report_no_swap(self, tmp_path, capsys):
        pol = _write(tmp_path, "pol.yml", _merged_pol(
            [_t("allow-tcp-SSH", "SSH", src="NET_MGMT"), DROP],
            [_et("allow-egress-HTTP", "HTTP", dst="LOOPBACK"), self.LOG_DROP]))
        cmd_diff(argparse.Namespace(old=pol, new=pol, defs=_defs(tmp_path),
                                    output="sh", direction="out"))
        assert "terminal" not in capsys.readouterr().out

    def _apply(self, pol, new, tmp_path, only):
        return cmd_apply(argparse.Namespace(
            pol=pol, from_=new, base=None, only=only, narrow=False, prune=False,
            scoring=None, defs=_defs(tmp_path), dry_run=False, direction="out"))

    def test_apply_never_adopts_a_terminal_mechanically(self, tmp_path):
        pol, new = self._pair(tmp_path)
        self._apply(pol, new, tmp_path, only=None)
        assert "log-drop-egress-ANY" not in _read(pol)

    def test_the_commented_command_performs_the_swap(self, tmp_path):
        # rm allow-ANY && apply --only log-drop-egress-ANY, as emitted.
        pol, new = self._pair(tmp_path)
        cmd_rm(argparse.Namespace(pol=pol, term="allow-ANY"))
        self._apply(pol, new, tmp_path, only=["log-drop-egress-ANY"])
        names = [t["name"] for t in YAML().load(_read(pol))["filters"][1]["terms"]]
        assert names[-1] == "log-drop-egress-ANY"
        assert "allow-ANY" not in names

    def test_reversed_order_still_leaves_the_terminal_live(self, tmp_path, capsys):
        # Applied before the rm, the terminal goes in front of allow-ANY (so it
        # runs) and the now-dead accept is named for removal.
        pol, new = self._pair(tmp_path)
        self._apply(pol, new, tmp_path, only=["log-drop-egress-ANY"])
        out = capsys.readouterr().out
        names = [t["name"] for t in YAML().load(_read(pol))["filters"][1]["terms"]]
        assert names.index("log-drop-egress-ANY") < names.index("allow-ANY")
        assert "is now dead" in out and f"firru rm {pol} allow-ANY" in out


class TestRegroupIsNotARename:
    """A port folded into a group token classifies as cosmetic *at that port*,
    but copying the group token onto the old single-port term would widen it to
    the whole group. The group term arrives as an addition; the old term stays
    (for --prune to retire later)."""

    def _docs(self, tmp_path):
        d = tmp_path / "def"
        d.mkdir()
        (d / "services.yml").write_text(textwrap.dedent("""\
            services:
              TCP_5000:
                - {port: 5000, protocol: tcp}
              APPGROUP:
                - {port: 5000, protocol: tcp}
                - {port: 8080, protocol: tcp}
        """))
        (d / "networks.yml").write_text("networks:\n  LOOPBACK:\n    - {address: 127.0.0.1/32}\n")
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-TCP_5000", "TCP_5000"), DROP]))
        new = _write(tmp_path, "new.yml", _pol([_t("allow-tcp-appgroup", "APPGROUP"), DROP]))
        return str(d), pol, new

    def test_apply_does_not_widen_the_old_term(self, tmp_path):
        defs, pol, new = self._docs(tmp_path)
        cmd_apply(argparse.Namespace(pol=pol, from_=new, base=None, only=None,
                                     narrow=False, prune=False, scoring=None,
                                     defs=defs, dry_run=False, direction=None))
        doc = YAML().load(_read(pol))
        terms = {t["name"]: t for t in doc["filters"][0]["terms"]}
        assert terms["allow-tcp-TCP_5000"]["destination-port"] == "TCP_5000"
        assert terms["allow-tcp-appgroup"]["destination-port"] == "APPGROUP"

    def test_a_true_rename_still_propagates(self, tmp_path):
        # HXXP covers exactly HTTP's surface, so the rename is surface-preserving.
        defs = _defs(tmp_path)
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-HTTP", "HTTP"), DROP]))
        new = _write(tmp_path, "new.yml", _pol([_t("allow-tcp-HXXP", "HXXP"), DROP]))
        cmd_apply(argparse.Namespace(pol=pol, from_=new, base=None, only=None,
                                     narrow=False, prune=False, scoring=None,
                                     defs=defs, dry_run=False, direction=None))
        assert "allow-tcp-HXXP" in _read(pol)


class TestLootSide:
    """`firru diff pol.yml loot.json` synthesizes the loot in memory with the
    current code and diffs the result — observed × intended without writing."""

    def _loot(self, tmp_path, ports, hostname="h1", unknown_port=None):
        import json
        entries = [{"protocol": "tcp", "port": p, "bind_address": "0.0.0.0/0",
                    "process": {"name": "svc", "cmdline": "", "exe": "",
                                "services": [], "user": None, "pid": "1"},
                    "flags": ["world-listen"]} for p in ports]
        if unknown_port:
            entries.append({"protocol": "tcp", "port": unknown_port,
                            "bind_address": "0.0.0.0/0",
                            "process": {"name": "mystery", "cmdline": "", "exe": "",
                                        "services": [], "user": None, "pid": "2"},
                            "flags": ["world-listen"]})
        path = tmp_path / f"{hostname}.json"
        path.write_text(json.dumps(
            {"metadata": {"hostname": hostname, "os": "linux"},
             "listen_ports": entries}))
        return str(path)

    def test_a_new_listener_appears_as_added(self, tmp_path, capsys):
        defs = _defs(tmp_path)
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-SSH", "SSH"), DROP]))
        loot = self._loot(tmp_path, [22, 3306])
        rc = cmd_diff(argparse.Namespace(old=pol, new=loot, defs=defs,
                                         output="human", direction="in"))
        out = capsys.readouterr().out
        assert rc == 1 and "MYSQL" in out and "added (1)" in out

    def test_an_unnamed_port_cannot_vanish(self, tmp_path, capsys):
        # Port 4242 has no service token: it is in no synthesized term, so
        # the diff must raise it as `undefined`, and exit nonzero.
        defs = _defs(tmp_path)
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-SSH", "SSH"), DROP]))
        loot = self._loot(tmp_path, [22], unknown_port=4242)
        rc = cmd_diff(argparse.Namespace(old=pol, new=loot, defs=defs,
                                         output="human", direction="in"))
        out = capsys.readouterr().out
        assert rc == 1
        assert "undefined (1)" in out and "4242" in out and "mystery" in out

    def test_a_dynamic_range_listener_is_left_out_as_synthesis_does_and_said(self, tmp_path, capsys):
        # 42424 is in Linux's ephemeral range: synthesis gives it no term, so
        # neither does the diff, and the diff says it left one out.
        defs = _defs(tmp_path)
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-SSH", "SSH"), DROP]))
        loot = self._loot(tmp_path, [22], unknown_port=42424)
        cmd_diff(argparse.Namespace(old=pol, new=loot, defs=defs,
                                    output="human", direction="in"))
        out = capsys.readouterr().out
        assert "undefined" not in out and "added" not in out
        assert "dynamic range: 1 listener(s)" in out

    def test_reviewed_sources_are_kept_not_widened(self, tmp_path, capsys):
        # The review narrowed SSH; synthesis from loot says ANY. Loot carries
        # no source evidence, so that is not a widening to review.
        defs = _defs(tmp_path)
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-SSH", "SSH", src="NET_A"), DROP]))
        loot = self._loot(tmp_path, [22])
        cmd_diff(argparse.Namespace(old=pol, new=loot, defs=defs,
                                    output="human", direction="in"))
        out = capsys.readouterr().out
        assert "widened" not in out and "reviewed sources kept on 1 term(s)" in out

    def test_undefined_lines_in_sh_are_comments(self, tmp_path, capsys):
        defs = _defs(tmp_path)
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-SSH", "SSH"), DROP]))
        loot = self._loot(tmp_path, [22], unknown_port=42424)
        cmd_diff(argparse.Namespace(old=pol, new=loot, defs=defs,
                                    output="sh", direction="in"))
        for line in capsys.readouterr().out.splitlines():
            if "42424" in line:
                assert line.startswith("#")
                assert "edit-services add" in line

    def test_apply_from_loot_adds_the_listener(self, tmp_path):
        defs = _defs(tmp_path)
        pol = _write(tmp_path, "pol.yml", _pol([_t("allow-tcp-SSH", "SSH"), DROP]))
        loot = self._loot(tmp_path, [22, 3306])
        cmd_apply(argparse.Namespace(pol=pol, from_=loot, base=None, only=None,
                                     narrow=False, prune=False, scoring=None,
                                     defs=defs, dry_run=False, direction="in"))
        assert "MYSQL" in _read(pol)

    def test_a_matching_snapshot_diffs_clean_of_additions(self, tmp_path, capsys):
        defs = _defs(tmp_path)
        loot = self._loot(tmp_path, [22])
        # generate, then diff the generation against its own source snapshot
        cmd_apply(argparse.Namespace(pol=_write(tmp_path, "pol.yml", _pol([DROP])),
                                     from_=loot, base=None, only=None,
                                     narrow=False, prune=False, scoring=None,
                                     defs=defs, dry_run=False, direction="in"))
        capsys.readouterr()
        rc = cmd_diff(argparse.Namespace(old=str(tmp_path / "pol.yml"), new=loot,
                                         defs=defs, output="human", direction="in"))
        out = capsys.readouterr().out
        assert "added" not in out


class TestCommentSurvival:
    """The contract's inviolable class: a human comment anchored to the value
    being replaced (a scoring note after a source list, an evidence line after
    a scalar) must survive a mechanical peer edit."""

    POL = textwrap.dedent("""\
        metadata: {host: H1}
        filters:
          - header: {targets: {nftables: mixed input DROP}}
            terms:
              - name: allow-tcp-SSH
                protocol: tcp
                destination-port: SSH
                action: accept
                source-address:
                  - NET_A
                  - NET_B
        # !!! SCORING - DO NOT BLOCK: scored service
              - name: allow-tcp-HTTP
                protocol: tcp
                destination-port: HTTP
                action: accept
                source-address: ANY_V4  # IPv4 0.0.0.0/0 (node)
              - {name: drop-ANY, action: deny}
        """)

    def _write(self, tmp_path):
        p = tmp_path / "pol.yml"
        p.write_text(self.POL)
        return str(p)

    def test_a_comment_after_a_list_survives_set_source(self, tmp_path):
        pol = self._write(tmp_path)
        cmd_set_source(argparse.Namespace(pol=pol, term="allow-tcp-SSH",
                                          peers=["NET_MGMT"], defs="def"))
        text = _read(pol)
        assert "SCORING - DO NOT BLOCK" in text
        # and it still sits between SSH and HTTP, not somewhere else
        assert text.index("NET_MGMT") < text.index("SCORING") < text.index("allow-tcp-HTTP")

    def test_a_scalar_eol_comment_survives_a_list_replacement(self, tmp_path):
        pol = self._write(tmp_path)
        cmd_set_source(argparse.Namespace(pol=pol, term="allow-tcp-HTTP",
                                          peers=["NET_A", "NET_B"], defs="def"))
        text = _read(pol)
        assert "IPv4 0.0.0.0/0" in text
        # not interleaved between the key and its first item
        lines = text.splitlines()
        idx = next(i for i, l in enumerate(lines)
                   if "source-address" in l and i > lines.index("      - name: allow-tcp-HTTP"))
        assert "IPv4" not in lines[idx + 1] or "- NET_A" in lines[idx + 1]

    def test_a_comment_survives_clearing_to_any(self, tmp_path):
        pol = self._write(tmp_path)
        cmd_set_source(argparse.Namespace(pol=pol, term="allow-tcp-SSH",
                                          peers=["ANY"], defs="def"))
        text = _read(pol)
        assert "SCORING - DO NOT BLOCK" in text
        assert "source-address" not in text.split("allow-tcp-HTTP")[0].split("allow-tcp-SSH")[1]

    def test_the_edited_file_still_loads(self, tmp_path):
        pol = self._write(tmp_path)
        cmd_set_source(argparse.Namespace(pol=pol, term="allow-tcp-SSH",
                                          peers=["NET_MGMT"], defs="def"))
        doc = YAML().load(_read(pol))
        assert doc["filters"][0]["terms"][0]["source-address"] == "NET_MGMT"


class TestEmitShNamesTheOldTerm:
    def test_a_rename_plus_narrow_names_the_term_the_file_has(self, tmp_path, capsys):
        # OLD calls it allow-tcp-HTTP with ANY; NEW calls it allow-tcp-HXXP
        # narrowed to LOOPBACK. The command must name allow-tcp-HTTP.
        old = _write(tmp_path, "old.yml", _pol([_t("allow-tcp-HTTP", "HTTP"), DROP]))
        new = _write(tmp_path, "new.yml",
                     _pol([_t("allow-tcp-HXXP", "HXXP", src="LOOPBACK"), DROP]))
        cmd_diff(argparse.Namespace(old=old, new=new, defs=_defs(tmp_path),
                                    output="sh", direction=None))
        line = [l for l in capsys.readouterr().out.splitlines() if "set-source" in l][0]
        assert "allow-tcp-HTTP " in line and "allow-tcp-HXXP" not in line
        # and it runs against OLD
        parts = line.split("#")[0].split()
        rc = cmd_set_source(argparse.Namespace(pol=parts[2], term=parts[3],
                                               peers=[parts[4]], defs="def"))
        assert rc == 0
