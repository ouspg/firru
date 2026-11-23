# =============================================================================
# site_profile.py — what site/ says, as one Profile: heuristics.py (the
# site's guesses) and policy.py (its decisions), and the source suggestions
# synthesis and propose take from them.
#
# Who may reach a service is the site's to say, so it lives in a
# profile: a Python file, site/heuristics.py (or the definitions directory's), that
# sets any of the tables and hooks below; anything it leaves out is unset,
# and a service with no answer is ANY. A project without one gets firru's
# shipped heuristics.py (the stock def/): the few answers that hold anywhere
# (link-local discovery, SSDP), and the template to copy into site/ and edit.
#
# A profile is code and firru runs it: it belongs to the same project as the
# definitions beside it.
#
# Tables (all optional):
#   DENY_SERVICES            {service: proto}  explicit deny before drop-ANY
#   LINK_LOCAL_TOKENS        {service: (v4_token, v6_token)}
#   MGMT_SERVICES            [service]  sources from management_sources()
#   MGMT_ANY_FALLBACK        {service}  ...with ANY appended
#   DEFINITIONAL_SOURCES     {service: [tokens] | callable(zone) -> [tokens] | None}
#                            a source true by definition (NetBIOS is not
#                            routed); None falls through
#   TARGETS                  {os: generator}  e.g. {"windows": "windows_powershell"},
#                            the generator the policy header names (its
#                            options kept)
#
# Hooks (all optional):
#   management_sources(metadata) -> [tokens] | None
#       for MGMT_SERVICES; None falls through to the remaining rules.
#   rule(host, service, v4, v6, metadata, suggested, context)
#           -> rule | [rule] | None
#       sees every suggestion last and returns it, a replacement, a list of
#       rules (one term each, in order: a best guess, then a logged accept
#       for the rest while the guess is proven, say), or None for no term.
#       context: {"protocol", "port", "listeners"}, the listeners being the
#       loot's records for that port (process, services, bind address), or
#       {} where a caller has none.
#   dynamic_rules(host, protocol, owner, listeners, metadata)
#           -> rule | [rule] | None
#       listeners in the host's dynamic port range, which synthesis otherwise
#       leaves out, once per owner ({"program", "name", "services"}): on
#       Windows mostly RPC endpoints, which a rule can match by owner with an
#       option such as windows-rpc. None (the default) emits nothing.
#
# A rule is {"action": "accept", "source": tokens or None (ANY)} or
# {"action": "deny", "protocol": proto}, optionally with "logging": True,
# "options" (more Aerleon term keys, e.g. windows-program for a generator that
# reads it) and, for the second and later rules of a list, a "suffix" for the
# term name.
#
# What the site decides, as opposed to guesses about it, goes in a second
# file beside it, site/policy.py (optional). MGMT_SERVICES,
# MGMT_ANY_FALLBACK and management_sources belong there, and are taken from
# it first (heuristics.py, where older sites have them, second). Also:
#   scored(host, metadata) -> [(protocol, port[, note])] | {(protocol, port): note}
#       the ports that must stay open on the host, such as what an
#       availability check scores, read from wherever the site keeps them.
#       propose never narrows or denies a term covering one.
# =============================================================================

import importlib.util
import itertools
import os

PROFILE_FILE = "heuristics.py"
POLICY_FILE = "policy.py"


_seq = itertools.count()


def _module(path):
    if not path:
        return None
    spec = importlib.util.spec_from_file_location(
        f"firru_site_{next(_seq)}_{os.path.basename(path)[:-3]}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def shipped():
    """firru's shipped heuristics.py (the stock def/): sane defaults, and the
    template a project copies into site/ and edits."""
    from firru.defs_dir import STOCK
    return os.path.join(str(STOCK), PROFILE_FILE)


class Profile:
    """A site's source policy: its heuristics.py (all of it: nothing is
    layered underneath) and its policy.py. `Profile()` sets nothing."""

    def __init__(self, module=None, origin=None, policy=None, policy_origin=None):
        def get(name, default, mod=module):
            return getattr(mod, name, default) if mod is not None else default

        self.origin = origin
        self.deny_services = get("DENY_SERVICES", {})
        self.link_local_tokens = get("LINK_LOCAL_TOKENS", {})
        # Who may administer a host is the site's decision: site/policy.py,
        # with heuristics.py still read where a site has not moved it.
        def decided(name, default):
            return get(name, get(name, default), policy)
        self.mgmt_services = frozenset(decided("MGMT_SERVICES", ()))
        self.mgmt_any_fallback = frozenset(decided("MGMT_ANY_FALLBACK", ()))
        self.definitional_sources = get("DEFINITIONAL_SOURCES", {})
        self.management_sources = decided("management_sources", None)
        self.rule_hook = get("rule", None)
        self.dynamic_rules = get("dynamic_rules", None)
        self.targets = get("TARGETS", {})
        self.policy_origin = policy_origin
        self.scored = get("scored", None, policy)


#: The shipped heuristics.py: what a project without its own gets.
DEFAULT = Profile(_module(shipped()), origin=shipped())
_loaded = {}


def load_profile(defs_dir):
    """The profile in the project's site/heuristics.py, else in
    `defs_dir`/heuristics.py (where it lived before site/), else firru's
    shipped one, with the project's site/policy.py beside it. Whichever is
    found is all of it. Loaded once per pair of files."""
    from firru.defs_dir import STOCK
    from firru.project import site_path
    path = site_path(PROFILE_FILE, note=False)
    if path is None and defs_dir:
        legacy = os.path.join(defs_dir, PROFILE_FILE)
        # The stock one is what a project without its own gets anyway.
        if os.path.isfile(legacy) and os.path.realpath(defs_dir) != os.path.realpath(STOCK):
            path = legacy
    if path is None:
        site_path(PROFILE_FILE)          # inside a project, say what that costs
    if path is None and defs_dir:
        path = os.path.join(defs_dir, PROFILE_FILE)
    path = os.path.abspath(path) if path and os.path.isfile(path) else None
    policy = site_path(POLICY_FILE, note=False)
    policy = os.path.abspath(policy) if policy else None
    if not policy and (not path or path == os.path.abspath(shipped())):
        return DEFAULT
    path = path or os.path.abspath(shipped())
    key = (path, policy)
    if key not in _loaded:
        _loaded[key] = Profile(_module(path), origin=path,
                               policy=_module(policy), policy_origin=policy)
    return _loaded[key]


# =============================================================================
# Implementation
# =============================================================================

def _default_rule(service, v4, v6, metadata, profile):
    if service in profile.deny_services:
        return {"action": "deny", "protocol": profile.deny_services[service]}

    if service in profile.mgmt_services and profile.management_sources:
        srcs = profile.management_sources(metadata)
        if srcs is not None:
            srcs = list(srcs)
            if service in profile.mgmt_any_fallback:
                srcs.append("ANY")
            return {"action": "accept", "source": srcs}

    entry = profile.definitional_sources.get(service)
    src = entry(metadata.get("zone")) if callable(entry) else entry
    if src:
        return {"action": "accept", "source": list(src)}  # fresh: no YAML anchors

    if service in profile.link_local_tokens:
        t4, t6 = profile.link_local_tokens[service]
        srcs = []
        if v4: srcs.append(t4)
        if v6: srcs.append(t6)
        return {"action": "accept", "source": srcs} if srcs else None

    src = (
        "ANY"    if v4 and v6 else
        "ANY_V4" if v4 else
        "ANY_V6" if v6 else
        None
    )
    return {"action": "accept", "source": src}


def get_suggested_rule(host, service, v4, v6, metadata, profile=None, context=None):
    """
    The rule, or list of rules, for one service on one host, or None when no
    term should be emitted. See the header for the rule shape.
    """
    profile = profile or DEFAULT
    rule = _default_rule(service, v4, v6, metadata, profile)
    if profile.rule_hook:
        rule = profile.rule_hook(host, service, v4, v6, metadata, rule, context or {})
    return rule


#: Sources that say nothing about who may connect: never a floor.
_OPEN = {"ANY", "ANY_V4", "ANY_V6"}


def declared_sources(host, service, metadata, profile=None):
    """The sources the site's profile gives `service` on `host`, ANY left
    out: what the site declares, as opposed to what traffic suggested.
    Tightening narrows a term to the peers it saw, but never below these,
    since a source the site declares is review's decision, not a window's."""
    rules = get_suggested_rule(host, service, True, True, metadata or {}, profile)
    out = []
    for r in (rules if isinstance(rules, list) else [rules] if rules else []):
        if (r.get("action") or "accept") != "accept":
            continue
        src = r.get("source")
        for tok in ([src] if isinstance(src, str) else src or []):
            if tok not in _OPEN and tok not in out:
                out.append(tok)
    return out


def scored_ports(host, metadata, profile=None):
    """{(protocol, port): note} the site's policy says must stay open on
    `host`, such as what an availability check scores: {} without a hook.
    `scored(host, metadata)` may give (protocol, port) or (protocol, port,
    note) tuples, or such a mapping."""
    profile = profile or DEFAULT
    if not profile.scored:
        return {}
    got = profile.scored(host, metadata or {}) or {}
    if isinstance(got, dict):
        items = [(k[0], k[1], v) for k, v in got.items()]
    else:
        items = [tuple(x) + (None,) * (3 - len(x)) for x in got]
    out = {}
    for proto, port, note in items:
        try:
            out[(str(proto).lower(), int(port))] = note or "scored"
        except (TypeError, ValueError):
            raise ValueError(f"{profile.policy_origin}: scored({host!r}) gave "
                             f"{(proto, port)!r}, not a protocol and a port")
    return out


def get_dynamic_rules(host, entries, metadata, profile=None):
    """[(protocol, owner, listeners, [rule])] for the dynamic-range listeners
    `entries`, grouped by owner, for the owners the profile gives rules."""
    profile = profile or DEFAULT
    if not profile.dynamic_rules:
        return []
    groups = {}
    for e in entries:
        proc = e.get("process") or {}
        key = (e.get("protocol"), proc.get("exe") or "", proc.get("name") or "",
               tuple(proc.get("services") or ()))
        groups.setdefault(key, []).append(e)
    out = []
    for (protocol, program, name, services), listeners in sorted(groups.items()):
        owner = {"program": program, "name": name, "services": list(services)}
        rules = profile.dynamic_rules(host, protocol, owner, listeners, metadata)
        if rules:
            out.append((protocol, owner, listeners,
                        rules if isinstance(rules, list) else [rules]))
    return out


def get_suggested_source(host, service, v4, v6, metadata, profile=None):
    """The source of the first accept rule, or None (deny or no term)."""
    rule = get_suggested_rule(host, service, v4, v6, metadata, profile)
    rules = rule if isinstance(rule, list) else [rule]
    first = rules[0] if rules else None
    if first is None or first["action"] == "deny":
        return None
    return first.get("source")
