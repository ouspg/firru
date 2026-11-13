# =============================================================================
# src_heuristics.py — source suggestions for synthesized terms
#
# The engine. Who may reach a service is site policy, so it lives in a
# profile: a Python file, `heuristics.py` in the definitions directory, that
# sets any of the tables and hooks below. Anything it leaves out takes the
# default here, and with no profile at all every service is ANY except the
# few whose answer holds anywhere (link-local discovery, SSDP).
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
# =============================================================================

import importlib.util
import os

DEFAULT_DENY_SERVICES = {
    "SSDP": "udp",   # UPnP discovery — UDP 1900, no legitimate inbound use on servers
}

# Their multicast groups are link-local (224.0.0.251, 224.0.0.252, ff02::fb,
# ff02::1:3): a router will not forward them, so neither should a source rule.
DEFAULT_LINK_LOCAL_TOKENS = {
    "MDNS":  ("MDNS_SOURCES_V4",  "MDNS_SOURCES_V6"),
    "LLMNR": ("LLMNR_SOURCES_V4", "LLMNR_SOURCES_V6"),
}

PROFILE_FILE = "heuristics.py"


class Profile:
    """A site's source policy: a profile module's tables and hooks over the
    defaults. `Profile()` is the defaults alone."""

    def __init__(self, module=None, origin=None):
        def get(name, default):
            return getattr(module, name, default) if module is not None else default

        self.origin = origin
        self.deny_services = get("DENY_SERVICES", DEFAULT_DENY_SERVICES)
        self.link_local_tokens = get("LINK_LOCAL_TOKENS", DEFAULT_LINK_LOCAL_TOKENS)
        self.mgmt_services = frozenset(get("MGMT_SERVICES", ()))
        self.mgmt_any_fallback = frozenset(get("MGMT_ANY_FALLBACK", ()))
        self.definitional_sources = get("DEFINITIONAL_SOURCES", {})
        self.management_sources = get("management_sources", None)
        self.rule_hook = get("rule", None)
        self.dynamic_rules = get("dynamic_rules", None)
        self.targets = get("TARGETS", {})


DEFAULT = Profile()
_loaded = {}


def load_profile(defs_dir):
    """The profile in `defs_dir`/heuristics.py, or the defaults where there
    is none. Loaded once per directory."""
    path = os.path.abspath(os.path.join(defs_dir, PROFILE_FILE)) if defs_dir else None
    if not path or not os.path.isfile(path):
        return DEFAULT
    if path not in _loaded:
        spec = importlib.util.spec_from_file_location(
            f"firru_heuristics_{len(_loaded)}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _loaded[path] = Profile(module, origin=path)
    return _loaded[path]


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
