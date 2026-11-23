# Source policy: who may reach each synthesized service.
#
# firru's defaults, used as they are by a project without its own
# site/heuristics.py, and the template for one: copy this file into site/
# and edit it. A site's file is all of its configuration; nothing from this
# one is layered underneath, so keep what you want of the settings below.
# What the site decides rather than guesses (who may administer a host)
# goes in site/policy.py. firru/src_heuristics.py documents each name.
# This file is code, and firru runs it.

# Denied before the drop-ANY rather than given a term.
DENY_SERVICES = {
    "SSDP": "udp",   # UPnP discovery, udp/1900: no legitimate inbound use on servers
}

# Their multicast groups are link-local (224.0.0.251, 224.0.0.252, ff02::fb,
# ff02::1:3): a router will not forward them, so neither should a source rule.
LINK_LOCAL_TOKENS = {
    "MDNS":  ("MDNS_SOURCES_V4",  "MDNS_SOURCES_V6"),
    "LLMNR": ("LLMNR_SOURCES_V4", "LLMNR_SOURCES_V6"),
}

# Management services take their sources from management_sources(). Who
# may administer a host is a decision, so these belong in site/policy.py;
# here they still work for a site that has not moved them.
# MGMT_SERVICES = ["SSH", "RDP", "WINRM-HTTP", "WINRM-HTTPS"]
#
# def management_sources(metadata):
#     """metadata is the host's entry in host_metadata.json; None falls
#     through to the remaining rules (ANY)."""
#     zone = metadata.get("zone")
#     return [f"{zone.upper()}_ADMINS"] if zone else None

# Services whose source is true by definition: a list, or a function of the
# host's zone (None falls through to the remaining rules).
# _ZONE_HOSTS = lambda zone: [f"{zone.upper()}_HOSTS"] if zone else None
# DEFINITIONAL_SOURCES = {"NETBIOS-SSN": _ZONE_HOSTS, "WS-DISCOVERY": _ZONE_HOSTS}

# The last word on every term. Return `suggested`, a replacement, None (no
# term), or a list: here a best guess, and while it is being proven, everyone
# else accepted and logged rather than refused. context carries the protocol,
# port and the loot's listener records (process, services) for the port.
# What a host is for (a domain controller, a CA) is a role file instead, given
# to synth with --role: curated terms, scoped to their programs.
# def rule(host, service, v4, v6, metadata, suggested, context):
#     zone = metadata.get("zone")
#     if service == "POSTGRES" and zone:
#         return [{"action": "accept", "source": [f"{zone.upper()}_APP_SERVERS"]},
#                 {"action": "accept", "source": None, "logging": True, "suffix": "rest"}]
#     return suggested
