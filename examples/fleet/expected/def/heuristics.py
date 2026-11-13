# Source policy: who may reach each synthesized service.
#
# firru synth reads heuristics.py from the definitions directory. This one
# sets nothing, so every service gets ANY except link-local discovery (mDNS,
# LLMNR) and SSDP (denied). Copy it into your project's def/ and uncomment
# what your inventory supports; firru/src_heuristics.py documents each name.
# This file is code, and firru runs it.

# Management services take their sources from management_sources().
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
