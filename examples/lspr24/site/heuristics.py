# Guesses about who may reach what in the LSPR24 case study: answers true by
# definition, whatever the site decided (firru.site_profile has the
# contract). Who may administer a host is a decision, in site/policy.py.


# Kept from firru's shipped heuristics.py: a site's file is all of its
# configuration. SSDP (UPnP discovery, udp/1900) has no legitimate inbound
# use on a server, and mDNS and LLMNR are link-local (224.0.0.251,
# 224.0.0.252, ff02::fb, ff02::1:3): a router will not forward them, so
# neither should a source rule.
DENY_SERVICES = {"SSDP": "udp"}
LINK_LOCAL_TOKENS = {
    "MDNS":  ("MDNS_SOURCES_V4",  "MDNS_SOURCES_V6"),
    "LLMNR": ("LLMNR_SOURCES_V4", "LLMNR_SOURCES_V6"),
}


# Services whose right source is a definition rather than an observation.
# Only answers true by definition belong here: a file server may serve
# another zone, so SMB is absent; NetBIOS is not routed and has no such case.
# A host with no zone has no host group to name and falls through to ANY.
def _zone_hosts(zone):
    return [f"{zone.upper()}_HOSTS"] if zone else None


DEFINITIONAL_SOURCES = {
    "NETBIOS-SSN-LEGACY": _zone_hosts,
    "NETBIOS-NS-LEGACY":  _zone_hosts,
    "NETBIOS-DGM-LEGACY": _zone_hosts,
    # Discovery protocols, for the same reason: a service whose purpose is to
    # find peers on the local network has no case for answering another one.
    # WS-Discovery and CDP use the site-local group 239.255.255.250, which a
    # router will forward if asked; scoping them to the zone says nobody
    # should. (mDNS and LLMNR are link-local, a tighter default.)
    "WINDOWS-BRANCHCACHE-DISCOVERY": _zone_hosts,   # WS-Discovery, udp/3702
    "WS-DISCOVERY":                  _zone_hosts,
    "WINDOWS-CDP":                   _zone_hosts,   # Connected Devices, udp/5050
}
