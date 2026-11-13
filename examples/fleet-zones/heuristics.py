# Source policy for the zoned fleet (firru.src_heuristics reads this file
# from the definitions directory; see its header for the contract).
#
# Administration comes from the jump host and nowhere else, whatever the
# zone. NetBIOS and the discovery protocols stay inside the host's zone: they
# are not routed, so the zone's hosts are their only clients by definition.

MGMT_SERVICES = ["SSH", "RDP", "WINRM-HTTP", "WINRM-HTTPS"]


def management_sources(metadata):
    return ["jump1"]


def _zone_hosts(zone):
    return [f"{zone.upper()}_HOSTS"] if zone else None


DEFINITIONAL_SOURCES = {
    "NETBIOS-SSN-LEGACY": _zone_hosts,
    "NETBIOS-NS-LEGACY":  _zone_hosts,
    "NETBIOS-DGM-LEGACY": _zone_hosts,
    "WINDOWS-BRANCHCACHE-DISCOVERY": _zone_hosts,
    "WS-DISCOVERY":                  _zone_hosts,
    "WINDOWS-CDP":                   _zone_hosts,
}
