# Source policy for the LSPR24 case study (firru.src_heuristics reads this
# file from the definitions directory; see its header for the contract).
#
# Three sources administer the hosts in this capture, and none contains
# another: the green team's hosts in that network (<ZONE>_GT), the network's
# management entry point (<ZONE>_MGMT), and the blue team's own access
# (MGMT_HOSTS). A zone is one subnet (defs_from_expoid.py). The last two are assumptions, filled by
# assumptions.py. Of the 28 sources that got an answer on SSH or RDP
# overnight, 25 are green-team hosts and the other three are the blue team's
# (assumptions.yml). None is shared across networks: a segment spans several,
# and handing one network's management hosts to another is wider than meant.

MGMT_SERVICES = ['SSH', 'RDP', 'WINRM-HTTP', 'WINRM-HTTPS', 'WINDOWS-AD-ADWS']


def management_sources(metadata):
    """
    The green team's hosts in the host's zone, the zone's management entry
    point, then the blue team's access; or None (fall through) for a host with no zone.

    Any may be absent, and the inventory says so explicitly: `gt: null` for a
    zone with no labelled green-team host, `zone_mgmt: null` where none is
    assumed for the zone, `mgmt: null` where no blue-team range is defined at all.
    Each is a statement, not a gap. Naming a token the
    inventory leaves empty does not fail at synthesis; it fails when the
    policy is merged or compiled, a long way from the mistake.

    With none, the term is ANY: nothing is known about who may administer
    this host, and a restriction invented to fill the gap would be a claim
    the inventory cannot support.
    """
    zone = metadata.get("zone")
    if metadata.get("boundary"):
        # A boundary device is in no zone: its administrators are the blue
        # team's, and the entry points of the subnets it sits in.
        srcs = [*(metadata.get("zone_mgmt") or []), metadata.get("mgmt")]
        return [t for t in srcs if t] or None
    if not zone:
        return None
    green = metadata["gt"] if "gt" in metadata else f"{zone.upper()}_GT"
    entries = metadata.get("zone_mgmt") or []
    mgmt = metadata["mgmt"] if "mgmt" in metadata else "MGMT_HOSTS"
    return [t for t in (green, *entries, mgmt) if t] or ["ANY"]


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
