# Who may administer a host in the LSPR24 case study (firru.src_heuristics
# has the contract). A site writes its decisions here. Nobody in this capture
# decided anything that firru can read, so the policy is what the case study
# assumes: each assumption is in assumptions.yml with its source and
# reasoning, and assumptions.py writes it into def/ for this file to name.
#
# Three sources administer the hosts in this capture, and none contains
# another: the green team's hosts in that network (<ZONE>_GT), the network's
# management entry point (<ZONE>_MGMT), and the blue team's own access
# (MGMT_HOSTS). A zone is one subnet (defs_from_expoid.py). The last two are
# assumptions. Of the 28 sources that got an answer on SSH or RDP overnight,
# 25 are green-team hosts and the other three are the blue team's
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
