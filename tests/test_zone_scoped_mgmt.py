"""
Management sources are per zone, and a zone is one network.

A **zone** is one network (`corp_int`), a **segment** is the group of zones
sharing a name (`corp`). That distinction is load-bearing. `corp` spans an
interior 10.10.12.0/24 and an exterior 198.51.100.0/24; the management hosts of one are not the management
hosts of the other, so anything scoped to the segment hands every interior host
the exterior's addresses as an administrative source -- wider than intended,
and silently so.

A management term names two different parties and neither contains the other:
<ZONE>_GT is the green team's hosts in that network, MGMT_HOSTS is the blue
team's own access.

These are the Locked Shields case study's source policy
(examples/lspr24/def/heuristics.py), loaded the way synthesis loads it.
"""

import functools
import pathlib

from firru import src_heuristics
from firru.src_heuristics import load_profile

LS = load_profile(str(pathlib.Path(__file__).parent.parent / "examples" / "lspr24" / "def"))
get_suggested_source = functools.partial(src_heuristics.get_suggested_source, profile=LS)
get_suggested_rule = functools.partial(src_heuristics.get_suggested_rule, profile=LS)

CORP_INT = {"zone": "corp_int", "segment": "corp"}


def test_the_profile_was_found():
    assert LS.origin and LS.origin.endswith("heuristics.py")


def test_ssh_takes_the_zone_band():
    assert get_suggested_source("h1", "SSH", True, False, CORP_INT) \
        == ["CORP_INT_GT", "MGMT_HOSTS"]


def test_an_explicit_null_band_names_only_the_blue_team():
    """`gt: null` is a statement -- this zone has no known band."""
    md = {"zone": "core", "gt": None}
    assert get_suggested_source("h1", "SSH", True, False, md) == ["MGMT_HOSTS"]


def test_a_host_with_no_zone_names_no_band_at_all():
    """No zone means no band to name; it must not invent `None_GT`."""
    src = get_suggested_source("h1", "SSH", True, False, {}) or []
    assert not any(str(t).endswith("_GT") for t in src)


def test_no_blue_team_range_leaves_only_the_band():
    """`mgmt: null` -- the inventory defines no blue-team access."""
    md = {"zone": "corp_int", "gt": "CORP_INT_GT", "mgmt": None}
    assert get_suggested_source("h1", "SSH", True, False, md) == ["CORP_INT_GT"]


def test_neither_band_nor_blue_team_is_honest_ANY():
    """
    Nothing is known about who may administer this host. Aerleon raises on an
    empty token when it is queried, so naming one here would not fail at
    synthesis -- it would fail at merge, for every zone at once.
    """
    md = {"zone": "core", "gt": None, "mgmt": None}
    assert get_suggested_source("h1", "SSH", True, False, md) == ["ANY"]


# --- definitional sources: true without evidence -----------------------------

def test_netbios_is_zone_scoped_by_definition():
    """NetBIOS is not routed, so its source is the zone's hosts, under the
    names the definitions use."""
    for svc in ("NETBIOS-SSN-LEGACY", "NETBIOS-NS-LEGACY", "NETBIOS-DGM-LEGACY"):
        assert get_suggested_source("h1", svc, True, False, CORP_INT) \
            == ["CORP_INT_HOSTS"], svc


def test_a_definitional_source_still_needs_a_zone():
    """No zone, no host group to name; ANY is the honest answer."""
    src = get_suggested_source("h1", "NETBIOS-SSN", True, False, {})
    assert "HOSTS" not in str(src)


def test_smb_is_deliberately_not_definitional():
    """A file server may legitimately serve another zone; NetBIOS may not."""
    assert "HOSTS" not in str(get_suggested_source("h1", "SMB", True, False, CORP_INT))


def test_discovery_protocols_are_zone_scoped_by_definition():
    """
    Same argument as NetBIOS: a protocol whose whole purpose is finding peers on
    the local network has no case for answering another one. These were the last
    discovery terms left sitting at ANY.
    """
    for svc in ("WINDOWS-BRANCHCACHE-DISCOVERY", "WS-DISCOVERY", "WINDOWS-CDP"):
        assert get_suggested_source("h1", svc, True, False, CORP_INT) \
            == ["CORP_INT_HOSTS"], svc


def test_link_local_discovery_keeps_its_tighter_answer():
    """
    mDNS and LLMNR are not merely zone-scoped, they are link-local: their
    multicast groups are ones a router will not forward at all. The source
    token says so, and the zone rule must not widen them to the whole zone.
    """
    for svc in ("MDNS", "LLMNR"):
        src = str(get_suggested_source("h1", svc, True, True, CORP_INT))
        assert "SOURCES" in src and "CORP_INT_HOSTS" not in src, svc


def test_ssdp_stays_a_deny_rather_than_a_scoped_accept():
    """Scoping a protocol nothing should answer is weaker than refusing it."""
    assert get_suggested_rule("h1", "SSDP", True, False, CORP_INT)["action"] == "deny"
