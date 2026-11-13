"""Ephemeral port ranges, shared by the socket side and the flow side.

Both halves of the pipeline need the same notion of "this port number is a
client's, not a service's". On the socket side an ephemeral bind is a
transient artifact of the snapshot; on the flow side an ephemeral
destination port is return traffic recorded as an inbound flow. Filtering
them with two different constants is how the two halves quietly disagree,
so there is one definition here and both import it.
"""

import re

# Linux: net.ipv4.ip_local_port_range. Windows: the Vista-and-later default.
# These are the *defaults*; a host that has narrowed its range says so in its
# own OS metadata rather than needing an entry here. See declared_range.
EPHEMERAL_BY_OS = {
    "linux":   (32768, 60999),
    "windows": (49152, 65535),
}
DEFAULT_EPHEMERAL = EPHEMERAL_BY_OS["linux"]

#: A token at least this wide describes a dynamic range rather than naming a
#: service: the narrowest default range above (Windows, 16,384 ports). Without
#: the floor, WINDOWS-RPC-DYNAMIC is narrower than the Linux range and would
#: "name" every Linux client socket in 49152-60999 (avahi's, say).
RANGE_TOKEN_FLOOR = min(hi - lo + 1 for lo, hi in EPHEMERAL_BY_OS.values())

#: What only ever falls in *both* ranges. Not currently the fallback: see
#: range_for_os. Kept because the asymmetry it encodes is real and the choice
#: is worth revisiting deliberately rather than by accident.
UNKNOWN_EPHEMERAL = (max(EPHEMERAL_BY_OS["linux"][0], EPHEMERAL_BY_OS["windows"][0]),
                     min(EPHEMERAL_BY_OS["linux"][1], EPHEMERAL_BY_OS["windows"][1]))

_WINDOWS_HINTS = ("windows", "win-", "win_", "winnt", "msft", "microsoft")
_LINUX_HINTS = ("linux", "ubuntu", "debian", "rhel", "redhat", "red hat", "centos",
                "fedora", "suse", "alpine", "arch", "rocky", "alma", "gentoo",
                "raspbian", "amzn", "amazon linux")


_RANGE_IN_OS = re.compile(r"(?:^|[\s/:,])(\d{1,5})\s*-\s*(\d{1,5})\s*$")


def declared_range(os_name):
    """An explicit ephemeral range carried in the OS string, or None.

    A host whose dynamic port range has been narrowed is still Windows, and the
    tool has no way to know by how much. Recording it where the OS is already
    recorded keeps that a data change:

        os: windows_server_2022 49152-49651     # RPC range restricted
        os: linux 32768-40000                   # ip_local_port_range tightened

    The point is that a fleet with three different configurations needs three
    metadata values and no new code, which a table of named variants would not
    give: someone would have to add `windows_hardened` to it, and then
    `windows_hardened_2`, and the table would drift from what the hosts are
    actually set to.
    """
    m = _RANGE_IN_OS.search((os_name or "").strip())
    if not m:
        return None
    lo, hi = int(m.group(1)), int(m.group(2))
    if lo > hi or hi > 65535:
        return None
    return lo, hi


def os_family(os_name):
    """"windows", "linux", or None when the string does not say.

    Collectors do not agree on how much detail to record. Loot normalizes to
    `linux`/`windows`; an inventory may carry `windows_server_2022` or
    `ubuntu_24_04_desktop`. An exact-match table silently answered "linux" for
    every one of the detailed spellings, which is right by accident for Ubuntu
    and wrong for Windows, so the match is on family.
    """
    s = (os_name or "").strip().lower()
    s = _RANGE_IN_OS.sub("", s).strip()      # a declared range is not the name
    if not s:
        return None
    if any(h in s for h in _WINDOWS_HINTS):
        return "windows"
    if any(h in s for h in _LINUX_HINTS):
        return "linux"
    return None


def range_for_os(os_name, override=None):
    """The ephemeral range for an OS name, falling back to the Linux range.

    The fallback is unchanged and is worth a second look. Guessing costs
    differently in each direction: assume Windows on a Linux host and
    32768-49151 is kept as services, which is junk a reviewer can delete;
    assume Linux on a Windows host and the same band is dropped as ephemeral,
    which silently removes real services from the policy. `UNKNOWN_EPHEMERAL`
    above is the choice that never does the second thing. Changing to it is a
    behaviour change for every caller, so it is not made here.
    """
    if override:
        return override
    declared = declared_range(os_name)
    if declared:
        return declared
    fam = os_family(os_name)
    return EPHEMERAL_BY_OS[fam] if fam else DEFAULT_EPHEMERAL


def ephemeral_for(doc, override=None, protocol="tcp", os_name=None):
    """The ephemeral range for one host and protocol.

    The host's own range when its loot recorded one (loot-host writes
    `netsh int ipv4 show dynamicport` on Windows, ip_local_port_range on
    Linux), else the default for its OS. The defaults hold on every stock
    install firru-os-baselines measured, but a role can move them: Exchange
    setup sets TCP to 6005-64325 and leaves UDP at 49152-64325, which is why
    the protocol matters.
    """
    if override:
        return override
    meta = (doc or {}).get("metadata") or {}
    own = (meta.get("ephemeral") or {})
    rng = own.get(protocol) or own.get("tcp")
    if rng:
        return tuple(rng)
    return range_for_os(os_name or meta.get("os"))


def is_ephemeral(port, rng=DEFAULT_EPHEMERAL):
    """True when `port` falls in `rng`. A non-numeric port is never ephemeral."""
    try:
        p = int(port)
    except (TypeError, ValueError):
        return False
    return rng[0] <= p <= rng[1]


def parse_range(spec):
    """Parse a 'LO-HI' command-line override into a (lo, hi) tuple."""
    lo, _, hi = str(spec).partition("-")
    if not hi:
        raise ValueError(f"ephemeral range must be LO-HI, got {spec!r}")
    lo, hi = int(lo), int(hi)
    if lo > hi:
        raise ValueError(f"ephemeral range is inverted: {spec!r}")
    return lo, hi
