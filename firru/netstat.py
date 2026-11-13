"""
firru.netstat — BSD and macOS `netstat -an` as a listener source.

The counterpart to `firru.ss` for hosts that have no `ss`. Same contract, same
failure rule: a dump that cannot be read raises, because a host whose sockets
could not be parsed is not a host listening on nothing.

Two things this source does better than the Linux one, and one it cannot do.

Better: the address family is explicit. BSD writes `tcp4` and `tcp6` as the
protocol, so `network_protocol` comes across as a fact rather than an inference
from the bind address. Family is the dimension docs/design.md says everything
drops, and here it arrives for free. Better also: the bind address is real,
unlike an nmap-derived inventory which can only assume `0.0.0.0/0`.

Cannot: **there is no process attribution at all.** BSD `netstat` does not carry
a PID or a command name — that lives in `sockstat` on FreeBSD and `lsof` on
macOS, which are separate collections. So every listener from this source is
`UNKNOWN`, and that is reported rather than papered over: `loot-diff` already
treats a port attributed on one side and UNKNOWN on the other as an annotation
gap rather than a change, which is exactly what this is.

UDP has no state column, so a bound UDP socket is identified the way it is
everywhere else in firru: an unconnected one, with no foreign address. A UDP row
with a real peer is somebody's client socket, not a service.

That test is necessary and not sufficient, and deliberately so. A macOS host's
DNS and mDNS clients hold unconnected UDP sockets on ephemeral ports, and they
come through this filter looking exactly like services. They are not dropped
here, because the port number is not evidence about what a socket is for: that
question belongs to `firru.ephemeral` at the inventory level and to
`audit-services` at the traffic level, which answer it the same way for Linux.
A reader that silently discarded them would be deciding, and readers do not
decide.
"""

import re

import jc


class NetstatParseError(Exception):
    """A saved netstat dump could not be read.

    Distinct from an empty result, for the same reason as `ss.SsParseError`: a
    host that genuinely listens on nothing returns `[]`, and a dump that could
    not be parsed is a statement about the collection. Collapsing the two is how
    `--prune` strips a working host of every rule.
    """


#: BSD netstat opens with this, on FreeBSD, NetBSD, OpenBSD and macOS alike.
#: It is how a loot file is recognized without being told which OS wrote it.
_MARK = "Active Internet connections"


#: Sections newer netstat builds emit that jc's freebsd/osx parser does not
#: know. It reads their column header as a data row, and a header has no dotted
#: address in it, so the parse dies on `local_address.rsplit('.')[1]`.
_UNPARSABLE_SECTIONS = (
    # macOS 26 (and the MPTCP-capable builds before it). Dropping it matches
    # what the Linux reader already does with mptcp rows, and for the same
    # reason: a multipath listener is the tcp listener seen a second way, so
    # keeping it would double-count rather than add anything.
    "Active Multipath Internet connections",
    # A macOS guest on a hypervisor, which every hosted CI runner is. VSock
    # addresses are `3:1024` -- colon-separated, no dot -- so the same rsplit
    # dies on them. Not a network socket in any sense firru cares about: it is
    # the guest-to-host channel, reachable from nowhere on the network.
    "Active VSock sockets",
)


def _drop_unparsable_sections(text: str) -> str:
    """Cut sections jc cannot read, leaving the ones it can.

    This is a parser-compatibility patch and not a judgment about the data: the
    rows removed here carry no listener the `Active Internet connections`
    section does not already carry.

    Deliberately unconditional -- it never asks which jc is installed. That is
    what lets it outlive both the bug and the fix. A fixed jc parses these
    sections into rows firru discards anyway (nothing here has `kind` of
    `network`), so removing them first changes no result; an old jc crashes
    without it. Version sniffing would give the same answer today and become a
    second thing to maintain, and distro-packaged jc will be years behind
    whatever upstream ships, so the old path has to keep working regardless.

    Retire it only when the oldest jc firru supports handles every section
    listed below, and delete the whole function rather than narrowing it: a
    half-retired workaround is one nobody can reason about.
    """
    out, skipping = [], False
    for line in text.splitlines(True):
        stripped = line.strip()
        if stripped in _UNPARSABLE_SECTIONS:
            skipping = True
            continue
        # A new banner ends the skip. Every section starts with one of these.
        if skipping and (stripped.startswith("Active ")
                         or stripped.startswith("Registered ")):
            skipping = False
        if not skipping:
            out.append(line)
    return "".join(out)


def looks_like_netstat(text: str) -> bool:
    """Whether this text is BSD/macOS netstat output rather than Linux `ss`."""
    return _MARK in text[:400]


def parse_netstat_safe(filepath: str) -> list:
    """
    Parse a saved `netstat -an` file via jc, returning the network rows.

    Returns a list of dicts, possibly empty when the host really is listening on
    nothing. Raises `NetstatParseError` when the dump cannot be read.

    One flag trap is worth knowing and is checked here. macOS `netstat -An`
    (capital A, no lowercase a) prints *connections only* and omits every
    listening socket, so it parses perfectly and yields an inventory of nothing.
    That is the silent-empty failure this module exists to refuse, arriving
    through a correct parse instead of a broken one, so it is caught by looking
    at what came back rather than at whether parsing threw.
    """
    try:
        with open(filepath) as f:
            text = f.read()
    except OSError as e:
        raise NetstatParseError(f"{filepath}: cannot read: {e}") from e
    if not text.strip():
        raise NetstatParseError(f"{filepath}: empty file — netstat wrote nothing, "
                                f"which is not the same as a host with no listeners")
    if not looks_like_netstat(text):
        raise NetstatParseError(
            f"{filepath}: does not look like BSD/macOS netstat output "
            f"(no '{_MARK}' banner)")
    try:
        rows = jc.parse('netstat', _drop_unparsable_sections(text))
    except Exception as e:
        raise NetstatParseError(
            f"{filepath}: netstat output not understood ({e}). Add the dump to "
            f"tests/fixtures/ rather than letting the host read as empty.") from e

    net = [r for r in rows if r.get("kind") == "network"]
    if rows and not net:
        raise NetstatParseError(
            f"{filepath}: parsed {len(rows)} row(s) but none are network sockets "
            f"— a UNIX-domain-only dump is not a listener inventory")
    # The `-An` trap, detected on TCP rather than on listeners overall. An
    # unconnected UDP socket on an ephemeral port is somebody's DNS or mDNS
    # client, and a macOS connections-only dump is full of them, so "no
    # listeners at all" never fires. TCP always carries a state column, so a
    # dump with TCP sockets and not one in LISTEN is the signature, and a real
    # host with 49 established connections and zero listening ports is not a
    # thing.
    tcp = [r for r in net if (r.get("transport_protocol") or "").lower() == "tcp"]
    if tcp and not any(str(r.get("state") or "").upper() == "LISTEN" for r in tcp):
        raise NetstatParseError(
            f"{filepath}: {len(tcp)} TCP socket(s) and not one of them is "
            f"listening. This is what `netstat -An` looks like on macOS: capital "
            f"A without lowercase a prints connections only and hides every "
            f"listening socket, so the dump parses cleanly and inventories "
            f"nothing. Re-collect with `netstat -an`.")
    return net


def _is_listener(row) -> bool:
    """A bound service socket, as opposed to somebody's client connection."""
    proto = (row.get("transport_protocol") or "").lower()
    if proto in ("tcp", "sctp"):
        return str(row.get("state") or "").upper() == "LISTEN"
    if proto == "udp":
        # No handshake and no state column, so the unconnected socket is the
        # bound one. A UDP row carrying a real peer is a client.
        return str(row.get("foreign_address") or "*") in ("*", "*.*", "")
    return False


def iter_listeners(rows):
    """Yield (proto, family, bind_address, port) for each listening socket.

    `bind_address` keeps BSD's wildcard as-is; the caller decides what a
    wildcard means, exactly as it does for the Linux source.
    """
    for row in rows:
        if not _is_listener(row):
            continue
        port = row.get("local_port_num")
        if port is None:
            try:
                port = int(row.get("local_port"))
            except (TypeError, ValueError):
                continue
        fam = 6 if (row.get("network_protocol") or "").endswith("6") else 4
        yield ((row.get("transport_protocol") or "").lower(),
               fam,
               row.get("local_address") or "*",
               int(port))
