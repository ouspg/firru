"""
firru.arkime — Arkime session API client and flow normalization.

Canonical implementation — used by tighten.py and any other tools
that need to query or process Arkime session data.
"""

import time
import requests
from requests.auth import HTTPDigestAuth

_RETRY_DELAYS = [15, 30, 60]  # seconds between attempts on 403 or a timeout

#: The session fields process_flow() reads, as the viewer API names them. A
#: field left out comes back absent, not as an error: without firstPacket a flow
#: has no time, and without the packet counts a UDP flow never reads answered.
SESSION_FIELDS = [
    "source.ip", "destination.ip",
    "source.port", "destination.port",
    "protocol", "tcpflags.syn", "tcpflags.syn-ack", "tags",
    "firstPacket", "lastPacket", "source.packets", "destination.packets",
]

#: How deep offset paging may go. The viewer answers a deep offset slowly (a
#: dump of ~190k sessions timed out past ~108k), so a window is read in time
#: slices, an hour to start with, and a slice holding more sessions than this
#: is halved until it does not: a capture can put 90k sessions in one hour.
SLICE_SECONDS = 3600
MAX_PER_SLICE = 10000


def _to_epoch(value) -> int:
    """Convert an epoch or ISO datetime to integer Unix epoch seconds.

    Accepts epoch seconds, or ISO 8601 incl. timezone offsets and 'Z'
    (e.g. ``2026-04-20T06:00:00+03:00``). A *naive* string (no offset) is
    treated as UTC — pass an explicit offset to slice in exercise-local time.
    """
    if value is None:
        return None
    try:
        return int(value)   # already an epoch integer
    except (ValueError, TypeError):
        pass
    from datetime import datetime, timezone
    s = str(value).strip()
    dt = None
    try:
        dt = datetime.fromisoformat(s)   # date, datetime, +HH:MM, or Z (py3.11+)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
    if dt is None:
        raise ValueError(
            f"Cannot parse time: {value!r}  "
            f"(use epoch seconds or ISO like 2026-04-20T06:00:00+03:00)")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)   # naive -> UTC
    return int(dt.timestamp())


class ArkimeAPI:
    """
    Thin wrapper around the Arkime sessions API.

    Usage:
        from firru.arkime import ArkimeAPI
        from requests.auth import HTTPDigestAuth

        api = ArkimeAPI("http://localhost:8005", HTTPDigestAuth(user, pw))
        for session in api.search("ip.dst == 1.2.3.4", fields=[...], date="1"):
            ...
    """

    def __init__(self, base_url: str, auth=None):
        self.base = base_url.rstrip('/')
        self.auth = auth

    def get(self, path: str, **params):
        for attempt, delay in enumerate([0] + _RETRY_DELAYS):
            if delay:
                time.sleep(delay)
            last = attempt == len(_RETRY_DELAYS)
            try:
                resp = requests.get(f"{self.base}{path}", params=params,
                                    auth=self.auth, timeout=120)
            except (requests.Timeout, requests.ConnectionError) as e:
                if last:
                    raise
                print(f"  Arkime: {type(e).__name__} — retrying in "
                      f"{_RETRY_DELAYS[attempt]}s …", flush=True)
                continue
            if resp.status_code == 403 and not last:
                print(f"  Arkime 403 — retrying in {_RETRY_DELAYS[attempt]}s …", flush=True)
                continue
            resp.raise_for_status()
            return resp.json()

    def search(
        self,
        expression: str,
        fields: list,
        date: str = "48",
        start_time: str = None,
        stop_time: str = None,
        batch_size: int = 500,
        max_sessions: int = None,
    ):
        """
        Yield session dicts from the Arkime sessions API, paginating automatically.

        Args:
            expression:   Arkime search expression, e.g. "ip.dst == 1.2.3.4"
            fields:       List of field names to return
            date:         Lookback in hours as positive string, e.g. "24", or
                          "-1" for all time. Ignored when start_time is given.
            start_time:   ISO date/datetime string or Unix epoch, e.g. "2024-03-01"
                          or "2024-03-01T00:00:00". Converted to epoch seconds.
            stop_time:    ISO date/datetime string or Unix epoch for range end.
                          Defaults to now when start_time is given without stop_time.
            batch_size:   Sessions per API request (default 5000)
            max_sessions: Stop after this many sessions (None = no limit)
        """
        if max_sessions and max_sessions < batch_size:
            batch_size = max_sessions

        if start_time is not None:
            lo = _to_epoch(start_time)
            hi = _to_epoch(stop_time) if stop_time else int(time.time())
        elif str(date) == "-1":
            # All time: from the first session's first packet to past the last's.
            ends = []
            for order in ("asc", "desc"):
                data = self.get("/sessions", expression=expression, date=-1, length=1,
                                fields="firstPacket", order=f"firstPacket:{order}")
                rows = data.get("data") or []
                if not rows:
                    return
                ends.append(int(rows[0]["firstPacket"] // 1000))
            lo, hi = ends[0], ends[1] + 1
        else:
            hi = int(time.time())
            lo = hi - int(float(date) * 3600)

        # Time slices, each paged from offset 0, with the session counted in
        # the slice its first packet falls in (bounding=first): measured on
        # 6.4.0, abutting [t, t+3600] slices add up to the whole window, where
        # the default bounding counts a long session in every slice it spans.
        count = 0
        pending = [(t, min(t + SLICE_SECONDS, hi)) for t in range(lo, hi, SLICE_SECONDS)]
        while pending:
            a, b = pending.pop(0)
            params = {
                "expression": expression,
                "fields":     ",".join(fields),
                "length":     batch_size,
                "start":      0,
                "startTime":  a,
                "stopTime":   b,
                "bounding":   "first",
                "order":      "firstPacket:asc",
            }
            data = self.get("/sessions", **params)
            if data.get("recordsFiltered", 0) > MAX_PER_SLICE and b - a > 1:
                mid = (a + b) // 2
                pending[:0] = [(a, mid), (mid, b)]
                continue
            while True:
                sessions = data.get("data", [])
                if not sessions:
                    break
                for s in sessions:
                    yield s
                    count += 1
                    if max_sessions and count >= max_sessions:
                        return
                params["start"] += len(sessions)
                if params["start"] >= data.get("recordsFiltered", 0):
                    break
                data = self.get("/sessions", **params)


def process_flow(s: dict) -> dict | None:
    """
    Normalize a raw Arkime session dict into a simple flow dict.

    TCP originator is determined via tcpflags: if syn > 0 and no syn-ack,
    source is the originator. Incomplete TCP sessions are flagged but kept.

    Emits timing (timestamp/end_time, epoch seconds), per-direction packet
    counts (orig_pkts/resp_pkts), and a `responded` boolean (the
    admitted/blocked practice-outcome signal) alongside the 5-tuple.

    Returns None for sessions missing src/dst IP or protocol.
    """
    src_ip   = s.get("source",      {}).get("ip")
    dst_ip   = s.get("destination", {}).get("ip")
    src_port = s.get("source",      {}).get("port")
    dst_port = s.get("destination", {}).get("port")
    tags     = s.get("tags", [])
    protos   = s.get("protocol", [])

    if not src_ip or not dst_ip:
        return None

    # Canonicalise protocol to a single string
    if 'tcp' in protos:
        proto = 'tcp'
    elif 'udp' in protos:
        proto = 'udp'
    elif 'icmp' in protos:
        proto = 'icmp'
    elif protos:
        proto = '_'.join(protos)
    else:
        return None

    # TCP: filter to sessions with some handshake info
    originator = None
    if proto == 'tcp':
        syn     = s.get("tcpflags", {}).get("syn",     0)
        syn_ack = s.get("tcpflags", {}).get("syn-ack", 0)
        if not syn and not syn_ack and "incomplete-tcp" not in tags:
            return None   # no useful direction info, skip
        if syn and not syn_ack:
            originator = src_ip
        else:
            originator = src_ip   # completed handshake, src is initiator

    # Timing and per-direction counts (present in every Arkime session,
    # previously dropped). firstPacket/lastPacket are epoch ms in Arkime.
    def _epoch_s(v):
        if not isinstance(v, (int, float)):
            return None
        return int(v / 1000) if v > 1e12 else int(v)

    orig_pkts = s.get("source",      {}).get("packets")
    resp_pkts = s.get("destination", {}).get("packets")

    # Practice-outcome signal: did the listener respond? For TCP this is the
    # admitted/blocked axis (SYN-ACK seen, or any responder packet). More
    # robust than `incomplete` alone, but still best-effort under partial
    # capture: an uncaptured return path reads as not-responded.
    syn_ack   = s.get("tcpflags", {}).get("syn-ack", 0) if proto == 'tcp' else 0
    responded = bool(syn_ack) or bool(resp_pkts)

    return {
        "protocol":   proto,
        "src_ip":     src_ip,
        "dst_ip":     dst_ip,
        "src_port":   src_port,
        "dst_port":   dst_port,
        "originator": originator,
        "timestamp":  _epoch_s(s.get("firstPacket")),
        "end_time":   _epoch_s(s.get("lastPacket")),
        "orig_pkts":  orig_pkts,
        "resp_pkts":  resp_pkts,
        "responded":  responded,
        "incomplete": "incomplete-tcp" in tags,
        "tags":       [t for t in tags if t != "incomplete-tcp"],
        "source":     "arkime",
        # A session reaches here only with handshake evidence or an
        # incomplete-tcp tag, so TCP direction is settled. UDP and ICMP have
        # no handshake to settle it with, and Arkime's src is whichever end
        # the capture saw first -- the same guess Zeek's OTH represents.
        "direction_known": proto == "tcp",
    }
