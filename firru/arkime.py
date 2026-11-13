"""
firru.arkime — Arkime session API client and flow normalization.

Canonical implementation — used by tighten.py and any other tools
that need to query or process Arkime session data.
"""

import json
import time
import requests
from requests.auth import HTTPDigestAuth

_RETRY_DELAYS = [15, 30, 60]  # seconds between attempts on 403


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
                print(f"  Arkime 403 — retrying in {delay}s …", flush=True)
                time.sleep(delay)
            resp = requests.get(f"{self.base}{path}", params=params, auth=self.auth, timeout=60)
            if resp.status_code == 403 and attempt < len(_RETRY_DELAYS):
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
            date:         Lookback in hours as positive string, e.g. "24".
                          Ignored when start_time/stop_time are provided.
            start_time:   ISO date/datetime string or Unix epoch, e.g. "2024-03-01"
                          or "2024-03-01T00:00:00". Converted to epoch seconds.
            stop_time:    ISO date/datetime string or Unix epoch for range end.
                          Defaults to now when start_time is given without stop_time.
            batch_size:   Sessions per API request (default 5000)
            max_sessions: Stop after this many sessions (None = no limit)
        """
        if max_sessions and max_sessions < batch_size:
            batch_size = max_sessions

        params = {
            "expression": expression,
            "fields":     ",".join(fields),
            "length":     batch_size,
            "start":      0,
        }

        if start_time is not None:
            params["startTime"] = _to_epoch(start_time)
            params["stopTime"]  = _to_epoch(stop_time) if stop_time else int(__import__("time").time())
        else:
            params["date"] = date

        count = 0
        while True:
            data     = self.get("/sessions", **params)
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


def build_host_filter(host_ips: list) -> str:
    """Build an Arkime expression matching any flow destined for host_ips."""
    return " || ".join(f"ip.dst == {ip}" for ip in host_ips)


# Session SPI fields process_flow() consumes. Requesting these whole parent
# objects from _source is enough; Arkime stores them as nested objects, so the
# scroll hit's _source is shaped exactly like a viewer session dict.
_ES_SOURCE_FIELDS = [
    "source", "destination", "protocol", "tcpflags", "tags",
    "firstPacket", "lastPacket",
]


class ESClient:
    """
    Direct reader for Arkime's session SPI indices in Elasticsearch/OpenSearch,
    bypassing the viewer API and its offset-pagination rate limits.

    Yields raw session dicts (the scroll hit's ``_source``) shaped exactly like
    the viewer's session objects, so process_flow() consumes them unchanged.

    Uses the plain scroll API, which is identical across Elasticsearch 7/8 and
    OpenSearch (only point-in-time differs between them), so the same code runs
    against either backend. For a single-box analysis node with security
    disabled, pass no auth.

        es = ESClient("http://localhost:9200")
        for s in es.search(date="48"):
            flow = process_flow(s)
    """

    def __init__(self, base_url, index="arkime_sessions3-*", auth=None,
                 verify=True, scroll="2m", batch_size=5000):
        self.base = base_url.rstrip("/")
        self.index = index
        self.auth = auth
        self.verify = verify
        self.scroll = scroll
        self.batch_size = batch_size
        self._scale_cache = None

    def _json(self, method, path, body):
        """Single HTTP round-trip returning parsed JSON. Isolated for testing."""
        resp = requests.request(
            method, f"{self.base}{path}",
            json=body, auth=self.auth, verify=self.verify,
            headers={"Content-Type": "application/json"}, timeout=120,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _window_s(date, start_time, stop_time):
        """(gte, lte) epoch SECONDS from a lookback or an explicit range."""
        if start_time is not None:
            gte = _to_epoch(start_time)
            lte = _to_epoch(stop_time) if stop_time else int(time.time())
        else:
            now = int(time.time())
            gte = now - int(float(date)) * 3600
            lte = now
        return gte, lte

    def _scale(self):
        """Multiplier mapping epoch-seconds to the stored firstPacket unit:
        1000 if the index stores epoch-ms (modern Arkime), 1 if seconds.
        Detected once from a sample doc; defaults to ms."""
        if self._scale_cache is None:
            self._scale_cache = 1000
            try:
                d = self._json("POST", f"/{self.index}/_search",
                               {"size": 1, "_source": ["firstPacket"],
                                "query": {"exists": {"field": "firstPacket"}}})
                hits = d.get("hits", {}).get("hits", [])
                fp = hits[0]["_source"].get("firstPacket") if hits else None
                if fp and fp <= 1e12:        # ~ < year 33658 in seconds
                    self._scale_cache = 1    # index stores seconds
            except Exception:
                pass
        return self._scale_cache

    def search(self, fields=None, date="48", start_time=None, stop_time=None,
               ips=None):
        """
        Yield session _source dicts in the time window, optionally restricted to
        flows whose source or destination is one of ``ips``.

        ``fields`` is accepted for interface parity with ArkimeAPI.search but the
        whole parent objects process_flow needs are always fetched.
        """
        no_window = start_time is None and str(date).lower() in ("all", "-1", "none")
        filters = []
        if not no_window:
            scale = self._scale()
            gte, lte = self._window_s(date, start_time, stop_time)
            # Interval overlap: a session is in-window if it started at/before the
            # window end AND ended at/after the window start. Captures long-lived
            # flows that began before the slice but were active during it; a
            # firstPacket-only range would silently drop them.
            filters.append({"range": {"firstPacket": {"lte": lte * scale}}})
            filters.append({"range": {"lastPacket":  {"gte": gte * scale}}})
        if ips:
            filters.append({"bool": {
                "should": [
                    {"terms": {"source.ip": list(ips)}},
                    {"terms": {"destination.ip": list(ips)}},
                ],
                "minimum_should_match": 1,
            }})

        body = {
            "size": self.batch_size,
            "sort": ["_doc"],
            "_source": _ES_SOURCE_FIELDS,
            "query": {"bool": {"filter": filters}},
        }

        data = self._json("POST", f"/{self.index}/_search?scroll={self.scroll}", body)
        sid = data.get("_scroll_id")
        try:
            while True:
                hits = data.get("hits", {}).get("hits", [])
                if not hits:
                    break
                for h in hits:
                    yield h.get("_source", {})
                data = self._json("POST", "/_search/scroll",
                                  {"scroll": self.scroll, "scroll_id": sid})
                sid = data.get("_scroll_id", sid)
        finally:
            if sid:
                try:
                    self._json("DELETE", "/_search/scroll", {"scroll_id": [sid]})
                except Exception:
                    pass
