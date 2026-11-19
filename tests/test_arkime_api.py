"""ArkimeAPI against a fake viewer: what it asks for and how it pages."""

import requests

import firru.arkime as arkime
from firru.arkime import SESSION_FIELDS, ArkimeAPI, process_flow


class FakeViewer:
    """Sessions with a firstPacket each; answers /sessions as Arkime does for
    bounding=first, after `fail` timeouts."""

    def __init__(self, first_packets, fail=0):
        self.sessions = [{"firstPacket": t * 1000} for t in first_packets]
        self.calls, self.fail = [], fail

    def get(self, url, params=None, auth=None, timeout=None):
        if self.fail:
            self.fail -= 1
            raise requests.Timeout("slow")
        self.calls.append(dict(params))
        p = params
        if p.get("date") == -1:
            rows = sorted(self.sessions, key=lambda s: s["firstPacket"],
                          reverse=p["order"].endswith("desc"))
        else:
            assert p["bounding"] == "first"
            rows = [s for s in self.sessions
                    if p["startTime"] * 1000 <= s["firstPacket"] < p["stopTime"] * 1000]
        page = rows[p.get("start", 0):p.get("start", 0) + p["length"]]

        class R:
            status_code = 200
            def raise_for_status(self): pass
            def json(self): return {"data": page, "recordsFiltered": len(rows)}
        return R()


def test_a_window_is_read_an_hour_at_a_time_and_every_session_once(monkeypatch):
    fake = FakeViewer([0, 10, 3599, 3600, 3601, 7300])
    monkeypatch.setattr(arkime.requests, "get", fake.get)
    got = list(ArkimeAPI("http://x/api").search("", SESSION_FIELDS, start_time=0,
                                                stop_time=7400, batch_size=2))
    assert sorted(s["firstPacket"] for s in got) == [0, 10_000, 3_599_000, 3_600_000,
                                                     3_601_000, 7_300_000]
    slices = {(c["startTime"], c["stopTime"]) for c in fake.calls}
    assert slices == {(0, 3600), (3600, 7200), (7200, 7400)}
    assert max(c["start"] for c in fake.calls) <= 2      # no deep offsets


def test_all_time_is_bounded_by_the_first_and_last_session(monkeypatch):
    fake = FakeViewer([5000, 100, 9000])
    monkeypatch.setattr(arkime.requests, "get", fake.get)
    got = list(ArkimeAPI("http://x/api").search("", SESSION_FIELDS, date="-1"))
    assert len(got) == 3


def test_a_timeout_is_retried(monkeypatch):
    fake = FakeViewer([10], fail=1)
    monkeypatch.setattr(arkime.requests, "get", fake.get)
    monkeypatch.setattr(arkime.time, "sleep", lambda s: None)
    assert len(list(ArkimeAPI("http://x/api").search("", SESSION_FIELDS,
                                                     start_time=0, stop_time=60))) == 1


def test_the_fields_asked_for_are_the_fields_process_flow_reads():
    # Asking for fewer left every flow without a time, and every UDP flow
    # unanswered: an absent field is not an error, it is just absent.
    for f in ("firstPacket", "lastPacket", "source.packets", "destination.packets"):
        assert f in SESSION_FIELDS
    udp = {"source": {"ip": "10.0.0.1", "port": 5353, "packets": 1},
           "destination": {"ip": "10.0.0.2", "port": 53, "packets": 1},
           "protocol": ["udp"], "firstPacket": 1_776_150_000_123, "lastPacket": 1_776_150_001_000}
    f = process_flow(udp)
    assert f["responded"] is True and f["timestamp"] == 1_776_150_000


def test_a_crowded_slice_is_halved_until_paging_stays_shallow(monkeypatch):
    # 30 sessions in one hour, at most 8 a slice: no request pages past 8.
    fake = FakeViewer(list(range(0, 3600, 120)))
    monkeypatch.setattr(arkime.requests, "get", fake.get)
    monkeypatch.setattr(arkime, "MAX_PER_SLICE", 8)
    got = list(ArkimeAPI("http://x/api").search("", SESSION_FIELDS, start_time=0,
                                                stop_time=3600, batch_size=4))
    assert sorted(s["firstPacket"] for s in got) == [t * 1000 for t in range(0, 3600, 120)]
    assert max(c["start"] for c in fake.calls) <= 8
