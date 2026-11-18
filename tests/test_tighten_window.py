"""tighten's header says which flows its comments count: the source, and the
first and last flow that involved the host. A summary means little without
its window, and a later look at the full list should reproduce it."""
import json

from firru import flows
from firru.cli.tighten import collect_flows_from_file, collect_flows_multi, window_line

T0 = 1709748000          # 2024-03-06T18:00:00Z


class _Defs:
    def GetPortParents(self, port, proto):
        return ["SSH"] if port == 22 else []


def _write(tmp_path, rows):
    p = tmp_path / "flows.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return str(p)


def _flow(dst, ts, src="10.0.0.9"):
    return {"protocol": "tcp", "src_ip": src, "dst_ip": dst, "dst_port": 22, "timestamp": ts}


def test_a_group_carries_its_first_and_last_flow(tmp_path):
    path = _write(tmp_path, [_flow("10.0.0.1", T0 + 60), _flow("10.0.0.1", T0),
                             {"protocol": "tcp", "src_ip": "10.0.0.9", "dst_ip": "10.0.0.1",
                              "dst_port": 22}])
    (g,) = flows.iter_flow_groups(path)
    assert (g["n"], g["first"], g["last"]) == (3, T0, T0 + 60)


def test_the_span_is_the_hosts_own(tmp_path):
    """Two hosts in one file: each header gives the flows that involved it."""
    path = _write(tmp_path, [_flow("10.0.0.1", T0), _flow("10.0.0.1", T0 + 3600),
                             _flow("10.0.0.2", T0 + 7200)])
    spans = {}
    collect_flows_multi(path, {"h1": ["10.0.0.1"], "h2": ["10.0.0.2"]}, _Defs(), spans=spans)
    assert spans == {"h1": [T0, T0 + 3600], "h2": [T0 + 7200, T0 + 7200]}
    span = [None, None]
    collect_flows_from_file(path, ["10.0.0.1"], _Defs(), span=span)
    assert span == [T0, T0 + 3600]


def test_the_header_line(tmp_path):
    assert window_line("night.jsonl", [T0, T0 + 3599]) == \
        "Flows: night.jsonl, 2024-03-06T18:00:00Z to 2024-03-06T18:59:59Z"
    assert window_line("night.jsonl", [T0 * 1000, T0 * 1000]).endswith("18:00:00Z to 2024-03-06T18:00:00Z")
    assert window_line("night.jsonl", None) == "Flows: night.jsonl, none for this host"
