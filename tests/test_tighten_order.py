"""tighten's evidence comments and blocked lists are written to git, so the
same flows must give the same text whatever order they arrived in."""
from collections import Counter

from firru.cli.tighten import _blocked_sort_key, summarise_annotations


class _Ann:
    """annotate_ip stub: 192.0.2.x is host TEAMA, 198.51.100.x TEAMB, the rest EXTERNAL."""
    def annotate_ip(self, ip):
        if ip.startswith("192.0.2."):
            return {"type": "HOST", "host": "TEAMA", "parents": []}
        if ip.startswith("198.51.100."):
            return {"type": "HOST", "host": "TEAMB", "parents": []}
        return {"type": "EXTERNAL"}


def test_the_comment_does_not_depend_on_arrival_order():
    counts = {"192.0.2.9": 3, "192.0.2.1": 3, "198.51.100.7": 6,
              "203.0.113.5": 1, "203.0.113.4": 1, "2001:db8::1": 1}
    forward = Counter(counts)
    backward = Counter(dict(reversed(list(counts.items()))))
    assert summarise_annotations(forward, _Ann())[0] == summarise_annotations(backward, _Ann())[0]


def test_equal_groups_and_equal_addresses_are_ordered_by_value():
    comment = summarise_annotations(Counter({"198.51.100.7": 6, "192.0.2.9": 3, "192.0.2.1": 3}), _Ann())[0]
    # equal hits (TEAMA 6, TEAMB 6): by name; within TEAMA: by address
    assert comment == "6 hits: TEAMA (192.0.2.1, 192.0.2.9) | 6 hits: TEAMB (198.51.100.7)"


def test_blocked_entries_with_equal_hits_sort_by_value():
    a = {"proto": "tcp", "svc": "SSH", "src_ip": "192.0.2.2", "hits": 1, "reason": "r"}
    b = {"proto": "tcp", "svc": "SSH", "src_ip": "192.0.2.1", "hits": 1, "reason": "r"}
    assert sorted([a, b], key=_blocked_sort_key) == sorted([b, a], key=_blocked_sort_key) == [b, a]
