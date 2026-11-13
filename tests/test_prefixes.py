"""firru.prefixes.PrefixTree: the longest-prefix match that replaced pytricia.

The fixed cases always run. Where pytricia is installed (it needs a C
compiler, which is why firru no longer depends on it), the same operations on
random prefixes and addresses must give identical answers in both."""
import ipaddress
import random

import pytest

from firru.prefixes import PrefixTree


def test_longest_match_and_exact_keys():
    t = PrefixTree(32)
    t.insert("10.0.0.0/8", "big")
    t["10.1.0.0/16"] = "mid"
    t.insert("10.1.2.3/32", "host")
    assert t.get("10.1.2.3") == "host"
    assert t.get("10.1.9.9") == "mid"
    assert t.get("10.200.0.1") == "big"
    assert t.get("11.0.0.1") is None and t.get("11.0.0.1", "d") == "d"
    assert t.get("10.1.2.0/24") == "mid"            # a prefix looks up its container
    assert t.has_key("10.1.0.0/16") and not t.has_key("10.1.0.0/17")
    assert "10.9.9.9" in t and "11.0.0.1" not in t and len(t) == 3


def test_delete_exposes_the_parent_and_clears_the_cache():
    # The annotator finds a host's enclosing prefix by deleting it and looking up.
    t = PrefixTree(32)
    t.insert("10.1.0.0/16", "mid")
    t.insert("10.1.2.3/32", "host")
    assert t.get("10.1.2.3") == "host"                # cached
    t.delete("10.1.2.3/32")
    assert t.get("10.1.2.3") == "mid"
    with pytest.raises(KeyError):
        t.delete("10.1.2.3/32")


def test_ipv6_and_the_default_route():
    t = PrefixTree(128)
    t.insert("::/0", "any")
    t.insert("2001:db8::/32", "doc")
    assert t.get("2001:db8::1") == "doc"
    assert t.get("2001:0db8:0000:0000:0000:0000:0000:0001") == "doc"   # spelled out
    assert t.get("fe80::1") == "any"


def test_the_wrong_family_or_junk_is_a_value_error():
    t = PrefixTree(32)
    for bad in ("2001:db8::1", "nope", "10.0.0.0/33"):
        with pytest.raises(ValueError):
            t.get(bad)
    assert "2001:db8::1" not in t


@pytest.mark.parametrize("bits", [32, 128])
def test_same_answers_as_pytricia(bits):
    pytricia = pytest.importorskip("pytricia")
    rnd = random.Random(bits)
    ours, theirs = PrefixTree(bits), pytricia.PyTricia(bits)
    cls = ipaddress.IPv4Network if bits == 32 else ipaddress.IPv6Network
    addr = ipaddress.IPv4Address if bits == 32 else ipaddress.IPv6Address
    nets = []
    for i in range(2000):
        n = cls((rnd.getrandbits(bits), rnd.choice([0, 8, 12, 16, 20, 24, 28, 32] if bits == 32
                                                    else [0, 16, 32, 48, 56, 64, 96, 128])),
                strict=False)
        nets.append(str(n))
        ours.insert(str(n), i)
        theirs.insert(str(n), i)
    for n in rnd.sample(nets, 300):                    # deletes, as the annotator does
        if ours.has_key(n):
            ours.delete(n)
            theirs.delete(n)
    probes = [str(addr(rnd.getrandbits(bits))) for _ in range(3000)]
    probes += [n.split("/")[0] for n in nets[:1000]]
    for p in probes + nets[:500]:
        assert ours.get(p) == theirs.get(p), p
        assert ours.has_key(p) == theirs.has_key(p), p
    assert len(ours) == len(theirs)
