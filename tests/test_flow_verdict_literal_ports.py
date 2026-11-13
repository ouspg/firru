"""Terms that name ports literally instead of by service token.

Aerleon allows `destination-port: 829` and `destination-port: [1812, 1813]`,
and hand-edited policies use it, typically written mid-incident. flow-verdict resolved only tokens and lists of
tokens, so the first flow reaching that host crashed the whole run with
`TypeError: 'int' object is not iterable` -- 5 hours into a 46-hour build.
"""
import pytest

from firru.cli import flow_verdict as fv


class FakeDefs:
    """Minimal Naming stand-in: knows one token, raises on anything else."""

    def GetService(self, tok):
        if tok == "SSH":
            return ["22/tcp"]
        raise KeyError(tok)


@pytest.fixture(autouse=True)
def _clear_cache():
    fv._PORTS_CACHE.clear()
    yield
    fv._PORTS_CACHE.clear()


def test_literal_ports_helper():
    assert fv._literal_ports(829) == {829}
    assert fv._literal_ports("829") == {829}
    assert fv._literal_ports("1812-1813") == {1812, 1813}
    assert fv._literal_ports("SSH") is None
    assert fv._literal_ports("HIS-REG-STUFF") is None


def test_bare_int_resolves_instead_of_raising():
    assert fv.resolve_ports(829, "tcp", FakeDefs()) == {829}


def test_list_of_ints_resolves():
    assert fv.resolve_ports([1812, 1813], "udp", FakeDefs()) == {1812, 1813}


def test_mixed_token_and_literal():
    assert fv.resolve_ports(["SSH", 829], "tcp", FakeDefs()) == {22, 829}


def test_named_token_still_resolves_through_defs():
    assert fv.resolve_ports("SSH", "tcp", FakeDefs()) == {22}


def test_unknown_token_yields_no_ports_but_does_not_raise():
    assert fv.resolve_ports("NOT-A-TOKEN", "tcp", FakeDefs()) == set()


def test_absent_port_means_any():
    assert fv.resolve_ports(None, "tcp", FakeDefs()) is None
    assert fv.resolve_ports([], "tcp", FakeDefs()) is None


def test_cache_key_does_not_collide_across_spellings():
    """829 and "829" mean the same ports; SSH and 22 must not be conflated."""
    d = FakeDefs()
    assert fv.resolve_ports(829, "tcp", d) == fv.resolve_ports("829", "tcp", d)
    assert fv.resolve_ports("SSH", "tcp", d) == {22}
    assert fv.resolve_ports(22, "tcp", d) == {22}


def test_cache_key_is_hashable_for_every_shape():
    d = FakeDefs()
    for shape in (829, "829", ["SSH", 829], ("SSH",), "1812-1813"):
        fv.resolve_ports(shape, "tcp", d)
