"""The ephemeral range is shared by the socket side and the flow side.

These pin the contract both sides rely on, including the two spellings of
"no port" that reach it from real data.
"""
import pytest

from firru.ephemeral import (
    DEFAULT_EPHEMERAL, EPHEMERAL_BY_OS, ephemeral_for, is_ephemeral,
    parse_range, range_for_os,
)


def test_ranges_are_per_os():
    assert range_for_os("linux") == (32768, 60999)
    assert range_for_os("Windows") == (49152, 65535)
    assert range_for_os("  WINDOWS  ") == (49152, 65535)


def test_unknown_os_falls_back_to_linux():
    assert range_for_os(None) == DEFAULT_EPHEMERAL
    assert range_for_os("") == DEFAULT_EPHEMERAL
    assert range_for_os("plan9") == DEFAULT_EPHEMERAL


def test_override_wins_over_os():
    assert range_for_os("windows", override=(1, 2)) == (1, 2)


def test_ephemeral_for_reads_loot_metadata():
    assert ephemeral_for({"metadata": {"os": "windows"}}) == (49152, 65535)
    assert ephemeral_for({}) == DEFAULT_EPHEMERAL
    assert ephemeral_for(None) == DEFAULT_EPHEMERAL


def test_boundaries_are_inclusive():
    lo, hi = EPHEMERAL_BY_OS["linux"]
    assert is_ephemeral(lo) and is_ephemeral(hi)
    assert not is_ephemeral(lo - 1)
    assert not is_ephemeral(hi + 1)


def test_absent_port_is_never_ephemeral():
    # Zeek's text formats write "-", parquet writes a real null. Neither is
    # a port, and neither may raise.
    assert is_ephemeral(None) is False
    assert is_ephemeral("-") is False
    assert is_ephemeral("") is False


def test_numeric_strings_are_accepted():
    assert is_ephemeral("40000") is True
    assert is_ephemeral("443") is False


def test_parse_range():
    assert parse_range("1024-65535") == (1024, 65535)
    with pytest.raises(ValueError):
        parse_range("1024")
    with pytest.raises(ValueError):
        parse_range("65535-1024")
