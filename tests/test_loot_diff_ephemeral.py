"""
The ephemeral range is a property of the kernel, not of the fleet.

Linux allocates 32768-60999 by default; Windows has used 49152-65535 since
Vista. Applying the Linux range to a Windows host does two wrong things at
once: it calls 32768-49151 ephemeral, where Windows keeps ports across
restarts, and it stops at 60999 while Windows churn continues past it.

Measured across repeated loot snapshots of one estate. Linux churn by band: 0.28 below
32768, 0.85 in 32768-49151, 1.00 in 49152-60999, nothing above. Windows:
0.00-0.02 below 49152, then 0.31 and 0.38 above it.
"""

from firru.cli.loot_diff import EPHEMERAL_BY_OS, DEFAULT_EPHEMERAL, ephemeral_for


def doc(os_name):
    return {"metadata": {"os": os_name}, "listen_ports": []}


def test_linux_gets_the_kernel_range():
    assert ephemeral_for(doc("linux")) == (32768, 60999)


def test_windows_gets_the_dynamic_range():
    assert ephemeral_for(doc("windows")) == (49152, 65535)


def test_the_os_field_is_matched_case_insensitively():
    assert ephemeral_for(doc("Windows")) == EPHEMERAL_BY_OS["windows"]


def test_an_unknown_or_missing_os_falls_back_to_linux():
    assert ephemeral_for(doc(None)) == DEFAULT_EPHEMERAL
    assert ephemeral_for({}) == DEFAULT_EPHEMERAL
    assert ephemeral_for(doc("plan9")) == DEFAULT_EPHEMERAL


def test_an_explicit_override_beats_the_os():
    assert ephemeral_for(doc("windows"), (1, 2)) == (1, 2)
