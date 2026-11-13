"""
The ss parser against every iproute2 version we can reach.

Built by scripts/capture-ss-fixtures.sh: thirteen distro images spanning
iproute2 ss180129 through 6.17.0, each captured at both flag sets loot-host.sh
uses (`-tulnpe` on the host, `-tulnp` inside a netns) and, where the version
supports it, with `--cgroup`.

Each dump contains three deliberately hostile listeners rather than whatever the
container happened to be running. That is the whole design of the corpus: a bare
image has three sockets and none of them has an awkward name, so it exercises the
column layout and nothing else. These are named to hit the sanitizers -- one
plain, one with a space and a colon, one with parentheses that ss itself
truncates mid-token.

The corpus earned its keep on its first runs, both times on ordinary current
distros and both times silently:

  * jc returns the process block as a structured dict on some ss versions and
    as a raw string on others, and the string form is double-quoted on every
    modern ss. The reader only matched single quotes, so on the versions taking
    that branch every listener came back UNKNOWN -- ports correct, attribution
    gone. Ubuntu 22.04 among them, on the exact flags loot-host.sh collects
    with.
  * jc rewrites a parenthesis inside a quoted process name to a bracket, so
    `(sd-pam` reads as `[sd-pam`. That one does not raise; it just answers
    wrongly. `(sd-pam` is present on roughly nine in ten Linux hosts.

Neither would have produced a bug report. The first looked like a host whose
processes were merely unnamed; the second looked like nothing at all.
"""

import pathlib
import re

import pytest

from firru.ss import (get_process_name_pid, jc_keeps_process_names,
                      parse_ss_safe)

CORPUS = pathlib.Path(__file__).parent / "fixtures" / "ss"

#: The listeners scripts/capture-ss-fixtures.sh plants in every image, as ss
#: actually writes them.
PLANTED_TRUE = {
    "19001": "plain",
    "19002": "my proc:x",   # space and colon
    "19003": "svc(1",       # ss itself truncates at the open paren
}

#: What survives when the installed jc cannot handle those characters and
#: firru has to sanitize the names to get the dump parsed at all.
PLANTED_SANITIZED = {
    "19001": "plain",
    "19002": "my_proc_x",
    "19003": "svc_1",
}

#: Which of the two this jc can deliver. Asserting the sanitized spelling
#: unconditionally would fail the moment jc is fixed, and asserting the true
#: spelling unconditionally fails today — the contract is "the best this
#: parser can give", so the expectation follows the probe.
PLANTED = PLANTED_TRUE if jc_keeps_process_names() else PLANTED_SANITIZED

FIXTURES = sorted(CORPUS.glob("*.out"))


def _ids(p):
    return p.stem


def test_the_corpus_is_actually_present():
    """A corpus that quietly disappears turns every test below into a no-op."""
    assert len(FIXTURES) >= 30, f"only {len(FIXTURES)} fixtures found"
    families = {f.stem.split("-tuln")[0] for f in FIXTURES}
    assert len(families) >= 10, sorted(families)


@pytest.mark.parametrize("path", FIXTURES, ids=_ids)
def test_every_version_parses(path):
    rows = parse_ss_safe(str(path))
    assert rows, "parsed to nothing — the Debian 12 failure mode"


@pytest.mark.parametrize("path", FIXTURES, ids=_ids)
def test_every_version_yields_all_three_planted_listeners(path):
    ports = {r.get("local_port") for r in parse_ss_safe(str(path))}
    assert set(PLANTED) <= ports, f"missing {sorted(set(PLANTED) - ports)}"


@pytest.mark.parametrize("path", FIXTURES, ids=_ids)
def test_every_version_attributes_every_process(path):
    """The Ubuntu 22.04 failure mode: right ports, no names. It degrades into
    the `unattributed` class rather than into a wrong answer, which is why it
    could sit there unnoticed."""
    got = {}
    for r in parse_ss_safe(str(path)):
        port = r.get("local_port")
        if port in PLANTED:
            got[port] = get_process_name_pid(r)[0]
    assert got == PLANTED


@pytest.mark.parametrize("path", FIXTURES, ids=_ids)
def test_a_pid_comes_across_for_every_planted_listener(path):
    for r in parse_ss_safe(str(path)):
        if r.get("local_port") in PLANTED:
            _, pid = get_process_name_pid(r)
            assert pid and pid.isdigit(), f"no pid for {r.get('local_port')}"


def test_both_collected_flag_sets_are_covered():
    """loot-host.sh runs `ss -tulnpe` on the host and `ss -tulnp` in a netns.
    A corpus of one flag set tests half the real loot."""
    suffixes = {f.stem.rsplit("-", 1)[-1] for f in FIXTURES}
    assert "tulnpe" in suffixes and "tulnp" in suffixes


def test_the_corpus_spans_both_iproute2_naming_eras():
    """Old builds report `ss180129`-style dates, new ones semver. Keeping both
    is what makes the corpus a range rather than a snapshot -- the header shape
    and the opts layout both changed across that boundary."""
    versions = set()
    for f in FIXTURES:
        for line in f.read_text().splitlines()[:3]:
            if "iproute2-" in line:
                versions.add(line.split("iproute2-")[-1].strip())
    assert any(v.startswith("ss") for v in versions), versions
    assert any(v[0].isdigit() and int(v.split(".")[0]) >= 6 for v in versions), versions


#: A row where `ss` padded the users: column, leaving two or more spaces
#: between `users:(...)` and the `ino:`/`sk:`/`cgroup:` group that follows.
_PADDED_OPTS = re.compile(r"users:\(\(.*?\)\) {2,}\w+:")

#: Fixtures containing at least one such row.
PADDED = [f for f in FIXTURES if _PADDED_OPTS.search(f.read_text())]


class TestTheOptionsRegionSplitByPadding:
    """The jc limitation that kellyjonbrazil/jc#756 named but did not fix, and
    why firru does not depend on either side of it.

    jc splits an `ss` row on runs of two or more spaces. When `ss` pads inside
    the options region to align the users: column, the region scatters across
    columns, `dict(zip(header, entry))` keeps an entry that was never parsed,
    and `opts` arrives as a raw string with ino, sk and cgroup gone. #756
    shielded the `users:` block from having its *name* split out; it left the
    row split alone, so this outlived it. A follow-up is submitted.

    Six fixtures carry it -- Debian 13, Fedora 41 and Rocky 9, at both `-tulnpe`
    and `-tulnpe --cgroup` -- which is to say the newest iproute2 in the corpus
    and no older one. The tests upstream added alongside the fix (#757) use
    single-space separators and so do not reach it either. It appears nowhere in
    ~177k rows of real capture, which is why only a version-spanning corpus
    finds it.

    Distro-packaged jc runs years behind, so firru keeps reading the raw string
    when it gets one and these tests have to pass on both. They assert the name
    arrives, never that jc returns a particular type, and so stay true once the
    follow-up lands and those rows start coming back as dicts.
    """

    def test_the_corpus_actually_contains_the_case(self):
        """Without this the class below is three tests over an empty list."""
        assert len(PADDED) >= 6, sorted(f.stem for f in PADDED)
        rows = sum(len(_PADDED_OPTS.findall(f.read_text())) for f in PADDED)
        assert rows >= 12, rows

    def test_it_is_a_recent_iproute2_habit_rather_than_an_old_one(self):
        """Which is why it showed up only once the corpus spanned versions:
        every distro old enough to be the obvious test case writes the options
        region with single spaces and never triggers it."""
        assert all("tulnpe" in f.stem for f in PADDED)
        assert not any(f.stem.startswith(("debian-10", "debian-12", "ubuntu-18",
                                          "ubuntu-20", "alpine")) for f in PADDED)

    @pytest.mark.parametrize("path", PADDED, ids=_ids)
    def test_the_listener_is_named_however_jc_returns_the_row(self, path):
        """The contract. Whether `opts` arrives as a dict or as the raw string,
        the planted process is attributed with its pid."""
        got = {}
        for r in parse_ss_safe(str(path)):
            port = r.get("local_port")
            if port in PLANTED:
                name, pid = get_process_name_pid(r)
                got[port] = name
                assert pid and pid.isdigit(), f"no pid for {port}"
        assert got == PLANTED

    @pytest.mark.parametrize("path", PADDED, ids=_ids)
    def test_a_row_that_arrives_as_a_string_is_not_silently_unattributed(self, path):
        """The failure mode this guards is the quiet one: a string `opts` that
        no branch reads gives correct ports and UNKNOWN everywhere, which looks
        like a host whose processes merely have no names."""
        for r in parse_ss_safe(str(path)):
            if isinstance(r.get("opts"), str) and r.get("local_port") in PLANTED:
                assert get_process_name_pid(r)[0] != "UNKNOWN"
