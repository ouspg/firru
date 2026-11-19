"""journalctl-style times in a fixed zone, with named windows. `now` is
injected everywhere: a test that reads the clock passes or fails by the hour."""
from datetime import datetime, timedelta, timezone

import pytest

from firru.times import TimeParser, offset

UTC = timezone.utc
NOW = datetime(2030, 1, 21, 10, 15, tzinfo=UTC)          # 12:15 at +02:00


def p(zone="+02:00", now=NOW, **windows):
    return TimeParser(zone, windows=windows or {"day0": ("2030-01-14 08:00", "2030-01-14 15:00")}, now=now)


def utc(text, parser=None, **kw):
    return (parser or p()).parse(text, **kw).astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


class TestJournalctlForms:
    @pytest.mark.parametrize("text, want", [
        ("now", "2030-01-21 10:15:00"),
        ("today", "2030-01-20 22:00:00"),             # local midnight, in UTC
        ("yesterday", "2030-01-19 22:00:00"),
        ("tomorrow", "2030-01-21 22:00:00"),
        ("yesterday 08:00", "2030-01-20 06:00:00"),
        ("08:00", "2030-01-21 06:00:00"),
        ("8:00", "2030-01-21 06:00:00"),
        ("08:00:30", "2030-01-21 06:00:30"),
        ("2030-01-21", "2030-01-20 22:00:00"),
        ("2030-01-21 08:00", "2030-01-21 06:00:00"),
        ("2030-01-21T08:00Z", "2030-01-21 08:00:00"),  # an explicit zone wins
        ("2030-01-21 08:00+05:00", "2030-01-21 03:00:00"),
    ])
    def test_absolute(self, text, want):
        assert utc(text) == want

    @pytest.mark.parametrize("text, want", [
        ("-30min", "2030-01-21 09:45:00"),
        ("+2h", "2030-01-21 12:15:00"),
        ("1h 30min ago", "2030-01-21 08:45:00"),
        ("2d ago", "2030-01-19 10:15:00"),
        ("-1w", "2030-01-14 10:15:00"),
    ])
    def test_relative_is_elapsed_time(self, text, want):
        assert utc(text) == want

    def test_a_utc_suffix_overrides_the_zone(self):
        assert utc("08:00 UTC") == "2030-01-21 08:00:00"
        assert utc("yesterday 08:00 UTC") == "2030-01-20 08:00:00"


class TestWindows:
    def test_a_name_is_its_start_or_with_end_its_end(self):
        assert utc("day0") == "2030-01-14 06:00:00"
        assert utc("day0", end=True) == "2030-01-14 13:00:00"

    def test_a_name_with_a_time_is_that_time_on_its_first_day(self):
        assert utc("day0 12:00") == "2030-01-14 10:00:00"

    def test_window_returns_both_ends(self):
        start, end = p().window("day0")
        assert end - start == timedelta(hours=7)

    def test_an_unknown_window_names_the_known_ones(self):
        with pytest.raises(KeyError, match="known: day0"):
            p().window("night")

    def test_an_unknown_name_before_a_time_names_the_windows(self):
        with pytest.raises(ValueError, match=r"'day3' is no day or window \(windows: day0\)"):
            p().parse("day3 09:00")


class TestZone:
    def test_the_day_is_the_zones_not_utcs(self):
        """00:30 at +02:00 is still the previous day in UTC: 'today' is the
        local date, the trap a naive UTC date falls into."""
        just_after = datetime(2030, 1, 20, 22, 30, tzinfo=UTC)
        assert utc("today", p(now=just_after)) == "2030-01-20 22:00:00"
        assert utc("today", p(zone="UTC", now=just_after)) == "2030-01-20 00:00:00"

    def test_utc_is_the_default_and_the_machine_never_counts(self):
        assert TimeParser(now=NOW).tz is UTC

    @pytest.mark.parametrize("text, hours", [("+02:00", 2), ("-0530", -5.5), ("UTC", 0), ("Z", 0)])
    def test_offsets(self, text, hours):
        assert offset(text).utcoffset(None) == timedelta(hours=hours)

    def test_a_zone_name_is_refused(self):
        with pytest.raises(ValueError, match="fixed offset"):
            offset("Europe/Helsinki")


class TestErrors:
    @pytest.mark.parametrize("text", ["last tuesday", "30 parsecs ago", "-5xyz", "25:00"])
    def test_unreadable_input_lists_what_is_accepted(self, text):
        with pytest.raises(ValueError, match="use one of"):
            p().parse(text)
