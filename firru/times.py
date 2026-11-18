"""Points in time the way people type them: journalctl's --since/--until.

    parser = TimeParser("+02:00", windows={"day0": ("2030-01-14 08:00", "2030-01-14 15:00")})
    parser.parse("yesterday 08:00")       # 08:00 yesterday, at +02:00
    parser.parse("-30min")                # half an hour before now
    parser.parse("day0")                   # the start of window day0
    parser.parse("day0", end=True)         # its end, as for --until
    parser.parse("day0 12:00")             # 12:00 on day0's first day

The grammar is the subset of systemd.time(7) that a flow window needs:
`now`; `today`, `yesterday` and `tomorrow` (midnight); a bare `HH:MM[:SS]`
(today); a named day followed by a time; anything datetime.fromisoformat
reads (`2030-01-21 08:00`, `2030-01-21T08:00Z`); and relative times,
`-30min`, `+2h`, `1h 30min ago`. A ` UTC` suffix means UTC instead of the
parser's zone. A window name is one more named day, which is the only
addition to journalctl.

The zone is a fixed offset, UTC unless given, never the machine's: a capture's
timestamps are UTC, and a window read in whatever zone a laptop happens to be
in moves by hours without saying so. Day names are resolved in the parser's
zone; relative times are elapsed time, counted in UTC.
"""

import re
from datetime import datetime, time, timedelta, timezone

#: systemd.time(7) units, without months and years (no fixed length).
_UNITS = {
    "us": 1e-6, "usec": 1e-6, "ms": 1e-3, "msec": 1e-3,
    "s": 1, "sec": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hour": 3600, "hours": 3600,
    "d": 86400, "day": 86400, "days": 86400,
    "w": 604800, "week": 604800, "weeks": 604800,
}
_SPAN = re.compile(r"(\d+(?:\.\d+)?)\s*([a-z]+)")
_CLOCK = re.compile(r"^\d{1,2}:\d{2}(:\d{2})?$")
_FORMS = ("now, today, yesterday, tomorrow, HH:MM[:SS], a window name, "
          "'<day> HH:MM', 2030-01-21 08:00, -30min, '1h 30min ago', with ' UTC' to override the zone")


def offset(text):
    """A fixed offset from '+02:00', '-0530', 'UTC' or 'Z'."""
    text = (text or "UTC").strip()
    if text.upper() in ("UTC", "Z"):
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", text)
    if not m:
        raise ValueError(f"not a fixed offset: {text!r} (write +02:00, or UTC)")
    sign = 1 if m.group(1) == "+" else -1
    return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))


def _clock(text):
    """'8:00' or '08:00:30' as a time; one-digit hours are fine."""
    h, rest = text.split(":", 1)
    return time.fromisoformat(f"{int(h):02d}:{rest}")


def _seconds(spans):
    pairs = _SPAN.findall(spans)
    if not pairs or _SPAN.sub("", spans).strip():
        raise ValueError
    try:
        return sum(float(n) * _UNITS[u] for n, u in pairs)
    except KeyError:
        raise ValueError from None


class TimeParser:
    """Parse journalctl-style times in one fixed zone, with named windows.

    `windows` maps a name to (start, end), each anything `parse` reads without
    a window name; `now` is for tests, which must not depend on the clock."""

    def __init__(self, zone="UTC", windows=None, now=None):
        self.tz = zone if isinstance(zone, timezone) else offset(zone)
        self._now = now
        self.windows = {}
        for name, (start, end) in (windows or {}).items():
            self.windows[name] = (self.parse(start), self.parse(end))

    def now(self):
        return self._now or datetime.now(timezone.utc)

    def window(self, name):
        """(start, end) of a named window, or KeyError naming the known ones."""
        try:
            return self.windows[name]
        except KeyError:
            raise KeyError(f"no window {name!r}; known: {', '.join(sorted(self.windows)) or 'none'}") from None

    def _day(self, word, tz):
        today = self.now().astimezone(tz).date()
        named = {"today": today, "yesterday": today - timedelta(days=1),
                 "tomorrow": today + timedelta(days=1)}
        if word in named:
            return named[word]
        if word in self.windows:
            return self.windows[word][0].astimezone(tz).date()
        return None

    def parse(self, text, end=False):
        """An aware datetime for `text`. `end` picks a window's end over its
        start, for an --until that names a window."""
        raw = text.strip()
        tz = self.tz
        if raw.upper().endswith(" UTC"):
            raw, tz = raw[:-4].strip(), timezone.utc
        word = raw.lower()
        if word == "now":
            return self.now()
        if word in self.windows:
            return self.windows[word][1 if end else 0]
        day = self._day(word, tz)
        if day is not None:
            return datetime.combine(day, time(0), tz)
        head, _, clock = raw.rpartition(" ")
        if _CLOCK.match(clock):
            day = self._day(head.lower(), tz) if head else self.now().astimezone(tz).date()
            if day is not None:
                try:
                    return datetime.combine(day, _clock(clock), tz)
                except ValueError as e:
                    raise ValueError(f"cannot read time {text!r} ({e}); use one of: {_FORMS}") from None
            if not re.match(r"\d{4}-\d{2}-\d{2}", head):
                known = ", ".join(sorted(self.windows)) or "none"
                raise ValueError(f"cannot read time {text!r}: {head!r} is no day or window "
                                 f"(windows: {known})")
        if word.endswith(" ago") or word[:1] in "+-":
            sign = 1 if word.startswith("+") else -1
            spans = word.removesuffix(" ago").lstrip("+-")
            try:
                return self.now() + sign * timedelta(seconds=_seconds(spans))
            except ValueError:
                pass
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            raise ValueError(f"cannot read time {text!r}; use one of: {_FORMS}") from None
        return dt if dt.tzinfo else dt.replace(tzinfo=tz)
