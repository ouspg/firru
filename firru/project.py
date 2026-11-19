"""The project a command runs in, and the time window it reads flows for.

A project is a directory with a `firru.toml` in it. It is found the way git
finds a repository: $FIRRU_PROJECT if set, else the nearest directory upwards
from the current one that holds a firru.toml. Without either there is no
project, and a command does what it did before. The marker is the file, never
a def/ directory, so a firru checkout (which has one) is not taken for a
project.

    [flows]
    store    = "flows"           # a flow store, relative to the project
    timezone = "+02:00"          # the zone the windows below are written in

    [windows]
    night = ["2024-03-06 19:00", "2024-03-07 08:00"]

The zone is a fixed offset, UTC unless the file names one, and never the
machine's (firru.times). Windows are named once here and used by name:
`--window night`, `--since "night 23:00"`.
"""

import os
import pathlib
import tomllib
from datetime import timezone

from firru.times import TimeParser

MARKER = "firru.toml"


class Project:
    """A loaded firru.toml: its directory, its flow store, zone and windows."""

    def __init__(self, root, config=None):
        self.root = pathlib.Path(root)
        self.config = config or {}
        flows = self.config.get("flows") or {}
        if not isinstance(flows, dict):
            raise ValueError(f"{self.path}: [flows] must be a table")
        store = flows.get("store")
        self.store = (self.root / store) if store else None
        self.zone = flows.get("timezone", "UTC")
        windows = self.config.get("windows") or {}
        for name, span in windows.items():
            if (not isinstance(span, list) or len(span) != 2
                    or not all(isinstance(t, str) for t in span)):
                raise ValueError(f"{self.path}: window {name!r} must be "
                                 f"[\"start\", \"end\"], got {span!r}")
        self.windows = {name: tuple(span) for name, span in windows.items()}

    @property
    def path(self):
        return self.root / MARKER

    def times(self, now=None):
        """A TimeParser in the project's zone, knowing its windows."""
        try:
            return TimeParser(self.zone, windows=self.windows, now=now)
        except ValueError as e:
            raise ValueError(f"{self.path}: {e}") from None


def load(root):
    """The project at `root`; an absent firru.toml reads as an empty one."""
    path = pathlib.Path(root) / MARKER
    config = {}
    if path.is_file():
        with open(path, "rb") as f:
            try:
                config = tomllib.load(f)
            except tomllib.TOMLDecodeError as e:
                raise ValueError(f"{path}: {e}") from None
    return Project(root, config)


def find(start=None):
    """The project for a command started in `start` (default: the current
    directory), or None."""
    env = os.environ.get("FIRRU_PROJECT")
    if env:
        return load(pathlib.Path(env).expanduser())
    here = pathlib.Path(start or os.getcwd()).resolve()
    for d in (here, *here.parents):
        if (d / MARKER).is_file():
            return load(d)
    return None


# ---------------------------------------------------------------------------
# The time window a command reads flows for
# ---------------------------------------------------------------------------

def add_window_arguments(parser):
    """--window/--since/--until, read by window_from_args."""
    g = parser.add_argument_group(
        "flow window", "Times as journalctl takes them (firru.times): "
        "'2030-01-21 08:00', 'night 23:00', '-2h', ' UTC' to override the "
        "project's zone. Named windows and the zone come from firru.toml.")
    g.add_argument("--window", metavar="NAME",
                   help="a window firru.toml names: its start to its end")
    g.add_argument("--since", metavar="TIME",
                   help="flows from this time on (overrides --window's start)")
    g.add_argument("--until", metavar="TIME",
                   help="flows before this time (overrides --window's end)")
    return g


def window_from_args(args, project=None, now=None):
    """(start, end) as epoch seconds, either None for open; or None when no
    window was asked for. Raises ValueError with a message for the user."""
    window = getattr(args, "window", None)
    since = getattr(args, "since", None) or window
    until = getattr(args, "until", None) or window
    if not since and not until:
        return None
    # Without a project there are no window names and the zone is UTC;
    # absolute and relative times still read.
    times = project.times(now=now) if project is not None else TimeParser("UTC", now=now)
    if window and window not in times.windows:
        where = project.path if project is not None else "no firru.toml found"
        raise ValueError(f"no window {window!r} ({where}); known: "
                         f"{', '.join(sorted(times.windows)) or 'none'}")
    lo = times.parse(since).timestamp() if since else None
    hi = times.parse(until, end=True).timestamp() if until else None
    if lo is not None and hi is not None and lo >= hi:
        raise ValueError(f"the window ends before it starts ({since} .. {until})")
    return lo, hi


def flows_for(args, flows=None, now=None):
    """(flows, span, label) for a command: the flow source it names, else the
    project's store when a window was asked for; the span of
    window_from_args; and a label saying both, for a header. Raises
    ValueError with a message for the user."""
    if not _asked(args):
        return flows, None, None
    project = find()
    span = window_from_args(args, project, now=now)
    if not flows:
        if project is None or project.store is None:
            raise ValueError("a window needs flows: name them, or set "
                             "[flows] store in firru.toml")
        # Relative to where the command runs, as a path typed there would be:
        # it is written into headers, which get committed.
        flows = os.path.relpath(project.store)
    asked = " ".join(f"--{k} {v!r}" if " " in v else f"--{k} {v}"
                     for k in ("window", "since", "until")
                     if (v := getattr(args, k, None)))
    return flows, span, f"{asked}: {describe(span)}"


def _asked(args):
    return any(getattr(args, k, None) for k in ("window", "since", "until"))


def describe(span):
    """'2024-03-06 17:00Z to 2024-03-07 06:00Z' for a window, open ends said."""
    from datetime import datetime
    def fmt(t):
        return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%MZ")
    lo, hi = span
    return (f"{fmt(lo) if lo is not None else 'the start'} to "
            f"{fmt(hi) if hi is not None else 'the end'}")
