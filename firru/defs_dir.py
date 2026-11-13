"""Where the service and network definitions come from.

Every command takes --defs DIR, by default `def` in the working directory (a
project's own definitions). Without one, firru's stock definitions (`def/`
beside the package) are what there is: a first run in an empty directory
should work, and say which definitions it used. A directory named explicitly
and missing is an error, not a fallback.
"""
import os
import sys
from pathlib import Path

DEFAULT = "def"
_HERE = Path(__file__).resolve().parent


def _stock(installed, checkout):
    """Inside the installed package (a wheel carries def/ and baseline/ there),
    else beside it (a checkout)."""
    p = _HERE / installed
    return p if p.is_dir() else _HERE.parent / checkout


STOCK = _stock("_stock_def", "def")
# The stock-install records --baseline reads (firru baseline-synth), beside
# def/ for the same reason.
STOCK_BASELINE = _stock("_stock_baseline", "baseline")


def resolve(defs_dir):
    """`defs_dir` if it exists; the stock definitions for a missing default;
    exit with a message otherwise."""
    if os.path.isdir(defs_dir):
        return defs_dir
    if defs_dir == DEFAULT and STOCK.is_dir():
        print(f"firru: no ./{DEFAULT}/, using the stock definitions in {STOCK}"
              f" (--defs DIR for a project's own)", file=sys.stderr)
        return str(STOCK)
    print(f"firru: definitions directory {defs_dir!r} not found (--defs DIR)", file=sys.stderr)
    sys.exit(2)


def near(paths, defs_dir=None):
    """`defs_dir` if given; else the `def` directory nearest one of `paths`
    (beside it, or in a parent: a project keeps policies/ and def/ side by
    side), else `./def`, else the stock definitions. Says which, when it had
    to look."""
    if defs_dir:
        return resolve(defs_dir)
    for p in paths:
        for d in Path(p).resolve().parents:
            if (d / DEFAULT).is_dir():
                if d != Path.cwd().resolve():
                    print(f"firru: using the definitions in {d / DEFAULT} "
                          f"(--defs DIR for others)", file=sys.stderr)
                return str(d / DEFAULT)
    return resolve(DEFAULT)

