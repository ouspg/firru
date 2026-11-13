#!/usr/bin/env python3
"""
firru mass — run a stream of firru commands in one process.

The edit scripts firru emits (`firru diff ... -o sh`) are already a list of
firru commands, one per line. Piping them to `sh` runs each as a cold process,
paying Python startup and the aerleon import — and, for apply/diff, a fresh
Naming build — hundreds of times. `firru mass` reads the same lines and runs
them in a single process, with the Naming cache warm across the batch:

    firru diff pol.yml tightened.yml --flows w.jsonl -o sh | grep observed | firru mass
    firru mass out/edits/*.sh
    grep -v '# widened' out/edits/host.sh | firru mass

The input format is exactly the emitted script: `#` comment lines and blank
lines are skipped, a trailing `  # tag` on a command is stripped, and a leading
`firru` token is optional. Each line routes through the same dispatcher as the
CLI, so `mass` is a faster backend for a script, never a different one — the
script stays a portable shell script that also runs under `sh`.

A failing line is reported and the batch continues; the exit code is nonzero if
any line failed.
"""

import argparse
import shlex
import sys


def iter_commands(lines):
    """Yield argv lists for the runnable command lines in `lines`."""
    for raw in lines:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        # strip a trailing '  # tag' annotation (two spaces then #), which the
        # emitter uses; a bare '#' inside a quoted arg is left to shlex.
        cmd = s
        idx = cmd.find("  #")
        if idx != -1:
            cmd = cmd[:idx]
        try:
            argv = shlex.split(cmd)
        except ValueError as e:
            print(f"firru mass: cannot parse {s!r}: {e}", file=sys.stderr)
            yield None
            continue
        if not argv:
            continue
        if argv[0] == "firru":
            argv = argv[1:]
        yield argv or None


def main():
    parser = argparse.ArgumentParser(
        description="Run a stream of firru commands in one process (defs cached).")
    parser.add_argument("file", nargs="*",
                        help="Files of firru commands; default is stdin")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress each command's own output; report only the tally")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Print the commands that would run; execute nothing")
    args = parser.parse_args()

    if args.file:
        lines = []
        for f in args.file:
            try:
                lines.extend(open(f).read().splitlines())
            except OSError as e:
                print(f"firru mass: {e}", file=sys.stderr)
                return 1
    else:
        lines = sys.stdin.read().splitlines()

    from firru.cli.dispatch import dispatch_argv

    ok = failed = 0
    devnull = None
    if args.quiet:
        import os
        devnull = open(os.devnull, "w")

    for argv in iter_commands(lines):
        if argv is None:
            failed += 1
            continue
        if args.dry_run:
            print("firru " + " ".join(shlex.quote(a) for a in argv))
            continue
        saved_out = sys.stdout
        if devnull is not None:
            sys.stdout = devnull
        try:
            rc = dispatch_argv(argv)
        except Exception as e:  # a verb blew up; keep the batch going
            sys.stdout = saved_out
            print(f"firru mass: {' '.join(argv)!r} raised {type(e).__name__}: {e}",
                  file=sys.stderr)
            failed += 1
            continue
        finally:
            sys.stdout = saved_out
        if rc:
            failed += 1
        else:
            ok += 1

    if devnull is not None:
        devnull.close()
    if not args.dry_run:
        print(f"firru mass: {ok} ok, {failed} failed", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
