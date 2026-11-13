#!/usr/bin/env python3
"""
firru edit-services — deterministic edits to the service definitions in def/.

The def-file counterpart to `firru` on a policy: it automates the mechanical
half of maintaining `def/*.yml` and leaves every judgment to $EDITOR. The
judgment here is the one the comment contract names — what a group of ports is
called and which ports belong in it. Copying a token in, or taking an unused one
out, is not a judgment, and that is all this does.

    firru edit-services add def/funny.yml TCP_9191 9191/tcp
    firru edit-services add def/funny.yml VENDOR_P2P 40000/tcp 40000/udp
    firru edit-services rm  def/funny.yml TCP_9191 --policies policies/pol

`add` is the accept side of the `audit-services` stub: a funny port you have
decided is a real service, named. It writes only the structure; run
`firru annotate-services` afterwards to fill in the [auto] evidence.

`rm` is the prune side, and it re-runs its own safety checks rather than
trusting the command line that invoked it. A generated script gets saved,
edited and re-run against a tree that has moved on, so "the report said it was
unused" is not good enough at the moment of deletion.

Removal is refused when the token is referenced by a policy or is a member of
another definition. Those checks are a fast filter, not a proof: the total check
is to prune, regenerate, and diff the compiled output — if a single generated
ruleset changes, the token was reachable after all. Undo is `git checkout def/`.
"""

import argparse
import glob
import os
import re
import sys

from ruyaml import YAML

yaml_handler = YAML()
yaml_handler.indent(mapping=2, sequence=4, offset=2)
yaml_handler.preserve_quotes = True
yaml_handler.width = 4096


def _load(path):
    with open(path) as f:
        return yaml_handler.load(f)


def _write(path, doc):
    with open(path, "w") as f:
        yaml_handler.dump(doc, f)


def parse_entry(spec):
    """'9191/tcp' or '49152-65535/tcp' → {'port': …, 'protocol': …}."""
    if "/" not in spec:
        raise ValueError(f"want PORT/PROTO, got {spec!r}")
    port, proto = spec.rsplit("/", 1)
    proto = proto.lower()
    if proto not in ("tcp", "udp", "sctp"):
        raise ValueError(f"unknown protocol in {spec!r}")
    if "-" in port:
        lo, hi = port.split("-", 1)
        if not (lo.isdigit() and hi.isdigit()):
            raise ValueError(f"bad port range in {spec!r}")
        return {"port": f"{int(lo)}-{int(hi)}", "protocol": proto}
    if not port.isdigit():
        raise ValueError(f"bad port in {spec!r}")
    return {"port": int(port), "protocol": proto}


def token_references(token, def_dir, policy_dir=None):
    """
    Where else `token` appears: (policy_files, def_files).

    A word-boundary text search rather than a resolve, deliberately: a token can
    be reached through a group, a nested group, or a generator's own handling,
    and a search that over-reports keeps a live token alive while a clever one
    that under-reports deletes it.
    """
    pattern = re.compile(r"\b" + re.escape(token) + r"\b")
    pol_hits, def_hits = [], []
    for path in sorted(glob.glob(os.path.join(policy_dir or "", "*.yml"))) if policy_dir else []:
        try:
            if pattern.search(open(path).read()):
                pol_hits.append(path)
        except OSError:
            continue
    for path in sorted(glob.glob(os.path.join(def_dir, "*.yml"))):
        try:
            text = open(path).read()
        except OSError:
            continue
        # The definition of the token itself is not a reference to it; anything
        # beyond that first occurrence in its own file is.
        hits = len(pattern.findall(text))
        if hits > 1 or (hits == 1 and not _defines(path, token)):
            def_hits.append(path)
    return pol_hits, def_hits


def _defines(path, token):
    try:
        doc = _load(path)
    except Exception:
        return False
    return token in ((doc or {}).get("services") or {})


def cmd_add(args):
    try:
        entries = [parse_entry(s) for s in args.entries]
    except ValueError as e:
        print(f"firru edit-services: {e}", file=sys.stderr)
        return 2

    # A file not there yet is a new definitions file (the review script names
    # def/funny.yml before anyone has made it), not an error.
    new = not os.path.exists(args.file)
    doc = yaml_handler.load("services: {}\n") if new else _load(args.file)
    services = (doc or {}).get("services")
    if services is None:
        print(f"firru edit-services: {args.file} has no services: block", file=sys.stderr)
        return 1
    if args.token in services and not args.force:
        print(f"firru edit-services: {args.token} already in {args.file} "
              f"(--force to replace)", file=sys.stderr)
        return 1

    services[args.token] = entries
    if args.dry_run:
        print(f"(dry run) {args.file}: would add {args.token} "
              f"= {' '.join(args.entries)}")
        return 0
    _write(args.file, doc)
    print(f"{args.file}: {'created, ' if new else ''}added {args.token} = {' '.join(args.entries)}")
    print("  (run 'firru annotate-services' to fill in its [auto] evidence)")
    return 0


def cmd_rm(args):
    doc = _load(args.file)
    services = (doc or {}).get("services")
    if services is None or args.token not in services:
        print(f"firru edit-services: {args.token} not in {args.file}", file=sys.stderr)
        return 1

    def_dir = args.defs or os.path.dirname(args.file) or "."
    pol_hits, def_hits = token_references(args.token, def_dir, args.policies)

    if (pol_hits or def_hits) and not args.force:
        print(f"{args.file}: refusing to remove {args.token} — still referenced",
              file=sys.stderr)
        for p in pol_hits:
            print(f"    policy: {p}", file=sys.stderr)
        for p in def_hits:
            print(f"    def:    {p}", file=sys.stderr)
        print("  (--force to remove anyway; then regenerate and diff the compiled "
              "output before trusting it)", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"(dry run) {args.file}: would remove {args.token}")
        return 0
    del services[args.token]
    _write(args.file, doc)
    print(f"{args.file}: removed {args.token}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Deterministic edits to def/ service definitions.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="Add a service token")
    p_add.add_argument("file", metavar="DEFFILE")
    p_add.add_argument("token", metavar="TOKEN")
    p_add.add_argument("entries", metavar="PORT/PROTO", nargs="+",
                       help="e.g. 9191/tcp, or 49152-65535/tcp for a range")
    p_add.add_argument("--force", action="store_true", help="Replace an existing token")
    p_add.add_argument("--dry-run", "-n", action="store_true")
    p_add.set_defaults(func=cmd_add)

    p_rm = sub.add_parser("rm", help="Remove an unused service token")
    p_rm.add_argument("file", metavar="DEFFILE")
    p_rm.add_argument("token", metavar="TOKEN")
    p_rm.add_argument("--policies", default=None, metavar="DIR",
                      help="Policy directory to check for references (e.g. policies/pol)")
    p_rm.add_argument("--defs", default=None, metavar="DIR",
                      help="Definitions directory (default: the file's own directory)")
    p_rm.add_argument("--force", action="store_true",
                      help="Remove even when still referenced")
    p_rm.add_argument("--dry-run", "-n", action="store_true")
    p_rm.set_defaults(func=cmd_rm)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
