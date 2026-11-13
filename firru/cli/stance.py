#!/usr/bin/env python3
"""
firru stance — where each policy is on log-accept -> log-drop -> drop.

Reads policy YAML and reports, per side (in/out), the stage its terminal
catch-all is in and the stage after it. Read-only: promoting is a decision, and
it stays with whoever has read the log (see firru.stance for what each stage
means and why the name of the term is never consulted).

    firru stance policies/pol/*.yml
    firru stance policies/pol/*.yml -o json
    firru stance policies/pol/*.yml --at log-accept   # only those still there

Exit status is 0 when every policy was read, 2 when one could not be.
"""

import argparse
import json
import sys

from ruamel.yaml import YAML

from firru.stance import next_stage, policy_stances


def survey(paths):
    """``[{"policy", "stance": {side: stage}, "next": {side: stage|None}}]``,
    plus the paths that could not be read as ``[(path, reason)]``."""
    rows, failed = [], []
    yaml = YAML(typ="safe")
    for path in paths:
        try:
            with open(path) as f:
                doc = yaml.load(f)
        except Exception as e:                      # unreadable or not YAML
            failed.append((path, str(e).splitlines()[0] if str(e) else type(e).__name__))
            continue
        if not isinstance(doc, dict) or "filters" not in doc:
            failed.append((path, "not a policy (no `filters`)"))
            continue
        stance = policy_stances(doc)
        rows.append({
            "policy": path,
            "host": (doc.get("metadata") or {}).get("host"),
            "stance": stance,
            "next": {side: next_stage(st) for side, st in stance.items()},
        })
    return rows, failed


def main(argv=None):
    ap = argparse.ArgumentParser(prog="firru stance", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("policies", nargs="+", metavar="POLICY")
    ap.add_argument("--at", metavar="STAGE",
                    help="only policies with a side at this stage "
                         "(none, open, log-accept, log-drop, drop)")
    ap.add_argument("-o", "--output", choices=["human", "json"], default="human")
    args = ap.parse_args(argv)

    rows, failed = survey(args.policies)
    if args.at:
        rows = [r for r in rows if args.at in r["stance"].values()]

    if args.output == "json":
        json.dump({"policies": rows,
                   "unreadable": [{"policy": p, "reason": r} for p, r in failed]},
                  sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        for r in rows:
            if not r["stance"]:
                print(f"{r['policy']}: no side stated (zone pair or interface-bound)")
                continue
            sides = "  ".join(
                f"{side}={st}" + (f" (next: {r['next'][side]})" if r["next"][side] else "")
                for side, st in r["stance"].items())
            print(f"{r['policy']}: {sides}")
        for path, reason in failed:
            print(f"{path}: unreadable: {reason}", file=sys.stderr)
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
