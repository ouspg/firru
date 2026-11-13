#!/usr/bin/env python3
"""
firru — the policy-YAML editing core, as one command.

`firru <verb>` groups the tools that consume documented contracts (loot JSON,
flow JSONL, policy YAML) and produce or edit firru policy YAML. The boundary is
deliberate (docs/comment-contract.md): firru edits the ymls; it never touches
raw acquisition (ss dumps, live hosts) and it never converts to a foreign
target — those live in separate commands:

    acquisition (ss/pcap/live -> JSON):  loot-listeners, audit-services,
                                         loot-flows, zeek-to-flows, ...
    converters  (aerleon YAML -> target): aerleon-to-nftables, -calico, ...

Each verb delegates to its module's main(); `firru <verb> --help` shows that
verb's own options.
"""

import importlib
import importlib.util
import re
import sys

# Verbs handled by the edit subparser (firru/cli/edit.py).
_EDIT_VERBS = {"diff", "apply", "set-source", "set-destination", "rm"}

# Short names the help offers.
_ALIASES = {"set-dest": "set-destination"}

# Verbs that map straight to a module main().
_MODULES = {
    "synth":             "firru.cli.listeners_to_aerleon",  # loot JSON -> staged policy YAML
    "score":             "firru.cli.score_policy",          # annotate [score] notes
    "tighten":           "firru.cli.tighten",               # tighten sources from flows
    "merge-zones":       "firru.cli.merge_zones",           # per-host -> per-zone policy
    "annotate-services": "firru.cli.annotate_services",     # refresh [auto] evidence in def/
    "edit-services":     "firru.cli.edit_services",         # add / rm service tokens in def/
    "loot-diff":         "firru.cli.loot_diff",             # loot vs earlier loot, or vs a stock baseline
    "audit":             "firru.cli.audit",                 # loot x running firewall x baseline x policy
    "baseline-synth":    "firru.cli.baseline_synth",        # firru-os-baselines -> shipped baseline/
    "stance":            "firru.cli.stance",                # log-accept -> log-drop -> drop, per policy side
}

_HELP = """\
firru — network policy YAML toolkit

Usage: firru <command> [args]    (firru <command> --help for details)

Edit policy YAML:
  diff         preview, or emit runnable commands for, the delta between two policies
               (with --baseline REF LOOT: listeners added to a stock install, = loot-diff)
  apply        apply a generated delta onto a human policy (three-way merge)
  set-source   set an ingress term's source-address
  set-dest     set an egress term's destination-address (set-destination)
  rm           remove a term by name
  mass         run a stream of firru commands in one process (| firru mass)

Produce / transform policy YAML:
  synth        loot JSON -> staged host policy YAML
  score        annotate [score] "must stay open" notes
  tighten      tighten sources from observed flows (flows JSONL, or live Arkime)
  merge-zones  per-host policies -> per-zone firewall policy
  stance       where each policy is on log-accept -> log-drop -> drop (read-only; -o json)

Compare loot:
  loot-diff    listeners opened/closed between two loots, or against a stock
               baseline: firru loot-diff --baseline win2022-dc LOOT (list: --baseline list)
  audit        one host against its running firewall, a baseline and its policy;
               -o sh emits the policy fixes (firru audit LOOT --policy POL -o sh)

Maintain definitions:
  annotate-services  refresh the [auto] observed-evidence note on service tokens
  edit-services      add a service token, or remove an unreferenced one
  baseline-synth     the stock-install records firru ships, from firru-os-baselines

Converters (aerleon YAML -> target) and acquisition (ss/pcap -> JSON) are
separate commands, e.g. aerleon-to-nftables, loot-listeners, audit-services.
"""


def _present(mod_name):
    try:
        return importlib.util.find_spec(mod_name) is not None
    except ModuleNotFoundError:
        return False


# A tree may ship without some verbs' modules (the public release leaves out
# work still in development). Those verbs are not offered, rather than offered
# and failing on import.
_ABSENT = {v for v, m in _MODULES.items() if not _present(m)}
_MODULES = {v: m for v, m in _MODULES.items() if v not in _ABSENT}


def _without_absent(text):
    """The help text minus the entries, continuation lines included, of
    verbs whose module is not in this tree."""
    out, skipping = [], False
    for line in text.splitlines(keepends=True):
        m = re.match(r"  (\S+)\s", line)
        if m and not line.startswith("   "):
            skipping = m.group(1) in _ABSENT
        elif not line.startswith("   "):
            skipping = False
        if not skipping:
            out.append(line)
    return "".join(out)


_HELP = _without_absent(_HELP)


def dispatch_argv(argv):
    """Route one already-split argv to its verb and return its exit code,
    in-process. `firru mass` calls this per line; `main` calls it once.

    A verb's module main() may raise SystemExit (argparse errors, explicit
    sys.exit); that is caught and turned into a return code so a batch keeps
    going instead of tearing down the process on the first bad line.
    """
    if not argv:
        sys.stdout.write(_HELP)
        return 0
    sub, rest = argv[0], argv[1:]

    saved = sys.argv
    try:
        # `firru diff --baseline REF NEW`: loot against a stock install. The
        # policy diff has no --baseline, so the flag says which diff is meant.
        sub = _ALIASES.get(sub, sub)
        if sub == "diff" and any(a in ("--baseline", "--closest") or a.startswith(("--baseline=", "--closest=")) for a in rest):
            sub = "loot-diff"
        if sub in _EDIT_VERBS:
            from firru.cli import edit
            sys.argv = ["firru", sub, *rest]
            return edit.main() or 0
        if sub == "mass":
            from firru.cli import mass
            sys.argv = ["firru mass", *rest]
            return mass.main() or 0
        mod_name = _MODULES.get(sub)
        if mod_name is None:
            sys.stderr.write(f"firru: unknown command {sub!r}\n")
            return 2
        mod = importlib.import_module(mod_name)
        sys.argv = [f"firru {sub}", *rest]
        return mod.main() or 0
    except SystemExit as e:
        code = e.code
        return code if isinstance(code, int) else (0 if code is None else 1)
    finally:
        sys.argv = saved


def main():
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(_HELP)
        sys.exit(0)
    sys.exit(dispatch_argv(argv))


if __name__ == "__main__":
    main()
