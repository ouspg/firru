"""
What the installed aerleon can render.

A term key aerleon does not know is not an error there: the term compiles
without it. For windows-program, windows-service and windows-rpc that is the
difference between a rule for one program and a rule for every program on
the host, so a policy that uses them is checked against the aerleon that
will compile it, and the gap is reported where the policy is made.
"""

import importlib.util

from aerleon.lib import policy_builder

# Term keys whose absence widens the rule rather than failing it.
SCOPING_KEYS = ("windows-program", "windows-service", "windows-rpc")


def unknown_keys(terms):
    """The scoping keys `terms` use that the installed aerleon does not know."""
    known = policy_builder.BUILTIN_SPEC
    return sorted({k for t in terms for k in t if k in SCOPING_KEYS and k not in known})


def has_generator(name):
    return importlib.util.find_spec(f"aerleon.lib.{name}") is not None


def check_policy(policy):
    """Messages for what the installed aerleon would drop or refuse."""
    out = []
    for f in policy.get("filters") or []:
        targets = (f.get("header") or {}).get("targets") or {}
        for gen in targets:
            if not has_generator(gen):
                out.append(f"aerleon has no {gen} generator")
        keys = unknown_keys(f.get("terms") or [])
        if keys:
            out.append(f"aerleon does not know {', '.join(keys)}: those terms "
                       f"would compile unscoped (ppietikainen/aerleon "
                       f"firru-1.0.0-windows-rpc has them)")
    return sorted(set(out))
