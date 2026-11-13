"""
The enforcement stance of a policy: where it is on log-accept -> log-drop -> drop.

A policy does not go from open to enforced in one step. Its terminal catch-all
moves through stages, each one a bet that the explicit terms above it now cover
the legitimate traffic:

    open        allow-ANY, unlogged. Nothing is observed, nothing is refused.
    log-accept  accept + log. Initial deployment: unmatched traffic is seen.
    log-drop    deny + log. Rules settled; false positives surface before the
                drop goes silent.
    drop        deny. Confident. Silent.

Only the last three are a progression the tools promote through, and they are
reversible: a bad bet moves a policy back one stage. The stage is carried by the
terminal term's action and logging, nothing else. The term's *name* is a label
(`log-drop-ANY`, `log-drop-ANY-egress`), so this reads
the behavior and never the name; renaming a term cannot change the stage.

This module is the one definition of the machine. Generators that emit a
terminal (merge-zones) take its shape from `terminal_term`, and `firru stance`
reports it, so the stage a tool writes and the stage a tool reads back cannot
drift apart.
"""

from firru.policy import (
    DIR_IN, DIR_OUT, filter_directions, is_catch_all,
)

OPEN = "open"
LOG_ACCEPT = "log-accept"
LOG_DROP = "log-drop"
DROP = "drop"

#: The progression, in order. `open` and `none` sit outside it.
STAGES = (LOG_ACCEPT, LOG_DROP, DROP)

#: Not a stage: the filter ends without a catch-all, so its default policy
#: decides. Reported as its own state because guessing one would be wrong.
NONE = "none"

_REFUSE = ("deny", "reject", "drop", "discard")


def next_stage(stance):
    """The stage after this one, or None at `drop` and outside the progression."""
    if stance in STAGES[:-1]:
        return STAGES[STAGES.index(stance) + 1]
    return None


def previous_stage(stance):
    """The stage to fall back to when the bet was wrong, or None at the start."""
    if stance in STAGES[1:]:
        return STAGES[STAGES.index(stance) - 1]
    return None


def terminal_term(stage):
    """The canonical catch-all term for a stage of the progression.

    ``{"name", "action", "logging"?, "comment"?}``, a fresh dict on every call.
    Raises ValueError for anything outside STAGES, so a typo in a caller fails
    where it is made and not as a policy that silently ends open.
    """
    if stage == LOG_ACCEPT:
        return {
            "name":    "log-accept-ANY",
            "action":  "accept",
            "logging": True,
            "comment": (
                "INITIAL DEPLOYMENT: accept + log all unmatched traffic. "
                "Promote to log-drop (--terminal log-drop) once rules are stable."
            ),
        }
    if stage == LOG_DROP:
        return {
            "name":    "log-drop-ANY",
            "action":  "deny",   # aerleon keyword; the nftables generator renders it as drop
            "logging": True,
            "comment": (
                "SETTLING: drop + log unmatched traffic to catch false positives. "
                "Promote to drop (--terminal drop) when the log has been quiet."
            ),
        }
    if stage == DROP:
        return {"name": "drop-ANY", "action": "deny"}
    raise ValueError(f"unknown stance {stage!r}; expected one of {', '.join(STAGES)}")


def stance_of_term(term):
    """The stage a terminal catch-all term is in, from its action and logging."""
    action = str(term.get("action") or "").lower()
    logged = bool(term.get("logging"))
    if action == "accept":
        return LOG_ACCEPT if logged else OPEN
    if action in _REFUSE:
        return LOG_DROP if logged else DROP
    return NONE


def stance_of_terms(terms):
    """The stance of one filter's term list: that of its last catch-all."""
    for term in reversed(list(terms or ())):
        if is_catch_all(term):
            return stance_of_term(term)
    return NONE


def policy_stances(doc):
    """``{direction: stance}`` for a policy document, over the sides it states.

    A filter that names no direction contributes nothing (see
    `filter_directions`): a zone pair or an interface-bound ACL says no side,
    and filing it under one would report a stage for a half it may not govern.
    A filter that enforces both sides reports the same stage for each.
    """
    out = {}
    for filt in (doc or {}).get("filters") or []:
        stance = stance_of_terms(filt.get("terms"))
        for side in sorted(filter_directions(filt)):
            out[side] = stance
    return {side: out[side] for side in (DIR_IN, DIR_OUT) if side in out}
