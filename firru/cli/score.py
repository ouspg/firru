#!/usr/bin/env python3
"""
firru score — annotate host policies with [score] "must stay open" notes.

Reads a scoring YAML (host token → services that must stay reachable, see
firru.scoring) and a set of aerleon host policy YAMLs, and adds a ``[score]``
comment line to every term whose port surface covers a scored ``(proto, port)``.

This is the tag-aware replacement for the old inline scoring in
firru synth. It honors the comment contract
(docs/comment-contract.md): only ``[score]`` lines are (re)written; ``[auto]``
observation lines and untagged human lines are carried forward untouched.
Because the match resolves the term's ``destination-port`` through the defs, a
scored port folded into a group token (e.g. WINDOWS-DC-BASE) is annotated too —
the case the inline version missed.

Usage:
    firru score --scoring scoring.yml --defs def policies/pol/*.yml
    firru score --scoring scoring.yml --defs def --dry-run policies/pol/*.yml
"""

import argparse
import glob as _glob
import sys
from pathlib import Path

from aerleon.lib import naming
from ruyaml import YAML
from ruyaml.comments import CommentedMap, CommentedSeq

from firru.comments import (
    TAG_AUTO,
    TAG_SCORE,
    line_tag,
    tagged,
    partition_comment,
    preceding_raw_comment,
    set_term_comment,
)
from firru.policy import term_covers
from firru.scoring import load_scoring

yaml_handler = YAML()
yaml_handler.indent(mapping=2, sequence=4, offset=2)
yaml_handler.preserve_quotes = True


def _term_notes(term, host_scoring, defs):
    """Distinct scoring notes for every scored (proto, port) this term covers."""
    notes = []
    for (proto, port), note in host_scoring.items():
        if term_covers(defs, term, proto, port) and note not in notes:
            notes.append(note)
    return notes


def annotate_terms(old_terms, host_scoring, defs):
    """
    Rebuild a terms sequence with refreshed [score] lines. Returns
    (new_seq, n_annotated). [auto] and human lines are preserved and ordered
    [auto] → [score] → human.
    """
    new_terms = CommentedSeq()
    n = 0
    for i, term in enumerate(old_terms):
        # Drop stale [score]; keep [auto] + human.
        _, kept = partition_comment(preceding_raw_comment(old_terms, i), owned=TAG_SCORE)
        auto = [ln for ln in kept if line_tag(ln) == TAG_AUTO]
        human = [ln for ln in kept if line_tag(ln) != TAG_AUTO]

        score_lines = [tagged(TAG_SCORE, note) for note in _term_notes(term, host_scoring, defs)]
        if score_lines:
            n += 1

        new_term = CommentedMap()
        for k, v in term.items():
            new_term[k] = v
        set_term_comment(new_term, auto + score_lines + human, [])
        new_terms.append(new_term)
    return new_terms, n


def annotate_policy(doc, scoring_index, defs):
    """Annotate every filter's terms in a loaded policy doc in place. Returns
    the number of terms that gained a [score] line."""
    host = (doc.get("metadata") or {}).get("host")
    host_scoring = scoring_index.get(host, {})
    total = 0
    for filt in doc.get("filters", []):
        terms = filt.get("terms")
        if not terms:
            continue
        new_terms, n = annotate_terms(terms, host_scoring, defs)
        filt["terms"] = new_terms
        # ruyaml stores the first term's leading comment on the parent's
        # `terms` key; reassigning the value leaves it behind. Drop it — its
        # content is re-attached to the rebuilt first term.
        if hasattr(filt, "ca"):
            filt.ca.items.pop("terms", None)
        total += n
    return host, host_scoring, total


def _expand_inputs(patterns):
    paths = []
    for pat in patterns:
        p = Path(pat)
        if p.is_dir():
            paths.extend(sorted(p.glob("*.yml")))
        else:
            paths.extend(Path(f) for f in _glob.glob(pat))
    return sorted(set(paths))


def main():
    parser = argparse.ArgumentParser(
        description="Annotate host policies with [score] 'must stay open' notes."
    )
    parser.add_argument("policies", nargs="+",
                        help="Policy YAML files, directories, or glob patterns")
    parser.add_argument("--scoring", "-s", required=True,
                        help="Scoring YAML (host token → [{proto, port, note}])")
    parser.add_argument("--defs", "-d", default="def",
                        help="Aerleon definitions directory (default: def/)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report matches; write nothing")
    args = parser.parse_args()

    scoring_index = load_scoring(args.scoring)
    if not scoring_index:
        print(f"No scoring entries loaded from {args.scoring}", file=sys.stderr)
        sys.exit(1)

    defs = naming.Naming(args.defs)

    files = _expand_inputs(args.policies)
    if not files:
        print(f"No policy files found for: {args.policies}", file=sys.stderr)
        sys.exit(1)

    for path in files:
        with open(path) as f:
            doc = yaml_handler.load(f)
        host, host_scoring, n = annotate_policy(doc, scoring_index, defs)

        if not host_scoring:
            print(f"  {path.name}: host {host!r} not in scoring — unchanged", file=sys.stderr)
            continue

        if args.dry_run:
            print(f"  {path.name} ({host}): {n} term(s) would be annotated")
            continue

        with open(path, "w") as f:
            yaml_handler.dump(doc, f)
        print(f"  {path.name} ({host}): {n} term(s) annotated [score]")


if __name__ == "__main__":
    main()
