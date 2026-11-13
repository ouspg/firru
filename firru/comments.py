"""
firru.comments — tag-aware policy comment handling.

Implements the comment contract (docs/comment-contract.md): every comment line
is typed by the source that regenerates it. A leading ``[tag]`` marks a
machine-owned line; an untagged line is human-authored and inviolable.

    # [auto]  regenerated from loot / flow observations
    # [score] regenerated from scoring.yml
    # (untagged) authored by a human — never rewritten by a tool

A generator rewrites only its own tag's lines and carries every other line
forward unchanged. ruyaml stores the block of comment lines that visually
precede sequence item N as a trailing comment on item N-1's last key; the
readers here hide that quirk.
"""

import re

TAG_AUTO = "auto"
TAG_SCORE = "score"

_TAG_RE = re.compile(r"^\[(\w+)\]\s?(.*)$")


def _clean_lines(raw):
    """Split a ruyaml-stored comment block into clean text (no '#', no indent)."""
    if not raw:
        return []
    out = []
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("#"):
            s = s[1:].strip()
        if s:
            out.append(s)
    return out


def line_tag(line):
    """Tag of a clean comment line (e.g. 'auto'), or None if human-authored."""
    m = _TAG_RE.match(line)
    return m.group(1) if m else None


def tagged(tag, text):
    """Format a clean comment line carrying ``tag`` — e.g. '[auto] 3 flows'."""
    return f"[{tag}] {text}"


def partition_comment(raw, owned=TAG_AUTO):
    """
    Split a raw comment block into (owned_lines, kept_lines).

    owned_lines — clean text of lines carrying the ``owned`` tag; the caller
                  drops these and regenerates them.
    kept_lines  — every other line, verbatim (tag included) and in order:
                  human lines plus lines owned by other tools. Inviolable.
    """
    owned_lines, kept = [], []
    for line in _clean_lines(raw):
        (owned_lines if line_tag(line) == owned else kept).append(line)
    return owned_lines, kept


def preceding_raw_comment(seq, idx):
    """
    Raw comment block stored for the lines that visually precede seq[idx], or
    None. Hides ruyaml's "attach to previous sibling's last key" placement.
    """
    if idx >= 1:
        prev = seq[idx - 1]
        ca = getattr(prev, "ca", None)
        items = getattr(ca, "items", None) if ca is not None else None
        if items and hasattr(prev, "keys"):
            for key in reversed(list(prev.keys())):
                tok = items.get(key)
                if tok and len(tok) > 2 and tok[2] is not None:
                    return tok[2].value
        return None
    # idx == 0: a block before the first item is stored on the seq's own start.
    ca = getattr(seq, "ca", None)
    comment = getattr(ca, "comment", None) if ca is not None else None
    if comment and len(comment) > 1 and comment[1]:
        return "".join(t.value for t in comment[1])
    return None


def detached(term):
    """
    A shallow copy of ``term`` whose list values are copies too, without the
    comments ruyaml hung on them.

    ruyaml stores a comment written above a list item on the *previous* item's
    last value: the `# [auto]` line above term B lives on term A's
    `source-address` list. `CommentedMap(term)` copies the map but shares the
    list, so a generator that rebuilds or reorders terms carried B's line along
    under A. Those lines are recovered first (kept_comments_by_term) and
    regenerated or re-attached to their own term, so dropping them here loses
    nothing.
    """
    from ruyaml.comments import CommentedMap, CommentedSeq
    out = CommentedMap(term)
    for key, value in out.items():
        if isinstance(value, CommentedSeq):
            out[key] = CommentedSeq(value)
    return out


def kept_comments_by_term(seq, owned=TAG_AUTO):
    """
    Map term name → kept (carried-forward) comment lines for every named term
    in ``seq``. Lets a generator recover human/other-tool lines before it
    rebuilds the term list.
    """
    out = {}
    for i, term in enumerate(seq):
        name = term.get("name") if hasattr(term, "get") else None
        if name is None:
            continue
        _, kept = partition_comment(preceding_raw_comment(seq, i), owned=owned)
        if kept:
            out[name] = kept
    return out


def compose_start_comment(owned_lines, kept_lines, lead_blank=True):
    """
    Join owned + kept clean lines into text for ``yaml_set_start_comment``
    (which prefixes each line with '# '). Returns None if there is nothing to
    write. ``lead_blank`` adds a blank line before the block so consecutive
    terms stay visually separated.
    """
    lines = list(owned_lines) + list(kept_lines)
    if not lines:
        return None
    body = "\n".join(lines)
    return f"\n{body}" if lead_blank else body


def set_term_comment(term, owned_lines, kept_lines, lead_blank=True):
    """
    Set ``term``'s start comment to the regenerated owned lines followed by the
    carried-forward kept lines, or clear it if both are empty.
    """
    text = compose_start_comment(owned_lines, kept_lines, lead_blank=lead_blank)
    if text is not None:
        term.yaml_set_start_comment(text)
    return term
