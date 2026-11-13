#!/usr/bin/env python3
"""
firru annotate-services — refresh the observed-evidence comment on service tokens.

`def/services.yml` holds a naming decision: which ports belong together and what
that group is called. The evidence for it — which processes actually serve those
ports, on which hosts — is a regenerable view, and it goes stale the moment the
estate changes. This rewrites that view in place and touches nothing else.

    firru annotate-services --defs def --input loot/            # preview
    firru annotate-services --defs def --input fam/ exec/ --write
    firru annotate-services --defs def --input loot/ --max-hosts 6 --write

Per the comment contract, the annotation is written as an `[auto]` line and only
`[auto]` lines are replaced. Everything else on that key — a human's note, another
tool's tag — is carried forward untouched.

Tokens with no observed listener are left alone and counted, not annotated: a
service defined but never seen may be a dead definition, or may simply be one
this collection did not reach, and the tool cannot tell those apart.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from aerleon.lib import naming
from ruyaml import YAML
from ruyaml.error import CommentMark
from ruyaml.tokens import CommentToken

from firru.comments import TAG_AUTO, line_tag, tagged
from firru.policy import port_ranges
from firru.tokens import normalize_token

yaml_handler = YAML()
yaml_handler.indent(mapping=2, sequence=4, offset=2)
yaml_handler.preserve_quotes = True
yaml_handler.width = 4096  # keep a long Hosts list on one line


def observed_index(loot_paths):
    """
    Walk loot-listeners JSON into {(proto, port): {'procs': Counter, 'hosts': set}}.

    Accepts directories and single files, so a FAM and an EXEC tree can be
    annotated as one picture or as two.
    """
    files = []
    for p in loot_paths:
        path = Path(p)
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        elif path.is_file():
            files.append(path)
        else:
            print(f"Warning: no such loot path: {p}", file=sys.stderr)

    index = {}
    for f in files:
        try:
            with open(f) as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            print(f"Warning: skipping {f}: {e}", file=sys.stderr)
            continue
        host = normalize_token((doc.get("metadata") or {}).get("hostname") or f.stem)
        for rec in doc.get("listen_ports", []):
            proto, port = rec.get("protocol"), rec.get("port")
            if not proto or port is None:
                continue
            entry = index.setdefault((proto.lower(), int(port)),
                                     {"procs": Counter(), "hosts": set()})
            name = (rec.get("process") or {}).get("name")
            if name and name != "UNKNOWN":
                entry["procs"][name] += 1
            entry["hosts"].add(host)
    return index


def evidence_for(defs, token, index):
    """Merge the observations for every port `token` covers. None if unobserved."""
    ranges = port_ranges(defs, token)
    if not ranges:
        return None
    procs, hosts = Counter(), set()
    for (proto, port), entry in index.items():
        if any(proto == rp and lo <= port <= hi for rp, lo, hi in ranges):
            procs.update(entry["procs"])
            hosts |= entry["hosts"]
    if not hosts:
        return None
    return procs, hosts


def format_evidence(procs, hosts, max_hosts=0):
    """The `[auto]` line for one token's evidence."""
    shown = sorted(hosts)
    suffix = ""
    if max_hosts and len(shown) > max_hosts:
        suffix = f" +{len(shown) - max_hosts} more"
        shown = shown[:max_hosts]
    return tagged(TAG_AUTO,
                  f"Procs: {dict(procs.most_common())} | "
                  f"Hosts({len(hosts)}): {shown}{suffix}")


def _raw_comment(node, key):
    """The raw comment slot on a mapping key, or ''. May hold several lines."""
    slots = getattr(getattr(node, "ca", None), "items", {}).get(key)
    if not isinstance(slots, list) or len(slots) < 3 or slots[2] is None:
        return ""
    return slots[2].value


def _eol_comment(node, key):
    """Just the end-of-line comment text on a mapping key, or ''."""
    return _raw_comment(node, key).partition("\n")[0].strip()


def _set_eol_comment(node, key, text, tail=""):
    """
    Set a mapping key's end-of-line comment, preserving any comment block that
    precedes the key.

    ruyaml's own ``yaml_add_eol_comment`` raises on a key that already carries a
    preceding block (it extends a slot that holds a bare CommentToken rather
    than a list), and several def files open a section with exactly that kind of
    banner. Writing the token into its slot leaves the other slots untouched.
    """
    slots = node.ca.items.setdefault(key, [None, None, None, None])
    while len(slots) < 4:
        slots.append(None)
    slots[2] = CommentToken(f"# {text}\n{tail}".rstrip("\n") + "\n", CommentMark(0))


def split_eol(raw):
    """
    Split a key's comment slot into (replaceable, kept, tail).

    ruyaml stores a key's end-of-line comment and any full-line comments that
    follow it in one slot. Only the first line is the end-of-line comment and
    only it is ever rewritten:

    ``replaceable`` is this tool's own `[auto]` output on that first line.
    ``kept`` is a first line belonging to anyone else — a human's note, another
    tool's tag — returned so it can be re-appended.
    ``tail`` is every following line, verbatim, newlines included. Those are
    somebody's commented-out data (a disabled service entry, say) and are never
    touched.
    """
    if not raw:
        return "", "", ""
    first, _, rest = raw.partition("\n")
    tail = f"\n{rest.rstrip()}" if rest.strip() else ""
    text = first.lstrip("#").strip()
    if not text:
        return "", "", tail
    if line_tag(text) == TAG_AUTO:
        return text, "", tail
    return "", text, tail


def annotate_file(path, defs, index, max_hosts=0):
    """
    Refresh the `[auto]` evidence on every observed service token in one def
    file. Returns (doc_or_None, changed, unobserved, kept_human).
    """
    with open(path) as f:
        doc = yaml_handler.load(f)
    services = (doc or {}).get("services")
    if not services:
        return None, 0, 0, 0

    changed = unobserved = kept_human = 0
    for token in list(services.keys()):
        evidence = evidence_for(defs, token, index)
        if evidence is None:
            unobserved += 1
            continue
        raw = _raw_comment(services, token)
        _, kept, tail = split_eol(raw)
        if kept:
            kept_human += 1
        line = format_evidence(*evidence, max_hosts=max_hosts)
        new = f"{line}  {kept}" if kept else line
        if raw.partition("\n")[0].lstrip("#").strip() == new:
            continue
        _set_eol_comment(services, token, new, tail)
        changed += 1

    return doc, changed, unobserved, kept_human


def main():
    parser = argparse.ArgumentParser(
        description="Refresh the observed-evidence comment on service tokens in def/.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  firru annotate-services --defs def --input loot/
  firru annotate-services --defs def --input fam/ exec/ --write
        """
    )
    parser.add_argument("--defs", "-d", default="def", metavar="DIR",
                        help="Aerleon definitions directory (default: def)")
    parser.add_argument("--input", "-i", nargs="+", default=["loot"], metavar="PATH",
                        help="loot-listeners JSON directories or files (default: loot)")
    parser.add_argument("--max-hosts", type=int, default=0, metavar="N",
                        help="Truncate the host list to N names plus a count "
                             "(default: 0, list them all)")
    parser.add_argument("--write", action="store_true",
                        help="Write the files. Without it, nothing is modified.")
    args = parser.parse_args()

    try:
        defs = naming.Naming(args.defs)
    except Exception as e:
        print(f"firru annotate-services: cannot load definitions from {args.defs}: {e}",
              file=sys.stderr)
        return 1

    index = observed_index(args.input)
    if not index:
        print(f"firru annotate-services: no listeners found in {args.input}",
              file=sys.stderr)
        return 1
    print(f"{len(index)} observed (proto, port) pairs from {' '.join(args.input)}")

    def_files = sorted(p for p in Path(args.defs).glob("*.yml")
                       if not p.name.startswith("#") and not p.name.endswith("~"))

    total_changed = total_unobserved = total_kept = 0
    for path in def_files:
        try:
            doc, changed, unobserved, kept = annotate_file(path, defs, index,
                                                           max_hosts=args.max_hosts)
        except Exception as e:
            print(f"  ! {path.name}: {e}", file=sys.stderr)
            continue
        if doc is None:
            continue
        total_changed += changed
        total_unobserved += unobserved
        total_kept += kept
        note = f"  {path.name}: {changed} annotated, {unobserved} unobserved"
        if kept:
            note += f", {kept} with a human note kept"
        print(note)
        if changed and args.write:
            with open(path, "w") as f:
                yaml_handler.dump(doc, f)

    print(f"{total_changed} token(s) annotated, {total_unobserved} unobserved"
          + (f", {total_kept} human note(s) preserved" if total_kept else ""))
    if not args.write:
        print("(preview — nothing written; pass --write)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
