"""
firru.scoring — "must stay open" service annotations.

A scoring config names host services that must remain reachable regardless of
observed traffic (e.g. a business-critical or externally-required listener).
It is out-of-band evidence, authored by hand — not derived from flows. The
only thing firru does with it is annotate the matching policy terms with a
"DO NOT BLOCK" note; it never opens, closes, or scores anything itself.

YAML format (host token → list of services):

    WEB_FRONTEND:
      - {proto: tcp, port: 443, note: "public scoring endpoint"}
      - {proto: tcp, port: 80}
    DB_HOST:
      - {proto: tcp, port: 5432, note: "app backend"}
"""

import sys

import yaml

DEFAULT_NOTE = "must stay open (scoring config)"


def load_scoring(path: str) -> dict:
    """
    Load a scoring YAML into a nested index:

        { host_token: { (proto, port): note } }

    Returns {} for a missing/empty/unreadable path. Malformed service
    entries are skipped with a warning; a bad file never aborts the run.
    """
    if not path:
        return {}
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except (FileNotFoundError, yaml.YAMLError) as e:
        print(f"Warning: could not load scoring config {path}: {e}", file=sys.stderr)
        return {}

    index = {}
    for host_token, services in (data or {}).items():
        for svc in services or []:
            try:
                proto = svc["proto"]
                port = int(svc["port"])
            except (KeyError, TypeError, ValueError):
                print(f"Warning: skipping malformed scoring entry {svc!r} "
                      f"under {host_token!r}", file=sys.stderr)
                continue
            note = svc.get("note") or DEFAULT_NOTE
            index.setdefault(host_token, {})[(proto, port)] = note
    return index
