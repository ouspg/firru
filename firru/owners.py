"""
Who serves a service: owner hints read from the definitions' comments.

Two names can claim the same port -- COCKPIT and PROMETHEUS are both tcp/9090,
and DOCKER-SWARM and METALLB-MEMBERLIST share 7946 -- and the port alone cannot
say which one a host is running. The listener can: its process, its systemd
unit, or the Windows service behind svchost. An owner hint says which of those
belong to a name.

Hints live as comments beside the entry they describe, the way `# Source:` does,
because that is where a person editing the definitions will look:

    # Source: cockpit-project.org guide (cockpit.socket ListenStream=9090)
    # Owner: units=cockpit.socket processes=cockpit-ws,cockpit-tls
    COCKPIT:

A second key, `# Expect:`, lists the usual implementations of a name that no
one process identifies -- HTTP is nginx, apache2, caddy... It is not evidence
for choosing between names (python3 on 80 is still HTTP); it is what makes a
listener *unexpected*, so the synthesized term can say "HTTP-ALT served by
python3". An `# Owner:` line is an expectation too.

aerleon drops comments when it loads the definitions, so this module reads them
from the YAML text instead. The result is a plain table (token -> {kind:
[names]}); `python -m firru.owners DEFS_DIR` prints it as JSON for anything else
that wants it. It is rebuilt on every load, so there is no second file to fall
out of step with the YAML.
"""

import json
import re
import sys
from pathlib import Path

#: Evidence kinds an `# Owner:` line may name. A listener's process name and
#: exe basename are both matched against `processes`.
KINDS = ('units', 'processes', 'services')

_LINE = re.compile(r'^\s*#\s*(Owner|Expect):\s*(.*)$')
_KEY = re.compile(r'^  ([A-Za-z0-9][A-Za-z0-9_.-]*):\s*$')


def parse_owner_comments(text, label='Owner'):
    """{token: {kind: [names]}} from one definitions file's text.

    An `# Owner:` (or, with label='Expect', `# Expect:`) line belongs to the
    next service key below it, with only comments in between; a blank line or
    anything else ends the block.
    """
    owners, pending = {}, {}
    for line in text.splitlines():
        m = _LINE.match(line)
        if m:
            if m.group(1) != label:
                continue
            for field in m.group(2).split():
                kind, _, names = field.partition('=')
                if kind not in KINDS or not names:
                    raise ValueError(f"bad {m.group(1)} field {field!r} in: {line.strip()}")
                pending.setdefault(kind, []).extend(
                    n.strip().lower() for n in names.split(',') if n.strip())
            continue
        if line.lstrip().startswith('#'):
            continue
        k = _KEY.match(line)
        if k and pending:
            owners[k.group(1)] = pending
        pending = {}
    return owners


def load_owners(defs_dir, label='Owner'):
    """Owner (or Expect) hints from every *.yml / *.yaml in a definitions directory."""
    owners = {}
    d = Path(defs_dir)
    if not d.is_dir():
        return owners
    for f in sorted([*d.glob('*.yml'), *d.glob('*.yaml')]):
        for token, hints in parse_owner_comments(f.read_text(), label).items():
            if token in owners:
                raise ValueError(f"{token}: {label} hints in more than one file")
            owners[token] = hints
    return owners


def load_expected(defs_dir):
    """Who is expected to serve each name: its Owner hints plus its Expect hints."""
    expected = {t: {k: list(v) for k, v in h.items()} for t, h in load_owners(defs_dir).items()}
    for token, hints in load_owners(defs_dir, 'Expect').items():
        for kind, names in hints.items():
            expected.setdefault(token, {}).setdefault(kind, []).extend(names)
    return expected


def owner_evidence(entries):
    """
    The lowercased names that say who serves a port, from its listener records:
    process name, exe basename, systemd unit, and Windows services.
    """
    seen = set()
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        p = e.get('process') or {}
        for v in (p.get('name'), p.get('unit')):
            if v:
                seen.add(str(v).lower())
        exe = p.get('exe') or ''
        if exe:
            seen.add(re.split(r'[\\/]', exe)[-1].lower())
        for s in p.get('services') or []:
            seen.add(str(s).lower())
    seen.discard('unknown')
    return seen


def owner_matches(hints, evidence):
    """Whether any of a token's hinted names appears in the evidence."""
    return any(n in evidence for kind in KINDS for n in hints.get(kind, ()))


if __name__ == '__main__':
    d = sys.argv[1] if len(sys.argv) > 1 else 'def'
    json.dump({'owner': load_owners(d), 'expect': load_owners(d, 'Expect')},
              sys.stdout, indent=2, sort_keys=True)
    print()
