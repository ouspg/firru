"""
firru.readers — recognize and read whatever a host directory holds.

One entry point, `read_host()`, takes the directory a collection left behind
and returns normalized listeners plus a record of what it read and what it
could not. It replaces the chain that used to run `filename -> os label -> one
normalizer`, which had two failures worth naming because both were silent:

  * The BSD branch was unreachable. `firru.discovery` only ever set `os` to
    `linux` or `windows`, so the `netstat` reader could only be entered by
    hand-building an entry dict -- which is what its tests did, and why they
    passed while no real loot could reach it.
  * A file nothing recognized was dropped by a bare `else`. A host whose dump
    was named something unexpected inventoried as zero listeners, which is the
    same failure class as a parse error reported as an empty host.

So recognition here is by **content**, with the filename used only to order the
candidates. That is what makes third-party loot work: PoSh-R2 lays out a
Windows host differently from `loot-host.sh`, an appliance may only have
`netstat -anp`, and neither gets to depend on firru having guessed its naming
convention in advance. A file that no reader claims is reported in `problems`
rather than ignored.

Adding a source is a registry entry, not a branch. An annotator -- `lsof` on
macOS, `sockstat` on FreeBSD -- is the same, and joins on whatever key its
platform actually has.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import jc

from firru import listeners as _rec
from firru.netstat import parse_netstat_safe
from firru.ss import parse_ss_safe

# ---------------------------------------------------------------------------
# Sniffers — what a file *is*, decided from its content
# ---------------------------------------------------------------------------

#: How much of a file to look at. Every format below announces itself in its
#: first line or two; reading more would only slow down a walk over an estate.
_SNIFF_BYTES = 8192


def _head(text: str, n: int = 5) -> list:
    """First n significant lines: blanks and '#' provenance comments skipped."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        out.append(line)
        if len(out) >= n:
            break
    return out


def sniff_ss(text: str) -> bool:
    """Linux `ss`. The header names Recv-Q and either Netid or State, depending
    on whether the flag set asked for more than one socket family."""
    for line in _head(text, 2):
        if 'Recv-Q' in line and ('Netid' in line or line.lstrip().startswith('State')):
            return True
    return False


def sniff_linux_netstat(text: str) -> bool:
    """Linux net-tools `netstat`, as distinct from the BSD one.

    Both open with `Active Internet connections`. The tell is the state column:
    net-tools writes `State` (and `PID/Program name` with `-p`), BSD writes
    `(state)` in parentheses. Falling back to the address separator -- `:port`
    on Linux, `.port` on BSD -- would work too, but the header is present even
    on a host with no sockets at all.
    """
    if 'Active Internet connections' not in text:
        return False
    for line in _head(text, 4):
        if line.startswith('Proto'):
            return '(state)' not in line
    return False


def sniff_bsd_netstat(text: str) -> bool:
    """BSD and macOS `netstat -an`: the same banner, `(state)` in the header."""
    if 'Active Internet connections' not in text:
        return False
    for line in _head(text, 4):
        if line.startswith('Proto'):
            return '(state)' in line
    # Some builds emit the banner and no sockets at all, which is a real answer
    # about a host and must not be refused here.
    return 'Active Internet connections' in text


def sniff_windows_csv(text: str) -> bool:
    """Get-NetTCPConnection / Get-NetUDPEndpoint, exported by loot-host.sh's
    PowerShell counterpart or by PoSh-R2."""
    head = _head(text, 1)
    if not head:
        return False
    cols = head[0].replace('"', '')
    return 'LocalPort' in cols and ('LocalAddress' in cols or 'OwningProcess' in cols)


def sniff_windows_services_csv(text: str) -> bool:
    head = _head(text, 1)
    if not head:
        return False
    cols = head[0].replace('"', '')
    return 'ProcessId' in cols.replace('ProcessID', 'ProcessId') and 'Name' in cols


def sniff_psexe(text: str) -> bool:
    """`ps` output used for exe/cgroup annotation on Linux."""
    head = _head(text, 1)
    return bool(head) and 'PID' in head[0] and (
        'CMD' in head[0] or 'COMMAND' in head[0])


# ---------------------------------------------------------------------------
# Annotation readers
# ---------------------------------------------------------------------------

def read_psexe(filename):
    """
    Read Linux ps/proc annotation file (jc 'ps' format).
    Returns dict of pid_str -> {exepath, user, cmdline, cgroup, netns}.
    """
    if not filename or not os.path.exists(filename):
        return {}
    with open(filename) as f:
        data = jc.parse('ps', f.read())
    procs = {}
    for p in data:
        pid = str(p.get('pid', ''))
        procs[pid] = {
            'exepath': p.get('exe', ''),
            'user':    p.get('user', None),
            'cmdline': p.get('command', ''),
            'cgroup':  p.get('cgroup', ''),
            'netns':   p.get('netns', ''),
        }
    return procs


def read_services(filename):
    """
    Read Windows Services.csv (Win32_Service via Get-WmiObject).
    Returns dict of pid_str -> {process, exepath, services, descriptions}.
    """
    if not filename or not os.path.exists(filename):
        return {}
    with open(filename) as f:
        data = jc.parse('csv', f.read())
    services = {}
    for svc in data:
        # Both spellings are real. `Get-WmiObject Win32_Service` exported by
        # loot-host.sh's PowerShell writes `ProcessID`; PoSh-R2's fuller export
        # writes `ProcessId`. Accepting only the first read that file as 97
        # services with no pids, so every listener came back unannotated and
        # nothing said why.
        pid = str(svc.get('ProcessID') or svc.get('ProcessId') or '0')
        if pid == '0':
            continue
        if pid not in services:
            services[pid] = {
                'process':      svc.get('Name', ''),
                'exepath':      svc.get('PathName', ''),
                'services':     [],
                'descriptions': [],
            }
        services[pid]['services'].append(svc.get('Name', ''))
        services[pid]['descriptions'].append(svc.get('Description', ''))
    return services


def _read_windows_csv(path):
    with open(path) as f:
        return jc.parse('csv', f.read())


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Reader:
    """One way of reading one kind of file.

    `precedence` orders inventory sources when a host directory holds more than
    one. Lower wins. `ss` beats Linux `netstat` because it carries the cgroup,
    reports the kernel's `comm` rather than a truncated command line, and never
    loses a socket to an unprivileged collection's `-`.

    `annotators` names the annotation readers this source can consume. It is a
    list because the join key is the source's business: psexe joins on pid,
    which BSD netstat does not have, so an `lsof` annotator will join on
    (proto, address, port) instead.
    """
    name: str
    kind: str                       # 'inventory' | 'annotation' | 'context'
    sniff: Callable[[str], bool]
    hints: tuple = ()               # lowercase basenames that suggest this reader
    os: Optional[str] = None
    precedence: int = 50
    parse: Optional[Callable] = None        # path -> raw rows
    normalize: Optional[Callable] = None    # (row, annotation) -> record | None
    annotators: tuple = ()
    load: Optional[Callable] = None         # annotation readers: path -> dict


REGISTRY = (
    Reader(
        name='ss', kind='inventory', os='linux', precedence=10,
        hints=('ss',), sniff=sniff_ss,
        parse=parse_ss_safe, normalize=_rec.normalize_linux_entry,
        annotators=('psexe',),
    ),
    Reader(
        name='linux-netstat', kind='inventory', os='linux', precedence=20,
        hints=('netstat', 'netstat.txt', 'netstat-anp', 'netstat-tulnp'),
        sniff=sniff_linux_netstat,
        parse=lambda p: jc.parse('netstat', open(p).read(), quiet=True),
        normalize=_rec.normalize_linux_netstat_entry,
        annotators=('psexe',),
    ),
    Reader(
        name='bsd-netstat', kind='inventory', os='bsd', precedence=20,
        hints=('netstat', 'netstat.txt', 'netstat-an'),
        sniff=sniff_bsd_netstat,
        parse=parse_netstat_safe, normalize=_rec.normalize_bsd_entry,
    ),
    Reader(
        name='windows-csv', kind='inventory', os='windows', precedence=10,
        hints=('connections.csv',), sniff=sniff_windows_csv,
        parse=_read_windows_csv, normalize=_rec.normalize_windows_entry,
        annotators=('windows-services',),
    ),
    Reader(
        name='psexe', kind='annotation', os='linux',
        hints=('psexe',), sniff=sniff_psexe, load=read_psexe,
    ),
    Reader(
        name='windows-services', kind='annotation', os='windows',
        hints=('services.csv',), sniff=sniff_windows_services_csv,
        load=read_services,
    ),
)

#: Files a collection leaves behind that are neither inventory nor attribution.
#: Naming them is what keeps `problems` meaningful: an unrecognized file is a
#: real finding only if nothing expected it.
_CONTEXT_FILES = ('ipaddr', 'ipaddr.json', 'loot.json', 'hostname',
                  'os-release', 'uname',
                  # loot-host.ps1: firewall state, read by nothing yet but
                  # expected in every Windows collection.
                  'firewall.json',
                  # conn-audit.ps1 / conn-audit.sh: connections, not listeners.
                  # Their own directory normally, but a copy that lands next
                  # to the loot is context, not a problem.
                  'egress-config.json', 'wfp-connections.csv', 'http-urls.csv',
                  'http-servicestate.txt', 'http-urlacl.txt',
                  'sysmon-network.csv', 'sysmon-dns.csv',
                  'conn-audit.jsonl', 'conn-audit.meta', 'conn-audit-cgroups.tsv')


@dataclass
class HostInventory:
    """What one host directory turned out to contain.

    `problems` is not decoration. A dump that could not be read and a host that
    listens on nothing must never arrive as the same value -- that equivalence
    is how `firru apply --prune` once stripped a working host of every rule --
    so anything that went wrong is carried alongside the answer rather than
    replacing it or vanishing.
    """
    hostname: str = ''
    os: Optional[str] = None
    listeners: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    problems: list = field(default_factory=list)
    files: dict = field(default_factory=dict)   # reader name -> path


def identify(path) -> Optional[Reader]:
    """Which reader claims this file, or None.

    Filename first, but only to *order* the candidates: a file called `ss` is
    asked about `ss` before anything else, and content still decides. That
    matters more than it sounds -- `netstat` is a legal name for both the Linux
    and the BSD format, and the two need different normalizers.
    """
    p = Path(path)
    if not p.is_file():
        return None
    try:
        with open(p, errors='replace') as f:
            text = f.read(_SNIFF_BYTES)
    except OSError:
        return None
    if not text.strip():
        return None

    base = p.name.lower()
    hinted = [r for r in REGISTRY if base in r.hints]
    rest = [r for r in REGISTRY if r not in hinted]
    for reader in hinted + rest:
        try:
            if reader.sniff(text):
                return reader
        except Exception:
            continue
    return None


def _assemble(inv: HostInventory, paths, label: str) -> HostInventory:
    """Identify each path, choose an inventory source, normalize.

    Shared by the directory and the explicit-file entry points so that both
    resolve a file the same way. `label` is what to call the collection in an
    error: a host directory name, or the dump's filename.
    """
    found = {}          # reader name -> path
    candidates = []     # (precedence, name, reader, path)

    for fp in paths:
        fp = Path(fp)
        if not fp.is_file() or fp.name.lower() in _CONTEXT_FILES:
            continue
        reader = identify(fp)
        if reader is None:
            inv.problems.append(
                f"{fp.name}: no reader recognized this file — if it is a "
                f"listener dump, firru inventoried this host without it")
            continue
        found.setdefault(reader.name, str(fp))
        if reader.kind == 'inventory':
            candidates.append((reader.precedence, reader.name, reader, str(fp)))

    inv.files = dict(found)
    if not candidates:
        inv.problems.append(
            f"{label}: no listener inventory found — this is not a host with "
            f"no services, it is a host nothing could be read from")
        return inv

    candidates.sort(key=lambda c: (c[0], c[1]))
    _, _, chosen, path = candidates[0]
    inv.os = chosen.os
    inv.sources = [c[1] for c in candidates]

    annotation = {}
    for ann_name in chosen.annotators:
        if ann_name in found:
            reader = next(r for r in REGISTRY if r.name == ann_name)
            try:
                annotation.update(reader.load(found[ann_name]))
            except Exception as e:
                inv.problems.append(f"{ann_name}: {e}")

    try:
        rows = chosen.parse(path)
    except Exception as e:
        inv.problems.append(f"{Path(path).name}: {e}")
        return inv

    inv.listeners = [r for r in (chosen.normalize(row, annotation) for row in rows)
                     if r]
    return inv


def read_host(data_dir, hostname=None) -> HostInventory:
    """Read every recognized file in one host directory into normalized records.

    When several inventory sources are present, the one with the lowest
    `precedence` is used and the others are listed in `sources` as read but not
    chosen. They are not merged: two sources disagree about process names on
    real hosts (`ss` says `wsdd` where Linux `netstat` says `python3`, because
    one reports `comm` and the other a truncated command line), and silently
    preferring whichever field happened to be non-empty would invent a host that
    neither source observed. Picking one and saying which is the answer that can
    be checked.
    """
    d = Path(data_dir)
    inv = HostInventory(hostname=hostname or d.name)
    if not d.is_dir():
        inv.problems.append(f"{d}: not a directory")
        return inv
    return _assemble(inv, sorted(d.iterdir()), d.name)


def read_files(*paths, hostname=None) -> HostInventory:
    """Same, for a collection whose files are named explicitly.

    Needed because a network namespace is not a directory: `loot-host.sh` writes
    `netns0-ss` beside the host's own dump and the two share one `psexe`, so the
    caller knows the grouping and the filesystem does not.
    """
    paths = [p for p in paths if p]
    inv = HostInventory(hostname=hostname or '')
    label = Path(paths[0]).name if paths else 'collection'
    return _assemble(inv, paths, label)
