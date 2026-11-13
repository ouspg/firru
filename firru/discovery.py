"""
firru.discovery — Host data discovery for the policy pipeline.

Walks a directory tree and returns host entry dicts with paths to
listen files and annotation files for both Linux and Windows hosts.

Extra network namespaces (from loot-host.sh) are returned as additional
entries alongside the main host entry.  Each netnsN-ss file becomes its
own entry with hostname '<parent>-netnsN' (placeholder) plus a
'netns_ipaddr' field pointing to the corresponding netnsN-ipaddr file.
loot-listeners will attempt to resolve the real hostname from that file
if --defs is provided.
"""

import os
import re
from pathlib import Path

from firru.readers import REGISTRY, identify


# Matches netnsN-ss and netnsN-ipaddr filenames (case-insensitive)
_NETNS_RE = re.compile(r'^(netns\d+)-(ss|ipaddr|ipaddr\.json)$', re.IGNORECASE)


def get_discovery_list(target_path: str) -> list:
    """
    Walk target_path and return a list of host entry dicts:

        {
            'hostname':       str,
            'os':             'linux' | 'windows',
            'listenfile':     str,            # path to ss or connections.csv
            'annotationfile': str | None,     # path to psexe or services.csv
            'ipaddrfile':     str | None,     # path to ipaddr / ipaddr.json
            # extra fields present only for netns entries:
            'netns_ipaddr':     str | None,   # path to netnsN-ipaddr
            'parent_hostname':  str,          # hostname of the containing host dir
        }

    Recognised filenames:
        ss               Linux socket dump (ss -tulnp)
        psexe            Linux ps annotation
        connections.csv  Windows Get-NetTCPConnection/UDPEndpoint CSV
        services.csv     Windows Get-WmiObject Win32_Service CSV
        ipaddr           Host IP addresses (ip addr show)
        ipaddr.json      Host IP addresses (ip -j addr show) — preferred, it
                         is the form that carries the prefix length
        netnsN-ss        Extra netns socket dump (from loot-host.sh)
        netnsN-ipaddr    Extra netns IP addresses (ip addr show)
        netnsN-ipaddr.json  Same, machine-readable

    Also accepts a single file as target_path (type inferred from extension).
    """
    if os.path.isfile(target_path):
        parts = Path(target_path).parts
        hostname = parts[-2] if len(parts) >= 2 else 'manual_import'
        # Content, not the extension. A `.csv` that is not a connections export
        # used to be labelled windows and handed to the CSV normalizer anyway.
        reader = identify(target_path)
        return [{
            'hostname':       hostname,
            'os':             reader.os if reader else None,
            'listenfile':     target_path,
            'annotationfile': None,
            'otherfiles':     [],
        }]

    queue = []
    target = Path(target_path)

    # A single host given directly: a directory holding loot-host/ (a
    # firru-os-baselines run, a fetched host), or loot-host/ itself. Its
    # subdirectories are collection parts, not hosts; walking them named the
    # host "loot-host". Named after the directory above loot-host/, not the
    # loot's own hostname file, which on a fresh install is a random name.
    if (target / 'loot-host').is_dir():
        host_dirs = [(target, target.name)]
    elif target.name == 'loot-host':
        host_dirs = [(target, target.resolve().parent.name)]
    else:
        host_dirs = [(d, d.name) for d in sorted(target.iterdir())]

    for host_dir, hostname in host_dirs:
        if not host_dir.is_dir():
            continue

        # Prefer loot-host/ subdir (from loot-host.sh) or PoSh-R2_data/ (Windows);
        # fall back to host dir itself
        loot_dir = host_dir / 'loot-host'
        if loot_dir.is_dir():
            data_dir = loot_dir
        else:
            # Find any subdir containing connections.csv (case-insensitive)
            csv_subdir = next((
                d for d in sorted(host_dir.iterdir())
                if d.is_dir() and any(f.name.lower() == 'connections.csv' for f in d.iterdir() if f.is_file())
            ), None)
            data_dir = csv_subdir if csv_subdir else host_dir

        entry      = {'hostname': hostname}
        netns      = {}
        psexe_path = None
        inventory  = []     # (precedence, reader name, path)

        for fp in sorted(data_dir.iterdir()):
            if not fp.is_file():
                continue
            fl = fp.name.lower()

            # Namespaces first: `netns0-ss` is a socket dump, but it belongs
            # to a different host than the directory it sits in.
            m = _NETNS_RE.match(fl)
            if m:
                netns.setdefault(m.group(1).lower(), {})[m.group(2).lower()] = str(fp)
                continue

            if fl == 'ipaddr.json':
                entry['ipaddrfile'] = str(fp)      # preferred: carries the mask
                continue
            if fl == 'ipaddr':
                entry.setdefault('ipaddrfile', str(fp))
                continue

            # Everything else is classified by what is in it, not by what it is
            # called. The previous version matched filenames, so a host holding
            # only `netstat` was never queued at all -- and `os` was assigned
            # here from the filename, which is why the BSD reader could not be
            # reached by any collection.
            reader = identify(fp)
            if reader is None:
                continue
            if reader.kind == 'inventory':
                inventory.append((reader.precedence, reader.name, str(fp)))
                entry['os'] = reader.os
            elif reader.kind == 'annotation':
                # A directory can hold several files a sniffer accepts -- a
                # PoSh-R2 host carries both `Services.csv` and the much wider
                # `Services_Full.csv`. Prefer the one whose name the reader
                # actually expects, so the choice does not come down to which
                # sorted last.
                hinted = fl in reader.hints
                if hinted or 'annotationfile' not in entry:
                    entry['annotationfile'] = str(fp)
                    if reader.name == 'psexe':
                        psexe_path = str(fp)

        # Lowest precedence wins as the inventory; the rest are carried so the
        # reader can report them as read-but-not-chosen rather than silently
        # dropping a second dump the collection took.
        if inventory:
            inventory.sort(key=lambda c: (c[0], c[1]))
            entry['listenfile'] = inventory[0][2]
            entry['otherfiles'] = [c[2] for c in inventory[1:]]

        if entry.get('os') and entry.get('listenfile'):
            entry.setdefault('annotationfile', None)
            entry.setdefault('ipaddrfile', None)
            entry.setdefault('otherfiles', [])
            queue.append(entry)

            # Extra netns entries — share parent psexe for process annotation
            for key in sorted(netns):
                nf = netns[key]
                if 'ss' not in nf:
                    continue
                queue.append({
                    'hostname':        f"{hostname}-{key}",
                    'os':              'linux',
                    'listenfile':      nf['ss'],
                    'annotationfile':  psexe_path,
                    'ipaddrfile':      nf.get('ipaddr.json') or nf.get('ipaddr'),
                    'netns_ipaddr':    nf.get('ipaddr'),
                    'parent_hostname': hostname,
                })

    return queue


def get_ss_file_list(target_path: str) -> list:
    """
    Returns a list of (host_name, file_path) tuples for ss dump files.
    Accepts a single file, a host directory, or a root 'hosts/' folder.
    """
    file_list = []

    if os.path.isfile(target_path):
        parts = target_path.split(os.sep)
        host_name = parts[-3] if len(parts) >= 3 else 'manual_import'
        file_list.append((host_name, target_path))

    elif os.path.isdir(target_path):
        target = Path(target_path)
        for host_dir in sorted(target.iterdir()):
            if not host_dir.is_dir():
                continue
            hostname = host_dir.name
            loot_dir = host_dir / 'loot-host'
            data_dir = loot_dir if loot_dir.is_dir() else host_dir
            for fp in sorted(data_dir.iterdir()):
                if fp.is_file() and (fp.name == 'ss' or _NETNS_RE.match(fp.name.lower())):
                    file_list.append((hostname, str(fp)))

    return file_list
