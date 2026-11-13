#!/usr/bin/env python3
"""
loot-listeners — Collect and normalize listening port data from Linux and Windows hosts.

Converts raw socket dumps (Linux 'ss', Windows PowerShell Get-NetTCPConnection/Get-NetUDPEndpoint)
into a structured JSON schema suitable for:
  - Git diffing (stable, sorted output)
  - Aerleon policy generation (listeners-to-aerleon)
  - Security review (flags: root-owned, world-listen, etc.)

Usage:
    # Process a directory of host data
    loot-listeners hosts/ --output output/

    # Process a single host directory
    loot-listeners hosts/web1.example.org/ --output output/

    # Process a single file (type inferred from filename)
    loot-listeners hosts/web1.example.org/connections.csv --output output/

    # Compact output (e.g. for piping)
    loot-listeners hosts/ --output output/ --compact

The input path is positional; --input/-i is still accepted.

Input directory layout:
    hosts/
      <hostname>/
        ss              (Linux: raw 'ss -tulnp' output)
        netstat         (Linux net-tools, or BSD/macOS 'netstat -an')
        psexe           (Linux: optional 'ps' output for exe path annotation)
        connections.csv (Windows: Get-NetTCPConnection + Get-NetUDPEndpoint CSV)
        services.csv    (Windows: Get-WmiObject Win32_Service CSV)

Those are the names loot-host.sh writes, and they are a hint rather than a
requirement: firru.readers decides what a file is from its content, so a
collection that named things differently -- PoSh-R2's ~38 CSVs, an appliance
with only 'netstat -anp' -- still inventories. A file no reader recognizes is
reported on stderr rather than skipped, because a host that inventoried as
empty because its dump was named unexpectedly looks exactly like a host with no
services.

Output schema (one JSON file per host):
    {
      "metadata": {
        "hostname":        "web1.example.org",
        "os":              "windows" | "linux" | "bsd",
        "collected_at":    null,          # filled if timestamp available
        "listenfile":      "path/to/raw",
        "annotationfile":  "path/to/ann"  # or null
      },
      "listen_ports": [
        {
          "protocol":     "tcp" | "udp" | "sctp",
          "port":         135,
          "bind_address": "0.0.0.0/0",   # CIDR; /0 = wildcard, /32 or /128 = specific
          "process": {
            "name":     "svchost",
            "cmdline":  "svchost.exe -k RPCSS -p",
            "exe":      "C:\\Windows\\System32\\svchost.exe",  # or /proc path on Linux
            "services": ["RpcEptMapper", "RpcSs"],             # Windows services on PID
            "user":     null,   # Linux: socket owner; Windows: null for now
            "pid":      1234
          },
          "flags": ["world-listen"]   # see FLAG DEFINITIONS below
        }
      ]
    }

FLAG DEFINITIONS:
    world-listen    bind_address is 0.0.0.0/0 or ::/0 (all interfaces)
    specific-ip     bound to a single non-loopback IP (good — intentional)
    root-owned      Linux: socket owned by root (pid uid=0)
    high-port       port >= 1024 (informational)
    well-known      port < 1024
    ipv6-only       bind_address is ::/0 with no corresponding IPv4 entry
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import sys

from firru.discovery import get_discovery_list
from firru.listeners import process_entries, windows_dual_stack
from firru.readers import read_files
from firru.ss import SsParseError

# Re-exported for callers that imported them from here before the record layer
# moved to firru.listeners and file recognition to firru.readers. Nothing in
# this module uses them; they are kept so the move is not an API break.
from firru.listeners import (address_to_cidr, compute_flags,  # noqa: F401
                             normalize_bsd_entry, normalize_linux_entry,
                             normalize_linux_netstat_entry,
                             normalize_windows_entry, parse_ip_port)
from firru.readers import read_psexe, read_services  # noqa: F401


# ---------------------------------------------------------------------------
# Netns hostname resolution
# ---------------------------------------------------------------------------



def _release(d):
    """The host's release as a baseline-name prefix ('ubuntu-24.04',
    'almalinux-9.8', 'win2022', 'win11') and where it came from: the
    os-release file loot-host writes (Linux: /etc/os-release; Windows: the OS
    caption), or else release.added, written beside loot from before
    loot-host collected os-release by someone who knows what was installed.
    (None, None) when neither is there."""
    try:
        with open(os.path.join(d, 'os-release'), errors='replace') as f:
            kv = dict(l.strip().split('=', 1) for l in f if '=' in l)
    except OSError:
        return _release_added(d)
    return _release_from(kv), 'os-release'


def _release_added(d):
    try:
        with open(os.path.join(d, 'release.added'), errors='replace') as f:
            lines = [l.split('#', 1)[0].strip() for l in f]
    except OSError:
        return None, None
    rel = next((l for l in lines if l), None)
    return (rel, 'release.added') if rel else (None, None)


def _release_from(kv):
    kv = {k: v.strip('"') for k, v in kv.items()}
    if 'ID' in kv:
        return f"{kv['ID']}-{kv.get('VERSION_ID', '')}".rstrip('-')
    m = re.search(r'Windows (Server (\d{4})|(\d+))', kv.get('NAME', ''))
    if m:
        return f"win{m.group(2) or m.group(3)}"
    return None

def _collected_at(d, listenfile):
    """When the sockets were read, and where that came from: collected-at,
    which loot-host writes as it runs, or else the listener file's mtime, which
    is right only as long as every copy kept it. (None, None) without either."""
    try:
        with open(os.path.join(d, 'collected-at'), errors='replace') as f:
            at = f.read().strip()
        if at:
            return at, 'collected-at'
    except OSError:
        pass
    try:
        import datetime
        mtime = os.path.getmtime(listenfile)
    except OSError:
        return None, None
    return datetime.datetime.fromtimestamp(mtime, datetime.timezone.utc).isoformat(), 'mtime'


def _ephemeral_ranges(d):
    """The host's own ephemeral port ranges, {'tcp': [lo, hi], 'udp': [lo, hi]},
    from the files loot-host writes next to its listener dump: dynamicport.txt
    (Windows, netsh int ipv4 show dynamicport) or ip_local_port_range (Linux).
    None when the loot predates them."""
    out = {}
    try:
        with open(os.path.join(d, 'dynamicport.txt'), errors='replace') as f:
            proto = start = None
            for line in f:
                m = re.search(r'Protocol (tcp|udp)', line, re.I)
                if m:
                    proto = m.group(1).lower()
                m = re.match(r'\s*Start Port\s*:\s*(\d+)', line)
                if m:
                    start = int(m.group(1))
                m = re.match(r'\s*Number of Ports\s*:\s*(\d+)', line)
                if m and proto and start is not None:
                    out[proto] = [start, start + int(m.group(1)) - 1]
    except OSError:
        pass
    try:
        with open(os.path.join(d, 'ip_local_port_range')) as f:
            lo, hi = (int(x) for x in f.read().split()[:2])
            out = {'tcp': [lo, hi], 'udp': [lo, hi]}
    except (OSError, ValueError):
        pass
    return out or None

def parse_ipaddr_cidrs(path):
    """
    Return non-loopback, non-link-local addresses **with their prefix length**,
    from `ip -j addr show` (preferred) or the text form.

    The mask is the whole point. It is collected in the same run as the sockets
    and was previously discarded, which is why an address reached NetBox as a
    bare /32 -- true of the address, silent about the subnet it sits in, and so
    no help at all with the zone question.
    """
    try:
        with open(path) as f:
            content = f.read()
    except OSError:
        return []

    out = []
    stripped = content.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            doc = json.loads(content)
        except json.JSONDecodeError:
            doc = None
        if doc is not None:
            for iface in doc if isinstance(doc, list) else [doc]:
                for info in iface.get("addr_info", []) or []:
                    local, length = info.get("local"), info.get("prefixlen")
                    if not local or length is None:
                        continue
                    _keep_cidr(out, local, length)
            return out

    # Text fallback: same regex as before, but the prefix length is captured
    # rather than matched and thrown away.
    for m in re.finditer(r'\binet6?\s+([0-9a-fA-F:.]+)/(\d+)', content):
        _keep_cidr(out, m.group(1), m.group(2))
    return out


def _keep_cidr(out, local, prefixlen):
    try:
        addr = ipaddress.ip_address(local)
        length = int(prefixlen)
    except (ValueError, TypeError):
        return
    if addr.is_loopback or addr.is_link_local:
        return
    if length < 0 or length > addr.max_prefixlen:
        return
    cidr = f"{addr}/{length}"
    if cidr not in out:
        out.append(cidr)


def _parse_ipaddr_file(path):
    """Return list of non-loopback, non-link-local IPs from 'ip addr show' output."""
    ips = []
    try:
        with open(path) as f:
            content = f.read()
    except OSError:
        return ips
    for m in re.finditer(r'\binet6?\s+([0-9a-f:.]+)/', content):
        try:
            addr = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if addr.is_loopback or addr.is_link_local:
            continue
        ips.append(str(addr))
    return ips


def resolve_netns_hostname(ipaddr_file, annotator):
    """
    Try to resolve a netns hostname from its IP addresses using the policy
    definitions.  Returns a lowercased token name (e.g. 'net_dmz_host1') on success,
    or None if no /32 or /128 host token is found.
    """
    if not ipaddr_file:
        return None
    ips = _parse_ipaddr_file(ipaddr_file)
    if not ips:
        return None
    for ip in ips:
        try:
            result = annotator.annotate_ip(ip)
        except Exception:
            continue
        if result.get('type') == 'HOST' and result.get('action') == 'OK':
            token = result.get('host', '')
            if token and token not in ('EXTERNAL', 'UNKNOWN', 'INVALID'):
                return token.lower()
    return None


# ---------------------------------------------------------------------------
# Per-host processing
# ---------------------------------------------------------------------------

def process_host(entry, loopback=False):
    """
    Process one host entry dict → (metadata dict, listen_ports list).

    The three-way branch on `entry['os']` that used to live here is gone.
    Dispatch happens in `firru.readers` now, which decides what a file is from
    its content, so `os` comes back as a *result* rather than going in as an
    assumption. That is what makes a BSD host reachable at all: `firru.discovery`
    only ever labelled a host `linux` or `windows`, so the netstat reader could
    not be entered no matter what the directory actually held.

    A discovered `os` is kept only as a fallback for the metadata, so a host
    nothing could be read from still records what it was taken to be.
    """
    listenfile  = entry['listenfile']
    annotfile   = entry.get('annotationfile')
    hostname    = entry['hostname']

    inv = read_files(listenfile, annotfile, *entry.get('otherfiles', []),
                     hostname=hostname)
    for problem in inv.problems:
        print(f"  [{hostname}] {problem}", file=sys.stderr)
    if not inv.sources:
        raise SsParseError(
            f"{listenfile}: nothing here could be read as a listener dump. "
            f"That is not a host with no services.")

    entries = windows_dual_stack(inv.listeners) if inv.os == 'windows' else inv.listeners
    listen_ports = process_entries(entries, loopback)

    metadata = {
        'hostname':       hostname,
        'os':             inv.os or entry.get('os'),
        'collected_at':   None,   # fill from file mtime or filename if available
        'listenfile':     listenfile,
        'annotationfile': annotfile,
    }

    # Addresses with their masks, when the collection captured them. Absent on
    # loot taken before loot-host.sh wrote ipaddr.json, and absent for any
    # acquisition path that never stood on the host (nmap sees addresses, never
    # masks), so consumers must treat an empty list as "not collected" rather
    # than "no addresses".
    if entry.get('ipaddrfile'):
        addresses = parse_ipaddr_cidrs(entry['ipaddrfile'])
        if addresses:
            metadata['addresses'] = addresses

    rel, source = _release(os.path.dirname(listenfile))
    if rel:
        metadata['release'] = rel
        if source != 'os-release':
            # said by a person afterwards, not read on the host
            metadata['release_source'] = source
    eph = _ephemeral_ranges(os.path.dirname(listenfile))
    if eph:
        metadata['ephemeral'] = eph


    if entry.get('netns_ipaddr'):
        metadata['parent_hostname'] = entry.get('parent_hostname')
        metadata['netns_addresses'] = _parse_ipaddr_file(entry['netns_ipaddr'])

    at, source = _collected_at(os.path.dirname(listenfile), listenfile)
    if at:
        metadata['collected_at'] = at
        if source != 'collected-at':
            # an estimate: loot from before loot-host wrote the time down
            metadata['collected_at_source'] = source

    return metadata, listen_ports


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _windows_findings(entry, metadata, listen_ports):
    """Host findings for Windows loot, from firewall.json next to the listeners."""
    if metadata.get('os') != 'windows':
        return []
    return []


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Normalize listening port data from Linux (ss) and Windows "
            "(PowerShell) hosts into a structured JSON schema for policy generation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Process all hosts under hosts/:
    %(prog)s hosts/ --output output/

  Process a single host directory:
    %(prog)s hosts/web1.example.org/ --output output/

  Compact output (e.g. for piping):
    %(prog)s hosts/ --output output/ --compact

  Print to stdout instead of files:
    %(prog)s hosts/web1.example.org/ --stdout

  Two snapshots, then compare them:
    %(prog)s fam-ssdata/ --output fam/
    %(prog)s exec-ssdata/ --output exec/
    loot-diff fam/ exec/
        """
    )
    parser.add_argument(
        'input_path', nargs='?', metavar='INPUT',
        help='Input path: directory of hosts, single host directory, or single file'
    )
    parser.add_argument(
        '--input', '-i', dest='input_opt', metavar='INPUT',
        help='Same as the positional INPUT (kept for older invocations)'
    )
    parser.add_argument(
        '--output', '-o', default='loot',
        help='Output directory for JSON files (default: loot/)'
    )
    parser.add_argument(
        '--stdout', action='store_true',
        help='Print JSON to stdout instead of writing files (useful for single host)'
    )
    parser.add_argument(
        '--compact', action='store_true',
        help='Compact JSON output (default: pretty-printed)'
    )
    parser.add_argument(
        '--flags-only', action='store_true',
        help='Only output ports that have at least one of the specified flags'
    )
    parser.add_argument(
        '--flag', action='append', dest='flags', metavar='FLAG',
        help='Filter to ports with this flag (repeatable). E.g. --flag world-listen --flag root-owned'
    )
    parser.add_argument(
        '--defs', default=None, metavar='DIR',
        help='Aerleon definitions directory. Used to resolve netns hostnames from IP addresses.'
    )
    args = parser.parse_args()

    target = args.input_path or args.input_opt
    if not target:
        parser.error('input path required (positional INPUT, or --input)')
    if args.input_path and args.input_opt and args.input_path != args.input_opt:
        parser.error(f'two input paths given: {args.input_path!r} and {args.input_opt!r}')

    indent = None if args.compact else 2

    # Build annotator once if --defs provided (used for netns hostname resolution)
    _annotator = None
    if args.defs:
        try:
            from firru.annotator import PolicyAnnotator
            _annotator = PolicyAnnotator(args.defs)
        except Exception as e:
            print(f"Warning: could not load definitions from {args.defs}: {e}",
                  file=sys.stderr)

    discovery = get_discovery_list(target)
    if not discovery:
        print(f"No host data found under: {target}", file=sys.stderr)
        sys.exit(1)

    if not args.stdout:
        os.makedirs(args.output, exist_ok=True)

    for entry in discovery:
        hostname = entry['hostname']

        # Attempt netns hostname resolution from IP definitions
        if entry.get('netns_ipaddr') and _annotator:
            resolved = resolve_netns_hostname(entry['netns_ipaddr'], _annotator)
            if resolved:
                entry = dict(entry)
                entry['hostname'] = resolved
                hostname = resolved
                print(f"  {entry['parent_hostname']}/{entry.get('netns_ipaddr','').split('/')[-1].replace('-ipaddr','')}"
                      f" → resolved as {hostname}", file=sys.stderr)

        try:
            metadata, listen_ports = process_host(entry)
        except Exception as e:
            print(f"Error processing {hostname}: {e}", file=sys.stderr)
            continue

        # Optional flag filter
        if args.flags:
            listen_ports = [
                p for p in listen_ports
                if any(f in p.get('flags', []) for f in args.flags)
            ]

        doc = {'metadata': metadata, 'listen_ports': listen_ports}
        findings = _windows_findings(entry, metadata, listen_ports)
        if findings:
            doc['findings'] = findings

        if args.stdout:
            print(json.dumps(doc, indent=indent))
        else:
            outpath = os.path.join(args.output, f"{hostname}.json")
            with open(outpath, 'w') as f:
                json.dump(doc, f, indent=indent)
            print(f"  {hostname}: {len(listen_ports)} ports → {outpath}")


if __name__ == '__main__':
    main()
