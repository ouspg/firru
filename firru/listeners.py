"""
firru.listeners — the unified listener record.

Every acquisition path ends here. `ss` on Linux, `netstat` on Linux, `netstat`
on BSD and macOS, and PowerShell CSV on Windows all describe the same thing in
four different vocabularies, and everything downstream -- policy synthesis,
service naming, the drift diff -- reads only the shape this module defines.

Moved out of `firru.cli.loot_listeners` so that `firru.readers` can produce
normalized records without a core module importing a CLI one.

One rule holds across all four normalizers: **a field this source cannot carry
is reported as absent, never filled in.** BSD netstat has no PID column at all,
so every listener from it is `UNKNOWN` and says so. That is the `unattributed`
class of docs/design.md, and `loot-diff` already treats a port attributed on one
side and UNKNOWN on the other as an annotation gap rather than a change.
Inventing a name to fill the field would turn a known gap into a false fact.
"""

import ipaddress
import re
import sys

from firru.netstat import _is_listener as _bsd_is_listener
from firru.ss import get_process_name_pid
from firru.tokens import is_loopback


_UNIT = re.compile(r'([^/]+\.(?:service|socket|scope))/?$')


def unit_from_cgroup(cgroup):
    """
    The systemd unit a cgroup path ends in, or ''.

    `0::/system.slice/cockpit.socket` -> `cockpit.socket`. A socket-activated
    listener belongs to PID 1, so its process is `systemd` and names nothing;
    the cgroup is the only place the owning unit appears.
    """
    m = _UNIT.search((cgroup or '').strip())
    return m.group(1) if m else ''


def parse_ip_port(addr: str):
    """Parse 'IP:port' or '[IPv6]:port' into (ip_str, port_str)."""
    addr = addr.strip()
    if addr.startswith('['):
        ip, port = addr[1:].split(']:', 1)
        return ip, port
    if ':' in addr:
        ip, port = addr.rsplit(':', 1)
        return ip, port
    return "ANY", addr


def address_to_cidr(la: str, loopback=False):
    """
    Convert a local_address string to a canonical CIDR string.
    Returns None if the address should be skipped (loopback, unless loopback
    is set: a stock-install record keeps them).
    Returns a list of CIDR strings (a wildcard may cover both IPv4 and IPv6).

    The three wildcard spellings are three different sockets, and `ss` already
    tells them apart. From `inet_addr_print` in iproute2's misc/ss.c:

        family == AF_INET                      -> "0.0.0.0"
        AF_INET6, in6addr_any, v6only unset    -> "*"
        AF_INET6, in6addr_any, v6only set      -> "[::]"

    So `*` is not an ambiguous address. It is a dual-stack IPv6 socket, which
    really does serve IPv4 as well, and is the *only* spelling that covers both.
    `0.0.0.0` is IPv4 and nothing else; `[::]` is IPv6 and nothing else, because
    that spelling is exactly the case where v6only is set.

    `0.0.0.0` used to be listed alongside `*` and expanded to both, which put a
    `::/0` accept rule under every IPv4-only service: 2,649 of them across 67 of
    168 real hosts, `mysqld` on 3306 among them. The `0.0.0.0` branch below was
    unreachable, which is what hid it. The symmetry also explains why no `[::]`
    listener in that data lacks an IPv4 sibling -- a dual-stack socket is spelt
    `*`, so it never needed one.

    `ANY` is the one genuinely unknown case: it comes from `parse_ip_port` when
    an address arrived with no port separator at all, so nothing is known about
    its family and both are kept.
    """
    if la in ("*", "ANY"):
        return ["0.0.0.0/0", "::/0"]
    if la == "0.0.0.0":
        return ["0.0.0.0/0"]
    if la == "::":
        return ["::/0"]

    try:
        ip = ipaddress.ip_address(la)
    except ValueError:
        return None

    if is_loopback(ip) and not loopback:
        return None  # skip loopback

    prefix = 128 if ip.version == 6 else 32
    return [f"{ip}/{prefix}"]


def windows_dual_stack(entries):
    """
    Windows reports a dual-mode socket once, on `::`. Read it as dual-stack.

    `Get-NetTCPConnection` and `Get-NetUDPEndpoint` (loot-host.ps1) list the
    kernel's own listeners -- SMB 445, http.sys 80, WinRM 47001, all owned by
    System -- only as `::`, yet they accept IPv4: a stock Server 2022 DC
    listed 445 on `::` alone and nmap over IPv4 found it open. Windows has no
    `*` spelling as `ss` does, so `::` there means "IPv6, and IPv4 too unless
    the socket set v6only", which the export does not say.

    Taken per host: a `::` entry with no IPv4 entry for the same protocol and
    port becomes `*`, which address_to_cidr expands to both families. Where the
    process also bound IPv4 itself (svchost's RPC, dns.exe), that entry exists
    and nothing changes. A genuinely v6only socket would gain an IPv4 allow it
    does not need: the safe direction to be wrong in, since the other one cuts
    IPv4 off a DC. netstat-shaped loot (PoSh-R2) prints both rows already.
    """
    v4 = set()
    for e in entries:
        if not e:
            continue
        la = e.get('local_address', '')
        try:
            if la == '0.0.0.0' or ipaddress.ip_address(la).version == 4:
                v4.add(((e.get('proto') or '').lower(), e.get('local_port')))
        except ValueError:
            pass
    out = []
    for e in entries:
        if e and e.get('local_address') == '::' and \
                ((e.get('proto') or '').lower(), e.get('local_port')) not in v4:
            e = dict(e, local_address='*')
        out.append(e)
    return out


def compute_flags(bind_address: str, user: str, port: int) -> list:
    """Derive security-relevant flags from a listen entry."""
    flags = []
    try:
        net = ipaddress.ip_network(bind_address, strict=False)
        if net.prefixlen == 0:
            flags.append("world-listen")
        else:
            flags.append("specific-ip")
    except ValueError:
        pass

    if user == "root" or user == "0":
        flags.append("root-owned")

    if port < 1024:
        flags.append("well-known")
    else:
        flags.append("high-port")

    return flags


def normalize_linux_entry(entry, annotation):
    """
    Normalize a single Linux 'ss' entry (parsed by jc) into unified schema dict.
    annotation: dict of pid -> {exepath, cgroup, netns} from psexe file.
    Returns None for entries that should be skipped.
    """
    if not entry:
        return None

    proto = entry.get('netid', '').lower()
    if proto not in ('tcp', 'udp', 'sctp', 'mptcp'):
        return None
    if proto in ('tcp', 'sctp', 'mptcp') and entry.get('state') not in ('LISTEN', 'UNCONN'):
        return None
    if proto == 'mptcp':
        # MPTCP listeners are covered by tcp rules; skip to avoid duplicate/unknown entries
        print(f"  [mptcp] {entry.get('local_address', '*')}:{entry.get('local_port', '?')}"
              f" ({get_process_name_pid(entry)[0]}) — skipped, covered by tcp",
              file=sys.stderr)
        return None

    # Address parsing — SCTP/MPTCP may use 'path' field
    if proto in ('sctp',) and entry.get('path'):
        la, port = parse_ip_port(entry.get('path'))
    else:
        la = entry.get('local_address', '').strip('[]')
        port = entry.get('local_port')

    try:
        port = int(port)
    except (TypeError, ValueError):
        return None

    # Process info
    pid = None
    process_name, pid = get_process_name_pid(entry)

    ann = annotation.get(pid, {}) if pid else {}

    info = {
        'name':     process_name,
        'cmdline':  ann.get('cmdline', ''),
        'exe':      ann.get('exepath', ''),
        'services': [],
        'user':     ann.get('user', None),
    }
    # jc puts the cgroup under `opts`; older jc leaves `opts` a string.
    opts = entry.get('opts') if isinstance(entry.get('opts'), dict) else {}
    unit = unit_from_cgroup(opts.get('cgroup') or entry.get('cgroup')
                            or ann.get('cgroup', ''))
    if unit:
        info['unit'] = unit
    return {
        'proto':         proto,
        'local_address': la,
        'local_port':    port,
        'pid':           pid,
        'process_info':  info,
    }


def normalize_linux_netstat_entry(entry, annotation):
    """
    Normalize one Linux `netstat -tulnp` row (parsed by jc) into the unified
    schema. Returns None for entries that should be skipped.

    This is not a worse `ss`; it is a *different observation*, and the two
    disagree on real hosts. `ss` reports `comm`, truncated by the kernel to 15
    characters. Linux netstat reports the first token of the command line,
    truncated by net-tools to 20 including arguments. On one ordinary laptop,
    three of the five PIDs visible to both came back differently:

        pid 8229    ss='code'    netstat='Code --standar'
        pid 57835   ss='wsdd'    netstat='python3'

    Neither is wrong. `wsdd` is the name the process chose for itself and is the
    more useful answer; `python3` is the more useful answer for an unnamed
    script. So `ss` wins the precedence in firru.readers because it also carries
    the cgroup and never truncates mid-name, but a host that has only this file
    is still fully inventoried, which is the whole point of reading it.

    Family is a fact here rather than an inference: net-tools writes `tcp6`, so
    jc hands back `network_protocol` directly.

    One thing this source cannot tell you, and `ss` can: net-tools writes
    `:::22` for every AF_INET6 wildcard whether or not v6only is set, so a
    dual-stack socket is indistinguishable from an IPv6-only one and is recorded
    as IPv6-only. `ss` spells the two apart (`*` against `[::]`, see
    `address_to_cidr`), which is one more reason it takes precedence. A host
    read through this source alone may therefore be missing an IPv4 rule for a
    service that does answer on IPv4.
    """
    if not entry or entry.get('kind') != 'network':
        return None
    proto = (entry.get('transport_protocol') or '').lower()
    if proto not in ('tcp', 'udp', 'sctp'):
        return None
    # UDP has no state column, so a bound UDP socket is identified the way it is
    # everywhere else in firru: no foreign address. TCP must say LISTEN.
    if proto in ('tcp', 'sctp'):
        if str(entry.get('state') or '').upper() != 'LISTEN':
            return None
    elif entry.get('foreign_address') not in ('0.0.0.0', '::', '*', None, ''):
        return None

    try:
        port = int(entry.get('local_port_num') or entry.get('local_port'))
    except (TypeError, ValueError):
        return None

    la = (entry.get('local_address') or '').strip('[]')
    if la in ('*', ''):
        la = '::' if (entry.get('network_protocol') or '').endswith('6') else '0.0.0.0'

    # `-` in the PID/Program name column means netstat could not see the owner,
    # which is what an unprivileged collection produces for other users'
    # sockets. That is a gap in the observation, reported as one.
    pid = entry.get('pid')
    pid = str(pid) if pid is not None else None
    name = entry.get('program_name') or 'UNKNOWN'

    ann = annotation.get(pid, {}) if pid else {}

    return {
        'proto':         proto,
        'local_address': la,
        'local_port':    port,
        'pid':           pid,
        'process_info': {
            'name':     name,
            'cmdline':  ann.get('cmdline', ''),
            'exe':      ann.get('exepath', ''),
            'services': [],
            'user':     ann.get('user', None),
        },
    }


def normalize_bsd_entry(entry, annotation=None):
    """
    Normalize one BSD/macOS `netstat -an` row (parsed by jc) into the unified
    schema. Returns None for entries that should be skipped.

    The process block is empty and says so. BSD netstat carries no PID and no
    command name — that is `sockstat` on FreeBSD and `lsof` on macOS, separate
    collections firru does not have here — so every listener from this source is
    UNKNOWN. That is the annotation gap `loot-diff` already reports apart from
    real changes, and inventing a name to fill the field would turn a known gap
    into a false attribution.

    The wildcard is translated to the Linux source's spelling (`0.0.0.0`, `::`)
    rather than left as BSD's `*`, because everything downstream tests the bind
    address for world-listen and a `*` would read as a specific address.

    `annotation` is accepted and ignored so that every normalizer has one
    signature; there is no annotation file this platform produces today. When an
    `lsof` annotator lands it will join on (proto, address, port) rather than on
    pid, because pid is the field this source does not have.
    """
    if not entry or not _bsd_is_listener(entry):
        return None
    proto = (entry.get("transport_protocol") or "").lower()
    if proto not in ("tcp", "udp", "sctp"):
        return None
    try:
        port = int(entry.get("local_port_num") or entry.get("local_port"))
    except (TypeError, ValueError):
        return None
    la = entry.get("local_address") or "*"
    if la in ("*", ""):
        la = "::" if (entry.get("network_protocol") or "").endswith("6") else "0.0.0.0"
    return {
        "proto":         proto,
        "local_address": la,
        "local_port":    port,
        "pid":           None,
        "process_info": {
            "name":     "UNKNOWN",
            "cmdline":  "",
            "exe":      "",
            "services": [],
            "user":     None,
        },
    }


def normalize_windows_entry(d, svc):
    """
    Normalize a Windows PowerShell CSV row into unified schema dict.
    svc: dict of pid -> {process, exepath, services, descriptions} from services.csv.
    Returns None for entries that should be skipped.
    """
    proto = d.get('Protocol', '').lower()
    state = str(d.get('State', '')).upper()

    # `Get-NetTCPConnection` says Listen; `netstat -ano`, which is what PoSh-R2
    # parses, says LISTENING. Both have to be accepted: dropping the second
    # once read every PoSh-R2 Windows host as UDP-only, with no error.
    if proto == 'tcp' and state not in ('LISTEN', 'LISTENING'):
        return None

    la = d.get('LocalAddress', '').strip('[]')
    try:
        port = int(d.get('LocalPort', 0))
    except (TypeError, ValueError):
        return None

    # OwningProcess from Get-Net*; ProcessID from PoSh-R2's netstat parse.
    pid = str(d.get('OwningProcess', '') or d.get('ProcessID', '')
              or d.get('PID', ''))
    info = svc.get(pid, {})

    def _given(key):
        v = d.get(key) or ''
        return '' if v == 'N/A' else v

    return {
        'proto':         proto,
        'local_address': la,
        'local_port':    port,
        'pid':           pid or None,
        'process_info': {
            'name':     _given('ProcessName') or info.get('process', 'UNKNOWN'),
            'cmdline':  _given('CommandLine'),
            'exe':      _given('ProcessPath') or info.get('exepath', ''),
            'services': info.get('services', []),
            'user':     None,
        }
    }


def process_entries(entries, loopback=False):
    """
    Convert a list of normalized entry dicts into the flat listen_ports schema.
    Deduplicates (proto, port, bind_address, process) tuples.
    Skips loopback addresses unless loopback is set.
    Returns sorted list of listen_port records.
    """
    seen = set()
    records = []

    for entry in entries:
        if not entry:
            continue

        proto = entry.get('proto', '').lower()
        port  = entry.get('local_port')
        la    = entry.get('local_address', '')
        pid   = entry.get('pid')
        pinfo = entry.get('process_info', {})

        if not proto or port is None:
            continue

        cidrs = address_to_cidr(la, loopback)
        if cidrs is None:
            continue  # loopback or invalid

        for cidr in cidrs:
            # Dedup key
            key = (proto, port, cidr,
                   pinfo.get('name', ''),
                   pinfo.get('exe', ''))
            if key in seen:
                continue
            seen.add(key)

            flags = compute_flags(cidr, pinfo.get('user'), port)

            process = {
                'name':     pinfo.get('name', 'UNKNOWN'),
                'cmdline':  pinfo.get('cmdline', ''),
                'exe':      pinfo.get('exe', ''),
                'services': pinfo.get('services', []),
                'user':     pinfo.get('user'),
                'pid':      pid,
            }
            # Only where the source carried a cgroup; absent is not "no unit".
            if pinfo.get('unit'):
                process['unit'] = pinfo['unit']
            records.append({
                'protocol':     proto,
                'port':         port,
                'bind_address': cidr,
                'process':      process,
                'flags': flags,
            })

    # Stable sort for clean git diffs
    records.sort(key=lambda r: (r['protocol'], r['port'], r['bind_address']))
    return records
