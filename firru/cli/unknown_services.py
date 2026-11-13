#!/usr/bin/env python3
"""
unknown-services — Audit unknown ports from Linux ss dumps against aerleon service defs.

Scans ss output files, filters against a known services YAML, and emits
an aerleon-formatted YAML stub for any unrecognised (proto, port) combinations.
Flags anomalies: TCP UNCONN, Docker bind-all risks, one-off ports.

Usage:
    unknown-services <path>

    path can be a single ss file, a host directory, or a hosts/ root directory.
"""

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter

from ruyaml import YAML
from ruyaml.comments import CommentedMap

from firru.ss import SsParseError, parse_ss_safe, get_process_name_pid
from firru.discovery import get_ss_file_list
from firru.tokens import is_loopback

# --- Configuration ---
# Point this to your existing Aerleon services definition directory
SERVICES_DEF_DIR = './def'
yaml_handler = YAML()
yaml_handler.indent(mapping=2, sequence=4, offset=2)
yaml_handler.preserve_quotes = True

# --- Helper Functions ---

def is_loopback(address_str):
    """
    Checks if an address is a loopback (127.0.0.1, ::1, etc.).
    Keeps 0.0.0.0 or :: as they represent network-exposed listeners.
    """
    clean_addr = address_str.strip("[]").split('%')[0]
    if clean_addr in ('*', '0.0.0.0', '::', '0.0.0.0:*', '[::]:*'):
        return False
    try:
        return is_loopback(clean_addr)
    except ValueError:
        return False


def load_known_services(defs_folder):
    """Load known (proto, port) -> token from an Aerleon definitions folder.

    Uses Aerleon's own Naming loader: the canonical parser that reads every
    file under def/ (networks and services), not just services.yml, and
    tolerates inputs a hand-rolled YAML scan trips on (e.g. duplicate keys
    from a missing '-' between list entries, where the last value wins).
    Note that such a malformed entry still loses the dropped value; fix the
    definition file to keep every protocol/port.
    """
    known = set()
    port_to_token = {}
    try:
        from aerleon.lib import naming
        defs = naming.Naming(defs_folder)
    except Exception as e:
        print(f"# Warning: could not load definitions from {defs_folder}: {e}")
        return known, port_to_token

    for token in defs.GetServiceNames():
        try:
            entries = defs.GetService(token)
        except Exception:
            continue
        for svc in entries:
            try:
                port_str, proto = svc.split('/')
                key = (proto.lower(), int(port_str))
            except (ValueError, AttributeError):
                continue  # port ranges or malformed entries: skip exact-match keying
            known.add(key)
            port_to_token.setdefault(key, token)
    return known, port_to_token

# --- Core Logic ---


def sanitize_ss_line(line):
    """
    Specifically targets the process name inside the users:(("...")) block.
    Only replaces spaces/colons within the quotes to prevent jc parsing errors.
    """
    def clean_proc_name(match):
        full_users_block = match.group(0)
        proc_name = match.group(1)
        sanitized_name = re.sub(r'[:\s]', '_', proc_name)
        return full_users_block.replace(f'"{proc_name}"', f'"{sanitized_name}"')

    return re.sub(r'users:\(\(\"([^\"]+)\"', clean_proc_name, line)

def build_new_services(ss_files, known_services=None):
    """
    Analysis Stage: Uses python-jc to parse contents and find 'funnies'.
    """
    registry = {}
    known_services = known_services or set()
    unreadable = []

    for host_name, file_path in ss_files:
        try:
            data = parse_ss_safe(file_path)
        except SsParseError as e:
            # An audit over many hosts should not die on one bad dump, but a
            # host whose sockets could not be read is not a host with no funny
            # ports. Skipping it loudly keeps it out of the "nothing to see
            # here" column, which is the only wrong place for it to land.
            print(f"audit-services: skipping {host_name}: {e}", file=sys.stderr)
            unreadable.append(host_name)
            continue

        for entry in data:
            proto = entry.get('netid', '').lower()
            state = entry.get('state', '').upper()
            l_addr = entry.get('local_address', '')

            # Skip loopback; we only want potential network listeners
            if is_loopback(l_addr) or proto not in ('tcp', 'udp', 'sctp'):
                continue

            # Check for standard LISTEN state OR the 'interesting' TCP UNCONN
            is_anomaly = (proto == 'tcp' and state == 'UNCONN')
            if proto == 'tcp' and state != 'LISTEN' and not is_anomaly:
                continue

            try:
                port = int(entry.get('local_port'))
            except (ValueError, TypeError):
                continue

            if port <= 0 or (proto, port) in known_services:
                continue

            proc, _ = get_process_name_pid(entry)
            key = (proto, port)

            if key not in registry:
                registry[key] = {'procs': Counter(), 'hosts': set(), 'anomaly': is_anomaly}

            registry[key]['procs'][proc] += 1
            registry[key]['hosts'].add(host_name)

    if unreadable:
        # Say it once at the end as well as per host: a run that skipped four
        # hosts and found no funny ports has not audited the estate, and the
        # per-host lines will have scrolled past by the time the table prints.
        print(f"audit-services: {len(unreadable)} host(s) had unreadable ss "
              f"output and were NOT audited: {', '.join(sorted(unreadable))}",
              file=sys.stderr)
    return registry

#: Services a host legitimately makes unsolicited *outbound* UDP requests to.
#: A socket whose every conversation is with one of these is the client side of
#: it, not a listener. Extend with --client-of; the list is a claim about normal
#: client behaviour, not about which ports are safe.
CLIENT_TARGET_PORTS = (53, 123, 67, 68, 5353)


def peer_ports_from_flows(flow_paths, wanted):
    """
    For each (proto, port) in ``wanted``, count the ports it was seen talking to.

    Matching is by port, not by host address: the registry keys are (proto, port)
    across the whole estate, so two hosts using the same high port are pooled.
    Coarse on purpose — this decides whether a port is worth a human's attention,
    and pooling can only make it keep more, never drop more.
    """
    peers = {}
    for path in flow_paths:
        try:
            with open(path) as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        flow = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    proto = (flow.get('protocol') or '').lower()
                    sp, dp = flow.get('src_port'), flow.get('dst_port')
                    if sp is None or dp is None:
                        continue
                    for local, peer in ((int(sp), int(dp)), (int(dp), int(sp))):
                        if (proto, local) in wanted:
                            peers.setdefault((proto, local), Counter())[peer] += 1
        except OSError as e:
            print(f"# Warning: could not read {path}: {e}", file=sys.stderr)
    return peers


def audit_against_flows(registry, peers, client_of, protocols=('udp',)):
    """
    Split a funny-port registry into (kept, resolved) using flow evidence.

    A port is *resolved* — dropped from the funnies — when it appears in the
    flow record and every conversation it had was with a client-target service.
    That is the DNS/NTP client socket: funny-looking local port, ordinary
    service at the other end, nothing to review.

    A port is *kept* when it talked to something that is not a client target,
    which is the case worth a human ("funny on both ends"), or when the flow
    record says nothing about it at all. Silence is not evidence: an unobserved
    port stays on the list.

    Only UDP by default. A TCP listener announces itself with LISTEN state, so
    it needs no inference, and inferring here could drop a real one that happened
    to also talk to a resolver.
    """
    kept, resolved = {}, {}
    for key, info in registry.items():
        proto, _ = key
        seen = peers.get(key)
        if proto not in protocols or not seen:
            kept[key] = info
            continue
        if all(p in client_of for p in seen):
            resolved[key] = (info, seen)
        else:
            kept[key] = info
    return kept, resolved


def generated_token(proto, port, procs):
    """The placeholder token name for a funny port. One definition, so the YAML
    stub and the sh commands cannot drift into naming the same port differently."""
    top_proc = procs.most_common(1)[0][0] if procs else "UNKNOWN"
    return f"{top_proc}_{proto.upper()}_{port}".replace('-', '_').replace('.', '_')


def emit_edit_sh(registry, def_file):
    """
    Emit the accept side of the audit as runnable commands, one per funny port,
    carrying the same token name and ports as the YAML stub.

    That name is a placeholder, and it is exactly the part a human is expected to
    overwrite: naming is the decision, so the line is a starting point to edit,
    not an answer to run blind. The evidence rides in the comment, so
    `| grep docker-proxy` or `| grep -v UNKNOWN` narrows the list first.
    """
    for (proto, port), info in sorted(registry.items()):
        token = generated_token(proto, port, info['procs'])
        procs = ",".join(sorted(info['procs'])) or "unattributed"
        print(f"firru edit-services add {def_file} {token} {port}/{proto}"
              f"  # {procs}, {len(info['hosts'])} host(s)")


def export_audit_yaml(registry, port_to_token=None):
    """
    Output Stage: Generates Aerleon-formatted YAML with audit comments.

    With port_to_token supplied (``--all``), already-known (proto, port)
    pairs reuse their existing service token instead of a generated one,
    so the output is the full observed service surface rather than only
    the unrecognised ports. Newly seen ports are flagged ``[NEW]``.
    """
    if not registry:
        print("# No services found.")
        return

    port_to_token = port_to_token or {}
    root = CommentedMap()
    root['services'] = CommentedMap()

    for (proto, port), info in sorted(registry.items(), key=lambda x: (x[0][0], x[0][1])):
        top_proc = info['procs'].most_common(1)[0][0] if info['procs'] else "UNKNOWN"
        known_token = port_to_token.get((proto, port))
        token = known_token or generated_token(proto, port, info['procs'])

        entry = {'port': port, 'protocol': proto}
        if token in root['services']:
            # Token spans multiple ports (e.g. a known multi-port service)
            root['services'][token].append(entry)
        else:
            root['services'][token] = [entry]

        # Build audit flags. [NEW] only distinguishes in --all mode (where
        # port_to_token is supplied); in default mode every entry is unknown.
        flags = []
        if port_to_token and known_token is None: flags.append("[NEW]")
        if info['anomaly']: flags.append("[AUDIT: TCP-UNCONN]")
        if "DOCKER" in top_proc: flags.append("[RISK: DOCKER-BIND-ALL]")
        if len(info['hosts']) == 1: flags.append("[!] ONE-OFF")

        comment = f"{' '.join(flags)} | Procs: {dict(info['procs'])} | Hosts: {sorted(list(info['hosts']))}"
        root['services'].yaml_add_eol_comment(comment, key=token)

    yaml_handler.dump(root, sys.stdout)


def emit_report(registry, port_to_token=None):
    """Print a compact human-readable table of all listeners."""
    if not registry:
        print("# No listeners found.")
        return

    port_to_token = port_to_token or {}

    known_rows   = []
    unknown_rows = []

    for (proto, port), info in sorted(registry.items(), key=lambda x: x[0][1]):
        hosts    = sorted(info['hosts'])
        n_hosts  = len(hosts)
        token    = port_to_token.get((proto, port), "")
        procs    = [(p, n) for p, n in info['procs'].most_common() if p != 'UNKNOWN']
        unknowns = info['procs'].get('UNKNOWN', 0)
        proc_str = "  ".join(f"{p}({n})" for p, n in procs)
        if unknowns and not procs:
            proc_str = f"UNKNOWN({unknowns})"
        elif unknowns:
            proc_str += f"  UNKNOWN({unknowns})"
        flags    = []
        if info['anomaly']:  flags.append("[TCP-UNCONN]")
        if n_hosts == 1:     flags.append("[ONE-OFF]")
        flag_str = "  " + " ".join(flags) if flags else ""
        host_str = " ".join(hosts)

        if token:
            label = f"{token:<30}  {proto}/{port:<6}  {n_hosts:>3} hosts  {proc_str}{flag_str}"
        else:
            label = f"{'':30}  {proto}/{port:<6}  {n_hosts:>3} hosts  {proc_str}{flag_str}"

        row = (label, host_str)
        if token:
            known_rows.append(row)
        else:
            unknown_rows.append(row)

    for label, host_str in known_rows:
        print(label)
        print(f"{'':30}    {host_str}")

    if unknown_rows:
        print("\n# Unknown services (not in definitions):")
        for label, host_str in unknown_rows:
            print(label)
            print(f"{'':30}    {host_str}")


def main():
    parser = argparse.ArgumentParser(description="Audit unknown ports from ss dumps against aerleon service defs.")
    parser.add_argument('path', help="File or directory to scan (e.g. hosts/ or hosts/h1/ss/dump)")
    parser.add_argument('--report', action='store_true',
                        help="Report all listeners across hosts (ignores known-services filter)")
    parser.add_argument('--all', dest='emit_all', action='store_true',
                        help="Emit YAML for ALL listeners (known + unknown); known ports "
                             "reuse their existing token, new ones are flagged. The full "
                             "observed service surface.")
    parser.add_argument('--flows', '-f', action='append', metavar='JSONL',
                        help="Flow record to audit the funnies against (repeatable). A UDP "
                             "port that only ever talked to a client-target service is the "
                             "client side of it and is dropped from the list.")
    parser.add_argument('-o', '--output', choices=['yaml', 'sh'], default='yaml',
                        help="Rendering: yaml stub to paste or redirect (default, "
                             "unchanged), or sh commands that add each funny port "
                             "to a def file")
    parser.add_argument('--def-file', default='def/funny.yml', metavar='PATH',
                        help="Def file the -o sh commands target (default: def/funny.yml)")
    parser.add_argument('--client-of', metavar='PORTS',
                        default=",".join(str(p) for p in CLIENT_TARGET_PORTS),
                        help="Comma-separated services a host legitimately queries outbound "
                             f"(default: {','.join(str(p) for p in CLIENT_TARGET_PORTS)})")
    args = parser.parse_args()

    try:
        client_of = {int(p) for p in args.client_of.split(",") if p.strip()}
    except ValueError:
        parser.error(f"--client-of wants comma-separated port numbers, got {args.client_of!r}")

    # 1. Discover the files
    files = get_ss_file_list(args.path)

    # 2. Load known services via Aerleon's canonical loader (whole def/ folder,
    #    networks + services), rather than scanning services.yml by hand.
    known, port_to_token = load_known_services(SERVICES_DEF_DIR)

    if args.report:
        registry = build_new_services(files, known_services=set())
        emit_report(registry, port_to_token)
        return

    if args.emit_all:
        # Full observed service surface: every listener, known ports tagged
        # with their existing token.
        registry = build_new_services(files, known_services=set())
        export_audit_yaml(registry, port_to_token)
        return

    # 3. Analyze for new 'funnies'
    new_reg = build_new_services(files, known)

    # 4. Audit them against traffic, if we have any: a funny UDP port whose every
    #    conversation was with a resolver or a time server is a client socket.
    if args.flows:
        peers = peer_ports_from_flows(args.flows, set(new_reg))
        new_reg, resolved = audit_against_flows(new_reg, peers, client_of)
        for (proto, port), (info, seen) in sorted(resolved.items()):
            targets = ",".join(str(p) for p in sorted(seen))
            procs = ",".join(sorted(info['procs'])) or "unattributed"
            print(f"# resolved {proto}/{port} ({procs}): client of {targets}",
                  file=sys.stderr)
        print(f"# {len(resolved)} funny port(s) resolved as client sockets, "
              f"{len(new_reg)} left to review", file=sys.stderr)

    # 5. Output results
    if args.output == 'sh':
        emit_edit_sh(new_reg, args.def_file)
    else:
        export_audit_yaml(new_reg)


if __name__ == '__main__':
    main()
