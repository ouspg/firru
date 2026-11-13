#!/usr/bin/env python3
"""
loot-conntrack — conntrack in, flows.jsonl out.

Emits one JSON line per observed flow in the shape the rest of the pipeline
reads (`flows_to_listeners`, `tighten`), the same record Zeek, Arkime and
LSPR24 produce: protocol, addresses, ports, originator, timing, per-direction
packet counts and `responded`.

    sudo loot-conntrack >> flows.jsonl          # snapshot, then watch
    sudo loot-conntrack --no-snapshot           # watch only, as this used to
    sudo loot-conntrack --events new,destroy    # final records too
    loot-conntrack hosts/web1/loot-host/conntrack   # text saved on the host

Live, it needs conntrack-tools and CAP_NET_ADMIN on the box it runs on. A host
that should not carry firru gets `scripts/loot-host.sh` instead, which saves
the table as text with nothing but the shell; this reads that file back. The
parsing is jc's (1.26.1 and later), the same split as `ss` and `netstat`.

TWO OBSERVATIONS, AND WHY BOTH. `conntrack -E` only sees flows created after it
attaches, so a half-hour capture is blind to everything long-lived -- the box's
established sessions are exactly what a listener inventory is about. So this
starts with `conntrack -L`, the table as it stands, and then streams events.
The two do not overlap: a flow in the table was created before the stream
attached and will never emit a NEW event.

`[NEW]` says a flow was attempted, and nothing about whether it was answered.
`[DESTROY]` carries the final counters and status, which is the better evidence
but only arrives when the flow ends, so it is opt-in via `--events`. Asking for
DESTROY does overlap the snapshot: a flow alive at startup that ends during the
run is reported twice, once from each side.

WHAT THE KERNEL HAS TO BE TOLD TO REPORT. Counters and flow timing are off by
default and the extensions attach when a flow is *created*, so enabling them
does nothing for flows that already exist:

    net.netfilter.nf_conntrack_acct=1        packets= and bytes=, per direction
    net.netfilter.nf_conntrack_timestamp=1   delta-time=, and [start=]/[stop=]

Without them the record still carries the tuple, and `orig_pkts`, `resp_pkts`
and the timestamps are null -- absent, not zero, because "no counter" and "no
packets" are different statements. `-o ktimestamp` asks for the kernel times
and `-o timestamp` for conntrack's own wall clock on events; both are dropped
automatically if the local conntrack does not know them, so no version or
sysctl is ever consulted.
"""

import argparse
import json
import subprocess
import sys

import jc


def parse(text):
    """
    conntrack text as jc's records: one per tuple line, in jc's schema.

    jc gained this parser in 1.26.1, and it is the tokenizer that used to live
    here. Lines that are not tuples -- the `N flow entries have been shown.`
    summary, an error message on a merged stream -- come back as nothing.
    """
    return jc.parse('conntrack', text, quiet=True)


def to_flow(entry):
    """
    One jc conntrack record as a flow record, or None when it carries no usable
    tuple.

    `responded` is the admitted/blocked signal the other sources emit, and it
    is null rather than False on a `[NEW]` event: a flow that has just been
    created has not been answered *yet*, which is not the same as a flow that
    went unanswered. Reporting the first as the second would turn every
    attempt into evidence of a block.
    """
    if not entry:
        return None

    src_ip, dst_ip = entry.get('orig_src'), entry.get('orig_dst')

    if not src_ip or not dst_ip:
        return None

    proto = entry['protocol'].lower()

    if proto in ('icmp', 'icmpv6'):
        # conntrack spells ICMP with type/code, and this keeps the historical
        # mapping the rest of firru already reads from this tool
        src_port, dst_port = entry.get('orig_type'), entry.get('orig_code')
    else:
        # jc sets ports only for the protocols that have them, so GRE and
        # friends come through with null ports rather than being dropped
        src_port, dst_port = entry.get('orig_sport'), entry.get('orig_dport')

    status = entry.get('status') or []
    resp_pkts = entry.get('reply_packets')

    if entry.get('event') == 'NEW':
        responded = None
    elif 'UNREPLIED' in status:
        responded = False
    elif resp_pkts is not None:
        responded = resp_pkts > 0
    else:
        responded = True

    timestamp = entry.get('start_epoch')
    if timestamp is None:
        timestamp = entry.get('event_timestamp')

    return {
        'protocol': proto,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'originator': src_ip,
        'timestamp': timestamp,
        'end_time': entry.get('stop_epoch'),
        'orig_pkts': entry.get('orig_packets'),
        'resp_pkts': resp_pkts,
        'orig_bytes': entry.get('orig_bytes'),
        'resp_bytes': entry.get('reply_bytes'),
        'responded': responded,
        'incomplete': 'UNREPLIED' in status,
        'source': 'conntrack',
        # The kernel tracked this flow from its first packet, so the original
        # direction is the initiator -- unless it adopted the flow midstream,
        # which net.netfilter.nf_conntrack_tcp_loose (1 by default) allows and
        # the text output does not mark. On a host watching its own sockets
        # that is rare; on a gateway it is the same guess Zeek has to make.
        'direction_known': True,
        # conntrack's own vocabulary, kept under its own name: this is the
        # current TCP state machine position, not Zeek's whole-connection
        # summary, and the two must not share a field.
        'ct_state': entry.get('state'),
        'conntrack_event': entry.get('event'),
    }


def _emit(text, stream):
    """Write each flow in `text` to `stream`; return how many there were."""
    count = 0
    for entry in parse(text):
        flow = to_flow(entry)
        if flow:
            print(json.dumps(flow), file=stream, flush=True)
            count += 1
    return count


def _with_fallback(cmd, options, **kwargs):
    """
    Run conntrack, dropping the `-o` options if this build rejects them.

    `-o ktimestamp` predates most installs but not all of them, and a build
    that does not know an option exits with a usage error rather than ignoring
    it. Retrying without is cheaper than asking which conntrack this is, and
    the fields simply arrive absent.
    """
    full = cmd + ['-o', options]
    try:
        return subprocess.Popen(full, **kwargs), full
    except FileNotFoundError:
        sys.exit('conntrack not found — install conntrack-tools')


def snapshot(stream=None):
    """
    Emit the conntrack table as it stands.

    Returns the number of flows, or None when the table could not be read.
    A host with nothing in conntrack is a fact and returns 0; a host whose
    table this could not read is a statement about the collection, and a
    caller that cannot tell them apart appends nothing to flows.jsonl and
    reports success.
    """
    # resolved here rather than in the signature: a default argument binds
    # sys.stdout at import time, which pins the stream a caller redirects later
    stream = stream or sys.stdout
    proc, cmd = _with_fallback(['conntrack', '-L'], 'ktimestamp',
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate()

    if proc.returncode != 0:
        proc = subprocess.run(['conntrack', '-L'], capture_output=True,
                              text=True)
        if proc.returncode != 0:
            print(f"loot-conntrack: {' '.join(cmd)} failed: "
                  f"{(err or proc.stderr).strip()}", file=sys.stderr)
            return None
        print("loot-conntrack: this conntrack has no -o ktimestamp, so flows "
              "carry no start time", file=sys.stderr)
        out = proc.stdout

    return _emit(out, stream)


def watch(events, stream=None):
    """Stream conntrack events until interrupted. Returns the flow count."""
    stream = stream or sys.stdout
    proc, cmd = _with_fallback(['conntrack', '-E', '-e', events],
                               'timestamp,ktimestamp',
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, bufsize=1)

    count = 0
    try:
        for line in proc.stdout:
            if 'Operation failed' in line or 'invalid option' in line:
                print(f"loot-conntrack: {line.strip()}", file=sys.stderr)
                break
            if _emit(line, stream):
                count += 1
                if count % 100 == 0:
                    print(f"  {count} flows emitted", file=sys.stderr)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
    return count


def main():
    ap = argparse.ArgumentParser(
        prog='loot-conntrack',
        description='conntrack in, flows.jsonl out')
    ap.add_argument('--no-snapshot', action='store_true',
                    help='skip the conntrack -L pass and only watch events')
    ap.add_argument('--events', default='NEW',
                    help='which events to watch: NEW, DESTROY, or both '
                         '(default NEW). DESTROY carries the final counters '
                         'but overlaps the snapshot for flows that end during '
                         'the run')
    ap.add_argument('--snapshot-only', action='store_true',
                    help='emit the table and exit, without watching')
    ap.add_argument('files', nargs='*', metavar='FILE',
                    help='saved `conntrack -L` or `-E` text to read instead of '
                         'running conntrack ("-" for stdin)')
    args = ap.parse_args()

    if args.files:
        total = 0
        for name in args.files:
            if name == '-':
                total += _emit(sys.stdin.read(), sys.stdout)
            else:
                with open(name, errors='replace') as f:
                    total += _emit(f.read(), sys.stdout)
        print(f"{total} flows emitted total.", file=sys.stderr)
        return 0

    total = 0

    if not args.no_snapshot:
        count = snapshot()

        if count is None:
            print("loot-conntrack: the conntrack table could not be read, "
                  "which is not the same as a host with no flows",
                  file=sys.stderr)
            return 1

        total += count
        print(f"loot-conntrack: {count} flows from the conntrack table",
              file=sys.stderr)

    if not args.snapshot_only:
        print(f"Watching {args.events} events (Ctrl-C to stop)…",
              file=sys.stderr)
        total += watch(args.events.upper())

    print(f"\n{total} flows emitted total.", file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
