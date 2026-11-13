#!/usr/bin/env python3
"""
dump-flows — Dump Arkime sessions to a .jsonl file for offline use.

Collects all flows visible in Arkime and writes them as newline-delimited JSON
(one normalised flow dict per line). The output can be fed to tighten via
--flows-file when Arkime is no longer accessible.

Usage:
    # Dump everything from the last 48 hours
    dump-flows --arkime http://localhost:8005/api --user admin --password x

    # Dump only flows involving known hosts (smaller file)
    dump-flows --arkime ... --defs def/ --hosts-only

    # Append to an existing file (e.g. run twice a day during exercise)
    dump-flows --arkime ... --output flows.jsonl --append
"""

import argparse
import json
import sys
from pathlib import Path

from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from firru.arkime import ArkimeAPI, ESClient, process_flow

ARKIME_FIELDS = [
    "source.ip", "destination.ip",
    "source.port", "destination.port",
    "protocol", "tcpflags.syn", "tcpflags.syn-ack", "tags",
]


def main():
    parser = argparse.ArgumentParser(
        description="Dump Arkime flows to .jsonl for offline tighten runs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  dump-flows --arkime http://localhost:8005/api --user admin --password x

  # Incremental: run daily, append to same file
  dump-flows --arkime ... --date 24 --output flows.jsonl --append
        """,
    )
    parser.add_argument("--arkime",    "-a", default=None,
                        help="Arkime viewer API base URL, e.g. http://localhost:8005/api")
    parser.add_argument("--user",      "-u", default="admin")
    parser.add_argument("--password",  "-P", default=None)
    parser.add_argument("--basic-auth", action="store_true",
                        help="Use HTTP basic auth instead of digest auth")
    parser.add_argument("--es", default=None,
                        help="Read SPI directly from Elasticsearch/OpenSearch "
                             "(e.g. http://localhost:9200) — scroll API, no viewer "
                             "rate limit. Use instead of --arkime for bulk dumps.")
    parser.add_argument("--es-index", default="arkime_sessions3-*",
                        help="Session index pattern (default: arkime_sessions3-*)")
    parser.add_argument("--es-user", default=None,
                        help="ES/OpenSearch user (omit for a no-security node)")
    parser.add_argument("--es-password", default=None)
    parser.add_argument("--es-insecure", action="store_true",
                        help="Do not verify TLS certificate (self-signed ES)")
    parser.add_argument("--date",       default="48",
                        help="Lookback window in hours, e.g. 48 (default: 48). "
                             "NOTE: wrong knob for imported pcap — its sessions keep "
                             "their original capture time. Use --start-time/--stop-time.")
    parser.add_argument("--start-time", default=None,
                        help="Range start: epoch seconds or ISO incl. offset, "
                             "e.g. 2026-04-20T06:00:00+03:00 (naive = UTC)")
    parser.add_argument("--stop-time",  default=None,
                        help="Range end (default: now); same formats as --start-time")
    parser.add_argument("--all", dest="all_time", action="store_true",
                        help="No time window — dump the whole index. Cleanest when "
                             "ES holds only the slice you imported.")
    parser.add_argument("--expression", "-e", default="",
                        help="Optional Arkime filter expression")
    parser.add_argument("--output",    "-o", default="flows.jsonl",
                        help="Output file (default: flows.jsonl)")
    parser.add_argument("--append",    action="store_true",
                        help="Append to existing output file instead of overwriting")
    args = parser.parse_args()

    if not args.arkime and not args.es:
        parser.error("one of --arkime (viewer API) or --es (direct SPI read) is required")
    if args.arkime and args.es:
        parser.error("use either --arkime or --es, not both")

    if args.es:
        if args.expression:
            print("Note: --expression is ignored with --es (ES reads the whole "
                  "time window; filter downstream).", file=sys.stderr)
        es_auth = (args.es_user, args.es_password) if args.es_user else None
        source = ESClient(args.es, index=args.es_index, auth=es_auth,
                          verify=not args.es_insecure)
        sessions = source.search(date="all" if args.all_time else args.date,
                                 start_time=args.start_time,
                                 stop_time=args.stop_time)
        if args.start_time:
            from firru.arkime import _to_epoch
            print(f"  window: {args.start_time} .. {args.stop_time or 'now'}  "
                  f"(epoch {_to_epoch(args.start_time)}..{_to_epoch(args.stop_time) if args.stop_time else 'now'}, "
                  f"overlap on firstPacket/lastPacket)", file=sys.stderr)
        backend = f"ES {args.es} [{args.es_index}]"
    else:
        password = args.password
        if password is None:
            import getpass
            password = getpass.getpass(f"Arkime password for {args.user}: ")
        auth = (HTTPBasicAuth if args.basic_auth else HTTPDigestAuth)(args.user, password)
        sessions = ArkimeAPI(args.arkime, auth).search(
            args.expression, fields=ARKIME_FIELDS,
            date="-1" if args.all_time else args.date,
            start_time=args.start_time, stop_time=args.stop_time)
        backend = f"Arkime viewer {args.arkime}"

    mode = "a" if args.append else "w"
    out_path = Path(args.output)

    print(f"Querying {backend} (date={args.date}) → {out_path} "
          f"({'append' if args.append else 'overwrite'}) …", file=sys.stderr)

    written = skipped = 0
    with open(out_path, mode) as f:
        for raw in sessions:
            flow = process_flow(raw)
            if flow is None:
                skipped += 1
                continue
            f.write(json.dumps(flow) + "\n")
            written += 1
            if written % 5000 == 0:
                print(f"  {written} flows written…", file=sys.stderr)

    print(f"Done: {written} flows written, {skipped} skipped.", file=sys.stderr)


if __name__ == "__main__":
    main()
