#!/usr/bin/env python3
"""
loot-flows — Dump Arkime sessions to a .jsonl file for offline use.

Collects the flows Arkime's viewer API returns and writes them as
newline-delimited JSON (one normalised flow dict per line). The output can be
fed to tighten via --flows-file when Arkime is no longer accessible.

Usage:
    # Dump everything from the last 48 hours; the password comes from
    # ~/.netrc ($NETRC; firru.credentials), or is asked for
    loot-flows --arkime http://localhost:8005/api

    # An imported pcap keeps its capture time: name the window, or take all
    loot-flows --arkime ... --start-time 2026-04-14T06:00:00Z --stop-time 2026-04-14T14:00:00Z
    loot-flows --arkime ... --all

    # Append to an existing file (e.g. run twice a day during exercise)
    loot-flows --arkime ... --output flows.jsonl --append

For a bulk record, convert the capture with Zeek instead (zeek-to-flows): the
viewer pages a window an hour at a time, about 170 sessions a second.
"""

import argparse
import json
import sys
from pathlib import Path

from firru.arkime import ArkimeAPI, SESSION_FIELDS, process_flow


def main():
    parser = argparse.ArgumentParser(
        description="Dump Arkime flows to .jsonl for offline tighten runs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  loot-flows --arkime http://localhost:8005/api

  # Incremental: run daily, append to same file
  loot-flows --arkime ... --date 24 --output flows.jsonl --append
        """,
    )
    parser.add_argument("--arkime",    "-a", default=None,
                        help="Arkime viewer API base URL, e.g. http://localhost:8005/api "
                             "(default: firru.toml's [arkime] url)")
    parser.add_argument("--user",      "-u", default=None,
                        help="default: the netrc entry's, else admin")
    parser.add_argument("--password",  "-P", default=None,
                        help="default: the netrc entry ($NETRC, firru.toml's [arkime] netrc, ~/.netrc), else asked for "
                             "(a command line is visible to others)")
    parser.add_argument("--basic-auth", action="store_true",
                        help="Use HTTP basic auth instead of digest auth")
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
                        help="No time window: from the first session Arkime holds "
                             "to the last")
    parser.add_argument("--expression", "-e", default="",
                        help="Optional Arkime filter expression")
    parser.add_argument("--output",    "-o", default="flows.jsonl",
                        help="Output file (default: flows.jsonl)")
    parser.add_argument("--append",    action="store_true",
                        help="Append to existing output file instead of overwriting")
    args = parser.parse_args()

    from firru.project import find, service_key
    project = find()
    if not args.arkime:
        args.arkime = service_key(project, "arkime", "url")
        if not args.arkime:
            parser.error("--arkime, or an [arkime] url in firru.toml, is required")
    from firru.credentials import http_auth
    try:
        auth = http_auth(args.arkime, args.user, args.password,
                         args.basic_auth or service_key(project, "arkime", "auth") == "basic",
                         netrc=service_key(project, "arkime", "netrc"))
    except ValueError as e:
        parser.error(str(e))
    sessions = ArkimeAPI(args.arkime, auth).search(
        args.expression, fields=SESSION_FIELDS,
        date="-1" if args.all_time else args.date,
        start_time=args.start_time, stop_time=args.stop_time)
    backend = f"Arkime viewer {args.arkime}"

    mode = "a" if args.append else "w"
    out_path = Path(args.output)

    window = ("all of it" if args.all_time else
              f"{args.start_time} to {args.stop_time or 'now'}" if args.start_time else
              f"last {args.date} h")
    print(f"Querying {backend} ({window}) → {out_path} "
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
