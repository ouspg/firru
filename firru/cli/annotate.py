#!/usr/bin/env python3
"""
annotate — Resolve IP addresses to their most specific aerleon token.

Usage:
    annotate --defs def/ 10.1.2.3 10.1.2.4
    cat iplist.txt | annotate --defs def/
"""

import argparse
import sys

from firru.annotator import PolicyAnnotator


def main():
    parser = argparse.ArgumentParser(
        description="Resolve IPs to aerleon tokens.")
    parser.add_argument("--defs", "-d", default="def",
                        help="Aerleon definitions directory (default: def/)")
    parser.add_argument("ips", nargs="*",
                        help="IP addresses to resolve (or read from stdin)")
    args = parser.parse_args()

    ips = args.ips or [line.strip() for line in sys.stdin if line.strip()]
    if not ips:
        parser.print_help()
        sys.exit(1)

    ann = PolicyAnnotator(args.defs)

    for ip in ips:
        result = ann.annotate_ip(ip)
        host    = result.get("host")
        parents = result.get("parents", [])
        if host:
            token = host
            if parents:
                token += f"  ({', '.join(parents)})"
        elif parents:
            token = parents[0]
            if len(parents) > 1:
                token += f"  ({', '.join(parents[1:])})"
        else:
            token = "(unknown)"
        print(f"{ip:45s}  {token}")


if __name__ == "__main__":
    main()
