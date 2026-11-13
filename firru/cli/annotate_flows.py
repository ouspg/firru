#!/usr/bin/env python3
"""
annotate-flows — Annotate flows.jsonl with aerleon token names.

Reads flows from a .jsonl file (or stdin) and adds src_token / dst_token
fields by resolving IPs against aerleon network definitions.

Usage:
    annotate-flows --defs def/ --input flows.jsonl > annotated.jsonl
    cat flows.jsonl | annotate-flows --defs def/
    annotate-flows --defs def/ --input flows.jsonl --output annotated.jsonl
"""

import argparse
import json
import sys

from firru.annotator import PolicyAnnotator


def annotate_flow(flow: dict, annotator: PolicyAnnotator) -> dict:
    src   = annotator.annotate_ip(flow.get("src_ip"))
    dst   = annotator.annotate_ip(flow.get("dst_ip"))
    proto = flow.get("protocol", "")
    return {
        **flow,
        "src_token":   src["host"],
        "src_groups":  src.get("parents") or [],
        "dst_token":   dst["host"],
        "dst_groups":  dst.get("parents") or [],
        "dst_service": annotator.annotate_port(flow.get("dst_port"), proto),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Annotate flows.jsonl with aerleon token names."
    )
    parser.add_argument("--defs",   "-d", required=True,
                        help="Aerleon definitions directory")
    parser.add_argument("--input",  "-i", default="-",
                        help="Input .jsonl file (default: stdin)")
    parser.add_argument("--output", "-o", default="-",
                        help="Output .jsonl file (default: stdout)")
    args = parser.parse_args()

    print("Loading defs…", file=sys.stderr)
    annotator = PolicyAnnotator(args.defs)

    fin  = open(args.input)  if args.input  != "-" else sys.stdin
    fout = open(args.output, "w") if args.output != "-" else sys.stdout

    n = 0
    try:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            flow = json.loads(line)
            fout.write(json.dumps(annotate_flow(flow, annotator)) + "\n")
            n += 1
    finally:
        if fin  is not sys.stdin:  fin.close()
        if fout is not sys.stdout: fout.close()

    print(f"Annotated {n} flows.", file=sys.stderr)


if __name__ == "__main__":
    main()
