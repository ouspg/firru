"""
CIDR-set membership via longest-prefix trees (firru.prefixes).

Loads a set of IPv4/IPv6 CIDRs into two prefix trees and tests IP membership.
Used to tag flows against an arbitrary address set -- in practice the red-team
address list an exercise releases afterwards.

The file shape is whatever the exercise happened to publish: one releases a
mapping under `all_rt_ips`, the next one may not. `load_trees` therefore takes
a bare list, a mapping (under a named key, or under its only list-valued key),
or a plain text file with one CIDR per line, and adapting to a new one should
mean adding a shape here rather than a new loader.

Reading nothing is an error, never an empty set. An address list that failed to
parse would otherwise mark every flow as *not* red team, which is a claim about
the traffic rather than about the file.
"""

import ipaddress
import sys

from firru.prefixes import PrefixTree
import yaml


class AddressListError(Exception):
    """An address list was given, and no usable prefix came out of it."""


_SHAPES = ("a bare list, a mapping under `key`, a mapping with a single list "
           "value, or one CIDR per line")


def _entries(data, raw, key):
    """The CIDR list, from whichever shape the file turned out to have."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if key is not None:
            return data.get(key) or []
        lists = [v for v in data.values() if isinstance(v, list)]
        return lists[0] if len(lists) == 1 else []
    # A file of bare CIDRs folds into one YAML scalar (or fails to parse at
    # all), so go back to the text and read it line by line.
    return [ln.split("#", 1)[0] for ln in raw.splitlines()]


def load_trees(path: str, key: str = None) -> tuple:
    """Load CIDRs from `path` into (v4_tree, v6_tree).

    `key` picks one key out of a mapping; without it a mapping with exactly one
    list value is read as that list. Raises AddressListError if no prefix loads.
    """
    with open(path) as f:
        raw = f.read()
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        data = None

    pyt4 = PrefixTree(32)
    pyt6 = PrefixTree(128)
    rejected = []
    for entry in _entries(data, raw, key):
        text = str(entry).strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            rejected.append(text)
            continue
        tree = pyt6 if net.version == 6 else pyt4
        if not tree.has_key(str(net)):
            tree.insert(str(net), True)

    if not (len(pyt4) or len(pyt6)):
        raise AddressListError(
            f"{path}: no usable CIDR found. Expected {_SHAPES}."
            + (f" Rejected {len(rejected)} entr"
               f"{'y' if len(rejected) == 1 else 'ies'}, first: "
               f"{rejected[0]!r}." if rejected else ""))

    if rejected:
        print(f"  Warning: skipped {len(rejected)} unparseable "
              f"{'entry' if len(rejected) == 1 else 'entries'}, "
              f"first {rejected[0]!r}.", file=sys.stderr)
    print(f"Loaded {len(pyt4) + len(pyt6)} prefixes "
          f"({len(pyt4)} v4, {len(pyt6)} v6).", file=sys.stderr)
    return pyt4, pyt6


def ip_in_trees(ip_str, pyt4, pyt6) -> bool:
    """True if ip_str falls within any prefix in the matching tree."""
    if not ip_str:
        return False
    try:
        tree = pyt6 if ":" in ip_str else pyt4
        return bool(tree.get(ip_str))
    except Exception:
        return False
