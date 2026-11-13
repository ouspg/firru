"""
firru.nfteval — does the running nftables ruleset admit a new inbound
connection to a listener? An evaluator over `nft -j list ruleset`, for the
exposure check (firru audit).

nft-to-aerleon reads a ruleset into policy terms by chain, which is right for
a ruleset firru generated and loses the order of anything else: firewalld,
docker and hand-written rulesets route through jumps, and a flattened view
judges an INPUT packet by a FORWARD rule. This walks what the kernel walks:
every base chain on the input hook (any table, by priority), its rules in
order, into jumps and gotos and back on return, then the chain policy. A
packet must survive every input-hook chain.

The packet is a new connection from an unknown address on a non-loopback
interface, so the answer is per listener and per source class:

- a rule with no source condition decides for everyone;
- a rule that matches only some sources (address, interface, a match this
  parser cannot read) decides for those, and evaluation goes on for the rest:
  an accept there makes the listener 'scoped', a drop narrows it but does not
  close it;
- established/related accepts never admit a new connection, and rules on
  `lo` never see one.
"""

from firru.nftparse import named_sets, parse_rule

_TERMINAL = {"accept": "accept", "drop": "drop", "reject": "drop"}


def _verdict(rule):
    """('jump'|'goto'|'return'|'accept'|'drop'|None, target)"""
    for e in rule.get("expr") or ():
        for k in ("jump", "goto"):
            if k in e:
                return k, e[k].get("target")
        if "return" in e:
            return "return", None
        for k, v in _TERMINAL.items():
            if k in e:
                return v, None
    return None, None


def _ct_skips_new(rule):
    """A conntrack match a direct new connection does not satisfy: a ct state
    set without `new` (invalid, untracked), or ct status dnat (port-forwarded
    traffic, which is not a connection to this host's listener as addressed)."""
    for e in rule.get("expr") or ():
        m = e.get("match") if isinstance(e, dict) else None
        if not m or not isinstance(m.get("left"), dict) or "ct" not in m["left"]:
            continue
        if m["left"]["ct"].get("key") == "status":
            right = m.get("right")
            vals = right.get("set", right) if isinstance(right, dict) else right
            if "dnat" in (vals if isinstance(vals, list) else [vals]) and m.get("op", "==") in ("==", "in"):
                return True
            continue
        if m["left"]["ct"].get("key") != "state":
            continue
        right = m.get("right")
        states = right.get("set", right) if isinstance(right, dict) else right
        states = states if isinstance(states, list) else [states]
        has_new = "new" in states
        return (not has_new) if m.get("op", "==") in ("==", "in") else has_new
    return False


_L4 = {"tcp", "udp", "sctp", "dccp", "icmp", "icmpv6", "udplite"}


def _l4protos(rule):
    """Protocols the rule is restricted to, or None: a `meta l4proto` / `ip
    protocol` match, or any match on an L4 header field (`icmpv6 type` names
    icmpv6 as surely as `tcp dport` names tcp)."""
    for e in rule.get("expr") or ():
        m = e.get("match") if isinstance(e, dict) else None
        if not m:
            continue
        left = m.get("left")
        if isinstance(left, dict) and left.get("payload", {}).get("protocol") in _L4:
            return {left["payload"]["protocol"]}
    for e in rule.get("expr") or ():
        m = e.get("match") if isinstance(e, dict) else None
        if not m or m.get("op", "==") not in ("==", "in"):
            continue
        left = m.get("left")
        if isinstance(left, dict) and (left.get("meta", {}).get("key") == "l4proto"
                                       or left.get("payload", {}).get("field") in ("protocol", "nexthdr")):
            right = m.get("right")
            vals = right.get("set", right) if isinstance(right, dict) else right
            vals = vals if isinstance(vals, list) else [vals]
            return {str(v) for v in vals}
    return None


def _matches(rule, named):
    """parse_rule's match fields, for any rule (a jump has no verdict it knows)."""
    exprs = [e for e in rule.get("expr") or ()
             if not any(k in e for k in ("jump", "goto", "return"))]
    parsed, _ = parse_rule(dict(rule, expr=exprs + [{"accept": None}]), named)
    if parsed is not None:
        parsed["l4protos"] = _l4protos(rule)
    return parsed


def load(doc):
    """{(family, table, chain): (meta, [rules])} with rules in order."""
    chains, order = {}, []
    for obj in (doc or {}).get("nftables", []):
        if "chain" in obj:
            c = obj["chain"]
            chains[(c.get("family"), c.get("table"), c["name"])] = (c, [])
        elif "rule" in obj:
            r = obj["rule"]
            key = (r.get("family"), r.get("table"), r.get("chain"))
            chains.setdefault(key, ({"name": r.get("chain")}, []))[1].append(r)
    return chains


def _proto_ok(m, proto):
    if m["protocol"] and m["protocol"] != proto:
        return False
    l4 = m.get("l4protos")
    return l4 is None or proto in l4


def _port_ok(m, port):
    ports = m["destination-port"]
    return not ports or any(lo <= port <= hi for lo, hi in ports)


def _family_ok(family, v6):
    return family in ("inet", None) or (family == "ip6") == v6


def evaluate(doc, proto, port, v6=False):
    """
    (class, reasons) for a new connection to proto/port: 'open', 'scoped'
    (admitted from some sources only), 'blocked', or 'unknown' (no input hook
    in the ruleset). reasons name the deciding rules.
    """
    named = named_sets(doc)
    chains = load(doc)
    bases = sorted(((meta.get("prio", 0), key) for key, (meta, _) in chains.items()
                    if meta.get("hook") == "input" and meta.get("type", "filter") == "filter"
                    and _family_ok(key[0], v6)), key=lambda x: (x[0] if isinstance(x[0], int) else 0))
    if not bases:
        return "unknown", ["no input-hook chain"]

    reasons, scoped_by = [], []

    def walk(key, depth=0):
        """'accept' | 'drop' | None (fell off the end / returned)."""
        if depth > 32 or key not in chains:
            return None
        meta, rules = chains[key]
        for rule in rules:
            m = _matches(rule, named)
            verdict, target = _verdict(rule)
            if m is None or verdict is None or _ct_skips_new(rule):
                continue
            if m["established"] or not _proto_ok(m, proto) or not _port_ok(m, port):
                continue
            if m.get("source-interface") == "lo" or m.get("destination-interface") == "lo":
                continue
            partial = bool(m["source-address"] or m.get("source-interface")
                           or [i for i in m.get("ignored") or [] if "counter" not in i])
            if verdict in ("jump", "goto"):
                if partial:
                    # Only some packets go there; an accept inside is for them.
                    sub = walk((key[0], key[1], target), depth + 1)
                    if sub == "accept":
                        scoped_by.append(f"{key[2]} -> {target}")
                    if verdict == "goto":
                        continue
                    continue
                sub = walk((key[0], key[1], target), depth + 1)
                if sub is not None or verdict == "goto":
                    return sub
                continue
            if verdict == "return":
                if partial:
                    continue
                return None
            name = f"{key[2]}#{rule.get('handle', '?')}"
            if partial:
                if verdict == "accept":
                    scoped_by.append(name)
                continue
            reasons.append(name)
            return verdict
        if meta.get("hook"):
            pol = meta.get("policy", "accept")
            reasons.append(f"{key[2]} policy {pol}")
            return "drop" if pol == "drop" else "accept"
        return None

    for _, key in bases:
        if walk(key) == "drop":
            if scoped_by:
                return "scoped", list(dict.fromkeys(scoped_by))[:3]
            return "blocked", reasons[-1:]
    return "open", list(dict.fromkeys(reasons))[-2:]


def reachable_rules(doc):
    """(chain, rule, parsed match, verdict) for every rule reachable from an input hook."""
    named = named_sets(doc)
    chains = load(doc)
    seen, out = set(), []
    todo = [key for key, (meta, _) in chains.items() if meta.get("hook") == "input"]
    while todo:
        key = todo.pop()
        if key in seen or key not in chains:
            continue
        seen.add(key)
        for rule in chains[key][1]:
            verdict, target = _verdict(rule)
            if verdict in ("jump", "goto") and target:
                todo.append((key[0], key[1], target))
            m = _matches(rule, named)
            if m is not None and verdict is not None and not _ct_skips_new(rule):
                out.append((key[2], rule, m, verdict))
    return out


def stale_and_broad(doc, listeners):
    """Accept rules nothing listens behind, and accept-everything rules, on the input path."""
    have = {(l.get("protocol"), l.get("port")) for l in listeners}
    stale, broad = [], []
    for chain, rule, m, verdict in reachable_rules(doc):
        if verdict != "accept" or m["established"] or "lo" in (m.get("source-interface"),
                                                                m.get("destination-interface")):
            continue
        name = f"{chain}#{rule.get('handle', '?')}"
        protos = [m["protocol"]] if m["protocol"] else ["tcp", "udp"]
        if not m["destination-port"]:
            l4 = m.get("l4protos")
            if not m["source-address"] and not m.get("source-interface") and not m.get("ignored") \
                    and m["protocol"] in (None, "tcp", "udp") and (l4 is None or l4 & {"tcp", "udp"}):
                broad.append({"rule": name, "display": "", "peers": "Any",
                              "protocol": m["protocol"] or "any"})
            continue
        ports = [(lo, hi) for lo, hi in m["destination-port"]]
        if any((p, port) in have for p in protos for lo, hi in ports
               for port in ([lo] if lo == hi else range(lo, min(hi, lo + 4096) + 1))):
            continue
        stale.append({"rule": name, "display": "", "protocol": m["protocol"] or "any",
                      "ports": [str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ports],
                      "peers": ", ".join(map(str, m["source-address"])) or "Any",
                      "program": None, "service": None,
                      # nft names no program; below 1024 binding takes privilege.
                      "squattable": any(hi >= 1024 for _, hi in ports)})
    return stale, broad
