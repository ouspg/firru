"""
Reading an nftables ruleset back into policy.

The counter reader treated a chain as a name with a number attached, which is
enough to say whether a term was deployed and never enough to say whether it
was deployed *as written*. A chain whose source set someone widened to 0.0.0.0/0
by hand still has the committed name, and the shallow read calls it fine.

`nft -j` gives the matches, not just the verdicts, so the deeper read is
available for the asking: source and destination addresses as prefixes, ranges
and sets, ports the same way, the protocol, the connection-state match and the
verdict. That is the whole of what a generated term contains, which means the
conversion runs backwards -- ruleset to aerleon policy -- and the comparison
against the committed policy becomes an ordinary `policy-diff` rather than a
bespoke one.

Two honest limits, both structural.

Addresses come back as numbers, and a policy is written in tokens. A set of
addresses that exactly equals a token's expansion can be named with confidence;
anything else cannot, and this module reports the leftover rather than reaching
for the nearest token. Naming is the decision the pipeline does not automate,
and inventing a token to make a round-trip look clean would be the worst place
to start.

And a ruleset is the compiled artifact. Terms that compiled to nothing leave no
trace to read back, comments are gone unless the generator emitted them, and
the ordering that a generator produced from term order is only recoverable as
order. The round trip is lossy in the direction that matters least for the
question being asked -- did the running rule still say what the policy said --
and lossy in ways that matter for regenerating the source, so it is not that.
"""

import ipaddress

#: nft verdict -> aerleon action.
ACTIONS = {"accept": "accept", "drop": "deny", "reject": "reject"}

#: Statements that make a rule address translation rather than a filter
#: decision. Docker, netavark and libvirt rulesets are mostly these. They are
#: not policy this tool represents, and they are not failures to parse either,
#: so they are counted apart from both.
NAT = ("masquerade", "snat", "dnat", "redirect")


def _addrs(right, named=None):
    """
    (addresses, unresolved) behind a match's right-hand side.

    `named` maps a declared set's name to its elements, so `ip saddr @web-hosts`
    resolves from the same ruleset that referenced it. A reference to a set the
    document does not declare -- one nft holds elsewhere, or an ipset -- comes
    back unresolved rather than raising, because one unreadable operand should
    cost a match, not a whole ruleset.
    """
    out, bad = [], []
    named = named or {}
    if isinstance(right, str):
        if right.startswith("@"):
            name = right[1:]
            if name in named:
                for item in named[name]:
                    o, b = _addrs(item, named)
                    out.extend(o)
                    bad.extend(b)
            else:
                bad.append(right)
        else:
            try:
                out.append(ipaddress.ip_network(right, strict=False))
            except ValueError:
                bad.append(right)
    elif isinstance(right, dict):
        if "prefix" in right:
            p = right["prefix"]
            try:
                out.append(ipaddress.ip_network(f"{p['addr']}/{p['len']}",
                                                strict=False))
            except ValueError:
                bad.append(str(p))
        elif "range" in right:
            lo, hi = right["range"]
            try:
                out.extend(ipaddress.summarize_address_range(
                    ipaddress.ip_address(lo), ipaddress.ip_address(hi)))
            except ValueError:
                bad.append(f"{lo}-{hi}")
        elif "set" in right:
            for item in right["set"]:
                o, b = _addrs(item, named)
                out.extend(o)
                bad.extend(b)
        else:
            bad.append(next(iter(right), "?"))
    elif isinstance(right, list):
        for item in right:
            o, b = _addrs(item, named)
            out.extend(o)
            bad.extend(b)
    else:
        bad.append(str(right))
    return out, bad


def _ports(right, named=None):
    """(ports as (lo, hi) inclusive, unresolved operands)."""
    out, bad = [], []
    named = named or {}
    if isinstance(right, int):
        out.append((right, right))
    elif isinstance(right, str):
        if right.startswith("@") and right[1:] in named:
            for item in named[right[1:]]:
                o, b = _ports(item, named)
                out.extend(o)
                bad.extend(b)
        else:
            try:
                out.append((int(right), int(right)))
            except ValueError:
                bad.append(right)
    elif isinstance(right, dict):
        if "range" in right:
            lo, hi = right["range"]
            try:
                out.append((int(lo), int(hi)))
            except (TypeError, ValueError):
                bad.append(f"{lo}-{hi}")
        elif "set" in right:
            for item in right["set"]:
                o, b = _ports(item, named)
                out.extend(o)
                bad.extend(b)
        else:
            bad.append(next(iter(right), "?"))
    elif isinstance(right, list):
        for item in right:
            o, b = _ports(item, named)
            out.extend(o)
            bad.extend(b)
    return out, bad


#: Match kinds that narrow a rule and that this parser does not represent.
#: Ignoring one makes the emitted term *wider* than the rule it came from, so
#: they are counted and named rather than skipped quietly.
def _describe(expr):
    """A short name for a match this parser did not use."""
    if "match" in expr:
        left = expr["match"].get("left")
        if isinstance(left, dict):
            for key in ("payload", "meta", "ct"):
                if key in left:
                    inner = left[key]
                    field = inner.get("field") or inner.get("key") or key
                    return f"{key}.{field}"
            # A bitwise or arithmetic operand wraps the thing being matched;
            # naming the operator alone tells a reader nothing useful.
            for op in ("&", "|", "^", ">>", "<<"):
                if op in left and isinstance(left[op], list) and left[op]:
                    return f"{_describe({'match': {'left': left[op][0]}})} (masked)"
            return next(iter(left), "match")
        return "match"
    return next(iter(expr), "expr")


def parse_rule(rule, named=None):
    """
    One nft rule -> (match dict, ignored) — or (None, ignored) with no verdict.

    Deliberately tolerant. A ruleset from a host nobody generated -- a Calico
    node, a hand-written firewall, an appliance -- carries matches this parser
    has no representation for, and refusing the whole rule because of one of
    them converts nothing. Ignoring them converts almost everything, which is
    worth far more, provided the reader is told what was ignored and which way
    the error runs: a dropped *narrowing* match makes the emitted term wider
    than the rule, so `ignored` travels with the match rather than being
    swallowed.
    """
    ignored = []
    r = {"source-address": [], "destination-address": [],
         "source-port": [], "destination-port": [],
         "source-interface": None, "destination-interface": None,
         "protocol": None, "established": False, "logging": False,
         "action": None, "packets": None, "bytes": None, "family": None}
    for e in rule.get("expr") or ():
        if "match" in e:
            m = e["match"]
            left, right = m.get("left"), m.get("right")
            if isinstance(left, dict) and "payload" in left:
                pay = left["payload"]
                proto, field = pay.get("protocol"), pay.get("field")
                if field in ("saddr", "daddr"):
                    key = "source-address" if field == "saddr" else "destination-address"
                    got, bad = _addrs(right, named)
                    r[key].extend(got)
                    ignored.extend(f"{field}={b}" for b in bad)
                    r["family"] = proto
                elif field in ("sport", "dport"):
                    key = "source-port" if field == "sport" else "destination-port"
                    got, bad = _ports(right, named)
                    r[key].extend(got)
                    ignored.extend(f"{field}={b}" for b in bad)
                    r["protocol"] = r["protocol"] or proto
                elif field in ("protocol", "nexthdr"):
                    # `ip protocol icmp` / `ip6 nexthdr icmpv6`: the layer-4
                    # protocol named on the network header rather than by meta.
                    if isinstance(right, str):
                        r["protocol"] = r["protocol"] or right
                    else:
                        ignored.append(_describe(e))
                else:
                    ignored.append(_describe(e))
            elif isinstance(left, dict) and "meta" in left:
                key = left["meta"].get("key")
                if key == "l4proto":
                    r["protocol"] = right if isinstance(right, str) else r["protocol"]
                elif key in ("iifname", "oifname", "iif", "oif"):
                    # The interface is not decoration on a container host: it is
                    # what the policy is written in terms of. Ignoring it makes
                    # every docker and libvirt term read as fleet-wide.
                    # Negation has no representation here, so `iifname !=
                    # docker0` stays ignored rather than being inverted into
                    # something that looks equivalent and is not.
                    field = ("source-interface" if key.startswith("i")
                             else "destination-interface")
                    if m.get("op", "==") == "==" and isinstance(right, str):
                        r[field] = right
                    else:
                        ignored.append(_describe(e) + (" (negated)"
                                                       if m.get("op") == "!=" else ""))
                else:
                    ignored.append(_describe(e))
            elif isinstance(left, dict) and "ct" in left:
                if left["ct"].get("key") == "state":
                    states = right if isinstance(right, list) else [right]
                    if any(s in ("established", "related") for s in states):
                        r["established"] = True
                else:
                    ignored.append(_describe(e))
            else:
                ignored.append(_describe(e))
        elif "counter" in e:
            r["packets"] = int(e["counter"].get("packets", 0))
            r["bytes"] = int(e["counter"].get("bytes", 0))
        elif "log" in e:
            r["logging"] = True
        elif any(v in e for v in ACTIONS):
            for v, action in ACTIONS.items():
                if v in e:
                    r["action"] = action
        elif not any(k in e for k in ("jump", "goto", "return")):
            ignored.append(_describe(e))
    r["ignored"] = sorted(set(ignored))
    return (r if r["action"] else None), r["ignored"]


def merge_rules(rules):
    """
    The rules of one chain -> one term.

    Aerleon emits a rule per address family for a single term, so the term is
    the union of its rules. A chain whose rules disagree on protocol or action
    was not generated from one term and is returned as several.
    """
    groups = {}
    for r in rules:
        key = (r["protocol"], r["action"], r["established"], r["logging"],
               r["source-interface"], r["destination-interface"])
        g = groups.setdefault(key, {"source-address": [], "destination-address": [],
                                    "source-port": [], "destination-port": [],
                                    "protocol": r["protocol"], "action": r["action"],
                                    "established": r["established"],
                                    "logging": r["logging"],
                                    "source-interface": r["source-interface"],
                                    "destination-interface": r["destination-interface"],
                                    "packets": 0, "counted": False,
                                    "ignored": set()})
        for k in ("source-address", "destination-address",
                  "source-port", "destination-port"):
            g[k].extend(r[k])
        g["ignored"].update(r.get("ignored") or ())
        if r["packets"] is not None:
            g["counted"] = True
            g["packets"] += r["packets"]
    for g in groups.values():
        for k in ("source-address", "destination-address"):
            g[k] = _collapse(g[k])
        for k in ("source-port", "destination-port"):
            g[k] = sorted(set(g[k]))
        g["ignored"] = sorted(g["ignored"])
    return list(groups.values())


def _collapse(nets):
    """Collapse per family: the two are one term but not one address space."""
    out = []
    for version in (4, 6):
        same = [n for n in nets if n.version == version]
        if same:
            out.extend(ipaddress.collapse_addresses(same))
    return out


_INDEX_CACHE = {}


def token_index(defs):
    """[(size, token, expansion)] for every network token, largest first.

    Built by expanding the definitions rather than by asking which token owns
    an address. `GetNetParents` answers for an address exactly as written, and
    the addresses coming back from a ruleset are collapsed prefixes that no
    definition contains verbatim: a token holding five /32s is invisible to a
    lookup on the /31 the kernel reported. Expanding once and comparing sets
    avoids the whole question.
    """
    key = id(defs)
    if key in _INDEX_CACHE:
        return _INDEX_CACHE[key]
    index = []
    for tok in getattr(defs, "networks", {}) or {}:
        try:
            exp = set(_collapse([ipaddress.ip_network(str(a), strict=False)
                                 for a in defs.GetNetAddr(tok)]))
        except Exception:
            continue
        if exp:
            index.append((sum(n.num_addresses for n in exp), tok, exp))
    index.sort(key=lambda t: (-t[0], t[1]))
    _INDEX_CACHE[key] = index
    return index


def resolve_tokens(nets, defs):
    """
    (tokens, leftover) for a set of networks, naming only an exact cover.

    Greedy, largest token first, taking a token only when every address it
    names is present. A token that would widen the rule is never taken: that is
    the direction in which a wrong guess opens a firewall. Whatever is left
    over is returned as addresses and stays a human's decision, because minting
    a token to make the round trip look clean is naming by convenience.
    """
    if not nets or defs is None:
        return [], list(nets)
    remaining = set(_collapse(list(nets)))
    taken = []
    for _, tok, exp in token_index(defs):
        if exp <= remaining:
            taken.append(tok)
            remaining -= exp
            if not remaining:
                break
    return sorted(taken), sorted(remaining, key=str)


def named_sets(doc):
    """{set name: elements} declared in the same ruleset.

    A rule that matches `@web-hosts` is not opaque: the set it names is usually
    right there in the document, and reading it turns a reference this parser
    would have to ignore into the addresses it stands for.
    """
    out = {}
    for obj in (doc or {}).get("nftables", []):
        if "set" in obj and isinstance(obj["set"], dict):
            st = obj["set"]
            if "name" in st:
                out[st["name"]] = st.get("elem") or []
    return out


def is_nat(rule):
    """Whether a rule translates addresses rather than deciding a packet."""
    return any(any(k in e for k in NAT) for e in rule.get("expr") or ())


def _is_dispatch(rule):
    """Whether a rule routes rather than decides.

    A conditional jump (`ip daddr 10.88.0.0/16 jump NETAVARK_ISOLATION_2`) still
    routes: the decision is in the chain it enters, which is read on its own.
    Counting it as an unparsed rule understates coverage on exactly the
    rulesets -- docker, netavark -- that are built out of them.
    """
    exprs = rule.get("expr") or ()
    if not exprs:
        return False
    if any(any(v in e for v in ACTIONS) for e in exprs):
        return False
    return any(any(k in e for k in ("jump", "goto", "return")) for e in exprs)


def chains_with_rules(doc):
    """
    ({chain: (meta, [rules])}, {chain: [ignored...]}, {chain: nat rule count}).

    The second half is the rules that carried no verdict this parser knows --
    a jump into a chain it will read separately, a NAT or mark rule, anything
    an appliance put there. They are returned rather than counted internally so
    a caller can say how much of the ruleset it actually understood.
    """
    chains, rules, skipped, nat = {}, {}, {}, {}
    named = named_sets(doc)
    for obj in (doc or {}).get("nftables", []):
        if "chain" in obj:
            c = obj["chain"]
            chains[c["name"]] = {"family": c.get("family"), "table": c.get("table"),
                                 "base": "hook" in c, "policy": c.get("policy"),
                                 "hook": c.get("hook")}
            rules.setdefault(c["name"], [])
        elif "rule" in obj:
            parsed, ignored = parse_rule(obj["rule"], named)
            if parsed:
                rules.setdefault(obj["rule"]["chain"], []).append(parsed)
            elif is_nat(obj["rule"]):
                nat.setdefault(obj["rule"]["chain"], 0)
                nat[obj["rule"]["chain"]] += 1
            elif not _is_dispatch(obj["rule"]):
                # A rule that only jumps somewhere is the generator's structure,
                # not a policy statement, and counting it as unparsed would put
                # the coverage figure well below what was actually understood.
                skipped.setdefault(obj["rule"]["chain"], []).append(ignored)
    return ({n: (meta, rules.get(n, [])) for n, meta in chains.items()},
            skipped, nat)
