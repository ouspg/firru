"""propose -o sh: one host's proposal as firru commands, one edit per line,
each ending in its reason.

The verb is the class of change, and the reason is the trailing comment, so a
posture is a grep (`grep observed`, `grep -e observed -e unexercised`). A
line that must not run by accident is itself a comment, so `| sh` on the
whole output never widens a policy, never adds egress, and never touches what
the site declared or scored:

  remove-source   a narrowing to a subset of the tokens the term names
  set-source      a narrowing from ANY, or a group replaced by its members
  set-action      a listener nothing reached in the window, denied and logged
  # add-source    a widening that only adds peers          (widened REVIEW)
  # set-source    any other widening, [old] -> [new]       (widened REVIEW)
  # add-term      an egress term, from the proposal file   (egress proposed)

Ingress is compared term by term, by name: propose changes the peers of the
terms a policy has and nothing else, and two terms may cover one port (a
service token naming tcp and udp beside a tcp-only term), which a comparison
by port would fold into one.
"""

import ipaddress

from firru.cli.edit import _named_peers, _scored_term_names
from firru.policy import (ANY_PEERS, DIR_IN, DIR_OUT, diff_surface, filter_directions,
                          peer_families, source_peers, term_covers)


def _fmt(tokens):
    if not tokens:
        return "ANY"
    return tokens[0] if len(tokens) == 1 and tokens[0].startswith("ANY") else \
        "[" + ", ".join(tokens) + "]"


def _terms(doc, direction):
    out = {}
    for filt in doc.get("filters", []):
        if filter_directions(filt) == {direction}:
            for t in filt.get("terms", []):
                out.setdefault(t.get("name"), t)
    return out


def _nets(peers):
    nets = []
    for p in peers:
        try:
            nets.append(ipaddress.ip_network(str(p), strict=False))
        except ValueError:
            nets.append(str(p))       # an unresolvable token compares by name
    return nets


def _within(new, old):
    """Every network of `new` inside some network of `old`."""
    def inside(n, o):
        if isinstance(n, str) or isinstance(o, str):
            return n == o
        return n.version == o.version and n.subnet_of(o)
    return all(any(inside(n, o) for o in old) for n in new)


_FAMILY_ANY = {"ANY_V4": {4}, "ANY_V6": {6}}


def _families(defs, src):
    """The address families a source admits. ANY_V4 and ANY_V6 resolve to
    ANY for comparison (firru.policy), so their family is read off the token."""
    toks = [src] if isinstance(src, str) or src is None else list(src)
    fams = set()
    for t in toks:
        if t in _FAMILY_ANY:
            fams |= _FAMILY_ANY[t]
        elif t is None or str(t).upper() == "ANY":
            fams |= {4, 6}
        else:
            fams |= peer_families(source_peers(defs, t))
    return fams


def classify(defs, old_term, new_term):
    """'narrowed', 'widened' or None, by what the sources resolve to. Gaining
    an address family is a widening, whatever the peers."""
    old_src, new_src = old_term.get("source-address"), new_term.get("source-address")
    if _families(defs, new_src) - _families(defs, old_src):
        return "widened"
    old = source_peers(defs, old_src)
    new = source_peers(defs, new_src)
    if old == new:
        return None
    if new is ANY_PEERS or new == ANY_PEERS:
        return "widened"
    if old is ANY_PEERS or old == ANY_PEERS:
        return "narrowed"
    return "narrowed" if _within(_nets(new), _nets(old)) else "widened"


def _written(term):
    """The source tokens as the policy writes them (ANY_V4 stays ANY_V4)."""
    src = term.get("source-address")
    if src is None:
        return []
    return [src] if isinstance(src, str) else [str(t) for t in src]


def _source_line(pol, name, old, new, cls, shown=None):
    why = f"{_fmt(shown[0])} -> {_fmt(shown[1])}" if shown else f"{_fmt(old)} -> {_fmt(new)}"
    if cls == "narrowed":
        if old and set(new) <= set(old):
            gone = [t for t in old if t not in new]
            return f"firru remove-source {pol} {name} {' '.join(gone)}  # narrowed observed: {why}"
        return f"firru set-source {pol} {name} {' '.join(new) or 'ANY'}  # narrowed observed: {why}"
    if old and set(old) <= set(new):
        added = [t for t in new if t not in old]
        return f"# firru add-source {pol} {name} {' '.join(added)}  # widened REVIEW: {why}"
    return f"# firru set-source {pol} {name} {' '.join(new) or 'ANY'}  # widened REVIEW: {why}"


def _scored_by_site(defs, term, ports):
    """The first (protocol, port, note) of `ports` the term covers, or None."""
    for (proto, port), note in ports.items():
        if term_covers(defs, term, proto, port):
            return proto, port, note
    return None


def ingress_lines(pol, original, proposed, defs, unused, declared, scored_ports=None):
    """`scored_ports` is the site's {(protocol, port): note} for the host
    (src_heuristics.scored_ports): a term covering one is left as it is."""
    old_terms = _terms(original, DIR_IN)
    new_terms = _terms(proposed, DIR_IN)
    scored = _scored_term_names(list(old_terms.values()))
    by_site = {name: hit for name, t in old_terms.items()
               if (hit := _scored_by_site(defs, t, scored_ports or {}))}
    lines = []
    for name, old_term in old_terms.items():
        new_term = new_terms.get(name)
        if new_term is None or str(old_term.get("action", "accept")).lower() != "accept":
            continue
        cls = classify(defs, old_term, new_term)
        if cls and name in by_site:
            proto, port, note = by_site[name]
            lines.append(f"# {name}: {cls} in the proposal, kept: the site scores "
                         f"{proto}/{port} ({note})  # pinned")
        elif cls:
            lines.append(_source_line(pol, name, _named_peers(old_term, "source-address"),
                                      _named_peers(new_term, "source-address"), cls,
                                      (_written(old_term), _written(new_term))))
    for u in unused:
        name = u["name"]
        term = old_terms.get(name)
        if term is None or str(term.get("action", "accept")).lower() != "accept":
            continue
        pinned = [t for t in _named_peers(term, "source-address") if t in declared(u["svc"])]
        if name in by_site:
            proto, port, note = by_site[name]
            lines.append(f"# {name}: no flows in the window, kept: the site scores "
                         f"{proto}/{port} ({note})  # pinned")
        elif name in scored:
            lines.append(f"# {name}: no flows in the window, kept: scored  # pinned")
        elif pinned:
            lines.append(f"# {name}: no flows in the window, kept: the site declares "
                         f"{', '.join(pinned)}  # pinned")
        else:
            lines.append(f"firru set-action {pol} {name} deny --log  # denied unexercised: "
                         f"no flows in the window")
    return lines


def egress_lines(pol, proposal, defs_dir, original, proposed, defs):
    """Egress is rebuilt from the traffic, so it is diffed by port, and every
    line is a comment: acting on egress is opt-in."""
    result = diff_surface(original, proposed, defs, DIR_OUT)
    lines = []
    for cls in ("added", "narrowed", "widened", "cosmetic"):
        for term, _ in result[cls]:
            lines.append(f"# firru add-term {pol} {term.get('name')} --from {proposal} "
                         f"--direction out --defs {defs_dir}  # egress proposed ({cls})")
    for term, _ in result["removed"]:
        lines.append(f"# firru rm {pol} {term.get('name')}  # egress proposed (removed)")
    return lines


def emit_host(pol, proposal, defs_dir, original, proposed, defs, unused, declared, window,
              scored_ports=None):
    """Print the commands that take `original` (the policy at `pol`) to what
    `proposed` (written to `proposal`) says, for one host."""
    host = (original.get("metadata") or {}).get("host") or pol
    print(f"\n# {host}: {pol}")
    print(f"#   proposal: {proposal}")
    print(f"#   {window}")
    lines = (ingress_lines(pol, original, proposed, defs, unused, declared, scored_ports)
             + egress_lines(pol, proposal, defs_dir, original, proposed, defs))
    for line in lines:
        print(line)
    if not lines:
        print("#   no edits proposed")
