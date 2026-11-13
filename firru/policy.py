"""
firru.policy — resolve a policy term's port surface against aerleon defs.

The comment contract matches records keyed by a raw ``(proto, port)`` — scoring
entries, diff deltas — against policy terms whose ``destination-port`` is
usually a service *token* (SSH, WINDOWS-DC-BASE). Expanding that token through
the defs is what makes the match robust to renames and group collapsing: a
scored port folded into a group token still resolves to the same surface
(docs/comment-contract.md, "Term identity").
"""

from functools import lru_cache


def _parse_entry(entry):
    """aerleon service entry '443/tcp' or '49152-65535/tcp' → (proto, lo, hi)."""
    port_part, proto = entry.rsplit("/", 1)
    proto = proto.lower()
    if "-" in port_part:
        lo, hi = port_part.split("-", 1)
        return proto, int(lo), int(hi)
    p = int(port_part)
    return proto, p, p


def port_ranges(defs, destination_port, protocol=None):
    """
    Coverage of a term's ``destination-port`` as a set of ``(proto, lo, hi)``
    ranges.

    ``destination_port`` may be a service token, an int/str port, a 'lo-hi'
    string, or a list of any of these. ``protocol`` is the term's protocol,
    used as the fallback proto for bare numeric ports (tokens carry their own).
    Unknown tokens and port-less terms (loopback, icmp) yield an empty set.
    """
    if destination_port is None:
        return set()
    if isinstance(destination_port, (list, tuple)):
        out = set()
        for item in destination_port:
            out |= port_ranges(defs, item, protocol)
        return out

    val = destination_port
    # Service token: a non-numeric string. Resolve through the defs.
    if isinstance(val, str) and not val[:1].isdigit():
        try:
            entries = defs.GetService(val)
        except Exception:
            return set()
        return {_parse_entry(e) for e in entries}

    # Bare numeric port or 'lo-hi' range — needs the term's protocol.
    proto = (protocol or "").lower() or None
    if proto is None:
        return set()
    s = str(val)
    try:
        if "-" in s:
            lo, hi = s.split("-", 1)
            return {(proto, int(lo), int(hi))}
        p = int(s)
    except ValueError:
        return set()
    return {(proto, p, p)}


def term_covers(defs, term, proto, port):
    """True if ``term`` (a mapping with destination-port/protocol) admits the
    given ``(proto, port)`` — including when the port is inside a group token."""
    proto = proto.lower()
    ranges = port_ranges(defs, term.get("destination-port"), term.get("protocol"))
    return any(rp == proto and lo <= port <= hi for rp, lo, hi in ranges)


# ---------------------------------------------------------------------------
# Port-surface diff — classify what changed between two generated policies.
# Identity is the resolved (direction, proto, port) surface, never the term
# name, so a rename or a group-collapse is a cosmetic change rather than a
# spurious add+remove (docs/comment-contract.md, "Term identity").
# ---------------------------------------------------------------------------

_ANY_SRC = {None, "ANY", "ANY_V4", "ANY_V6"}


def normalize_source(src):
    """Canonical source-address for comparison: ANY wildcards collapse to
    'ANY'; a token list becomes a sorted tuple."""
    if isinstance(src, (list, tuple)):
        toks = tuple(sorted(src))
        return "ANY" if any(t in _ANY_SRC for t in toks) else toks
    return "ANY" if src in _ANY_SRC else src


#: Sentinel peer-set: every address, i.e. an unrestricted source.
ANY_PEERS = "ANY_PEERS"


@lru_cache(maxsize=None)
def _resolve_token(defs, tok):
    """One network token expanded to its address strings (frozenset), cached
    per (defs, token). Token expansion through aerleon naming re-parses every
    address in the group, and a diff resolves the same handful of tokens
    (MGMT_HOSTS, the big NET_* groups) once per term across thousands of terms —
    so the reusable unit, the token, is memoized. An unresolvable token falls
    back to its own name so it still compares consistently with itself.

    Keyed on the defs object's identity: cached_naming hands out one Naming per
    defs dir, so the cache is warm for the process and shared across a mass
    batch. A distinct defs object is a distinct cache key."""
    try:
        nets = defs.GetNetAddr(tok)
    except Exception:
        nets = None
    if nets:
        return frozenset(str(n) for n in nets)
    return frozenset((str(tok),))


def source_peers(defs, src):
    """
    A term's source-address as a resolved peer-set: a frozenset of address
    strings, or ``ANY_PEERS`` when unrestricted.

    Resolving through the defs — rather than comparing token names — is what
    lets a rename or a regroup compare equal, the same reason term identity is
    the port surface and not the term name (docs/comment-contract.md). A token
    the defs cannot resolve falls back to its own name, so an unresolvable
    source still compares consistently with itself.
    """
    norm = normalize_source(src)
    if norm == "ANY":
        return ANY_PEERS
    toks = list(norm) if isinstance(norm, tuple) else [norm]
    peers = set()
    for tok in toks:
        peers.update(_resolve_token(defs, tok))
    return frozenset(peers)


def peer_families(peers):
    """Which address families a peer-set spans: a subset of {4, 6}."""
    if peers is ANY_PEERS or peers == ANY_PEERS:
        return {4, 6}
    fams = set()
    for p in peers:
        fams.add(6 if ":" in str(p) else 4)
    return fams


def compare_peers(old_peers, new_peers):
    """
    Classify a peer-set change as 'narrowed', 'widened', or None (equal).

    Widened means *anything* was granted that was not granted before, so an
    exchange of one peer for another is widened, not narrowed: it admits
    somebody new, and admitting somebody new is never a mechanical decision.
    """
    if old_peers == new_peers:
        return None
    if new_peers is ANY_PEERS or new_peers == ANY_PEERS:
        return "widened"
    if old_peers is ANY_PEERS or old_peers == ANY_PEERS:
        return "narrowed"
    return "widened" if (new_peers - old_peers) else "narrowed"


#: How each generator spells the two directions in a filter's target options.
#: aerleon's nftables writes "mixed input DROP" / "mixed output"; its
#: windows_advfirewall writes a bare "in" / "out". Matching the substring
#: "output" therefore saw every nftables egress filter and no windows one, so a
#: windows policy's outbound half was read as inbound by everything that asks.
#: Matched as whole words, since "out" is a substring of too much to test that
#: way (a "routed" or "timeout" option would read as egress).
#:
#: These six words cover every generator that states a direction in the header:
#: nftables, iptables, speedway and ipset (input/output), juniper, gce, k8s and
#: gcp_hf (ingress/egress), windows_advfirewall, packetfilter and proxmox
#: (in/out).

#: The two sides of a policy. Direction is part of surface identity because the
#: same (proto, port) names two unrelated relations: tcp/443 inbound is a
#: service this host offers, tcp/443 outbound is one it consumes. Keyed on the
#: port alone, a merged ingress+egress policy collapses the two into one entry
#: and the diff compares a term against its opposite number.
DIR_IN = "in"
DIR_OUT = "out"

_DIR_WORDS = {
    "in": DIR_IN, "input": DIR_IN, "ingress": DIR_IN,
    "out": DIR_OUT, "output": DIR_OUT, "egress": DIR_OUT,
}

#: FORWARD is a direction, but not one of *this* host's two halves: it governs
#: traffic the host routes, which owns no local socket. Named so a forward
#: filter reads as "not our surface" rather than as "direction unstated".
_TRANSIT_WORDS = frozenset(("forward",))

#: Generators whose header may legally omit the direction, and what they then
#: enforce. pf is the case that matters: `pass quick ...` with no `in`/`out`
#: matches both ways, so one filter genuinely is both halves. No entry is
#: needed for windows_advfirewall, which refuses any filter name but in/out.
_GENERATOR_DEFAULT = {
    "packetfilter": frozenset((DIR_IN, DIR_OUT)),
}


def _targets(filt):
    return (filt.get("header") or {}).get("targets") or {}


def _words(value):
    return set(str(value).lower().replace(",", " ").split())


def _target_words(filt):
    for v in _targets(filt).values():
        yield from _words(v)


def target_names(filt):
    """The generators a filter targets, for reporting one we could not read."""
    return sorted(str(g) for g in _targets(filt))


def filter_directions(filt):
    """Which sides of the host's own surface this filter enforces, as a subset
    of {DIR_IN, DIR_OUT}.

    The empty set means the document does not say, and there are three ways to
    land there: the direction is carried by a zone pair (paloaltofw,
    junipersrx, fortigate), it is bound to an interface outside the policy file
    (cisco, ciscoasa, arista, aruba, openconfig, sonic, nokiasrl), or the filter
    is transit. None of the three is recoverable from the document, so a caller
    must handle the empty set rather than fall back to one side. Falling back
    is exactly what read every windows policy as ingress.
    """
    dirs = set()
    for gen, value in _targets(filt).items():
        words = _words(value)
        named = {_DIR_WORDS[w] for w in words if w in _DIR_WORDS}
        if named:
            dirs |= named
        elif not (words & _TRANSIT_WORDS):
            dirs |= _GENERATOR_DEFAULT.get(str(gen).lower(), frozenset())
    return frozenset(dirs)


def is_output_filter(filt):
    """True if this filter enforces the host's outbound half."""
    return DIR_OUT in filter_directions(filt)


def is_input_filter(filt):
    """True if this filter enforces the host's inbound half.

    Not the negation of is_output_filter: a pf filter that names no direction
    is both halves, and a cisco ACL is neither.
    """
    return DIR_IN in filter_directions(filt)


def is_transit_filter(filt):
    """True for a FORWARD filter: a direction, but not one of the host's own."""
    return (not filter_directions(filt)
            and any(w in _TRANSIT_WORDS for w in _target_words(filt)))


def filter_direction(filt):
    """The one side this filter enforces, or None when the document does not
    pin it to one -- unstated, transit, or both at once.

    Prefer ``filter_directions`` when walking a policy: it keeps a
    bidirectional filter in both halves instead of dropping it from each.
    """
    dirs = filter_directions(filt)
    return next(iter(dirs)) if len(dirs) == 1 else None


def peer_field(direction):
    """The term key holding the peer set on this side: who may reach us
    inbound, whom we may reach outbound."""
    return "destination-address" if direction == DIR_OUT else "source-address"


def term_peers(defs, term, direction):
    """A term's peer-set, read from whichever field its direction uses.

    Reading ``source-address`` on an egress term finds nothing and resolves to
    ANY_PEERS, which reads as an unrestricted rule whatever the term actually
    says — so the field must follow the direction, not the other way round.
    """
    return source_peers(defs, term.get(peer_field(direction)))


def is_accept_term(term):
    """True unless the term's action denies (deny/drop/reject)."""
    return str(term.get("action", "accept")).lower() not in ("deny", "drop", "reject")


def is_catch_all(term):
    """A term matching everything: no protocol, no port, no peer restriction.

    Terminal whatever its action: after it, nothing else in the filter runs.
    """
    return not any(term.get(k) for k in
                   ("protocol", "destination-port", "source-port",
                    "source-address", "destination-address"))


def terms_surface(defs, terms, direction):
    """The surface of a bare term list, plus the two shapes a port surface
    cannot hold: ``(surface, blanket_protos, has_catch_all)``.

    - ``surface`` maps ``(direction, proto, port)`` to the covering accept term.
    - ``blanket_protos``: protocols accepted with no port at all (allow-icmp).
    - ``has_catch_all``: an unrestricted accept ends the filter open.

    This is what any flow-vs-terms check should match against; matching a
    term's ``destination-port`` *token* against a flow's service name breaks
    the moment a group token covers the port under a different name.
    """
    surface = {}
    blanket = set()
    catch_all = False
    for term in terms:
        if not is_accept_term(term):
            continue
        if is_catch_all(term):
            catch_all = True
            continue
        proto = term.get("protocol")
        if proto and not term.get("destination-port"):
            for pr in (proto if isinstance(proto, list) else [proto]):
                blanket.add(pr)
            continue
        for proto, lo, hi in port_ranges(defs, term.get("destination-port"), proto):
            for port in range(lo, hi + 1):
                surface[(direction, proto, port)] = term
    return surface, blanket, catch_all


def iter_accept_terms(doc, direction=None):
    """Yield ``(direction, term)`` for every accept (non deny/drop/reject) term,
    optionally restricted to one side of the policy.

    A filter enforcing both sides yields each of its terms twice, once per
    side, because a bidirectional rule really does open both. A filter whose
    direction the document never states yields nothing: there is no side to
    file its ports under, and inventing one is the bug this module exists to
    keep out.
    """
    for filt in (doc or {}).get("filters", []):
        dirs = filter_directions(filt)
        if direction is not None:
            dirs = dirs & {direction}
        for d in sorted(dirs):
            for term in filt.get("terms", []):
                if str(term.get("action", "accept")).lower() not in ("deny", "drop", "reject"):
                    yield d, term


def port_surface(doc, defs, direction=None):
    """Map every resolvable ``(direction, proto, port)`` an accept term admits
    to that term object. Later terms win on overlap, matching first-match policy
    order only loosely — adequate for diffing, where we care which ports exist.

    ``direction`` restricts the surface to one side. A generator that speaks
    only one side produces a document with only that filter, and an unrestricted
    diff reads the absent side as wholly removed — which, with ``--prune``,
    deletes it.
    """
    surface = {}
    for d, term in iter_accept_terms(doc, direction):
        for proto, lo, hi in port_ranges(defs, term.get("destination-port"), term.get("protocol")):
            for port in range(lo, hi + 1):
                surface[(d, proto, port)] = term
    return surface


def term_ports(defs, term):
    """The full set of (proto, port) a single term admits. Direction-free: the
    caller knows which filter the term came from, and prefixes it."""
    out = set()
    for proto, lo, hi in port_ranges(defs, term.get("destination-port"), term.get("protocol")):
        out |= {(proto, p) for p in range(lo, hi + 1)}
    return out


def term_surface_keys(defs, term, direction):
    """``term_ports`` lifted into surface keys for one side of the policy."""
    return {(direction, proto, port) for proto, port in term_ports(defs, term)}


def _group_by_term(ports, surface):
    """Bucket a set of surface keys by their covering term; return
    [(term, sorted_ports)] so a report shows one line per term, not per port."""
    groups = {}
    for pp in ports:
        term = surface[pp]
        groups.setdefault(id(term), (term, []))[1].append(pp)
    return sorted(
        ((term, sorted(ps)) for term, ps in groups.values()),
        key=lambda tp: tp[0].get("name") or "",
    )


def diff_surface(old_doc, new_doc, defs, direction=None):
    """
    Classify the change from ``old_doc`` to ``new_doc`` at the port surface.

    Ingress and egress are diffed separately: a policy carrying both sides has
    two terms at tcp/443 that have nothing to do with each other, and each is
    compared against its own side's peer field. ``direction`` narrows the whole
    comparison to one side, for a generator that proposes only that side.

    Returns a dict with one entry per class, each a list of ``(term, ports)``,
    where each port is a ``(direction, proto, port)`` surface key:
      added    — ports present only in new (grouped by the new covering term)
      removed  — ports present only in old (grouped by the old term)
      narrowed — common ports whose peer-set shrank: every remaining peer was
                 already allowed. Cannot weaken enforcement, so it is safe to
                 apply; this is what a tighten pass produces.
      widened  — common ports whose peer-set grants somebody it did not before,
                 including an exchange of one peer for another. Never applied
                 mechanically.
      modified — narrowed + widened together, for callers that do not care which
      cosmetic — common ports, same peers, but the covering term's name or
                 destination-port token changed (rename / regroup)
      families — common ports whose address-family coverage changed, as
                 ``[(term, ports, old_families, new_families)]``. A term whose
                 sources resolve to one family only admits that family, whatever
                 the filter target says; losing a family silently is how a rule
                 comes to read as enforced while one family is wide open.
    """
    old_s = port_surface(old_doc, defs, direction)
    new_s = port_surface(new_doc, defs, direction)
    old_p, new_p = set(old_s), set(new_s)
    common = old_p & new_p

    narrowed_ports, widened_ports, cosmetic_ports = set(), set(), set()
    family_ports = {}
    for pp in common:
        ot, nt = old_s[pp], new_s[pp]
        direction = pp[0]
        old_peers = term_peers(defs, ot, direction)
        new_peers = term_peers(defs, nt, direction)
        verdict = compare_peers(old_peers, new_peers)
        if verdict == "narrowed":
            narrowed_ports.add(pp)
        elif verdict == "widened":
            widened_ports.add(pp)
        elif ot.get("name") != nt.get("name") or ot.get("destination-port") != nt.get("destination-port"):
            cosmetic_ports.add(pp)
        old_fam, new_fam = peer_families(old_peers), peer_families(new_peers)
        if old_fam != new_fam:
            family_ports[pp] = (old_fam, new_fam)

    families = [
        (term, ports, family_ports[ports[0]][0], family_ports[ports[0]][1])
        for term, ports in _group_by_term(set(family_ports), new_s)
    ]

    return {
        "added":    _group_by_term(new_p - old_p, new_s),
        "removed":  _group_by_term(old_p - new_p, old_s),
        "narrowed": _group_by_term(narrowed_ports, new_s),
        "widened":  _group_by_term(widened_ports, new_s),
        "modified": _group_by_term(narrowed_ports | widened_ports, new_s),
        "cosmetic": _group_by_term(cosmetic_ports, new_s),
        "families": families,
        "_old": old_s,
        "_new": new_s,
    }
