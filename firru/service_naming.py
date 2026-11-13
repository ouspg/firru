"""
Naming a port from what is listening on it.

A port with no registry name is a policy subject with no name, and synthesis
emits `TCP_9099` for it. The socket inventory already carries the evidence that
would fix that -- the process -- and this is the table and the rules for using
it.

Three kinds of answer, and keeping them apart is the whole point:

  curated    the process is a host for many services and says nothing on its
             own, so the (protocol, port, process) triple is what identifies
             the service. `svchost` on udp/5050 is Connected Devices Platform;
             `svchost` on udp/3702 is WS-Discovery; `svchost` by itself is
             nothing at all.
  derived    the process names itself. `gitea` on tcp/3000 is GITEA, and no
             table is needed to say so.
  ambiguous  the port carries different processes on different hosts, so no
             single token covers it. Reported, never guessed.

Nothing here writes policy. It proposes inventory entries, which a human
accepts, edits or rejects -- the naming decision is the one place the pipeline
deliberately does not automate, because a wrong name is a wrong rule that looks
right.
"""

import re

#: Processes that host other services and therefore name nothing by themselves.
#: A port served by one of these is identified by the port, not by the process,
#: so it needs a curated entry or it stays unnamed.
OPAQUE_PROCESSES = {
    "svchost", "system", "unknown", "n/a", "docker-proxy", "dockerd",
    "containerd", "java", "python", "python3", "node", "ruby", "perl",
    "sh", "bash", "systemd", "inetd", "xinetd", "rpc.statd",
}

#: (protocol, port, process) -> token, for ports an opaque process serves.
#: Every entry is a naming decision someone made once; the comment says on what
#: grounds, because "svchost on 5050" is only Connected Devices Platform if you
#: already know that, and a reader a year later will not.
#:
#: Entries must be true of the software, not of one estate. A port that means
#: something only on the network you happened to measure belongs in that
#: network's definitions, where it can be argued with, not in a table every
#: user of the tool inherits.
CURATED = {
    ("udp", 5050, "svchost"): (
        "WINDOWS-CDP",
        "Connected Devices Platform (CDPSvc): Nearby Sharing and cross-device "
        "resume, announced to the site-local multicast group."),
    ("tcp", 5040, "svchost"): (
        "WINDOWS-CDP",
        "Connected Devices Platform, the TCP half of the same service."),
    ("udp", 3702, "svchost"): (
        "WINDOWS-BRANCHCACHE-DISCOVERY",
        "WS-Discovery, used by BranchCache to find peers holding cached content."),
    ("udp", 1900, "svchost"): (
        "SSDP",
        "UPnP discovery. Named so it can be denied by name rather than dropped "
        "silently."),
}

#: A derived name is the process, uppercased, with packaging noise stripped.
#: The trailing `d` of a daemon is deliberately NOT stripped: it turned `httpd`
#: into HTTP, which is an existing registry token for a different port, and a
#: proposal that collides with a real name is worse than an ugly one.
_STRIP = re.compile(r"(\.exe|\.bin|-server|-serv)$", re.I)


def _looks_like_a_name(process):
    """Whether a process name is specific enough to name a service after."""
    p = (process or "").strip().lower()
    if not p or p in OPAQUE_PROCESSES:
        return False
    # A truncated `ss` name (comm is 15 chars) is still usable; a bare number or
    # a single letter is not.
    return len(p) >= 3 and not p.isdigit()


def derive_token(process):
    """The token a self-naming process suggests, or None."""
    if not _looks_like_a_name(process):
        return None
    base = _STRIP.sub("", process.strip())
    tok = re.sub(r"[^A-Za-z0-9]+", "-", base).strip("-").upper()
    return tok or None


def _common_suite(names, min_len=5):
    """The shared prefix of several process names, when they are one product.

    `open5gs-smfd` and `open5gs-upfd` are two daemons of one 5G core, and a port
    both serve belongs to the core. Requires a separator so `nginx` and `nginy`
    do not become a suite, and a prefix long enough to mean something.
    """
    names = sorted(names)
    if len(names) < 2:
        return None
    head = names[0]
    for other in names[1:]:
        while head and not other.startswith(head):
            head = head[:-1]
    head = head.rstrip("-_.")
    if len(head) < min_len:
        return None
    # every name must actually continue past the prefix with a separator
    if not all(len(n) > len(head) and n[len(head)] in "-_." for n in names):
        return None
    return head


def name_port(protocol, port, process_hosts, taken=()):
    """
    Propose a name for one (protocol, port).

    `process_hosts` maps a process name to the hosts observed running it, so the
    proposal can say how much of the port the naming process actually accounts
    for. `taken` is the set of tokens already in the definitions; a proposal
    that collides with one is refused rather than renamed, because the two are
    not the same service and quietly merging them is the worst outcome.

    Returns (token, basis, comment).
    """
    counts = {(p or "?").strip().lower(): len(h) for p, h in process_hosts.items()}
    total = sum(counts.values())
    taken = {t.upper() for t in taken}

    curated = {CURATED[(protocol, int(port), p)] for p in counts
               if (protocol, int(port), p) in CURATED}
    if len(curated) == 1:
        token, comment = curated.pop()
        return token, "curated", comment

    named = {p: n for p, n in counts.items() if _looks_like_a_name(p)}
    if len(named) > 1:
        suite = _common_suite(named)
        if suite:
            return suite.upper(), "suite", (
                "Served by " + ", ".join(sorted(named)) + ", which are components "
                f"of the same `{suite}` suite, so the port belongs to the suite "
                "rather than to any one of them. Check the name: a suite token is "
                "right for a private port and wrong for a standard one.")
        return None, "ambiguous", (
            "Served by " + ", ".join(sorted(named)) + " on different hosts, so "
            "one token cannot cover it.")
    if len(named) == 1:
        p, n = next(iter(named.items()))
        tok = derive_token(p)
        if tok and tok in taken:
            return None, "collides", (
                f"The obvious name from `{p}` is {tok}, which the definitions "
                f"already use for something else. Needs a name a human picks.")
        share = f"{n} of {total} hosts on this port" if n < total else "every host on this port"
        basis = "derived" if n * 2 >= total else "minority"
        opaque = sorted(set(counts) - set(named))
        note = (f" The other {total - n} run " + ", ".join(opaque) + ", which name nothing."
                if opaque else "")
        return tok, basis, f"Named after `{p}`, which serves {share}.{note}"
    return None, "opaque", (
        "Served only by " + (", ".join(sorted(counts)) or "an unnamed process")
        + ", which hosts many services and identifies none.")


# ---------------------------------------------------------------------------
# Choosing between tokens that all contain the port
# ---------------------------------------------------------------------------

def token_width(defs, token):
    """How many ports a token grants. None when it will not resolve."""
    try:
        entries = defs.GetService(token)
    except Exception:
        return None
    total = 0
    for entry in entries:
        spec = entry.partition("/")[0]
        if "-" in spec:
            lo, hi = spec.split("-", 1)
            try:
                total += int(hi) - int(lo) + 1
            except ValueError:
                return None
        else:
            total += 1
    return total


def _is_auto(token):
    """A placeholder token minted for an unnamed port, e.g. TCP_9099."""
    return str(token).upper().startswith(("TCP_", "UDP_"))


def best_token(defs, tokens):
    """
    Pick the token to grant a port under, from every token containing it.

    `GetPortParents` returns them in definition order and the caller has
    historically taken the first, which is arbitrary: tcp/445 is in both
    WINDOWS-SMB and a site's WINDOWS-DC-BASE, and the second grants the whole
    dynamic RPC range along with it. The narrowest token is the one that
    describes the port rather than the suite it can belong to.

    A real name beats a placeholder even when the placeholder is narrower, since
    TCP_9099 grants one port and says nothing. Ties break on the name so the
    output is stable.
    """
    if not tokens:
        return None
    scored = []
    for t in tokens:
        w = token_width(defs, t)
        scored.append((_is_auto(t), w if w is not None else 10 ** 9, str(t), t))
    scored.sort()
    return scored[0][3]


def choose_token(defs, tokens, owners=None, evidence=()):
    """
    (token, note): `best_token`, but for a port two names claim equally.

    Narrowest-wins cannot separate COCKPIT from PROMETHEUS (both tcp/9090, one
    port each), and the tie used to break on the name -- every Prometheus
    server became COCKPIT. The listener says which it is, so ask it:

      1. a name whose owner hints (firru.owners) match the listener's process,
         unit or Windows service wins, even over a narrower one: dockerd on
         7946 is DOCKER-SWARM although METALLB-MEMBERLIST is narrower;
      2. otherwise, among the narrowest names, a single name without hints is
         the generic default: System on 443 is HTTPS, and only Hyper-V's vmms
         makes it WINDOWS-HYPERV-REPLICA-HTTPS;
      3. otherwise nothing decides it, and the note says so. The token is still
         the deterministic `best_token` choice, so output is stable, but the
         note puts the guess in front of the reviewer instead of hiding it.
    """
    if not tokens:
        return None, None
    owners = owners or {}
    evidence = set(evidence or ())

    from firru.owners import owner_matches
    matched = [t for t in tokens if t in owners and owner_matches(owners[t], evidence)]
    if matched:
        return best_token(defs, matched), None

    first = best_token(defs, tokens)
    width = token_width(defs, first)
    ties = [t for t in tokens
            if token_width(defs, t) == width and _is_auto(t) == _is_auto(first)]
    if len(ties) == 1:
        return first, None
    generic = [t for t in ties if t not in owners]
    if len(generic) == 1:
        return generic[0], None
    who = ", ".join(sorted(evidence)) or "no attribution"
    return first, (f"ambiguous: {'/'.join(sorted(ties))} all claim this port and "
                   f"the owner ({who}) matches none of them; {first} is a guess")


# ---------------------------------------------------------------------------
# A known name served by an unexpected process
# ---------------------------------------------------------------------------

#: Processes that pass a port on to something else. The name on the port is
#: only as good as whatever sits behind them.
FORWARDERS = {"docker-proxy", "socat", "rootlessport", "pasta", "slirp4netns",
              "sshd", "stunnel", "stunnel4"}

#: Language runtimes: the process names the interpreter, not the program. A
#: script on a web port is the classic ad-hoc listener.
RUNTIMES = {"python", "python3", "python2", "java", "node", "nodejs", "ruby",
            "perl", "php", "php-fpm", "dotnet", "bun", "deno", "pwsh",
            "powershell", "sh", "bash"}


def owner_surprise(token, entries, expected):
    """
    One line when a named port is served by something its definition does not
    expect, else None.

    `expected` is firru.owners.load_expected(): HTTP-ALT expects nginx, apache2,
    caddy...; python3 serving it is worth a reviewer's look even though the
    name, and the rule, are right. Graded by what the process is, because
    docker-proxy on 80 says "look behind me" and an unknown binary on 80 says
    "look at me":

      forwarded     docker-proxy, socat...: the real service is behind it
      runtime       python3, java, node...: names the interpreter, not the program
      unattributed  no process at all
      other         a self-named program that is not the expected one

    No expectation for the token means no opinion, not a finding.
    """
    from firru.owners import owner_evidence, owner_matches
    hints = (expected or {}).get(token)
    if not hints:
        return None
    if owner_matches(hints, owner_evidence(entries)):
        return None
    procs = sorted({((e.get("process") or {}).get("name") or "").lower()
                    for e in entries or () if isinstance(e, dict)} - {""})
    if not procs or procs == ["unknown"]:
        what = "no process attribution"
    else:
        named = [p for p in procs if p != "unknown"]
        if all(p in FORWARDERS for p in named):
            what = f"forwarded by {', '.join(named)}; the service is behind it"
        elif any(p in RUNTIMES for p in named):
            what = f"served by {', '.join(named)} (a language runtime, not a named server)"
        else:
            what = f"served by {', '.join(named)}"
    # In the definition's own order: whoever wrote it put the usual ones first.
    usual = list(dict.fromkeys(n for k in ("processes", "units", "services")
                               for n in hints.get(k, ())))
    more = f", +{len(usual) - 6} more" if len(usual) > 6 else ""
    return f"unexpected owner: {token} {what}; expected {', '.join(usual[:6])}{more}"


# ---------------------------------------------------------------------------
# When the registry name and the process disagree
# ---------------------------------------------------------------------------

#: Processes whose service class is known and narrow enough that serving an
#: unrelated well-known port means something. Deliberately short: a general
#: "the process does not match the token" test fires on `nginx` behind HTTPS
#: and is useless. These are daemons that do one thing, so the same daemon on
#: another port is that thing wearing another port's clothes.
PROCESS_CLASS = {
    "unbound": "dns", "dnsmasq": "dns", "named": "dns", "coredns": "dns",
    "systemd-resolve": "dns", "kresd": "dns", "pdns_recursor": "dns",
    "pdns_server": "dns", "knot-resolver": "dns", "stubby": "dns",
    "ntpd": "ntp", "chronyd": "ntp",
    "openvpn": "vpn", "wg": "vpn", "wireguard": "vpn",
}

#: The ports each class is unremarkable on. Anything else is worth a line.
CLASS_PORTS = {
    "dns": {53, 853, 5353, 5355, 5053, 5335},
    "ntp": {123},
    "vpn": {1194, 51820, 500, 4500},
}


def contradicted(protocol, port, processes):
    """
    (process, note) when a port's registry name and its process disagree, else
    None. The process comes back so the caller can scope the finding to the
    hosts running it: 58 hosts serve tcp/443 and the contradiction is about the
    six of them running a resolver.

    `unbound` on 443 is DNS-over-HTTPS. The port resolves to HTTPS and the term
    reads `allow-tcp-HTTPS`, which on a nameserver is a web server as far as any
    reviewer can tell. The name is not wrong exactly -- it is the right name for
    the wire protocol and the wrong one for the service -- and that is precisely
    the sort of thing a review queue should raise rather than settle.
    """
    for proc in sorted({(p or "").strip().lower() for p in processes}):
        cls = PROCESS_CLASS.get(proc)
        if cls and int(port) not in CLASS_PORTS.get(cls, ()):
            return proc, (
                f"served by `{proc}`, which is a {cls} daemon; on "
                f"{protocol}/{port} that is {cls} over another protocol, not "
                f"the service the port's name suggests")
    return None
