"""
firru.ss — Linux ss output parsing and process info extraction.
"""

import re
from functools import lru_cache

import jc


def _strip_cgroup(line: str) -> str:
    """Remove cgroup:... fields from ss output — they contain colons that trip jc's parser."""
    return re.sub(r'\s+cgroup:\S+', '', line)


def _sanitize_proc_name(line: str) -> str:
    """
    Sanitize process names inside users:(("...")) blocks so jc can parse them.

    Replaces spaces, colons, and parentheses within the quoted name with '_'.
    These characters confuse jc's ss parser (spaces/colons break tokenization,
    open-parens cause unterminated string literal errors).
    """
    def _clean(m):
        name = m.group(1)
        sanitized = re.sub(r'[ :()]', '_', name)
        return m.group(0).replace(f'"{name}"', f'"{sanitized}"', 1)
    return re.sub(r'users:\(\(\"([^\"]+)\"', _clean, line)


class SsParseError(Exception):
    """A saved ss dump could not be read.

    Distinct from an empty result on purpose. A host that genuinely listens on
    nothing is a fact and returns `[]`; a dump this code could not parse is a
    statement about the *collection*, and the two must never arrive as the same
    value. They used to: every failure was swallowed and returned `[]`, so an
    unreadable dump became "this host listens on nothing", which synthesizes to
    an empty policy and then diffs against the committed one as the whole host
    removed. Under `firru apply --prune` that is a real host stripped of every
    rule because a parser hit an ss version it did not know.

    That is the `unattributed` class of docs/design.md reported as fact, and the
    model is explicit that such a finding "is always a statement about the
    observation, never about the system." So this raises, and a caller that
    wants to keep going past a bad host has to say so.
    """


#: A real `ss -tulnpe` row shape, used only to ask the installed jc a question.
#: The column alignment is load-bearing: jc derives its columns from the header
#: and from run-lengths of spaces, so a hand-spaced approximation proves nothing.
_PROBE_HDR = ("Netid State  Recv-Q Send-Q Local Address:Port  "
              "Peer Address:PortProcess\n")
_PROBE_ROW = ('tcp   LISTEN 0      5            0.0.0.0:19001      0.0.0.0:*    '
              'users:(("{}",pid=3201,fd=3)) ino:2415307 sk:a004 cgroup:/ <->\n')

#: One name carrying all three characters that broke jc: a space, a colon and
#: an opening paren. Real names have them -- `(sd-pam` is on ~90% of Linux
#: hosts, `tmux: server` and `gunicorn: worke` are ordinary too.
_PROBE_NAME = 'a b:c(d'


@lru_cache(maxsize=1)
def jc_keeps_process_names() -> bool:
    """Whether the installed jc returns a process name unaltered.

    Asked by parsing, not by reading a version number, and the difference is
    not academic. jc's fix is not released yet, so there is no version to
    compare against; a distro may backport it without touching the version; and
    a locally patched checkout reports whatever version it forked from. A probe
    is right in all three cases and needs no table of versions to maintain.

    The check has to look at the *value*, not at whether parsing raised. A name
    containing a paren does not raise on a broken jc -- it comes back with the
    paren rewritten to a bracket, so `(sd-pam` reads as `[sd-pam`. Silent is
    what makes that one dangerous, and an exception-based probe would call the
    broken parser healthy.
    """
    try:
        rows = jc.parse('ss', _PROBE_HDR + _PROBE_ROW.format(_PROBE_NAME))
        block = rows[0].get('process') or rows[0].get('opts')
        if not isinstance(block, dict):
            return False
        names = [v.get('user') for v in (block.get('process_id') or {}).values()]
        return names == [_PROBE_NAME]
    except Exception:
        return False


def parse_ss_safe(filepath: str) -> list:
    """
    Parse a saved 'ss -tulnp' output file via jc.

    Filters lines to tcp/udp/sctp only before parsing — the jc ss parser
    chokes on other netid types (unix sockets, netlink, etc.). The filtering
    and the two sanitizers above are the part worth testing against a new ss
    version; jc itself is tested upstream.

    Returns a list of dicts, which may be empty when the host really is
    listening on nothing. Raises `SsParseError` when the dump cannot be read,
    because that is not the same answer.
    """
    try:
        with open(filepath) as f:
            raw_lines = f.readlines()
    except OSError as e:
        raise SsParseError(f"{filepath}: cannot read: {e}") from e
    if not raw_lines:
        raise SsParseError(f"{filepath}: empty file — ss wrote nothing, which is "
                           f"not the same as a host with no listeners")
    # A saved fixture may carry provenance as leading '#' lines (which ss
    # version, which flags), and the header has to be the first line jc sees.
    # Without this the comment *becomes* the header and every column name is
    # wrong, which is how a corpus of 36 good dumps reads as 33 parse failures.
    # Real ss never emits '#', so skipping them costs nothing on live output.
    body = raw_lines
    while body and body[0].lstrip().startswith('#'):
        body = body[1:]
    if not body:
        raise SsParseError(f"{filepath}: nothing but comments")
    rows = [line for line in body
            if any(proto in line for proto in ('tcp', 'udp', 'sctp'))]

    # Two repairs, tried least-lossy first, because they are not equally cheap.
    #
    # Sanitizing process names is unconditional: 23 of the 36 dumps in
    # tests/fixtures/ss/ fail to parse without it, across every distro. It costs
    # the exact spelling of a name containing a space, colon or paren, which is
    # a real loss and a far smaller one than the whole host failing to parse.
    #
    # Stripping `cgroup:` is a *fallback*, and used to be unconditional. Current
    # jc parses that field and hands back `cgroup: /system.slice/ssh.service` --
    # the systemd unit, which is better attribution than the comm name firru
    # otherwise has to work with. Discarding it by default threw away evidence
    # to accommodate a jc that may not be the one installed. So keep it, and
    # strip only if that fails, which is what an older jc needs. Neither branch
    # asks which jc this is; the fallback is what makes the version question
    # unnecessary.
    # On a jc that keeps names, sanitizing is pure loss: it would turn the real
    # `(sd-pam` into `_sd-pam` and `tmux: server` into `tmux__server` for no
    # benefit. So the repair ladder starts where the installed parser actually
    # is, rather than at the worst case.
    if jc_keeps_process_names():
        repairs = (
            lambda line: line,
            _strip_cgroup,
        )
    else:
        repairs = (
            _sanitize_proc_name,
            lambda line: _sanitize_proc_name(_strip_cgroup(line)),
        )
    last = None
    for repair in repairs:
        try:
            parsed = jc.parse('ss', ''.join([body[0]] + [repair(l) for l in rows]))
        except Exception as e:      # try the next repair before giving up
            last = e
            continue
        return _recover_cgroup(parsed, rows)
    raise SsParseError(
        f"{filepath}: ss output not understood ({last}). This is usually a "
        f"field a newer ss emits that the sanitizers above do not handle; add "
        f"the dump to tests/fixtures/ss/ and fix the sanitizer rather than "
        f"letting the host read as empty.") from last


_CGROUP = re.compile(r'\scgroup:(\S+)')


def _recover_cgroup(parsed: list, rows: list) -> list:
    """
    Put back the cgroup jc did not keep, from the raw row.

    jc files `cgroup:` under `opts` only when it can split the options. EL9's
    `ss` pads after `users:(...)`, jc then keeps `opts` as the bare users string,
    and the cgroup -- the systemd unit, the best attribution there is -- is gone;
    so is it whenever the fallback above stripped it. jc returns one entry per
    row, so the raw row is still at hand. If the counts disagree the pairing is
    unknown, and nothing is added rather than something wrong.
    """
    if len(parsed) != len(rows):
        return parsed
    for entry, row in zip(parsed, rows):
        opts = entry.get('opts')
        if isinstance(opts, dict) and opts.get('cgroup'):
            continue
        m = _CGROUP.search(row)
        if m:
            entry['cgroup'] = m.group(1)
    return parsed


def get_process_name_pid(entry: dict) -> tuple:
    """
    Extract (process_name, pid_str) from a jc ss entry.

    Handles both structured 'process' dicts (newer jc versions) and
    raw 'opts' strings (older jc versions / some distros).

    Returns ('UNKNOWN', None) if neither format is parseable.
    """
    import re
    process_data = entry.get('process') or entry.get('opts') or entry.get('peer_address')

    # Structured dict: {'process_id': {'1234': {'user': 'sshd', ...}}}
    if isinstance(process_data, dict):
        pid_data = process_data.get('process_id', {})
        if pid_data:
            pid = next(iter(pid_data))
            name = pid_data[pid].get('user', 'UNKNOWN')
            return name, str(pid)

    # Raw opts string: users:(("sshd",pid=1234,fd=5))
    #
    # Both quote styles, and the reason is not cosmetic. jc hands back a
    # structured dict on some ss versions and this raw string on others, and the
    # string form quotes the command name with double quotes on every modern ss.
    # Matching only the single-quoted form meant every listener on the versions
    # that take this branch came back UNKNOWN -- Ubuntu 22.04 among them, via
    # `ss -tulnpe`, which is the flag set loot-host.sh actually collects with.
    # The ports were right, so nothing failed; the estate just quietly lost its
    # process attribution, which is what service naming and the [auto] evidence
    # comments are built on.
    if isinstance(process_data, str):
        m_name = re.search(r"""users:\(\(["']([^"']+)["']""", process_data)
        m_pid  = re.search(r"pid=(\d+)", process_data)
        name   = m_name.group(1) if m_name else 'UNKNOWN'
        pid    = m_pid.group(1) if m_pid else None
        return name, pid

    return 'UNKNOWN', None
