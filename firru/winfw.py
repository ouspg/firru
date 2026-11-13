"""
firru.winfw — Windows Firewall rules as loot-host.ps1 collects them
(firewall.json: profiles, interfaces, and every ActiveStore rule joined with
its port, address, application and service filters), normalized once so the
ruleset reader (winfw-to-aerleon) and the exposure check read them alike.

What Windows evaluates and the normalization keeps:

- Profiles. A rule applies to the profiles named in it ("Any", or a list of
  Domain/Private/Public); which profile is live comes from each interface's
  network category. A disabled profile means the firewall is off there.
- Precedence. An enabled Block rule beats any Allow rule (authenticated-bypass
  rules aside), so order is not first-match: blocks are a veto.
- Scope by program and service. A rule for one program admits that program's
  sockets on any port it names; port Any plus a program is common and means
  "whatever that program opens". aerleon cannot say this, so the reader widens
  such rules (and says so), while the exposure check matches them exactly.
- Port keywords. RPCEPMap is 135; RPC is the dynamic endpoint range, admitting
  only RPC servers; IPHTTPS is 443. Others are kept as unrecognized keywords.
"""

import ipaddress
import re
from firru.tokens import is_loopback

PROFILE_OF_CATEGORY = {'public': 'Public', 'private': 'Private',
                       'domainauthenticated': 'Domain', 'domain': 'Domain'}
ALL_PROFILES = frozenset({'Domain', 'Private', 'Public'})
PORT_KEYWORDS = {'rpcepmap': [(135, 135)], 'iphttpsin': [(443, 443)], 'iphttpsout': [(443, 443)]}
#: The dynamic range RPC endpoints are taken from (Vista on), for the RPC keyword.
RPC_DYNAMIC = (49152, 65535)
PROTOCOLS = {'tcp': 'tcp', '6': 'tcp', 'udp': 'udp', '17': 'udp', 'icmpv4': 'icmp', '1': 'icmp',
             'icmpv6': 'icmpv6', '58': 'icmpv6', 'any': None, '': None}
_ENV = {'%systemroot%': r'c:\windows', '%windir%': r'c:\windows',
        '%programfiles%': r'c:\program files', '%programfiles(x86)%': r'c:\program files (x86)',
        '%programdata%': r'c:\programdata', '%systemdrive%': 'c:'}


def _bool(v):
    return str(v).strip().lower() in ('true', '1', 'yes')


def _list(v):
    if v is None:
        return []
    return [str(x) for x in v] if isinstance(v, list) else [str(v)]


def _any(values):
    return not values or any(v.lower() in ('any', '*') for v in values)


def norm_path(p):
    p = (p or '').strip().strip('"').lower()
    for k, v in _ENV.items():
        p = p.replace(k, v)
    return p


def profile_state(fw):
    """{profile: (enabled, default inbound action)}"""
    return {p['Name']: (_bool(p.get('Enabled')), str(p.get('DefaultInboundAction') or 'Block'))
            for p in fw.get('profiles') or [] if p.get('Name')}


def active_profiles(fw):
    """Profiles live on the host's interfaces; all three when not recorded."""
    live = {PROFILE_OF_CATEGORY.get(str(i.get('category') or '').lower())
            for i in fw.get('interfaces') or []}
    live.discard(None)
    return frozenset(live) or ALL_PROFILES


def firewall_off(fw, profiles=None):
    """Live profiles whose firewall is disabled."""
    state = profile_state(fw)
    return sorted(p for p in (profiles or active_profiles(fw))
                  if p in state and not state[p][0])


def parse_ports(values):
    """(ranges, keywords, any) for a LocalPort list."""
    vals = _list(values)
    if _any(vals):
        return [], [], True
    ranges, kws = [], []
    for v in vals:
        m = re.fullmatch(r'\s*(\d+)\s*(?:-\s*(\d+))?\s*', v)
        if m:
            lo = int(m.group(1))
            ranges.append((lo, int(m.group(2) or lo)))
        elif v.lower() in PORT_KEYWORDS:
            ranges.extend(PORT_KEYWORDS[v.lower()])
        else:
            kws.append(v)
    return ranges, kws, False


def parse_addrs(values):
    """(networks, keywords, any) for a RemoteAddress list."""
    vals = _list(values)
    if _any(vals):
        return [], [], True
    nets, kws = [], []
    for v in vals:
        try:
            if '-' in v and '/' not in v:
                lo, hi = (ipaddress.ip_address(x.strip()) for x in v.split('-', 1))
                nets.extend(ipaddress.summarize_address_range(lo, hi))
            else:
                nets.append(ipaddress.ip_network(v.strip(), strict=False))
        except ValueError:
            kws.append(v)
    return nets, kws, False


def parse_profiles(v):
    vals = [x.strip() for x in re.split(r'[,\s]+', str(v or 'Any')) if x.strip()]
    if not vals or any(x.lower() == 'any' for x in vals):
        return None
    return frozenset(x.capitalize() for x in vals)


def inert(r):
    """Windows' own word that an enabled rule has no effect: an EnforcementStatus
    reason starting with 'No' (NoDynamicTransport, NoRemoteAddress, NoLocalPort
    ...). Absent in loot from before loot-host.ps1 collected it."""
    return any(t.startswith('No') for t in re.split(r'[\s,]+', str(r.get('Enforcement') or '')) if t)


def rules(fw, direction='Inbound'):
    """Enabled, effective rules of one direction, normalized."""
    out = []
    for r in fw.get('rules') or []:
        if not _bool(r.get('Enabled')) or str(r.get('Direction')) != direction or inert(r):
            continue
        ranges, port_kws, port_any = parse_ports(r.get('LocalPort'))
        nets, addr_kws, remote_any = parse_addrs(r.get('RemoteAddress'))
        proto = str(r.get('Protocol') or 'Any').strip().lower()
        program = r.get('Program')
        service = r.get('Service')
        out.append({
            'name': r.get('Name') or r.get('DisplayName') or '?',
            'display': r.get('DisplayName') or '',
            'action': 'deny' if str(r.get('Action')).lower() == 'block' else 'accept',
            'protocol': PROTOCOLS.get(proto, proto),
            'ports': ranges, 'port_keywords': port_kws, 'port_any': port_any,
            'remote': nets, 'remote_keywords': addr_kws, 'remote_any': remote_any,
            'program': None if _any(_list(program)) else norm_path(program),
            # An AppContainer package SID scopes the rule to one store app, as a
            # program does; its sockets cannot be told apart in the loot.
            # Owner is where a store-app rule keeps its AppContainer SID when
            # the application filter has no Package; older loot has neither,
            # and a resource-string group (@{Package...}) is the remaining tell.
            'package': r.get('Package') or r.get('Owner')
                       or ('group' if str(r.get('Group') or '').startswith('@{') else None),
            'interface_type': None if str(r.get('InterfaceType') or 'Any') in ('Any', 'None', '')
                              else str(r.get('InterfaceType')),
            'interface_alias': None if _any(_list(r.get('InterfaceAlias'))) else _list(r.get('InterfaceAlias')),
            'service': None if _any(_list(service)) and str(service) != '*' else str(service),
            'profiles': parse_profiles(r.get('Profile')),
            'icmp_types': [] if _any(_list(r.get('IcmpType'))) else _list(r.get('IcmpType')),
        })
    return out


def applies(rule, profiles):
    return rule['profiles'] is None or bool(rule['profiles'] & profiles)


def _loopback(bind):
    return is_loopback(bind)


def on_interface(rule, fw):
    """Could the rule apply on one of the host's interfaces? Interface types
    other than wired (Wireless, RemoteAccess, Wi-Fi Direct) are taken not to
    exist on the hosts measured here; an alias list must name one present."""
    if rule.get('interface_alias'):
        names = {str(i.get('ifname')) for i in fw.get('interfaces') or []}
        if not names & set(rule['interface_alias']):
            return False
    t = (rule.get('interface_type') or '').lower()
    return not t or 'wired' in t or 'lan' in t


def admits(rule, listener):
    """Does this rule match traffic to this listener (ignoring the peer)?"""
    proto = listener.get('protocol')
    if rule['protocol'] and rule['protocol'] != proto:
        return False
    port = listener.get('port')
    if not rule['port_any']:
        hit = any(lo <= port <= hi for lo, hi in rule['ports'])
        if not hit and any(k.lower() == 'rpc' for k in rule['port_keywords']):
            hit = RPC_DYNAMIC[0] <= port <= RPC_DYNAMIC[1]
        if not hit:
            return False
    proc = listener.get('process') or {}
    if rule.get('package'):
        return False
    if rule['program']:
        exe = norm_path(proc.get('exe'))
        if rule['program'] == 'system':
            if (proc.get('name') or '').lower() != 'system':
                return False
        elif not exe or exe != rule['program']:
            return False
    if rule['service']:
        services = [s.lower() for s in proc.get('services') or []]
        if rule['service'] == '*':
            if not services:
                return False
        elif rule['service'].lower() not in services:
            return False
    return True


def _peers(rule):
    if rule['remote_any']:
        return 'Any'
    return ', '.join([str(n) for n in rule['remote']] + rule['remote_keywords'])


def _httpsys_owner(listener, http_urls):
    """'System (HTTP.sys: svchost /WSMAN/)' for a System-owned port with registrations."""
    if not http_urls or ((listener.get('process') or {}).get('name') or '').lower() != 'system':
        return None
    rows = [u for u in http_urls if str(u.get('Port')) == str(listener.get('port'))]
    if not rows:
        return None
    who = sorted({(u.get('Image') or '?').split('\\')[-1] + ' ' +
                  re.sub(r'^https?://[^/]*', '', u.get('Url') or '', flags=re.I) for u in rows})
    return 'System (HTTP.sys: ' + ', '.join(who) + ')'


def exposure(fw, listeners, ipsec_rules=0, http_urls=None):
    """
    Each listener judged against the running Windows Firewall, and the allow
    rules that admit a port nothing listens on. Returns {'listeners': [...],
    'stale': [...], 'broad': [...], 'off': [profiles]}.

    http_urls: loot-host.ps1's http-urls.csv rows (Port, Url, ProcessId, Image),
    which name the process behind a System-owned HTTP.sys port.

    Listener classes: open (admitted from any address), scoped (from some),
    blocked (a Block rule or the default), local (loopback only).
    """
    profiles = active_profiles(fw)
    state = profile_state(fw)
    off = firewall_off(fw, profiles)
    inbound = [r for r in rules(fw) if applies(r, profiles) and on_interface(r, fw)]
    allows = [r for r in inbound if r['action'] == 'accept']
    blocks = [r for r in inbound if r['action'] == 'deny']
    default_allow = any(state.get(p, (True, 'Block'))[1].lower() == 'allow' for p in profiles)

    used = set()
    out = []
    for lst in listeners:
        rec = {'protocol': lst.get('protocol'), 'port': lst.get('port'),
               'process': _httpsys_owner(lst, http_urls) or (lst.get('process') or {}).get('name') or 'UNKNOWN',
               'bind': lst.get('bind_address')}
        hits = [r for r in allows if admits(r, lst)]
        used.update(r['name'] for r in hits)
        if _loopback(lst.get('bind_address') or ''):
            rec.update(cls='local', why='loopback only')
        elif off:
            rec.update(cls='open', why=f"firewall off ({', '.join(off)})")
        elif any(admits(r, lst) for r in blocks):
            b = next(r for r in blocks if admits(r, lst))
            rec.update(cls='blocked', why=f"Block rule {b['name']}")
        elif any(r['remote_any'] for r in hits):
            r = next(r for r in hits if r['remote_any'])
            rec.update(cls='open', why=f"{r['name']}" + (f" ({len(hits)} rules)" if len(hits) > 1 else ''))
        elif hits:
            rec.update(cls='scoped', why='; '.join(f"{r['name']} from {_peers(r)}" for r in hits[:3]))
        elif default_allow:
            rec.update(cls='open', why='default inbound action Allow')
        else:
            rec.update(cls='blocked', why='no rule admits it (default block)')
        out.append(rec)

    stale, broad = [], []
    for r in allows:
        if r['protocol'] not in ('tcp', 'udp', None):
            continue
        if r.get('package'):
            continue
        if r['port_any'] and not r['program'] and not r['service']:
            broad.append({'rule': r['name'], 'display': r['display'], 'peers': _peers(r),
                          'protocol': r['protocol'] or 'any'})
            continue
        if r['name'] in used or r['port_any'] or (r['port_keywords'] and not r['ports']):
            continue
        stale.append({'rule': r['name'], 'display': r['display'], 'protocol': r['protocol'] or 'any',
                      'ports': [f'{lo}' if lo == hi else f'{lo}-{hi}' for lo, hi in r['ports']],
                      'peers': _peers(r), 'program': r['program'], 'service': r['service'],
                      # A rule for any program admits whatever binds the port; a rule
                      # for System admits any URL registered through HTTP.sys, which
                      # takes an admin (or a URL reservation); others need that program.
                      'squattable': (True if not r['program'] and not r['service']
                                     else 'httpsys' if r['program'] == 'system' else False)})
    return {'listeners': out, 'stale': stale, 'broad': broad, 'off': off,
            'profiles': sorted(profiles)}


# ---------------------------------------------------------------------------
# A host's rules against a stock install's (from firru-os-baselines'
# fw-baseline.py): how was the firewall weakened, and did hardening take.
# ---------------------------------------------------------------------------

#: The fields that decide what a rule admits; a change in one is a scope change.
SCOPE = ('Action', 'Direction', 'Profile', 'Protocol', 'LocalPort', 'RemotePort',
         'LocalAddress', 'RemoteAddress', 'Program', 'Service')
_GUID = re.compile(r'^\{[0-9A-Fa-f-]{36}\}$')


def rule_key(r):
    """Rule identity: Name (stable across display languages), unless Name is a
    per-install GUID (rules added by netsh or applications), then what the rule
    says it is."""
    if _GUID.match(r.get('Name') or ''):
        return ('guid', r.get('DisplayName'), r.get('Direction'), r.get('Protocol'),
                (r.get('Program') or '').lower())
    return r.get('Name')


def _norm_rule(r):
    """One spelling per meaning, so a compact firewall.json (absent = Any)
    compares equal to a full one ("Any", ["Any"], all three profiles)."""
    r = dict(r, Enabled=_bool(r.get('Enabled')))
    if r.get('Profile') == 'Domain, Private, Public':
        r['Profile'] = 'Any'
    for k in SCOPE + ('IcmpType', 'Package', 'Owner'):
        v = r.get(k)
        if v in (None, '', 'Any', [], ['Any']):
            r[k] = None
        elif isinstance(v, list):
            r[k] = [str(x) for x in v]
    # Paths and service names are case-insensitive, and builds disagree on
    # case: Server 2025 writes C:\WINDOWS\System32 where 2022 wrote C:\Windows.
    for k in ('Program', 'Service'):
        if isinstance(r.get(k), str):
            r[k] = norm_path(r[k]) if k == 'Program' else r[k].lower()
    # A store app's rule: package SID, owner, or (older loot) a @{...} group.
    if not r.get('Package') and (r.get('Owner') or str(r.get('Group') or '').startswith('@{')):
        r['Package'] = r.get('Owner') or 'app'
    return r


def _exposure_order(r):
    """Inbound enabled allow first; app-package rules after the rest."""
    return (r.get('Direction') != 'Inbound', r.get('Action') != 'Allow', not r.get('Enabled'),
            bool(r.get('Package')), str(r.get('Name')))


def layer_matcher(layers):
    """layers: {name: {'rules': [{'name': regex, 'display': regex}], ...}} -> rule -> [layer]."""
    def match(r):
        hits = []
        for layer, spec in (layers or {}).items():
            for sig in spec.get('rules') or ():
                if all(re.search(sig[k], r.get('Name' if k == 'name' else 'DisplayName') or '')
                       for k in ('name', 'display') if k in sig):
                    hits.append(layer)
                    break
        return hits
    return match


def rule_diff(base_fw, host_fw):
    """{'profiles': [(name, {field: (stock, host)})], 'added', 'enabled', 'disabled',
    'removed': [rule], 'changed': [(rule, [(field, stock, host)])]}"""
    base = {rule_key(r): _norm_rule(r) for r in base_fw.get('rules') or []}
    host = {rule_key(r): _norm_rule(r) for r in host_fw.get('rules') or []}
    bp = {p.get('Name'): p for p in base_fw.get('profiles') or []}
    profiles = []
    for p in host_fw.get('profiles') or []:
        q = bp.get(p.get('Name'), {})
        d = {k: (q.get(k), p.get(k)) for k in p if k != 'Name' and str(q.get(k)) != str(p.get(k))}
        if d:
            profiles.append((p.get('Name'), d))
    common = sorted(base.keys() & host.keys(), key=str)
    changed = []
    for n in common:
        ks = [(k, base[n].get(k), host[n].get(k)) for k in SCOPE if base[n].get(k) != host[n].get(k)]
        if ks:
            changed.append((host[n], ks))
    return {
        'profiles': profiles,
        'added': sorted((host[n] for n in host.keys() - base.keys()), key=_exposure_order),
        'enabled': sorted((host[n] for n in common
                           if not base[n]['Enabled'] and host[n]['Enabled']), key=_exposure_order),
        'disabled': [base[n] for n in common if base[n]['Enabled'] and not host[n]['Enabled']],
        'changed': changed,
        'removed': sorted((base[n] for n in base.keys() - host.keys()), key=lambda r: str(r.get('Name'))),
    }


def show_rule(r):
    v = lambda k: (','.join(map(str, r[k])) if isinstance(r.get(k), list) else str(r[k])) \
        if r.get(k) not in (None, '', []) else 'Any'
    port = (f"icmp={v('IcmpType')}" if str(r.get('Protocol') or '').upper().startswith('ICMP')
            else f"port={v('LocalPort')}")
    return (f"{str(r.get('Direction', ''))[:3]} {r.get('Action', '')} {v('Protocol')} {port} "
            f"from={v('RemoteAddress')} prof={v('Profile')}"
            + (f" prog={r['Program']}" if r.get('Program') not in (None, 'Any') else '')
            + (f" svc={r['Service']}" if r.get('Service') not in (None, 'Any') else '')
            + (' pkg' if r.get('Package') else '')
            + f"  {r.get('DisplayName', '')!r}")
