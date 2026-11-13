"""Listeners against the running firewall: Windows (winfw), nftables (nfteval), and firru audit."""
import json

from firru import nfteval, winfw
from firru.cli.winfw_to_aerleon import convert


def lst(port, proto='tcp', name='svc', exe='', services=(), bind='0.0.0.0/0'):
    return {'protocol': proto, 'port': port, 'bind_address': bind,
            'process': {'name': name, 'exe': exe, 'services': list(services)}}


def rule(name, port='Any', action='Allow', proto='TCP', program='Any', service='Any',
         remote='Any', profile='Any', package=None, enabled=True):
    return {'Name': name, 'DisplayName': name, 'Enabled': enabled, 'Direction': 'Inbound',
            'Action': action, 'Profile': profile, 'Protocol': proto,
            'LocalPort': [port] if isinstance(port, str) else port, 'RemoteAddress': [remote],
            'Program': program, 'Package': package, 'Service': service, 'IcmpType': ['Any']}


def fw(rules, enabled='True', category='Public'):
    return {'profiles': [{'Name': p, 'Enabled': enabled, 'DefaultInboundAction': 'Block'}
                         for p in ('Domain', 'Private', 'Public')],
            'interfaces': [{'ifname': 'Ethernet', 'category': category}], 'rules': rules}


def classes(e):
    return {(l['protocol'], l['port']): l['cls'] for l in e['listeners']}


def test_windows_rules_by_port_program_service_and_scope():
    f = fw([rule('ssh', '22'),
            rule('winrm', '5985', remote='LocalSubnet'),
            rule('app', program=r'%ProgramFiles%\App\app.exe'),
            rule('svc', service='Spooler'),
            rule('priv', '8080', profile='Private'),
            rule('blk', '9999', action='Block'), rule('allow9999', '9999'),
            rule('store', package='S-1-15-2-1')])
    e = winfw.exposure(f, [lst(22), lst(5985), lst(7777, exe=r'C:\Program Files\App\app.exe'),
                           lst(7778, services=['Spooler']), lst(8080), lst(9999), lst(4444),
                           lst(53, bind='127.0.0.1/32')])
    assert classes(e) == {('tcp', 22): 'open', ('tcp', 5985): 'scoped', ('tcp', 7777): 'open',
                          ('tcp', 7778): 'open', ('tcp', 8080): 'blocked', ('tcp', 9999): 'blocked',
                          ('tcp', 4444): 'blocked', ('tcp', 53): 'local'}
    assert e['broad'] == []          # the package rule is scoped to one app


def test_windows_stale_rules_and_who_can_squat_them():
    f = fw([rule('hole', '8443'), rule('progonly', '8444', program=r'C:\x.exe'),
            rule('everything')])
    e = winfw.exposure(f, [])
    stale = {s['rule']: s['squattable'] for s in e['stale']}
    assert stale == {'hole': True, 'progonly': False}
    assert [b['rule'] for b in e['broad']] == ['everything']


def test_windows_firewall_off_is_open():
    e = winfw.exposure(fw([], enabled='False'), [lst(445)])
    assert classes(e) == {('tcp', 445): 'open'} and e['off'] == ['Public']




def test_winfw_reader_orders_blocks_first_and_flags_what_it_widens():
    doc, stats = convert(fw([rule('a', '80'), rule('b', '81', action='Block'),
                             rule('rpc', 'RPC', program=r'C:\Windows\System32\svchost.exe'),
                             rule('icmp', 'RPC', proto='ICMPv4')]), defs=None)
    terms = doc['filters'][0]['terms']
    assert [t['name'] for t in terms] == ['b', 'a', 'rpc', 'icmp', 'drop-ANY']
    assert terms[2]['destination-port'] == '49152-65535'
    assert 'destination-port' not in terms[3]           # ICMP's stray RPC keyword is not a port
    assert stats['partial'] == 1                        # the program-scoped RPC rule
    doc, stats = convert(fw([rule('a', '80')], enabled='False'), defs=None)
    assert [t['name'] for t in doc['filters'][0]['terms']] == ['firewall-off']
    assert stats['default'] == 'accept'


# --- nftables: firewalld's shape --------------------------------------------

def _r(chain, handle, *expr, table='firewalld', family='inet'):
    return {'rule': {'family': family, 'table': table, 'chain': chain, 'handle': handle,
                     'expr': list(expr)}}


def _dport(proto, port):
    return {'match': {'op': '==', 'left': {'payload': {'protocol': proto, 'field': 'dport'}},
                      'right': port}}


def _saddr(net):
    a, n = net.split('/')
    return {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}},
                      'right': {'prefix': {'addr': a, 'len': int(n)}}}}


def firewalld(extra=()):
    chain = lambda name, **kw: {'chain': dict({'family': 'inet', 'table': 'firewalld', 'name': name}, **kw)}
    ct = lambda states: {'match': {'op': 'in', 'left': {'ct': {'key': 'state'}}, 'right': {'set': states}}}
    return {'nftables': [
        chain('filter_INPUT', hook='input', type='filter', prio=10, policy='accept'),
        chain('filter_IN_public'), chain('filter_IN_public_allow'),
        _r('filter_INPUT', 1, ct(['established', 'related']), {'accept': None}),
        _r('filter_INPUT', 2, ct(['invalid']), {'drop': None}),
        _r('filter_INPUT', 3, {'match': {'op': 'in', 'left': {'ct': {'key': 'status'}}, 'right': 'dnat'}},
           {'accept': None}),
        _r('filter_INPUT', 4, {'jump': {'target': 'filter_IN_public'}}),
        _r('filter_INPUT', 5, {'reject': None}),
        _r('filter_IN_public', 6, {'match': {'op': '==', 'left': {'meta': {'key': 'l4proto'}},
                                             'right': {'set': ['icmp', 'ipv6-icmp']}}}, {'accept': None}),
        _r('filter_IN_public', 7, {'jump': {'target': 'filter_IN_public_allow'}}),
        _r('filter_IN_public_allow', 8, _dport('tcp', 22), {'accept': None}),
        _r('filter_IN_public_allow', 9, _dport('tcp', 9090), {'accept': None}),
        *extra]}


def test_nft_walks_jumps_and_ignores_what_a_new_connection_never_matches():
    doc = firewalld([_r('filter_IN_public_allow', 10, _saddr('10.0.0.0/8'), _dport('tcp', 5432),
                        {'accept': None})])
    assert nfteval.evaluate(doc, 'tcp', 22)[0] == 'open'
    assert nfteval.evaluate(doc, 'tcp', 111)[0] == 'blocked'     # not the ICMP accept, not dnat
    assert nfteval.evaluate(doc, 'tcp', 5432)[0] == 'scoped'
    stale, broad = nfteval.stale_and_broad(doc, [lst(22)])
    assert [(s['ports'], s['squattable']) for s in stale] == [(['9090'], True), (['5432'], True)]
    assert broad == []


def test_no_input_hook_means_nothing_filters():
    assert nfteval.evaluate({'nftables': []}, 'tcp', 80)[0] == 'unknown'


def test_firru_audit_on_raw_windows_loot(tmp_path, capsys, monkeypatch):
    from firru.cli import dispatch
    lh = tmp_path / 'dc01' / 'loot-host'
    lh.mkdir(parents=True)
    (lh / 'connections.csv').write_text(
        '"LocalAddress","LocalPort","RemoteAddress","RemotePort","State","OwningProcess","Protocol"\n'
        '"0.0.0.0","8443","0.0.0.0","0","Listen","4","TCP"\n')
    (lh / 'firewall.json').write_text(json.dumps(fw([rule('hole', '9443')], enabled='False')))
    monkeypatch.chdir(tmp_path)
    assert dispatch.dispatch_argv(['audit', str(tmp_path / 'dc01')]) == 0
    out = capsys.readouterr().out
    assert 'FIREWALL OFF' in out and 'tcp/8443' in out
    assert dispatch.dispatch_argv(['audit', str(tmp_path / 'dc01'), '-o', 'sh']) == 0
    sh = capsys.readouterr().out
    assert all(l.startswith('#') for l in sh.splitlines() if l.strip())   # no policy: comments only
    assert (tmp_path / 'loot' / 'dc01.json').is_file()


def test_rule_diff_against_stock_finds_the_weakening():
    stock = fw([rule('RemoteDesktop-UserMode-In-TCP', '3389', enabled=False),
                rule('FPS-SMB-In-TCP', '445', remote='LocalSubnet'),
                rule('CoreNet-DHCP-In', '68', proto='UDP')])
    host = fw([rule('RemoteDesktop-UserMode-In-TCP', '3389'),
               rule('FPS-SMB-In-TCP', '445'),
               rule('{0E4C8A2B-1111-2222-3333-444455556666}', '22')], enabled='False')
    host['rules'][2]['DisplayName'] = 'OpenSSH SSH Server (sshd)'
    rd = winfw.rule_diff(stock, host)
    assert [n for n, d in rd['profiles']] == ['Domain', 'Private', 'Public']
    assert [r['DisplayName'] for r in rd['added']] == ['OpenSSH SSH Server (sshd)']
    assert [r['Name'] for r in rd['enabled']] == ['RemoteDesktop-UserMode-In-TCP']
    assert [(r['Name'], ks[0][0]) for r, ks in rd['changed']] == [('FPS-SMB-In-TCP', 'RemoteAddress')]
    assert [r['Name'] for r in rd['removed']] == ['CoreNet-DHCP-In']
    match = winfw.layer_matcher({'win_openssh': {'rules': [{'display': '^OpenSSH'}]}})
    assert match(rd['added'][0]) == ['win_openssh']


def test_absent_fields_read_as_any():
    full = fw([rule('ssh', '22'), rule('off', '23', enabled=False),
               rule('icmp', 'Any', proto='ICMPv4')])
    # Older loot lacks fields newer loot-host.ps1 writes; absent means Any.
    compact = {'profiles': full['profiles'], 'interfaces': full['interfaces'], 'rules': [
        {'Name': 'icmp', 'DisplayName': 'icmp', 'Enabled': True, 'Direction': 'Inbound',
         'Action': 'Allow', 'Protocol': 'ICMPv4'},
        {'Name': 'off', 'DisplayName': 'off', 'Enabled': False, 'Direction': 'Inbound',
         'Action': 'Allow', 'Protocol': 'TCP', 'LocalPort': ['23']},
        {'Name': 'ssh', 'DisplayName': 'ssh', 'Enabled': True, 'Direction': 'Inbound',
         'Action': 'Allow', 'Protocol': 'TCP', 'LocalPort': ['22']}]}
    rd = winfw.rule_diff(full, compact)
    assert not any(rd[k] for k in ('added', 'enabled', 'disabled', 'changed', 'removed'))
    assert classes(winfw.exposure(compact, [lst(22), lst(23)])) == \
        classes(winfw.exposure(full, [lst(22), lst(23)]))


def test_rule_diff_ignores_path_case_and_reads_app_rules():
    a = fw([rule('kdc', '88', program=r'C:\Windows\System32\lsass.exe')])
    b = fw([rule('kdc', '88', program=r'C:\WINDOWS\System32\lsass.exe'),
            dict(rule('start'), Group='@{Microsoft.Windows.StartMenu?ms-resource://x}')])
    rd = winfw.rule_diff(a, b)
    assert rd['changed'] == []
    assert rd['added'][0]['Package'] == 'app'


def test_rules_windows_reports_inert_are_ignored():
    wfd = dict(rule('WiFiDirect-KM-Driver-In-TCP', program='System'),
               Enforcement='ProfileInactive NoDynamicTransport', Status='Inactive')
    live = dict(rule('ssh', '22'), Enforcement='Enforced', Status='OK')
    e = winfw.exposure(fw([wfd, live]), [lst(445, name='System'), lst(22)])
    assert classes(e) == {('tcp', 445): 'blocked', ('tcp', 22): 'open'}
    assert winfw.inert(wfd) and not winfw.inert(live)
    assert not winfw.inert(dict(live, Enforcement='ProfileInactive Enforced'))


def test_system_scoped_stale_rules_are_open_to_httpsys_and_owners_resolve():
    f = fw([rule('RemoteDesktop-In-TCP-WSS', '3392', program='System'),
            rule('winrm', '5985', program='System')])
    urls = [{'Port': '5985', 'Url': 'HTTP://+:5985/WSMAN/', 'ProcessId': '1464',
             'Image': r'C:\Windows\System32\svchost.exe'}]
    e = winfw.exposure(f, [lst(5985, name='System')], http_urls=urls)
    assert [(s['rule'], s['squattable']) for s in e['stale']] == [('RemoteDesktop-In-TCP-WSS', 'httpsys')]
    assert e['listeners'][0]['process'] == 'System (HTTP.sys: svchost.exe /WSMAN/)'
