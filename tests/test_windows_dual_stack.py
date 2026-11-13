"""A Windows `::` listener without an IPv4 sibling is dual-stack (GOAD srv02, 2026-10-16)."""
from firru.listeners import process_entries, windows_dual_stack


def e(proto, la, port, name='System'):
    return {'proto': proto, 'local_address': la, 'local_port': port, 'pid': 4,
            'process_info': {'name': name}}


def binds(entries, port):
    return sorted(r['bind_address'] for r in process_entries(windows_dual_stack(entries))
                  if r['port'] == port)


def test_kernel_listener_on_v6_wildcard_alone_serves_both_families():
    # SMB as loot-host.ps1 sees it: one row, on ::. nmap over IPv4 finds it open.
    assert binds([e('TCP', '::', 445)], 445) == ['0.0.0.0/0', '::/0']


def test_v6_wildcard_with_its_own_ipv4_bind_is_left_alone():
    # svchost RPC binds both itself; the :: row is the IPv6 half only.
    rows = [e('TCP', '0.0.0.0', 135, 'svchost'), e('TCP', '::', 135, 'svchost')]
    assert binds(rows, 135) == ['0.0.0.0/0', '::/0']


def test_a_specific_ipv4_bind_also_counts_as_the_ipv4_half():
    rows = [e('UDP', '192.168.56.10', 53, 'dns'), e('UDP', '::', 53, 'dns')]
    assert binds(rows, 53) == ['192.168.56.10/32', '::/0']


def test_protocols_are_paired_separately():
    # A UDP IPv4 socket on 445 is not the IPv4 half of the TCP one.
    rows = [e('UDP', '0.0.0.0', 445), e('TCP', '::', 445)]
    tcp = sorted(r['bind_address'] for r in process_entries(windows_dual_stack(rows))
                 if r['protocol'] == 'tcp')
    assert tcp == ['0.0.0.0/0', '::/0']


def test_entries_are_not_mutated():
    row = e('TCP', '::', 80)
    windows_dual_stack([row])
    assert row['local_address'] == '::'
