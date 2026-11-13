"""
The unified record, and the wildcard question underneath it.

`address_to_cidr` decides which address families a listener covers, and every
generated accept rule rests on that. It had three wildcard branches, one of
which could never run: `0.0.0.0` was matched by the first branch alongside `*`
and expanded to both families, so the `0.0.0.0`-only branch below was dead code
and every IPv4-only service acquired an IPv6 accept rule.

Measured on the real corpus before the fix: 2,649 phantom `::/0` records across
67 of 168 hosts, `mysqld` on 3306 among them. The whole suite passed throughout,
which is the point of this file.
"""

import pytest

from firru.listeners import address_to_cidr, process_entries


class TestTheThreeWildcardSpellings:
    """`ss` distinguishes them, so firru must not flatten them together.
    From `inet_addr_print` in iproute2 misc/ss.c:

        family == AF_INET                    -> "0.0.0.0"
        AF_INET6, in6addr_any, v6only unset  -> "*"
        AF_INET6, in6addr_any, v6only set    -> "[::]"
    """

    def test_an_ipv4_wildcard_is_ipv4_only(self):
        """The bug. A v4 socket cannot accept v6, and saying it does writes a
        rule for traffic that can never reach the service."""
        assert address_to_cidr("0.0.0.0") == ["0.0.0.0/0"]

    def test_a_bare_star_covers_both(self):
        """Not an ambiguous address: a dual-stack IPv6 socket, which genuinely
        serves IPv4 too. It is the only spelling that covers both."""
        assert address_to_cidr("*") == ["0.0.0.0/0", "::/0"]

    def test_a_bracketed_v6_wildcard_is_ipv6_only(self):
        """`[::]` is written only when v6only is set, so this one really is
        IPv6 and nothing else."""
        assert address_to_cidr("::") == ["::/0"]

    def test_the_three_are_all_different(self):
        """A regression guard with a name. Collapsing any two of these is the
        original bug, and it is an easy one to reintroduce because they look
        interchangeable."""
        got = [address_to_cidr(a) for a in ("0.0.0.0", "*", "::")]
        assert len({tuple(g) for g in got}) == 3

    def test_an_address_with_no_family_information_keeps_both(self):
        """`ANY` comes from `parse_ip_port` when there was no port separator at
        all, so nothing is known. That is the one case where both is right."""
        assert address_to_cidr("ANY") == ["0.0.0.0/0", "::/0"]


class TestLoopbackIsDropped:
    @pytest.mark.parametrize("addr", ["127.0.0.1", "127.0.0.53", "::1",
                                      "::ffff:127.0.0.1"])
    def test_every_spelling_of_loopback(self, addr):
        """Including the v4-mapped form, which appears 31 times in the real
        corpus and is a loopback bind however it is written."""
        assert address_to_cidr(addr) is None

    def test_a_real_address_survives_as_a_host_route(self):
        assert address_to_cidr("10.4.20.5") == ["10.4.20.5/32"]
        assert address_to_cidr("2001:db8::1") == ["2001:db8::1/128"]

    def test_nonsense_is_refused_rather_than_guessed_at(self):
        assert address_to_cidr("not-an-address") is None


class TestItReachesTheGeneratedRecords:
    """Unit-level correctness is not the claim that matters; what reaches the
    policy is."""

    def _entry(self, addr, port=3306, name="mysqld"):
        return {
            "proto": "tcp", "local_address": addr, "local_port": port,
            "pid": "1", "process_info": {"name": name, "cmdline": "", "exe": "",
                                         "services": [], "user": None},
        }

    def test_an_ipv4_only_service_gets_no_ipv6_rule(self):
        out = process_entries([self._entry("0.0.0.0")])
        assert [r["bind_address"] for r in out] == ["0.0.0.0/0"]

    def test_a_dual_stack_service_gets_both(self):
        out = process_entries([self._entry("*")])
        assert [r["bind_address"] for r in out] == ["0.0.0.0/0", "::/0"]

    def test_a_v6only_service_gets_only_the_v6_rule(self):
        out = process_entries([self._entry("::")])
        assert [r["bind_address"] for r in out] == ["::/0"]

    def test_a_host_binding_both_families_separately_still_gets_both(self):
        """The common case, and the reason the bug survived: most services bind
        `0.0.0.0` and `[::]` as two sockets, so the spurious `::/0` from the
        first was deduplicated against the real one from the second and the
        totals looked right."""
        out = process_entries([self._entry("0.0.0.0"), self._entry("::")])
        assert sorted(r["bind_address"] for r in out) == ["0.0.0.0/0", "::/0"]
