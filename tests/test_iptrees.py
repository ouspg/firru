import textwrap

import pytest

from firru.iptrees import AddressListError, load_trees, ip_in_trees


def _write_yaml(tmp_path, body):
    p = tmp_path / "cidrs.yml"
    p.write_text(textwrap.dedent(body))
    return str(p)


class TestLoadTrees:
    def test_loads_v4_and_v6(self, tmp_path):
        path = _write_yaml(tmp_path, """
            all_rt_ips:
              - 10.0.0.0/24
              - 192.168.1.5
              - 2001:db8::/32
        """)
        pyt4, pyt6 = load_trees(path)
        assert len(pyt4) == 2
        assert len(pyt6) == 1

    def test_custom_key(self, tmp_path):
        path = _write_yaml(tmp_path, """
            watchlist:
              - 172.16.0.0/12
        """)
        pyt4, pyt6 = load_trees(path, key="watchlist")
        assert len(pyt4) == 1

    def test_bare_list(self, tmp_path):
        # No wrapping key at all.
        path = _write_yaml(tmp_path, """
            - 10.0.0.0/24
            - 2001:db8::/32
        """)
        pyt4, pyt6 = load_trees(path)
        assert len(pyt4) == 1 and len(pyt6) == 1

    def test_mapping_with_one_list_is_read_without_naming_the_key(self, tmp_path):
        # The next exercise will not necessarily call it `all_rt_ips`.
        path = _write_yaml(tmp_path, """
            next_exercise_prefixes:
              - 10.0.0.0/24
        """)
        assert len(load_trees(path)[0]) == 1

    def test_one_cidr_per_line(self, tmp_path):
        path = tmp_path / "cidrs.txt"
        path.write_text("10.0.0.0/24\n# a comment\n2001:db8::/32  # trailing\n")
        pyt4, pyt6 = load_trees(str(path))
        assert len(pyt4) == 1 and len(pyt6) == 1

    def test_reading_nothing_raises_instead_of_marking_everything_clean(self, tmp_path):
        # An empty set is not a fact about the traffic. Silently loading zero
        # prefixes would annotate every flow rt_src: false.
        path = _write_yaml(tmp_path, "other: []\n")
        with pytest.raises(AddressListError):
            load_trees(path)

    def test_a_wrong_key_raises_rather_than_returning_empty(self, tmp_path):
        path = _write_yaml(tmp_path, """
            all_rt_ips:
              - 10.0.0.0/24
        """)
        with pytest.raises(AddressListError):
            load_trees(path, key="not_the_key")

    def test_all_entries_unparseable_raises(self, tmp_path):
        path = _write_yaml(tmp_path, """
            all_rt_ips:
              - not-an-ip
              - also-not
        """)
        with pytest.raises(AddressListError) as e:
            load_trees(path)
        assert "not-an-ip" in str(e.value)

    def test_invalid_entry_skipped(self, tmp_path):
        path = _write_yaml(tmp_path, """
            all_rt_ips:
              - 10.0.0.0/24
              - not-an-ip
        """)
        pyt4, _ = load_trees(path)
        assert len(pyt4) == 1


class TestIpInTrees:
    def test_membership(self, tmp_path):
        path = _write_yaml(tmp_path, """
            all_rt_ips:
              - 10.0.0.0/24
              - 2001:db8::/32
        """)
        pyt4, pyt6 = load_trees(path)
        assert ip_in_trees("10.0.0.5", pyt4, pyt6) is True
        assert ip_in_trees("10.0.1.5", pyt4, pyt6) is False
        assert ip_in_trees("2001:db8::dead", pyt4, pyt6) is True
        assert ip_in_trees("2001:dead::1", pyt4, pyt6) is False

    def test_empty_ip(self, tmp_path):
        path = _write_yaml(tmp_path, """
            all_rt_ips:
              - 10.0.0.0/24
        """)
        pyt4, pyt6 = load_trees(path)
        assert ip_in_trees("", pyt4, pyt6) is False
        assert ip_in_trees(None, pyt4, pyt6) is False
