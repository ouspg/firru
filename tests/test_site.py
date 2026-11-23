"""site/: a file that is there is used, a missing one is said once, an empty
one is the site saying none (README.md)."""

import pytest

from firru import project, site_profile
from firru.defs_dir import STOCK


@pytest.fixture
def proj(tmp_path, monkeypatch):
    monkeypatch.delenv("FIRRU_PROJECT", raising=False)
    monkeypatch.setattr(project, "_noted", set())
    (tmp_path / "firru.toml").write_text("")
    (tmp_path / "site").mkdir()
    (tmp_path / "sub").mkdir()
    monkeypatch.chdir(tmp_path / "sub")
    return tmp_path


def test_a_site_file_is_found_from_anywhere_in_the_project(proj):
    (proj / "site" / "host_metadata.json").write_text("{}\n")
    assert project.site_path("host_metadata.json") == "../site/host_metadata.json"


def test_a_missing_site_file_is_said_once_with_its_cost(proj, capsys):
    assert project.site_path("host_metadata.json") is None
    assert project.site_path("host_metadata.json") is None
    err = capsys.readouterr().err
    assert err.count("no site/host_metadata.json") == 1 and "no zones" in err


def test_an_empty_site_file_is_quiet(proj, capsys):
    (proj / "site" / "host_metadata.json").write_text("")
    assert project.site_path("host_metadata.json") == "../site/host_metadata.json"
    assert capsys.readouterr().err == ""


def test_outside_a_project_nothing_is_looked_for_or_said(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("FIRRU_PROJECT", raising=False)
    monkeypatch.chdir(tmp_path)
    assert project.site_path("host_metadata.json") is None
    assert capsys.readouterr().err == ""


def test_site_heuristics_win_over_the_definitions_directorys(proj):
    (proj / "def").mkdir()
    (proj / "def" / "heuristics.py").write_text("MGMT_SERVICES = ['OLD']\n")
    (proj / "site" / "heuristics.py").write_text("MGMT_SERVICES = ['SSH']\n")
    profile = site_profile.load_profile(str(proj / "def"))
    assert profile.mgmt_services == {"SSH"}
    assert profile.origin.endswith("site/heuristics.py")


def test_management_is_read_from_site_policy_first(proj):
    """Who may administer a host is a decision, so site/policy.py may set it;
    heuristics.py still counts where the site has not moved it."""
    (proj / "site" / "heuristics.py").write_text(
        "MGMT_SERVICES = ['SSH']\n"
        "def management_sources(m):\n    return ['OLD']\n")
    (proj / "site" / "policy.py").write_text(
        "def management_sources(m):\n    return ['MGMT_HOSTS']\n")
    profile = site_profile.load_profile(None)
    assert profile.management_sources({}) == ["MGMT_HOSTS"]
    assert profile.mgmt_services == {"SSH"}
    assert profile.policy_origin.endswith("site/policy.py")


def test_a_site_policy_alone_is_a_profile(proj):
    (proj / "site" / "policy.py").write_text("MGMT_SERVICES = ['RDP']\n")
    assert site_profile.load_profile(None).mgmt_services == {"RDP"}


def test_def_heuristics_still_read_where_there_is_no_site_one(proj, capsys):
    (proj / "def").mkdir()
    (proj / "def" / "heuristics.py").write_text("MGMT_SERVICES = ['RDP']\n")
    assert site_profile.load_profile(str(proj / "def")).mgmt_services == {"RDP"}
    assert capsys.readouterr().err == ""


def test_only_the_stock_template_is_having_none(proj, capsys):
    site_profile.load_profile(str(STOCK))
    assert "no site/heuristics.py" in capsys.readouterr().err
