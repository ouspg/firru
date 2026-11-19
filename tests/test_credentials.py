"""Credentials from netrc: owner-only, by host, the command line first."""

import os

import pytest
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from firru import credentials

FILE = """\
machine arkime.example login firru password one
machine other.example login else password two
"""


@pytest.fixture
def creds(tmp_path, monkeypatch):
    p = tmp_path / "netrc"
    p.write_text(FILE)
    os.chmod(p, 0o600)
    monkeypatch.setenv("NETRC", str(p))
    return p


def test_an_entry_is_found_by_host(creds):
    assert credentials.lookup("http://arkime.example:8005/api") == ("firru", "one")
    assert credentials.lookup("https://other.example/x") == ("else", "two")
    assert credentials.lookup("http://unknown.example:8005/api") is None


def test_a_file_others_can_read_is_refused(creds):
    os.chmod(creds, 0o644)
    with pytest.raises(ValueError, match="chmod 600"):
        credentials.lookup("http://arkime.example:8005/api")


def test_no_file_is_no_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("NETRC", str(tmp_path / "absent"))
    assert credentials.lookup("http://arkime.example:8005/api") is None


def test_the_file_fills_in_what_the_command_line_did_not_say(creds):
    a = credentials.http_auth("http://arkime.example:8005/api", prompt=False)
    assert isinstance(a, HTTPDigestAuth) and (a.username, a.password) == ("firru", "one")
    a = credentials.http_auth("http://arkime.example:8005/api", basic=True, prompt=False)
    assert isinstance(a, HTTPBasicAuth)


def test_a_password_on_the_command_line_wins_and_the_file_is_not_read(creds):
    os.chmod(creds, 0o644)        # would be refused if it were read
    a = credentials.http_auth("http://arkime.example:8005/api", user="me",
                              password="given", prompt=False)
    assert (a.username, a.password) == ("me", "given")


def test_the_project_names_the_netrc_and_netrc_env_wins(tmp_path, monkeypatch):
    p = tmp_path / "named"
    p.write_text("machine arkime.example login named password three\n")
    os.chmod(p, 0o600)
    monkeypatch.delenv("NETRC", raising=False)
    assert credentials.lookup("http://arkime.example/api", str(p)) == ("named", "three")
    monkeypatch.setenv("NETRC", str(tmp_path / "absent"))
    assert credentials.lookup("http://arkime.example/api", str(p)) is None


def test_firru_toml_names_a_service_url_auth_and_netrc(tmp_path):
    from firru.project import load
    (tmp_path / "firru.toml").write_text(
        '[arkime]\nurl = "http://a:8005/api"\nauth = "basic"\nnetrc = "~/.netrc-a"\n')
    a = load(tmp_path).arkime
    assert (a.url, a.auth, a.netrc) == ("http://a:8005/api", "basic", "~/.netrc-a")
    assert load(tmp_path).service("opnsense") is None
    (tmp_path / "firru.toml").write_text('[arkime]\nurl = "http://a"\nauth = "ntlm"\n')
    with pytest.raises(ValueError, match="digest, basic"):
        load(tmp_path)
    (tmp_path / "firru.toml").write_text('[arkime]\nauth = "basic"\n')
    with pytest.raises(ValueError, match="needs a url"):
        load(tmp_path)
