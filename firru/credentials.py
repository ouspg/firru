"""Credentials for the services a project names, kept out of the project.

A project is copied and shared, so a password never goes in its firru.toml.
It goes in a netrc file of your own, the format curl and git read too:
$NETRC if set, else the file the project's firru.toml names (`netrc`), else
~/.netrc.

    machine arkime.example login firru password ...

An entry is found by the URL's host name. The file is refused if anyone but
its owner can read it.
"""

import netrc
import os
import pathlib
import stat
from urllib.parse import urlparse


def path(named=None):
    return pathlib.Path(os.environ.get("NETRC") or named or "~/.netrc").expanduser()


def lookup(url, named=None):
    """(login, password) for `url`'s host, or None. Raises ValueError when the
    file is readable by anyone but its owner, or does not parse."""
    p = path(named)
    if not p.is_file():
        return None
    mode = p.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError(f"{p} is readable by others (mode {stat.S_IMODE(mode):o}); "
                         f"chmod 600 it")
    try:
        entry = netrc.netrc(str(p)).authenticators(urlparse(url).hostname or "")
    except netrc.NetrcParseError as e:
        raise ValueError(f"{p}: {e}") from None
    return (entry[0], entry[2]) if entry else None


def http_auth(url, user=None, password=None, basic=False, prompt=True, netrc=None):
    """A requests auth for `url`: what the command line gave, else the netrc
    entry for its host (`netrc` names the file, as path() reads it), else a
    prompt. Digest unless `basic`."""
    from requests.auth import HTTPBasicAuth, HTTPDigestAuth
    if password is None:
        entry = lookup(url, netrc)
        if entry:
            user = user or entry[0]
            password = entry[1]
    user = user or "admin"
    if password is None and prompt:
        import getpass
        password = getpass.getpass(f"Password for {user} at {url}: ")
    return (HTTPBasicAuth if basic else HTTPDigestAuth)(user, password)
