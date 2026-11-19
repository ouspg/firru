"""suggest-services writing a services file: what gets a name, what stays a
port number, and what is left out."""

import gzip
import json
import subprocess
import sys

import yaml


def loot(tmp_path, name, os_name, ports):
    """ports: [(protocol, port, process, bind)]"""
    d = tmp_path / "loot"
    d.mkdir(exist_ok=True)
    (d / f"{name}.json").write_text(json.dumps({
        "metadata": {"hostname": name, "os": os_name},
        "listen_ports": [{"protocol": p, "port": n, "bind_address": b,
                          "process": {"name": proc}} for p, n, proc, b in ports],
    }))
    return d


def baseline(tmp_path, run, os_name, ports):
    d = tmp_path / "baselines"
    d.mkdir(exist_ok=True)
    doc = {"metadata": {"hostname": run, "os": os_name},
           "listen_ports": [{"protocol": p, "port": n, "bind_address": "0.0.0.0/0",
                             "process": {"name": proc, "services": svc}}
                            for p, n, proc, svc in ports]}
    with gzip.open(d / f"{run}.json.gz", "wt") as f:
        json.dump({"documents": {run: doc}}, f)
    return d


def defs(tmp_path):
    d = tmp_path / "def"
    d.mkdir()
    (d / "services.yml").write_text("services:\n  SSH: [{port: 22, protocol: tcp}]\n")
    (d / "networks.yml").write_text("networks:\n  H: {values: [{address: 10.0.0.1/32}]}\n")
    return d


def run(tmp_path, d, l, *extra, env_baselines=None):
    out = d / "services-observed.yml"
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path),
           "FIRRU_BASELINES": str(env_baselines or tmp_path / "none")}
    r = subprocess.run([sys.executable, "-m", "firru.cli.suggest_services",
                        "--input", str(l), "--defs", str(d), "--yaml", str(out), *extra],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    return out


def services(path):
    return {t: {(e["protocol"], e["port"]) for e in v}
            for t, v in yaml.safe_load(path.read_text())["services"].items()}


def test_a_stock_process_names_the_port_and_a_self_claim_does_not(tmp_path):
    d = defs(tmp_path)
    l = loot(tmp_path, "mail", "windows_server_2022", [
        ("tcp", 475, "MSExchangeDelivery", "0.0.0.0/0"),
        ("tcp", 4505, "salt-master", "0.0.0.0/0")])
    b = baseline(tmp_path, "win2022-exchange-g1", "windows",
                 [("tcp", 475, "MSExchangeDelivery", ["MSExchangeDelivery"])])
    out = run(tmp_path, d, l, env_baselines=b)
    got = services(out)
    assert got["MSEXCHANGEDELIVERY"] == {("tcp", 475)}
    # salt-master names itself, which is a claim these hosts make: a hint only.
    assert got["TCP_4505"] == {("tcp", 4505)}
    assert "SALT-MASTER (derived)" in out.read_text()
    assert "win2022-exchange-g1" in out.read_text()


def test_a_baseline_of_another_os_family_says_nothing(tmp_path):
    d = defs(tmp_path)
    l = loot(tmp_path, "h", "ubuntu_24_04", [("tcp", 475, "MSExchangeDelivery", "0.0.0.0/0")])
    b = baseline(tmp_path, "win2022-exchange-g1", "windows",
                 [("tcp", 475, "MSExchangeDelivery", ["MSExchangeDelivery"])])
    assert "TCP_475" in services(run(tmp_path, d, l, env_baselines=b))


def test_curated_names_hold_without_any_baseline(tmp_path):
    d = defs(tmp_path)
    l = loot(tmp_path, "ws", "windows_11", [("udp", 5050, "svchost", "0.0.0.0/0")])
    assert services(run(tmp_path, d, l))["WINDOWS-CDP"] == {("udp", 5050)}


def test_loopback_only_and_ephemeral_ports_are_listed_not_named(tmp_path):
    d = defs(tmp_path)
    l = loot(tmp_path, "h", "linux", [
        ("tcp", 323, "chronyd", "127.0.0.1/32"),
        ("tcp", 8080, "app", "127.0.0.1/32"), ("tcp", 8080, "app", "10.0.0.1/32"),
        ("tcp", 40000, "client", "0.0.0.0/0"),
        ("tcp", 33060, "mysqld", "0.0.0.0/0")])
    out = run(tmp_path, d, l)
    got = services(out)
    assert "TCP_8080" in got            # bound off-host too, so a term is for it
    assert "TCP_323" not in got and "TCP_40000" not in got
    assert "TCP_33060" in got           # registered inside the range
    text = out.read_text()
    assert "#   tcp/323" in text and "#   tcp/40000" in text


def test_a_token_another_file_defines_is_never_written_again(tmp_path):
    # Aerleon refuses a definitions directory that defines a token twice.
    d = defs(tmp_path)
    (d / "site.yml").write_text("services:\n"
                                "  TCP_4505: [{port: 4505, protocol: tcp}]\n"
                                "  WINDOWS-CDP: [{port: 5050, protocol: udp}]\n")
    l = loot(tmp_path, "h", "windows_11", [
        ("tcp", 4505, "salt-master", "0.0.0.0/0"),
        ("tcp", 5040, "svchost", "0.0.0.0/0")])
    out = run(tmp_path, d, l)
    got = services(out)
    assert "TCP_4505" not in got and "WINDOWS-CDP" not in got
    assert got["TCP_5040"] == {("tcp", 5040)}
    assert "already use WINDOWS-CDP" in out.read_text()
    from aerleon.lib import naming
    naming.Naming(str(d))               # loads: no token defined twice


def test_a_baseline_process_matches_with_or_without_exe(tmp_path):
    d = defs(tmp_path)
    l = loot(tmp_path, "mail", "windows_server_2022",
             [("tcp", 475, "MSExchangeDelivery", "0.0.0.0/0")])
    b = baseline(tmp_path, "win2022-exchange-g1", "windows",
                 [("tcp", 475, "MSExchangeDelivery.exe", ["MSExchangeDelivery"])])
    assert "MSEXCHANGEDELIVERY" in services(run(tmp_path, d, l, env_baselines=b))


def test_no_temporary_directory_is_left_behind(tmp_path):
    import tempfile
    d = defs(tmp_path)
    l = loot(tmp_path, "h", "linux", [("tcp", 4505, "salt-master", "0.0.0.0/0")])
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    out = d / "services-observed.yml"
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "TMPDIR": str(tmpdir),
           "FIRRU_BASELINES": str(tmp_path / "none")}
    subprocess.run([sys.executable, "-m", "firru.cli.suggest_services", "--input", str(l),
                    "--defs", str(d), "--yaml", str(out)], check=True, env=env,
                   capture_output=True)
    assert list(tmpdir.iterdir()) == []


def test_a_rerun_does_not_count_its_own_output_as_a_name(tmp_path):
    d = defs(tmp_path)
    l = loot(tmp_path, "h", "linux", [("tcp", 4505, "salt-master", "0.0.0.0/0")])
    first = run(tmp_path, d, l).read_text()
    assert run(tmp_path, d, l).read_text() == first
