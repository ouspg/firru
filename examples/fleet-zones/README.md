# A zoned fleet from stock installs

Twelve hosts from [firru-os-baselines](https://github.com/ouspg/firru-os-baselines)
in four zones (DMZ, SERVERS, CLIENTS, MGMT), taken from host policy to one
policy per zone for the firewall between them:

```sh
mkdir /tmp/fleet-zones && cd /tmp/fleet-zones
BASELINES=~/firru-os-baselines FIRRU=~/firru bash ~/firru/examples/fleet-zones/run.sh
```

| file | what it stands for |
|---|---|
| `configure.py` | the site's configuration: a stock install answers only on loopback, so PostgreSQL, BIND, Samba, Apache TLS and sshd are opened the way an admin would. Step 2's `loot-diff` lists exactly these changes. |
| `make-defs.py` | the site's networks: a subnet per zone, a token per host, `<ZONE>_HOSTS`, and `host_metadata.json` naming each host's zone |
| `heuristics.py` | the source policy: administration from the jump host only, NetBIOS and discovery inside the zone |
| `make-flows.py` | a day of made-up traffic, fixed seed |

What to look at:

- **Step 5**: dc1's Kerberos, LDAP, SMB and endpoint mapper narrow from `ANY`
  to `CLIENTS_HOSTS`; the web and mail ports stay `ANY`, since their clients
  are the internet.
- **Step 6**: tighten narrows db1's PostgreSQL to `[web1, ws2]`, because ws2
  connected too. What happened is not what is intended, so the review sets it
  to `web1` by hand.
- **Step 7**: `zones/pol/SERVERS.yml`. Intra-zone access is left to the host
  firewalls (NetBIOS gets an explicit deny), addresses in a zone that no policy
  names are dropped, and the rest is logged and dropped (`--terminal
  log-drop`).

The services nobody used are still open from `ANY` in the zone policy: a
stock domain controller listens on more than its clients need, and
review-then-deploy only narrows what traffic exercised. `firru diff
--zero-evidence` emits a `rm` for each of them, the block-early posture, at
the risk of what the window did not see.
