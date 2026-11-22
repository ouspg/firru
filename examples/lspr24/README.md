# LSPR24 case study

firru end to end on a public dataset: real listening sockets and real traffic
in, reviewable firewall policy out, and the gap between what the hosts were
set up to serve and what the network actually did with them.

The data is the Locked Shields Partner Run 2024 release,
[10.5281/zenodo.14900873](https://doi.org/10.5281/zenodo.14900873), CC0: a
flow capture of one blue team's network (~20.2M flows, 2024-03-01..07, with
the asset name of each end) and the Wazuh archive of the same hosts. Neither
file is vendored. Everything derived from them is committed, so the results
below can be read without the 7 GB download; `make all` regenerates all of it.

What it shows:

- **Policy against practice.** On every one of the 54 hosts whose running
  policy can be reconstructed from traffic, SSH admitted more than the sources
  the traffic shows administering the hosts, and 47 had services nobody used.
- **Host state splits what traffic cannot.** The capture names no blocked
  connection. Joined to the hosts' listening tables, 35,499 unanswered IPv4
  flows turn out to be to ports that *were* listening: the enforcement axis.
- **Synthesis on real loot.** 59 hosts, 1,000 sockets, each policy term named by
  a definition with a source, and every port nothing names noted rather than
  opened.
- **Block-early.** Source tightening denies none of the red team's admitted
  traffic; removing never-used services denies 10.9% of it. Everything else
  came in from outside over the public services, which no ingress rule can
  close.

And what it cannot show, stated where it matters below: no deployed
configuration is in the data, the Windows listeners are filled in from
baselines rather than measured, and most clients are unnamed addresses that no
policy can narrow to.

## Run it

Besides firru's own requirements (see its README), `make` and `curl`, and
about 9 GB of disk: 7.8 GB of dataset, the flow store and the outputs.

```sh
git clone https://github.com/ouspg/firru && cd firru
pip install '.[lspr24]'
cd examples/lspr24
make fetch                # the two dataset files from the record, 7.8 GB
make verify-inputs        # the publisher's MD5s, pinned in INPUTS.md5
make all                  # about a minute
make ladder               # the block-early counterfactual
make enforced-diff        # the synthesized policy against what the network did
make hourly               # d2, an hour at a time, against the night-tightened policy
```

`make all` is these steps, each a firru command or a script here:

```sh
cp <firru>/def/{services,windows-services,cloud-native,base-networks}.yml def/
python3 defs_from_expoid.py --parquet data/lspr24_v2.parquet --out def/ \
    --green-label Label_src=2                       # inventory, from the dataset
ossec-to-loot data/ossec-archive-host-logs.json --output loot-ossec/   # real loot
resolve-identity --loot loot-ossec/ --defs def/ --assert identity-assertions.yml
python lspr24_to_flows.py data/lspr24_v2.parquet --store data/flows   # 20M flows, ~20 s
python3 assumptions.py --loot loot-ossec/ --defs def/ --assumptions assumptions.yml \
    --out loot-assumed/ --flows data/flows/ --window night   # all assumed, checked
suggest-services --input loot-assumed/ --defs def/ --yaml def/services-observed.yml
firru synth --input loot-assumed/ --defs def/ --meta def/host_metadata.json \
    --output policies/r1-synthesized/
firru tighten --policy policies/r1-synthesized --defs def/ \
    --window night --outdir policies/r2-tightened      # flows: firru.toml's store
python3 flows_to_enforced.py ... --out policies/r3-apparent/
python3 block_early.py --flows data/flows/ --window night ... --out policies/r4-block-early/
firru merge-zones --hosts 'policies/<variant>/*.yml' --defs def/ --outdir zones/<variant>
```

| directory | what it holds |
| --- | --- |
| `loot-ossec/` | the measured loot, as the archive has it |
| `loot-assumed/` | the same with `assumptions.yml` applied: what the policies are built from |
| `policies/r1-synthesized/` | from the sockets: 460 service terms over 59 hosts |
| `policies/r2-tightened/` | sources narrowed against the night window: 117 terms, each with `# was:`; a term nothing matched says `log-drop candidate`. What the narrowing would deny is `firru diff` with `--flows` |
| `policies/r3-apparent/` | INFERRED from traffic: the policy that appears to have been running |
| `policies/r4-block-early/` | r2 with every service the night window never saw removed: 269 of 460 terms, on 51 hosts |
| `reports/` | precomputed reports, so the results read without the dataset: `hourly/`, one host's d2 an hour at a time (`make hourly`); `check/`, the night-trained policy against d2's first hour (`make check-live`) |
| `zones/<variant>/` | each variant merged per network, the form a firewall takes |

Every policy and zone file compiles with Aerleon against `def/`. Files are
named by inventory token (`dc1_int_beg_05_berylia_org.yml`) rather than the
collector's label, because the label is not unique: this archive has a `DC1`
and a `dc1` that are domain controllers in two different zones.

## What it shows

### The policy against what the network did

There is no deployed configuration in the data, but its effect on traffic is.
`flows_to_enforced.py` renders that as a policy: for each service the loot
confirms was listening, which sources got an answer. `make enforced-diff`
compares it with the synthesized one. One host of the 54 it can be built for:

```
alert-system:
  widened (1) — grants new peers, REVIEW:
    ! allow-tcp-SSH            tcp/22                 source [BGP_5_GT, MGMT_HOSTS] -> ANY
  removed (3) — no longer observed, advisory (scoring vetoes):
    - allow-tcp-REDIS          tcp/6379
    - allow-tcp-TCP_5001       tcp/5001
    - allow-tcp-TCP_5002       tcp/5002
```

All 54 widened terms have that shape: SSH answered sources other than the hosts'
administrators (the green-team hosts and MGMT_HOSTS). Whatever the blue
team ran, it did not restrict administrative access anywhere the capture can
see. The 47 hosts with removed terms are the block-early bet stated per host:
services synthesis has to decide about that no client used.

It is inference, not a recovered configuration: a drop, a host that was down,
an application refusing above the transport and one-sided capture all leave
the same trace. Two guards keep the worst of that out, and the second exists
because the first version got it wrong: a deny needs a refused source, and the
host must have answered on some other port in the same window. Without the
second, the three `fiveg-ue` simulators read as SSH-filtered when they
answered nothing at all. With both, **no inferred deny survives**: every
listening service that was tried answered somebody.

### Host state splits what traffic cannot

LSPR24's `Conn_state` names no blocked connection: `S0` and `REJ` occur zero
times in 20.2M rows, and its IPv6 TCP rows, which carry no flags, could not
show them. What the capture does show is that 38.5% of flows got
nothing back. Joined to the listening tables, that splits in two:

| inbound TCP | family | flows | no reply |
| --- | --- | --- | --- |
| to a port with **no listener** | IPv4 | 1,220,362 | 228,219 (18.7%) |
| | IPv6 | 1,386,236 | 252,612 (18.2%) |
| to a port the loot confirms was **listening** | IPv4 | 1,187,692 | **35,499 (3.0%)** |
| | IPv6 | 418,754 | 43,701 (10.4%) |

Without the loot, the unanswered flows are one pile. With it, 35,499 IPv4 flows
are *something was listening and still did not answer*: the enforcement axis,
recovered from host state the dataset was never asked for. The rate is stable
across the exercise windows (2.9% d1, 3.4% night, 2.8% d2). They stay
candidates rather than denials: no rule can be named as the cause. The IPv6
rows are reported but not relied on: they carry no TCP header (see the limits
below), and their no-reply share rises from 8.0% to 12.1% over the same
windows. `make listening-split` reproduces the table from the measured loot.

### Synthesis on real loot

The Wazuh archive carries the rootcheck `netstat listening ports` check, a
host's whole listening table on every scan, with process names on most of it.
`ossec-to-loot` reads it into 59 hosts and 1,000 sockets: 50 Linux hosts from
netstat, and 8 Windows hosts and one unknown from syscollector, whose 35
observed sockets `assumptions.py` fills in to the stock install of each host's
role (301 listeners, each flagged `inferred`; see the assumptions).
netstat writes a dual-stack socket and an IPv6-only one the same way, so 98
of the sockets are the IPv4 half of an IPv6 wildcard with no IPv4 entry of
its own. 49 of those answered IPv4 in the capture, one was tried and never
answered, and the other 48 saw no IPv4 traffic.

`def/` starts from firru's stock definitions, where every entry cites its
source, so terms carry names like `K8S-KUBELET`, `NODE-EXPORTER`,
`METALLB-MEMBERLIST` and `DNP3` rather than numbers. Where two names claim a
port (Docker Swarm and MetalLB on 7946), the listening process decides. What
nothing names, `suggest-services` writes to `def/services-observed.yml`: 57
ports. Eighteen get a name (nine tokens) from evidence that holds beyond
these hosts: Exchange's internal ports from the stock Exchange baselines, and
Connected Devices Platform from firru's curated table. The other 39 are
`TCP_<port>` or `UDP_<port>`, with the process and host as the only evidence. Another 49 it leaves unnamed on purpose
and lists why: 28 bind only to loopback, so no term could ever match them, and
21 are in the host's dynamic range, where a port is a client socket the
snapshot caught. A tightened
Kubernetes worker reads:

```yaml
# [auto] 377 flows total | 377 hits: k8s-worker02_beg_05_berylia_org (100.97.5.32) | via: NODE-EXPORTER/tcp/9100
      - name: allow-tcp-NODE-EXPORTER
        protocol: tcp
        destination-port: NODE-EXPORTER
        action: accept
        source-address: k8s-worker02_beg_05_berylia_org  # was: ANY_V6
```

### Tightening, and why most terms keep ANY

Tightening narrowed 117 of the 460 terms, onto the green-team hosts, the
cluster members and the zone groups the inventory defines. It never narrows
away a source `def/heuristics.py` declares for the service, such as a zone's
management entry point or its own hosts for NetBIOS: 79 terms keep one the
night never showed. 200 kept `ANY`,
and that is the right answer rather than a failure: their clients are the
exercise's simulated internet, addresses with no asset behind them. An
address resolves to nothing, so the term stays open; minting a token per
address would only look tighter, since the address is a different host next
week.

The durable name for an external peer is a name, not an address. LSPR24
cannot demonstrate that: its flow table carries no DNS payload, and the only
naming material in the record is a few hundred SNI and HTTP host headers in
`eve.log`.

### The next day, an hour at a time

The flows are one store of the whole dataset (`make flows`: 20M flows, 0.4 GB,
written in about 20 seconds), and each command reads the window it is given,
by the names in `firru.toml`. Tightening above is `firru tighten --window
night`. The same store answers the question before a deploy: what would the
tightened policy have done to traffic it was not tightened on?

`make hourly` asks it of five hosts, for each hour of d2 (`hourly.py`, which
is `firru diff --flows` once an hour), and ends with who was cut in most hours.
The results are in [`reports/hourly/`](reports/hourly/). Each host shows a
different kind of miss:

| host | cut on d2 | mostly |
| --- | --- | --- |
| dc1 (Windows DC) | 15,456 flows, 8 peers | the organisers every hour on Kerberos and LDAP, from the DMZ (`BEG_5_GT`), and the other DC, dc2, in 8 of 10 hours |
| salt-master | 1,359 flows, 4 peers | the organisers every hour, and the gas-hmi minion on 4505 in 9 of 10 |
| k8s-worker01 | 155 flows, 1 peer | the cluster's own control plane, on the kubelet, in 7 of 10 hours |
| gas-hmi (OT) | 1,137 flows, 1 peer | its subnet's management entry point, on the HMI's web ports, in 5 of 10 hours |
| www | 5,707 flows, 51 peers | its users: the internet the night did not show; 234 of the flows are red team |

The night is quiet in a way the day is not: it shows the services' own
clients, and not the organisers' daytime checks, the second domain
controller's replication or a control plane's periodic calls. Daytime
administration is not among the cuts: SSH from MGMT_HOSTS and the entry
points is declared, so tightening keeps it whatever the night shows. The
entry point's other traffic is not, which is why gas-hmi's web ports are
still cut. A peer cut in most hours is the window's gap, not noise, and `firru diff -o sh` comments
out a narrowing it contradicts instead of emitting it. On www the cut is the
point only for the red-team share; narrowing a public web server to the
clients of one night closes it to its users.

### The check before a deploy

`make check-live` asks the question to ask before deploying: what would each
host's policy, trained on the night window, refuse of the first live hour,
08:00-09:00 on d2? It is `firru tighten --check`, which reads the whole policy
rather than a change to it, so it also reports traffic to a port no term
covers. The hourly diffs above cannot show that: they compare two policies,
and a port neither has a term for is in neither. The results are in
[`reports/check/`](reports/check/):

| host | refused, 08:00-09:00 | mostly |
| --- | --- | --- |
| dc1 (Windows DC) | 1,216 flows, 21 sources | dynamic RPC from the other DC and 14 domain hosts, the organisers' Kerberos and LDAP from the DMZ, and `tcp/134`, the listener nothing explains |
| k8s-worker01 | 274 flows, 9 sources | the cluster's own traffic: 10249 and IP-in-IP between the nodes, and high ports from the control plane |
| www | 146 flows, 2 sources | HTTP and HTTPS from the internet: its users |
| salt-master | 46 flows, 2 sources | the organisers on 4505 and 9999 |
| gas-hmi (OT) | 41 flows, 2 sources | dynamic RPC from an unnamed host in its subnet and from salt-master |

Each line is a decision for the reviewer before the policy is deployed: a
term or a source to add, or a connection the policy is right to refuse.

dc1's dynamic RPC is the first kind. A domain member reaches a DC's endpoint
mapper and is then handed a port from the dynamic range, which no snapshot of
listening sockets holds, so the loot gives synthesis nothing to write a term
from. A site states it as a rule instead (`dynamic_rules` in its
`heuristics.py`, `firru.src_heuristics`): the DC's dynamic range, from the
domain's members. This example does not, because the capture does not say
who the members are. The beg DCs' Kerberos and LDAP clients are the
workstations, mail and the other DC, but also owncloud, which uses both, and
lemonldapng and k8s-worker02, which bind over LDAP alone. Which of those are
joined to the domain is a site's to state, and the check shows what leaving it
unstated costs.

owncloud's LDAP to dc1 is a source to add, and the plainest case
of what a training window is. owncloud asks dc1 over LDAP 664 times on d1 and
176 times on d2, and dc1 answers 659 of the 849. It never asks at night, so
the policy trained on the night has no owncloud in it, and the first live
hour refuses a client that is there every working day.

### Block-early

`make ladder` synthesizes from the loot, tightens on the attack-free `night`
window, then asks what each variant would have denied on the second execution
day:

```
361 services under policy | sampled 181 | kept ANY 156 | never sampled 180

attacker: 256 admitted tuples      clean: 1,473 admitted tuples
    R2           0  ( 0.0%)            R2          12  ( 0.8%)
    R4          28  (10.9%)            R4         132  ( 9.0%)
    R4+Rh       51  (19.9%)            R4+Rh      235  (16.0%)
```

Source tightening (R2) denies nothing, because 156 of the 181 sampled services
kept `ANY`. All of the gain comes from closing services the window never saw
(R4), which is also what `policies/r4-block-early/` renders per host.

**Where the rest comes in.** The 228 attacker tuples R4 still admits all come
from outside, from 58 red-team addresses: HTTPS (167), HTTP (35) and SSH (23)
on the internet-facing services (www, inventory, imagery, owncloud, nextcloud,
news and the rest). Every one rides a service that kept `ANY` because it
answered the simulated internet overnight; none got through because an
attacker address was in an allowed set. A public web server is open to every
address and the red team arrives on its users' port, so this is where a
firewall stops being the control, and the request path and egress take over.
SSH is the part a firewall can still reach, with an administrative source set.

`Rh`
adds a heuristic that needs no per-service evidence: management ports
reachable only from administrative sources. Those sources are recovered by
observation (a source reaching two or more hosts on a management port in the
quiet window: 16 sources, all of them the organiser's `Label_src=2`
infrastructure), not assumed: on LSPR24 most external SSH is legitimate, so
"management is never reachable from outside" costs far more clean traffic
than attacker traffic it denies.

The clean cost is unfiltered. LSPR24 ships no list of services the scoring
required to stay up, so nothing can be subtracted, and block-early reads
riskier here than it would for a deployment that knew its scored services;
`ladder.py --protected FILE` takes such a list.

The attacker column measures initial access only. `Label` marks red-team
hosts, which are all outside; once the red team works from a compromised
internal host, that host's traffic is labelled clean. Lateral movement inside
the zones is therefore in the clean column, not the attacker one, and this
counterfactual cannot score it.

## Assumptions, and why each holds

Everything here is derived from the two dataset files, except what two
hand-written files say, each entry with its source and reasoning:
`identity-assertions.yml` (which loot file is which host, where the data does
not settle it) and `assumptions.yml` (everything else). `assumptions.py` is the
only code that turns the second into data, and it leaves the measured loot
alone: `loot-ossec/` is what the archive says, `loot-assumed/` is that with the
assumptions applied, and the policies are built from the latter.

| assumption | where | why it holds |
| --- | --- | --- |
| The overnight window is the learning window | `night` in `firru.toml`, read with `--window night` | Red is not scheduled overnight, so the choice does not depend on the dataset's `Label`. It is not literally clean: 863 of its 9.4M flows involve a red-team peer, none reaching a named internal host. |
| Which inventory host each loot file is | `identity-assertions.yml`; `via` in `def/host_metadata.json` | 51 of 59 bind by unique name and 6 by the loot's own address; 2 are asserted, each with its evidence. |
| Each host's dynamic port range | `dynamic_ranges` in `assumptions.yml`; `metadata.ephemeral_source` in the loot | The archive records none. The OS defaults are what every stock install in firru-os-baselines has (102 Linux runs; 19 of 20 Windows runs). `mail` is an Exchange server, and Exchange moves TCP to 6005-64325, as the stock Exchange install shows. |
| The Windows services syscollector never saw change | `windows` in `assumptions.yml`; `inferred` and `inferred_from` on each filled-in listener | Each Windows host is the stock install of its role (DC, CA, Exchange member, domain workstation) plus the layers its traffic shows (OpenSSH, RDP, WinRM), each measured on its own. A listener the stock install bound to its own lab address is bound to the host's addresses instead, both families, since the baseline's addresses say nothing about this network. `assumptions.py --flows` checks it: every port that answered overnight is explained except one: `tcp/134` on both domain controllers, which the green-team checker opens about once a minute (Zeek `RSTO`: the handshake completed, then the checker reset it). Something listened there that neither the loot nor any baseline knows; it is left unexplained rather than assumed, so the policies deny it and tighten's would-block report shows it. |
| The blue team's own management sources | `mgmt_hosts` in `assumptions.yml`, MGMT_HOSTS in `def/networks.yml` | Of the 28 sources answered on SSH or RDP overnight, 25 are the green team, which the inventory names; the interior ones reach 26 hosts each on both, administration as well as scoring. The other three: the DMZ firewall's own address (administration through its NAT) and two exterior addresses. Over all windows 173 internal sources reached SSH or RDP: users and lateral movement inside the zones, not management. |
| Each subnet's management entry point | `zone_mgmt` in `assumptions.yml`; `<ZONE>_MGMT`, or `<ZONE>_<n>_MGMT` where a zone has several, in `def/networks.yml` | The top address of each internal subnet opens SSH, RDP and VNC to the hosts in that subnet and nowhere else, on both days and never at night: 64,159 answered flows from nine addresses, all labelled blue team. No asset is named at any of them, so the data shows that they carry management, not who operates them. |
| Who may administer a host | `def/heuristics.py` | The administrators the traffic shows, per zone: SSH, RDP and WinRM from the zone's green-team hosts, the management entry point of the host's own subnet and MGMT_HOSTS. NetBIOS and WS-Discovery come from the zone's own hosts, since neither has a reason to cross a zone. |
| Who the green team is | `<ZONE>_GT` in `def/networks.yml` | The dataset labels organiser traffic (`Label_src=2`). Used to *name* those hosts, never to score a policy. |
| This site's own services | `def/services-site.yml` | One: Keycloak's cluster transport on udp/46655, seen on the keycloak host and nowhere else. |
| Ports nobody named | `def/services-observed.yml` | Named by a stock-install baseline or firru's curated table where one covers the port; otherwise `TCP_<port>`, with the process and host as the evidence, so the claim is visibly weaker than a registry name. |

The `Label` column is used for nothing else. It is exactly `(Label_src == 1
or Label_dst == 1)`, *the peer is a red-team host*, not any behaviour, so an
allow-list learned from non-red traffic "catches" all red traffic by
construction. The ladder uses it only to say which admitted tuples were the
attacker's.

## What it cannot show

- **No deployed configuration.** R3 is reconstructed from traffic, so what was
  meant cannot be compared with what was deployed. That needs an exercise where
  the policy tree, the deployment and the capture are held together; LSPR24
  shows the gap rather than closing it.
- **Windows loot is filled in, not measured.** The netstat check is a Unix
  rootcheck; Windows sockets come only from syscollector's `dbsync_ports`, a
  stream of changes, so the 8 Windows hosts carry 35 observed sockets between
  them. Their policies rest on the baseline fill above. It is checked against
  the traffic, but a stock install plus layers is still a model of the host,
  and its versions are the baselines' (Server 2022 Standard for Datacenter,
  Windows 11 Pro for Windows 10 and 11 Enterprise N).
- **One team.** The release is one team's network, so nothing here generalizes
  across teams.
- **One day of loot.** The archive covers 2024-03-07, about 15 hours; flows
  span the week, so loot and flows overlap on one day.
- **No TCP header on IPv6.** All 2.41M IPv6 TCP rows have every TCP flag at
  zero and a window of 0: the CICFlowMeter that built the dataset does not
  parse the TCP header on its IPv6 path. Such a row cannot show a handshake or
  a refusal, so `lspr24_to_flows.py` records one as answered only when more
  than one packet came back, and otherwise as unknown, never as refused.

## The inventory

The object model is read out of the dataset's own asset identifiers
(`Expoid_src`/`Expoid_dst`) by `defs_from_expoid.py`: 147 assets in 19 zones,
with short-name aliases where a first label is unambiguous. An address with no
asset behind it stays unnamed on purpose.

**Zones are subnets.** Each internal subnet has its own management entry point,
and every management flow from one reaches a host in its own /24 and no other
(`zone_mgmt` in `assumptions.yml`). So a /24 is a network of its own. The asset
names group hosts more coarsely: `int.beg` holds 10.5.12, 10.5.19 and 10.5.22.
A zone is therefore the named zone where it has one subnet (`baf_int`), and the
named zone with the subnet's third octet where it has several (`beg_int_12`).
The data shows that `int.beg` has three subnets, not what each one is for.

A host with addresses in more than one subnet routes between them: a boundary
device, in no zone. There are nine: the three zone firewalls, `rtu`, and the
5G core (amf, smf, the two UPFs, webui). Each keeps a host policy of its own,
its own input rules, and is where a zone's policy would be enforced, so
`merge-zones` leaves it out of every zone. A subnet whose every member is a
boundary device is a transit network and no zone either: 10.5.16, 10.5.18,
100.99.5 and the firewalls' link networks. `fw2-baf` and `fw1-bgp` are
firewalls by name, but the capture shows each with one address, so they are
one-host zones on their link networks. A host reaching its own firewall
inside a zone meets the firewall's input rules, not the zone's.

| token | holds | use it? |
| --- | --- | --- |
| `beg_int_12` | the zone's address space, as prefixes | rarely |
| `BEG_INT_12_HOSTS` | the hosts that exist, `_WS` and `_GT` by reference | yes: this is what terms name |
| `BEG_INT_12_WS` | its workstations | by reference |
| `BEG_ALL_HOSTS` | every zone of a segment (`beg`) | for segment-wide rules |

The prefix token exists to be had: `merge-zones` asks whether a source falls
inside a zone, which a union of /32s cannot answer. A term sourced from it
would permit all 254 addresses of the subnet, of which 24 are hosts.

**Identity.** Name matching alone binds 51 of the 59 loot hosts. The other 8
are ambiguous rather than missing: `ns1` names a host in each of three zones,
`DC1` and `mail` in two. `resolve-identity` settles 6 of them from the Wazuh
record's `agent.ip` (`DC1` is `10.5.12.2`, the *beg* domain controller), and
`identity-assertions.yml` asks for prose for the other two, because an
assertion that does not carry its evidence reads as a guess a year later.
`siem-server` is the one worth reading: it reports itself as Wazuh agent 000,
the manager, which carries no `agent.ip`, and its sockets say the same
(`wazuh-remoted` on 1514, `wazuh-authd` on 1515). It has no asset record
because it is blue-team infrastructure, not part of the estate, so it gets a
host policy but no zone: `merge-zones` leaves out a host the definitions
cannot address, and says so.

