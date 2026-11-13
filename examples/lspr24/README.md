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
  policy can be reconstructed from traffic, SSH was open wider than the hosts'
  own management model, and 47 had services nobody used.
- **Host state splits what traffic cannot.** The capture names no blocked
  connection. Joined to the hosts' listening tables, 79,200 unanswered flows
  turn out to be to ports that *were* listening: the enforcement axis.
- **Synthesis on real loot.** 59 hosts, 902 sockets, each policy term named by
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
about 15 GB of disk: 7.8 GB of dataset and the outputs.

```sh
git clone https://github.com/ouspg/firru && cd firru
pip install '.[lspr24]'
cd examples/lspr24
make fetch                # the two dataset files from the record, 7.8 GB
make verify-inputs        # the publisher's MD5s, pinned in INPUTS.md5
make all                  # about 10 minutes
make ladder               # the block-early counterfactual
make enforced-diff        # the synthesized policy against what the network did
```

`make all` is these steps, each a firru command or a script here:

```sh
cp <firru>/def/{services,windows-services,cloud-native,base-networks}.yml def/
python3 defs_from_expoid.py --parquet lspr24_v2.parquet --out def/ \
    --green-label Label_src=2                       # inventory, from the dataset
ossec-to-loot ossec-archive-host-logs.json --output loot-ossec/   # real loot
resolve-identity --loot loot-ossec/ --defs def/ --assert identity-assertions.yml
python lspr24_to_flows.py lspr24_v2.parquet --window night > night.jsonl
python3 assumptions.py --loot loot-ossec/ --defs def/ --assumptions assumptions.yml \
    --out loot-assumed/ --flows night.jsonl         # everything assumed, checked
python3 services_from_loot.py --loot loot-assumed/ --defs def/
firru synth --input loot-assumed/ --defs def/ --meta def/host_metadata.json \
    --output policies/r1-synthesized/
firru tighten --policy policies/r1-synthesized --defs def/ \
    --flows-file night.jsonl --outdir policies/r2-tightened
python3 flows_to_enforced.py ... --out policies/r3-apparent/
python3 block_early.py --flows night.jsonl ... --out policies/r4-block-early/
firru merge-zones --hosts 'policies/<variant>/*.yml' --defs def/ --outdir zones/<variant>
```

| directory | what it holds |
| --- | --- |
| `loot-ossec/` | the measured loot, as the archive has it |
| `loot-assumed/` | the same with `assumptions.yml` applied: what the policies are built from |
| `policies/r1-synthesized/` | from the sockets: 468 service terms over 59 hosts |
| `policies/r2-tightened/` | sources narrowed against the night window: 180 terms, each with `# was:`; beside them `*.blocked.yml` (27 hosts: flows the narrowing would deny) and `*.dead.yml` (23 hosts: rules nothing matched) |
| `policies/r3-apparent/` | INFERRED from traffic: the policy that appears to have been running |
| `policies/r4-block-early/` | r2 with every service the night window never saw removed: 277 of 468 terms, on 51 hosts |
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
    ! allow-tcp-SSH            tcp/22                 source BGP_GT -> ANY
  address family (1) — coverage changed:
    # allow-tcp-SSH            tcp/22                 v4 -> v4+v6
  removed (3) — no longer observed, advisory (scoring vetoes):
    - allow-tcp-REDIS          tcp/6379
    - allow-tcp-TCP_5001       tcp/5001
    - allow-tcp-TCP_5002       tcp/5002
```

All 54 widened terms have that shape: SSH answered sources outside the hosts'
management model (the green-team proxies and MGMT_HOSTS). Whatever the blue
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
times in 20.2M rows. What the capture does show is that 38.5% of flows got
nothing back. Joined to the listening tables, that splits in two:

| inbound TCP | flows | no reply |
| --- | --- | --- |
| to a port with **no listener** | 2,606,598 | 480,831 (18.4%) |
| to a port the loot confirms was **listening** | 1,606,446 | **79,200 (4.9%)** |

Without the loot, 560,031 unanswered flows are one pile. With it, 79,200 are
*something was listening and still did not answer*: the enforcement axis,
recovered from host state the dataset was never asked for. The rate is stable
across all three days (4.0 / 5.1 / 4.8%), including 03-07, where loot and flows
overlap exactly. They stay candidates rather than denials: no rule can be
named as the cause.

### Synthesis on real loot

The Wazuh archive carries the rootcheck `netstat listening ports` check, a
host's whole listening table on every scan, with process names on most of it.
`ossec-to-loot` reads it into 59 hosts and 902 sockets: 50 Linux hosts from
netstat, and 8 Windows hosts and one unknown from syscollector, whose 35
observed sockets `assumptions.py` fills in to the stock install of each host's
role (301 listeners, each flagged `inferred`; see the assumptions).

`def/` starts from firru's stock definitions, where every entry cites its
source, so terms carry names like `K8S-KUBELET`, `NODE-EXPORTER`,
`METALLB-MEMBERLIST` and `DNP3` rather than numbers. Where two names claim a
port (Docker Swarm and MetalLB on 7946), the listening process decides. What
nothing names, `services_from_loot.py` writes to `def/services-observed.yml`
as `TCP_<port>`, with the process and host as the only evidence: 57 ports,
most of them Exchange's internal ones. Another 49 it leaves unnamed on purpose
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

Tightening narrowed 180 of the 468 terms, onto the green-team hosts, the
cluster members and the zone groups the inventory defines. 216 kept `ANY`,
and that is the right answer rather than a failure: their clients are the
exercise's simulated internet, addresses with no asset behind them. An
address resolves to nothing, so the term stays open; minting a token per
address would only look tighter, since the address is a different host next
week. Group suggestion fired 19 times, all on the Windows hosts, where several
directory services share one set of clients.

The durable name for an external peer is a name, not an address. LSPR24
cannot demonstrate that: its flow table carries no DNS payload, and the only
naming material in the record is a few hundred SNI and HTTP host headers in
`eve.log`.

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
| The overnight window is the learning window | `lspr24_to_flows.py --window night` | Red is not scheduled overnight, so the choice does not depend on the dataset's `Label`. It is not literally clean: 863 of its 9.4M flows involve a red-team peer, none reaching a named internal host. |
| Which inventory host each loot file is | `identity-assertions.yml`; `via` in `def/host_metadata.json` | 51 of 59 bind by unique name and 6 by the loot's own address; 2 are asserted, each with its evidence. |
| Each host's dynamic port range | `dynamic_ranges` in `assumptions.yml`; `metadata.ephemeral_source` in the loot | The archive records none. The OS defaults are what every stock install in firru-os-baselines has (102 Linux runs; 19 of 20 Windows runs). `mail` is an Exchange server, and Exchange moves TCP to 6005-64325, as the stock Exchange install shows. |
| The Windows services syscollector never saw change | `windows` in `assumptions.yml`; `inferred` and `inferred_from` on each filled-in listener | Each Windows host is the stock install of its role (DC, CA, Exchange member, domain workstation) plus the layers its traffic shows (OpenSSH, RDP, WinRM), each measured on its own. `assumptions.py --flows` checks it: every port that answered overnight is explained except one: `tcp/134` on both domain controllers, which the green-team checker opens about once a minute (Zeek `RSTO`: the handshake completed, then the checker reset it). Something listened there that neither the loot nor any baseline knows; it is left unexplained rather than assumed, so the policies deny it and tighten's would-block report shows it. |
| The blue team's own management sources | `mgmt_hosts` in `assumptions.yml`, MGMT_HOSTS in `def/networks.yml` | Of the 28 sources answered on SSH or RDP overnight, 25 are the green team, which the inventory names; the interior ones reach 26 hosts each on both, administration as well as scoring. The other three: the DMZ firewall's own address (administration through its NAT) and two exterior addresses. Over all windows 173 internal sources reached SSH or RDP: users and lateral movement inside the zones, not management. |
| Who may administer a host | `def/heuristics.py` | Locked Shields' management model: SSH, RDP and WinRM from the zone's green-team band and MGMT_HOSTS; NetBIOS and WS-Discovery from the zone's own hosts, since neither has a reason to cross a zone. |
| Who the green team is | `<ZONE>_GT_OTHER` in `def/networks.yml` | The dataset labels organiser traffic (`Label_src=2`). Used to *name* those hosts, never to score a policy. |
| Where a green-team band would be | `<ZONE>_GT` in `def/networks.yml` | A convention (the top addresses of each subnet), kept apart from `_GT_OTHER` because on this dataset it is wrong: it reaches 0 of the 16 labelled IPv4 hosts. |
| This site's own services | `def/services-site.yml` | One: Keycloak's cluster transport on udp/46655, seen on the keycloak host and nowhere else. |
| Ports nobody named | `def/services-observed.yml` | Named `TCP_<port>` with the process and host as the evidence, so the claim is visibly weaker than a registry name. |

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

## The inventory

The object model is read out of the dataset's own asset identifiers
(`Expoid_src`/`Expoid_dst`) by `defs_from_expoid.py`: 147 assets in 10 zones,
with short-name aliases where a first label is unambiguous. An address with no
asset behind it stays unnamed on purpose.

**Zones, segments, and why terms name `_HOSTS`.** A zone is one network
(`beg_int`); a segment is the zones sharing a name (`beg`). `beg` spans an
interior 10.5.12.0/24 and an exterior 100.97.5.0/24, and the management hosts
of one are not those of the other, so anything scoped to the segment hands
every interior host the exterior's administrators.

| token | holds | use it? |
| --- | --- | --- |
| `beg_int` | the zone's address space, as prefixes | rarely |
| `BEG_INT_HOSTS` | the hosts that exist, `_WS` and `_GT_OTHER` by reference | yes: this is what terms name |
| `BEG_INT_WS` | its workstations | by reference |
| `BEG_ALL_HOSTS` | every zone of a segment | for segment-wide rules |

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

