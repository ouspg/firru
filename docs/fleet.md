# Running firru on a fleet

From nothing to compiled, tightened host firewalls for a set of hosts, then
what they do against an attacker. Every step below runs as written in
`examples/fleet/run.sh`, on four real hosts: stock installs from
[firru-os-baselines](https://github.com/ouspg/firru-os-baselines), each with
one change, so the output quoted here is what you get
(`examples/fleet/expected/`).

| host | what it is | the change |
|---|---|---|
| web1 | Ubuntu 24.04.5 server | Apache (the LAMP task) |
| mon1 | Ubuntu 24.04.5 server | munin-node |
| win1 | Windows Server 2022 | OpenSSH Server |
| dc1  | Windows Server 2022 | domain controller |

```sh
git clone https://github.com/ouspg/firru-os-baselines
git clone https://github.com/ouspg/firru && pip install ./firru
mkdir walk && cd walk
BASELINES=../firru-os-baselines FIRRU=../firru bash ../firru/examples/fleet/run.sh
```

## 1. Collect

Run the collector on every host, as root, and bring each output directory
back as `hosts/<hostname>/loot-host/`:

```sh
sudo scripts/loot-host.sh /tmp/loot         # Linux: the host and every network namespace
powershell -ExecutionPolicy Bypass -File scripts\loot-host.ps1 C:\loot   # Windows, elevated
```

A collection is the listening sockets with their processes, the addresses, the
routes and the firewall as it is running. It takes seconds and is about a
megabyte. Nothing is installed on the host.

## 2. Normalize

```sh
loot-listeners hosts/ --output loot/
```

One JSON document per host. dc1 reports 7,568 ports: the DNS server holds
thousands of UDP sockets for source-port randomization, and the domain
services sit in the dynamic RPC range.

## 3. What the fleet runs beyond stock

A stock install of the same OS and role explains most of what a host listens
on. Compare each host with one, and read only the difference:

```sh
firru diff --baseline baselines/ loot/ \
    --assign 'dc*=win2022-std-desktop-dc-g2' \
    --assign 'win*=win2022-std-desktop-public-g2' \
    --assign '*=ubuntu-24.04.5-server-g1'
```

```
  dc1   = dynamic ports of 9 stock processes: dfsrs/tcp, dns/tcp, dns/udp, lsass/tcp, ...
  (shortened; each host also says which baseline it was compared with)
  mon1  + tcp/4949  munin-node  [world-listen]
  web1  + tcp/80  apache2  [world-listen]
  win1  + tcp/22  sshd  [world-listen]
3 added, 0 widened, 0 other process, 0 missing, across 4 hosts
```

The domain controller's thousands of sockets are all stock. What a person has
to look at is three lines. `baselines/` holds the stock runs, normalized the
same way; `firru loot-diff --baseline list` names those in a clone of
firru-os-baselines. With `-o sh` the same comparison becomes a review script:

```
# firru edit-services add def/funny.yml TCP_4949 4949/tcp  # unnamed: munin-nodex1; 1 host(s)
# + HTTP 80/tcp  (apache2; 1 host(s)) beyond the baseline
# + SSH 22/tcp  (sshd; 1 host(s)) beyond the baseline
firru synth --input loot/ --output policies/staged --defs def --overwrite
```

`docs/fleet-review.md` says how to read and order that review.

## 4. Definitions

firru writes Aerleon policy, so ports and addresses get names. Start from the
definitions firru ships (`def/`: services with a source for every entry, and
the base networks generated policies use), then add the site's own:

```sh
cp -r firru/def def
firru edit-services add def/servers.yml MUNIN 4949/tcp
```

Port 4949 had no name, so the review suggested `TCP_4949`. Naming it is a
decision, once for the fleet: here it is munin, in a file of the site's own.
Then the inventory, `def/networks.yml`: each host's addresses (the walk-through
writes them from the loot) and the groups the site has, here a monitoring host
and an admin network:

```yaml
networks:
  mon1:
    values:
      - address: 192.168.150.169/32
  MONITORING:
    values:
      - address: 192.168.150.250/32
        comment: the munin master
  ADMIN:
    values:
      - address: 192.168.150.0/28
        comment: admin workstations
```

## 5. Synthesize, review, commit

```sh
firru synth --input loot/ --output policies/staged --defs def
```

One policy per host, every term with an `[auto]` line saying what was
listening. A port with no name gets a note, not a term, so nothing is allowed
by accident. Read `policies/staged/`, and commit what you accept to
`policies/pol/`. From here on `policies/pol/` is the reviewed truth and firru
only ever proposes changes to it.

## 6. Traffic

Policies from sockets say what may be reached, not from where. Flows from
Zeek (`zeek-to-flows`), Arkime (`loot-flows`) or conntrack (`loot-conntrack`)
say who did reach it (`docs/flow-record.md`). The walk-through uses made-up
flows (`examples/fleet/make-flows.py`): munin polled by the monitoring host,
SSH from two admin workstations, HTTP from 40 scattered clients.

```sh
firru tighten --policy policies/pol/*.yml --defs def --flows-file flows.jsonl --outdir policies/tightened
firru diff policies/pol/mon1.yml policies/tightened/mon1.yml --defs def --flows flows.jsonl
```

```
mon1:
  narrowed (1) — fewer peers, safe to apply (--narrow):
    > allow-tcp-MUNIN          tcp/4949               source ANY -> MONITORING  observed (288 flows)
  address family (1) — coverage changed:
    # allow-tcp-MUNIN          tcp/4949               v4+v6 -> v4
```

win1's SSH narrows to `ADMIN` the same way. web1 does not change: 40 unrelated
clients have no common source to name, and `ANY` is the honest answer there.
The proposal is written beside the policy, never into it. Note the second line:
both groups are IPv4 only, so the narrowed term no longer admits IPv6.

## 7. Apply what you accept

```sh
firru diff policies/pol/mon1.yml policies/tightened/mon1.yml --defs def -o sh
# firru set-source policies/pol/mon1.yml allow-tcp-MUNIN MONITORING --defs def  # narrowed
```

Each change is one command; keep the ones you accept (`| grep narrowed | sh`)
and commit. `firru diff` exits 1 when there are changes, like `diff`.

## 8. Compile and deploy

```sh
aclgen --base_directory policies/pol --policy_file policies/pol/mon1.yml \
    --definitions_directory def --output_directory out
```

nftables for the Linux hosts, a Windows Firewall script for the Windows ones;
deploy them as you deploy anything else. mon1's munin term:

```
ip saddr 192.168.150.250/32 tcp dport 4949 ct state new accept
```

## 9. Keep checking

Policy and practice drift apart: someone opens a port by hand, a package adds
a listener, a rule is never reloaded. Collect again, and:

- `firru audit LOOT --policy POL` puts a host's sockets, its running firewall,
  its baseline and its reviewed policy side by side. Each of the four tells
  its own story. dc1's stock rules open every directory service to any
  address. mon1 and web1 have no input chain at all, so nothing filters
  inbound. On win1 the running firewall *blocks* the SSH server someone
  installed: OpenSSH added an allow rule for the Private profile, and the
  host's network is Public; seven allow rules have nothing listening behind
  them. Against its stock install each host shows only its one change
  (`+ tcp/22 sshd` on win1), and against its reviewed policy nothing: the
  narrowed sources are the review's, and loot cannot contradict them.
- `firru diff POL nft.json` (or `winfw-to-aerleon` for Windows) compares the
  reviewed policy with the ruleset the host is running.
- `loot-diff OLD NEW` says what opened, closed or changed hands between two
  collections.
- `flow-verdict` marks each flow with the verdict of the policy in force, and
  `aerleon-to-bpf` turns a policy into per-term BPF filters, so a single
  packet a term should not see is a finding.

Every artifact is text in git, so each of these is a diff someone reviews, and
nothing is applied without a person.

## 10. Day 2: an attacker

The next day the same traffic comes back, and with it an attacker
(`make-flows.py 2`). From 203.0.113.99 it scans web1, tries passwords on
win1's SSH and sends requests to web1's web server; then, from web1, it
reaches for mon1's munin port and the domain controller. `flow-verdict`
scores each flow against the policy in force, and against a second one: the
same policy with every term day 1 never used removed (`firru diff
--zero-evidence`, the block-early posture).

```sh
flow-verdict --pol policies/pol --defs def --rt-ips attacker.txt \
    --variant block-early=policies/block-early flows-day2.jsonl > verdict-day2.jsonl
```

The attacker's flows (`rt_src`), counted:

```
host    port flows  reviewed  block-early
dc1      389     6  allow     deny
dc1      445     4  allow     deny
mon1    4949     3  deny      deny
web1     80    30  allow     allow
web1     ...         (the scan: eight ports, each deny)
win1      22   200  deny      deny
```

The narrowing did its job: the passwords never reach win1's SSH, and munin
answers only the monitoring host. web1's web server answers the attacker as
it answers everyone; that is what it is for. The difference between the two
postures is dc1. Nobody used LDAP or SMB on day 1, so the reviewed policy
still has them open from anywhere, and the attacker on web1 gets in.
Block-early would have refused them, and would also refuse the first
legitimate client that needs them, which the learning window did not see.

## 11. Had day 2 been the learning window

```sh
firru tighten --policy policies/staged/*.yml --defs def --flows-file flows-day2.jsonl \
    --outdir policies/learned-day2
firru diff policies/staged/mon1.yml policies/learned-day2/mon1.yml --defs def
```

```
mon1:
  narrowed (1) — fewer peers, safe to apply (--narrow):
    > allow-tcp-MUNIN          tcp/4949               source ANY -> [MONITORING, web1]
```

Tightening learns whatever the window holds. With the attacker in it, the
compromised web1 becomes a legitimate munin client, and win1's SSH cannot
narrow at all: an internet address was among its peers, so it stays `ANY`.
Learn from a window you have reason to trust, and read what tightening
proposes before you accept it.

`examples/fleet-zones/` goes on from here: twelve hosts in four zones, merged
into one policy per zone for the firewall between them.
