# firru

firru derives host firewall policy from what the hosts actually run, then keeps
checking the two against each other. It reads the listening sockets of every
host and network namespace, writes them as reviewable
[Aerleon](https://github.com/aerleon/aerleon) policy, narrows each rule's
sources from observed traffic, and compares the result with the firewall the
host is running and with the flows that happened. Every artifact is plain text
in git, and the diff between two of them is the finding.

firru is the companion tool to the paper *firru: A Continuous Pipeline for
Making Firewall Policy Meet Practice*, which describes the method and evaluates
it at Locked Shields 2026, the live-fire cyber defense exercise of the NATO
CCDCOE. See [Citing](#citing).

## See it work

Two examples show the result before the method does.

**Four hosts, three lines** ([docs/fleet.md](docs/fleet.md), scripted in
`examples/fleet/run.sh`). A domain controller reports 7,568 listening ports. A
stock install of the same role explains all of them, so the difference for the
whole fleet is three lines: Apache on one host, munin on another, OpenSSH on a
third. A reviewer turns those three into firewall rules and reads nothing else.

**A real exercise network** ([examples/lspr24/](examples/lspr24/), public CC0
data from the Locked Shields 2024 partner run). firru read real listening-socket
logs and 20.2M flows, wrote policy, and compared the policy with what the
network did. SSH was open wider than the hosts' own management model on all 54
hosts whose policy can be reconstructed, and 47 of them ran services nobody
used. Removing the unused services would have blocked 10.9% of the red team's
admitted traffic, and narrowing sources would have blocked none. The rest came
in over public services that no ingress rule can close. The derived results are
committed, so they can be read without the 7 GB download.

## How it works

1. **Observe.** `scripts/loot-host.sh` (Linux) and `scripts/loot-host.ps1`
   (Windows) record the listening sockets with their owning processes,
   addresses, routes and the running firewall, for the host and every network
   namespace on it. `loot-listeners` normalizes the result. To try firru
   without running a collector, save `ss -tulnpe` as `hosts/<hostname>/ss`.
   That is the same socket table, minus the namespaces, the running firewall
   and the fuller process detail.
2. **Annotate.** Addresses resolve to Aerleon network tokens from your
   definitions, ports to service tokens from `def/`.
3. **Synthesize.** `firru synth` writes one Aerleon policy per host. A port it
   cannot name gets a note instead of a term, so nothing is allowed by accident,
   and a known port held by an unexpected process is flagged on its term.
   Sources are `ANY` unless a profile, `heuristics.py` in your definitions,
   says who may reach what; `def/heuristics.py` is a commented template.
4. **Tighten.** `firru tighten` narrows `ANY` sources to the peers seen in
   traffic. Its proposals are written beside the reviewed policy, never into it.
5. **Validate.** `firru diff` shows what a proposal changes and, given flows,
   which of them it would block. `aerleon-to-bpf` compiles a policy into one
   BPF filter per term, so a single matching packet flags a violation.

A person reviews and commits every change. `firru diff -o sh` writes the change
as runnable `firru` commands, so a reviewer can apply a subset with `grep`.

## Quick start

To look first, save the output of one read-only command:

```sh
mkdir -p hosts/web1
sudo ss -tulnpe > hosts/web1/ss
```

It prints the host's listening sockets and the process behind each, which is
enough input for `loot-listeners` and `firru synth`. Root is needed only for the
process names: as an ordinary user, `ss` left 16 of 33 sockets on one laptop
unnamed.

The collector below adds the network namespaces, the running firewall and fuller
process detail, all of which the drift and audit steps need. It is one shell
script. It reads, and it writes one directory. Its header lists every command it
runs and everything it collects, so a reader, or a model asked to check it, can
verify it before running it as root.

```sh
# on each host, as root; bring the directory back as hosts/<hostname>/loot-host/
sudo scripts/loot-host.sh /tmp/loot-web1
# on Windows, as Administrator (a PoSh-R2 directory under hosts/<hostname>/ works too)
powershell -ExecutionPolicy Bypass -File scripts\loot-host.ps1 C:\loot-win1

loot-listeners hosts/ --output loot/
firru synth --input loot/*.json --defs def --output policies/staged/

# review policies/staged/, commit what you accept to policies/pol/; flows from
# the collector's conntrack snapshot, or from Zeek or Arkime (below), then
loot-conntrack hosts/web1/loot-host/conntrack > flows.jsonl
firru tighten --policy policies/pol/*.yml --defs def \
    --flows-file flows.jsonl --outdir policies/tightened/
firru diff policies/pol/web1.yml policies/tightened/web1.yml \
    --defs def --flows flows.jsonl
firru diff policies/pol/web1.yml policies/tightened/web1.yml \
    --defs def -o sh | grep narrowed | sh

# compile what is committed
aclgen --base_directory policies --definitions_directory def --output_directory out/
```

`def/` is an Aerleon definitions directory. Start it from the service
definitions firru ships in its own `def/` (services that cite a source for every
entry, and the base networks generated policies name), and add your own
`networks.yml`. aclgen compiles the reviewed policies to nftables or Windows
Firewall; it reads every directory named `pol` below `--base_directory`, so
point it at `policies/`, not `policies/pol/`, or it finds nothing and says so
only in its log.

## Drift and conformance

- `firru diff POLICY nft.json` compares a committed policy with the nftables
  ruleset `loot-host.sh` collected; `winfw-to-aerleon` reads a running Windows
  Firewall the same way. A difference is reported for review, never applied.
- `loot-diff OLD NEW` reports what opened, closed or changed hands between two
  collections. With `--baseline REF` it compares a host with a stock install
  of its operating system from
  [firru-os-baselines](https://github.com/ouspg/firru-os-baselines)
  (`$FIRRU_BASELINES`).
- `firru audit LOOT --policy POL` puts one host's sockets, running firewall,
  baseline and reviewed policy side by side.
- `flow-verdict` marks each flow with the verdict of the policy in force and
  whether the listener answered.

Flows come from Arkime (`loot-flows`), Zeek (`zeek-to-flows`) or conntrack
(`loot-conntrack`). All three write the record described in
`docs/flow-record.md`.

## Windows hosts: a role and the residual

A stock Windows server listens on hundreds of ports, and what it is for (a
domain controller, a CA) is better said once, by a person, than synthesized
port by port. `loot-diff --baseline REF LOOT --residual DIR` cuts a host's loot
to what its stock install does not explain; `firru synth --input DIR --role
'dc*=roles/dc.yaml'` puts a curated role, an Aerleon file of `terms:`, before
what it synthesizes from the rest. A port the role covers gets no second term.
Role terms scoped to a program, service or dynamic RPC (`windows-program`,
`windows-service`, `windows-rpc`) need the fork's `upstream-windows-rpc` branch, tagged for this release
(`pip install git+https://github.com/ppietikainen/aerleon@firru-1.0.0-windows-rpc`);
synth warns when the installed Aerleon would compile them unscoped.

## More commands

Each takes `--help`.

- `firru apply POL --from NEW`: merge a generated policy's changes onto the
  reviewed one, three-way with `--base OLD`; narrowings with `--narrow`,
  removals with `--prune`, widenings never.
- `firru set-source`, `firru set-dest`, `firru rm`: one edit to one term, the
  commands `firru diff -o sh` writes. `firru mass` runs a stream of them in one
  process.
- `firru merge-zones`: per-host policies into per-zone policy;
  `aerleon-to-nftables` renders zones as nftables chain fragments.
- `nft-to-aerleon`: a running nftables ruleset back into policy YAML.
- `audit-services`: the ports `def/` cannot name. `firru edit-services` adds
  or removes a service token; `firru annotate-services` refreshes the evidence
  note on each.
- `firru baseline-synth CHECKOUT`: rebuild the shipped `baseline/` records
  from a firru-os-baselines checkout.
- `firru stance POLICY...`: which enforcement stage each policy is at
  (log-accept, log-drop or drop), read-only; `-o json` for scripts.
- `ossec-to-loot`, `resolve-identity` and `examples/lspr24/lspr24_to_flows.py`:
  the case study's inputs (`examples/lspr24/`).
- `scripts/conn-audit.sh`, `scripts/conn-audit.ps1`: which process connected
  where, collected beside `loot-host/`. Nothing in firru 1.0 reads it yet;
  `firru tighten` builds egress terms from flows.

## Status

The paper evaluates the five stages with Arkime traffic, on Linux and Windows
hosts. Implemented since, but not yet evaluated: collection of running
nftables and Windows Firewall rule sets, conformance over Zeek and conntrack
flows, an enforcement probe (`policy-to-nmap`), the process-mismatch flag, and
comparison against stock operating system baselines.

## Install

Python 3.11 or later, and git: pip fetches the Aerleon fork from it.

```sh
pip install .              # extras: [parquet] flow stores, [asn] ASN grouping, [lspr24] the case study, [test]
```

firru depends on a fork of Aerleon: 1.18.0 plus fixes not yet merged upstream.
`tests/test_aerleon_upstream.py` lists what firru needs from it; when that file
passes on an Aerleon release, firru will depend on the release.

## Documentation

- `docs/fleet.md`: a fleet from first collection to compiled, tightened
  firewalls, step by step on four public hosts (`examples/fleet/run.sh`).
- `examples/lspr24/`: a case study on a public exercise dataset (CC0): real
  loot and traffic, the policy against what the network did, and block-early.
- `docs/fleet-review.md`: reading a fleet against stock baselines.
- `docs/comment-contract.md`: how generators and people share a policy file.
- `docs/flow-record.md`: the flow record every source writes.

## Tests

```sh
pip install '.[test]' && pytest
```

The tests use synthetic fixtures only. firru ships no capture data.

## Citing

<!-- Fill in on publication: the DTRAP reference, or the self-archived/arXiv one if DTRAP is delayed. -->

*firru: A Continuous Pipeline for Making Firewall Policy Meet Practice.*
Reference to follow on publication.

## License

Apache License 2.0 (`LICENSE`), the same as Aerleon. firru's changes to
Aerleon itself are contributed upstream.
