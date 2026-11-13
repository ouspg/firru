#!/bin/bash
# The fleet walk-through of docs/fleet.md, end to end, on four stock hosts
# from firru-os-baselines with one change each. The runs it uses are copied
# into examples/baselines/. Run from an empty directory:
#   FIRRU=~/firru bash $FIRRU/examples/fleet/run.sh
# Needs firru installed (pip install FIRRU) and aclgen (Aerleon, which firru
# depends on) on PATH.
set -euo pipefail
: "${FIRRU:?a clone of firru (for def/ and this example)}"
BASELINES=${BASELINES:-$FIRRU/examples/baselines}   # or a firru-os-baselines clone
export FIRRU_BASELINES=$BASELINES   # loot-diff and audit pick baselines from these runs only
R=$BASELINES/runs
step() { printf '\n== %s\n' "$*"; }

step "1. collect: one loot-host directory per host (here: copied from the baselines)"
take() { mkdir -p "$1/$2" && cp -r "$R/$3/loot-host" "$1/$2/"; }
take hosts web1 ubuntu-24.04.5-server+lamp-server-g1      # Ubuntu + Apache
take hosts mon1 ubuntu-24.04.5-server+munin-node-d3       # Ubuntu + munin-node
take hosts win1 win2022-std-desktop-ssh-g1                # Server 2022 + OpenSSH
take hosts dc1  win2022-std-desktop-dc-g3k                # a domain controller
take stock ubuntu-24.04.5-server-g1 ubuntu-24.04.5-server-g1
take stock win2022-std-desktop-public-g2 win2022-std-desktop-public-g2
take stock win2022-std-desktop-dc-g2 win2022-std-desktop-dc-g2

step "2. normalize"
loot-listeners hosts/ --output loot/
loot-listeners stock/ --output baselines/

step "3. what the fleet runs beyond stock"
firru diff --baseline baselines/ loot/ \
    --assign 'dc*=win2022-std-desktop-dc-g2' --assign 'win*=win2022-std-desktop-public-g2' \
    --assign '*=ubuntu-24.04.5-server-g1' -o sh > review.sh || true
cat review.sh

step "4. definitions: firru's own, then the site's names and networks"
cp -r "$FIRRU/def" def
firru edit-services add def/servers.yml MUNIN 4949/tcp
python3 - <<'PY'
import glob, json
with open("def/networks.yml", "w") as f:
    f.write("networks:\n")
    for p in sorted(glob.glob("loot/*.json")):
        m = json.load(open(p))["metadata"]
        ips = [a.split("/")[0] for a in m["addresses"] if not a.startswith(("127.", "::1", "fe80"))]
        f.write(f"  {m['hostname']}:\n    values:\n" + "".join(f"      - address: {ip}/32\n" for ip in ips))
    f.write("  MONITORING:\n    values:\n      - address: 192.168.150.250/32\n        comment: the munin master\n")
    f.write("  ADMIN:\n    values:\n      - address: 192.168.150.0/28\n        comment: admin workstations\n")
PY

step "5. synthesize, review, accept"
firru synth --input loot/ --output policies/staged --defs def --overwrite
cp -r policies/staged policies/pol            # the review: here, accept all

step "6. traffic, and what it says about the sources"
python3 "$FIRRU/examples/fleet/make-flows.py" > flows.jsonl
firru tighten --policy policies/pol/*.yml --defs def --flows-file flows.jsonl --outdir policies/tightened
for h in mon1 win1 web1 dc1; do
  firru diff policies/pol/$h.yml policies/tightened/$h.yml --defs def --flows flows.jsonl || true
done

step "7. apply the narrowings you accept"
for h in mon1 win1 dc1; do
  # diff exits 1 when there are changes, like diff(1)
  { firru diff policies/pol/$h.yml policies/tightened/$h.yml --defs def -o sh || true; } | grep narrowed | sh
done

step "8. compile, and a detector for each restricted term"
mkdir -p out
for p in policies/pol/*.yml; do
  aclgen --base_directory policies/pol --policy_file "$p" --definitions_directory def \
      --output_directory out > aclgen.log 2>&1 || { cat aclgen.log; exit 1; }
  aerleon-to-bpf --policy "$p" --defs def > "out/$(basename "$p" .yml).bpf"
done
ls out

step "9. and keep checking: each host against its running firewall"
# Each against the stock install step 3 compared it with. (Left out, audit
# takes the closest run; here that would be the host's own, as these hosts
# are baseline runs.)
for hb in dc1=win2022-std-desktop-dc-g2 win1=win2022-std-desktop-public-g2 \
          mon1=ubuntu-24.04.5-server-g1 web1=ubuntu-24.04.5-server-g1; do
  h=${hb%%=*}
  firru audit hosts/$h/loot-host --baseline "${hb#*=}" --policy policies/pol/$h.yml --defs def || true
done

step "10. day 2: the policy against an attacker"
python3 "$FIRRU/examples/fleet/make-flows.py" 2 > flows-day2.jsonl
# The attacker's addresses, web1's too once it is theirs. A real list comes
# from the incident, or from an exercise's red team.
printf '203.0.113.99/32\n192.168.150.126/32\n' > attacker.txt
# block-early: the reviewed policy without the terms day 1 never used.
rm -rf policies/block-early && cp -r policies/pol policies/block-early
for p in policies/pol/*.yml; do
  { firru diff "$p" "$p" --defs def --flows flows.jsonl --zero-evidence -o sh || true; } \
    | { grep zero-evidence || true; } | sed 's#policies/pol/#policies/block-early/#' | sh > /dev/null
done
flow-verdict --pol policies/pol --defs def --rt-ips attacker.txt \
    --variant block-early=policies/block-early flows-day2.jsonl > verdict-day2.jsonl
python3 - <<'PY'
import collections, json
rows = collections.Counter()
for line in open("verdict-day2.jsonl"):
    f = json.loads(line)
    if f.get("rt_src"):
        rows[(f["host"], f["dst_port"], f["policy_verdict"], f.get("verdict_block-early"))] += 1
print(f"{'host':6} {'port':>5} {'flows':>5}  reviewed  block-early")
for (host, port, rev, early), n in sorted(rows.items()):
    print(f"{host:6} {port:>5} {n:>5}  {rev:9} {early}")
PY

step "11. and had day 2 been the learning window"
firru tighten --policy policies/staged/*.yml --defs def --flows-file flows-day2.jsonl \
    --outdir policies/learned-day2 > /dev/null 2>&1
for h in mon1 win1 dc1; do
  firru diff policies/staged/$h.yml policies/learned-day2/$h.yml --defs def || true
done
