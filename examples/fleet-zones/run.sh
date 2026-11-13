#!/bin/bash
# A zoned fleet from stock installs: twelve hosts from firru-os-baselines in
# four zones, synthesized, tightened against made-up traffic, then merged into
# one policy per zone for a central firewall. The runs it uses are copied into
# examples/baselines/. Run from an empty directory:
#   FIRRU=~/firru bash $FIRRU/examples/fleet-zones/run.sh
# Needs firru installed (pip install FIRRU) and aclgen (Aerleon) on PATH.
set -euo pipefail
: "${FIRRU:?a clone of firru (for def/ and this example)}"
BASELINES=${BASELINES:-$FIRRU/examples/baselines}   # or a firru-os-baselines clone
export FIRRU_BASELINES=$BASELINES   # loot-diff and audit pick baselines from these runs only
R=$BASELINES/runs
EX=$FIRRU/examples/fleet-zones
step() { printf '\n== %s\n' "$*"; }

step "1. collect: one loot-host directory per host (here: stock installs)"
take() { mkdir -p "hosts/$1" && cp -r "$R/$2/loot-host" "hosts/$1/"; }
take web1   ubuntu-24.04.5-server+lamp-server-g1         # DMZ
take mail1  ubuntu-24.04.5-server+mail-server-g1
take ns1    almalinux-10.2-dns-server-g1
take dc1    win2022-std-desktop-dc-g3k                   # SERVERS
take files1 win2022-std-desktop-file-g2
take print1 win2022-std-desktop-print-g2
take db1    ubuntu-24.04.5-server+postgresql-server-g1
take smb1   almalinux-10.2-smb-server-g1
take ws1    win11-pro-26300-member-g3                    # CLIENTS
take ws2    ubuntu-24.04.5-desktop-minimal-g1
take ws3    fedora-44-workstation-g1
take jump1  ubuntu-24.04.5-server+openssh-server-g1      # MGMT

step "2. normalize, then what the site changed (configure.py: a stand-in for configured hosts)"
loot-listeners hosts/ --output stock/
python3 "$EX/configure.py" stock/ loot/
loot-diff stock/ loot/ || true

step "3. definitions: firru's services, the site's networks, zones and source policy"
cp -r "$FIRRU/def" def
# The stock installs all sat on one lab network; the zones are this site's,
# so the addresses come from the definitions, not from the loot.
python3 "$EX/make-defs.py" def
cp "$EX/heuristics.py" def/heuristics.py

step "4. synthesize, review, accept"
firru synth --input loot/ --output policies/staged --defs def --meta def/host_metadata.json --overwrite
cp -r policies/staged policies/pol            # the review: here, accept all

step "5. traffic, and what tighten makes of it"
python3 "$EX/make-flows.py" > flows.jsonl
firru tighten --policy policies/pol/*.yml --defs def --flows-file flows.jsonl --outdir policies/tightened
for h in dc1 db1 web1; do
  firru diff policies/pol/$h.yml policies/tightened/$h.yml --defs def --flows flows.jsonl || true
done

step "6. accept the narrowings, then one decision tighten cannot make"
for p in policies/pol/*.yml; do
  h=$(basename "$p" .yml)
  # diff exits 1 when there are changes, grep when a host has none to accept
  { firru diff "$p" policies/tightened/$h.yml --defs def -o sh || true; } | { grep narrowed || true; } | sh
done
# ws2 talked to the database too. Observed is not intended: the app server is.
firru set-source policies/pol/db1.yml allow-tcp-POSTGRES web1

step "7. merge: one policy per zone, for the firewall between them"
firru merge-zones --hosts 'policies/pol/*.yml' --defs def --outdir zones/pol --terminal log-drop
cat zones/pol/SERVERS.yml

step "8. compile: the hosts, and the zones"
mkdir -p out/hosts out/zones
aclgen --base_directory policies --definitions_directory def --output_directory out/hosts > aclgen.log 2>&1 \
  || { cat aclgen.log; exit 1; }
aclgen --base_directory zones --definitions_directory def --output_directory out/zones > aclgen.log 2>&1 \
  || { cat aclgen.log; exit 1; }
ls out/hosts out/zones
