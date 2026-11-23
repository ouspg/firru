# LSPR24 case study. Neither input is vendored: the flow parquet and the
# OSSEC archive are ~2.6 GB and ~4.7 GB, so point at your copies.
#
#   make fetch          download the two dataset files from the Zenodo record
#   make verify-inputs  the datasets you fetched are the ones this was built on
#   make all            everything committed here, from those two files
#   make ladder         the block-early counterfactual against red-team traffic
#   make enforced-diff  the synthesized policy against what the network did
#   make hourly         d2 an hour at a time, for the hosts in reports/hourly/
#   make check-live     the night-trained policies against d2's first hour, for
#                       the same hosts, into reports/check/
#
# Committed, because regenerating them needs the 7 GB download and the point
# is that a reader who has not downloaded anything can inspect the output:
# def/ (inventory, read from the dataset), loot-ossec/ (real listening
# sockets, 59 hosts), loot-assumed/ (the same with assumptions.yml applied),
# policies/ and zones/ (the four variants).

# Point these at your copies, e.g. make LSPR24=~/Downloads/lspr24_v2.parquet
LSPR24 ?= data/lspr24_v2.parquet
OSSEC  ?= data/ossec-archive-host-logs.json
# loot-ossec/ is the measured record; loot-assumed/ is it with assumptions.yml
# applied, and everything downstream reads that.
MEASURED ?= loot-ossec
LOOT     ?= loot-assumed
# The window tightening learns from, one of firru.toml's.
LEARN  ?= night

.PHONY: help all clean fetch verify-inputs defs stock-defs services identity assumptions flows tighten block-early enforced enforced-diff merged loot-ossec policies ladder listening-split hourly

# A bare `make` prints the targets above. It used to run the first target,
# `defs`, which rewrites committed definitions and leaves the rest stale.
.DEFAULT_GOAL := help
help:
	@sed -n '/^#   make /p' Makefile

# Network object model from the dataset's own asset identity, replacing the
# flow-derived hostmap and its 893 per-address ext_ tokens.
defs: stock-defs
	python3 defs_from_expoid.py --parquet $(LSPR24) --out def/ \
	    --green-label Label_src=2

# firru's stock definitions, as the fleet walk-through starts from them: every
# entry cites its source. What is this site's own is in def/services-site.yml;
# what the loot shows and nothing names is in def/services-observed.yml
# (`make services`).
STOCK_DEFS = services.yml windows-services.yml cloud-native.yml base-networks.yml
stock-defs:
	@d=$$(python3 -c 'from firru.defs_dir import STOCK; print(STOCK)'); \
	for f in $(STOCK_DEFS); do cp "$$d/$$f" def/; done; \
	echo "stock definitions from $$d: $(STOCK_DEFS)"

# Name the ports the loot shows that no definition file names, so
# terms carry a token rather than a bare number. Depends on the loot, not on
# the parquet. Run it after `loot-ossec`, before `policies`. The baselines are
# the ones firru ships, so another machine's checkout cannot change the names.
services:
	FIRRU_BASELINES=$$(python3 -c 'from firru.defs_dir import STOCK_BASELINE; print(STOCK_BASELINE)') \
	suggest-services --input $(LOOT)/ --defs def/ --yaml def/services-observed.yml

# Bind loot to the inventory by evidence: by name where the collector's label
# is unique, by the host's own address where it is not, by assertion where
# neither settles it. Writes back into def/host_metadata.json, so it runs
# after `defs` and again if `defs` is re-run.
identity:
	resolve-identity --loot $(MEASURED)/ --defs def/ \
	    --assert identity-assertions.yml

# Everything here claims to regenerate from these two files. Run this once
# after downloading; it is not a prerequisite of the other targets because
# hashing 7.4 GB on every invocation is not worth the 30 seconds.
verify-inputs:
	@for f in "$(LSPR24)" "$(OSSEC)"; do \
	  b=$$(basename "$$f"); \
	  want=$$(awk -v b="$$b" '$$2==b {print $$1}' INPUTS.md5); \
	  [ -n "$$want" ] || { echo "$$b: no pinned hash in INPUTS.md5"; exit 1; }; \
	  [ -f "$$f" ] || { echo "$$b: not found at $$f"; exit 1; }; \
	  got=$$(md5sum "$$f" | cut -d" " -f1); \
	  if [ "$$want" = "$$got" ]; then echo "$$b: OK"; \
	  else echo "$$b: MISMATCH (see INPUTS.md5)"; exit 1; fi; \
	done

# The whole chain, in dependency order. Everything committed under def/,
# The two dataset files, from the record itself (7.8 GB); verify-inputs then
# checks them against the publisher's MD5s. A file already here is kept.
ZENODO = https://zenodo.org/api/records/14900873/files
fetch:
	@for f in $(LSPR24) $(OSSEC); do \
	  [ -s "$$f" ] && { echo "have $$f"; continue; }; \
	  mkdir -p "$$(dirname "$$f")"; b=$$(basename "$$f"); \
	  echo "fetching $$b"; curl -fL --retry 3 -o "$$f.part" "$(ZENODO)/$$b/content" && mv "$$f.part" "$$f"; \
	done

# Everything committed is reproduced by this from the two dataset files plus
# the hand-written ones: identity-assertions.yml, assumptions.yml and site/.
all: defs loot-ossec identity assumptions services policies tighten block-early enforced merged


loot-ossec:
	ossec-to-loot $(OSSEC) --output $(MEASURED)/

# Everything the data does not record and the policies need: dynamic ranges,
# the Windows services syscollector never saw change, the blue team's own
# management sources. Each with its source and reasoning in assumptions.yml;
# --flows checks the Windows fill against what answered.
assumptions: flows
	python3 assumptions.py --loot $(MEASURED)/ --defs def/ \
	    --assumptions assumptions.yml --out $(LOOT)/ --flows data/flows/ --window $(LEARN)


# --overwrite because synth skips a host whose policy already exists, which
# makes a re-run after an inventory change silently a no-op.
policies: assumptions services identity
	firru synth --input $(LOOT)/ --defs def/ --overwrite \
	    --meta def/host_metadata.json --output policies/r1-synthesized/

# All of the dataset's flows as the store firru.toml names: 20M flows, 0.4 GB,
# about 20 seconds to rebuild, not committed. Commands then read one window of
# it, so the window is chosen where it is used, not when the file is written.
flows: data/flows/.complete
data/flows/.complete: $(LSPR24)
	rm -rf data/flows
	python lspr24_to_flows.py $(LSPR24) --store data/flows
	touch $@

# Narrow each term's sources to what the learn window shows, and mark the
# rules that never matched as log-drop candidates. The window is
# attack-free, so a source set derived from it is not shaped by the intrusion.
# No --flows-file: with a window and none named, tighten reads firru.toml's
# store.
tighten: flows
	firru tighten --policy policies/r1-synthesized --defs def/ \
	    --window $(LEARN) --outdir policies/r2-tightened --overwrite

# Reconstruct the policy that appears to have been running, from the listening
# table plus which flows got an answer, and diff it against what the sockets
# say should be reachable. INFERRED -- see the script's header.
ENFORCED ?= policies/r3-apparent
enforced:
	python3 flows_to_enforced.py --parquet $(LSPR24) --loot $(LOOT)/ \
	    --defs def/ --out $(ENFORCED)/ --window all

enforced-diff: enforced
	@for f in policies/r1-synthesized/*.yml; do \
	  h=$$(basename "$$f"); \
	  [ -f "$(ENFORCED)/$$h" ] || continue; \
	  firru diff "$$f" "$(ENFORCED)/$$h" --defs def/ --direction in; \
	done

# R4, the block-early bet as policy rather than as a rate: every service the
# learn window showed no client for is removed, not merely narrowed. One pass
# over the flows for all 59 hosts.
block-early: flows
	python3 block_early.py --flows data/flows/ --window $(LEARN) --loot $(LOOT)/ --defs def/ \
	    --policy policies/r2-tightened --out policies/r4-block-early

# Per-zone firewall policy for each variant, which is the form a firewall
# actually takes: one policy per network, not one per host.
merged:
	@for v in r1-synthesized r2-tightened r3-apparent r4-block-early; do \
	  rm -rf "zones/$$v"; \
	  firru merge-zones --hosts "policies/$$v/*.yml" --defs def/ \
	      --outdir "zones/$$v"; \
	done

# The block-early counterfactual: what a stricter variant would have denied,
# and what it would have cost. Reproduces the exercise evaluation's ladder on
# public data -- the counterfactual arm only, since nothing here was deployed.
# The README's table: unanswered inbound TCP, split by whether the measured
# loot says something was listening, and by address family.
listening-split:
	python3 listening_split.py --parquet $(LSPR24) --loot $(MEASURED)/ --defs def/

ladder:
	python3 ladder.py --parquet $(LSPR24) --loot $(LOOT)/ \
	    --learn $(LEARN) --eval d2

# The check before a deploy, an hour at a time: what each host's policy
# tightened on the learn window would have cut from each hour of d2, and who
# was cut in most hours. Committed for a few representative hosts, so the
# result can be read without the dataset: the Windows domain controller, and
# Linux management, OT, web and cluster hosts.
HOURLY_HOSTS ?= dc1_int_beg_05_berylia_org salt-master_beg_05_berylia_org \
    gas-hmi_beg_05_berylia_org www_bgp_05_berylia_org k8s-worker01_beg_05_berylia_org
hourly: flows
	python3 hourly.py --old policies/r1-synthesized --new policies/r2-tightened \
	    --window d2 --defs def/ --out reports/hourly/ $(HOURLY_HOSTS)

# The same check for the policy as a whole: what each host's policy, trained
# on the night window, would refuse of the first hour of live traffic. That
# is `tighten --check`, the question to ask before a deploy, and its answer
# includes ports no term covers, which a diff of two policies cannot show.
LIVE_SINCE ?= d2 08:00
LIVE_UNTIL ?= d2 09:00
check-live: flows
	@mkdir -p reports/check
	@for h in $(HOURLY_HOSTS); do \
	  { echo "# policies/r2-tightened/$$h.yml, trained on the $(LEARN) window,"; \
	    echo "# checked against $(LIVE_SINCE) to $(LIVE_UNTIL) (make check-live)"; \
	    firru tighten --policy policies/r2-tightened/$$h.yml --defs def/ --check \
	        --since "$(LIVE_SINCE)" --until "$(LIVE_UNTIL)" 2>/dev/null; \
	  } > reports/check/$$h.txt; \
	  echo "reports/check/$$h.txt"; \
	done


# Everything `make all` writes, so that `make clean all` followed by
# `git status` shows nothing: the committed outputs are exactly what the two
# dataset files and the hand-written inputs (assumptions.yml,
# identity-assertions.yml, def/services-site.yml, site/) produce. The
# datasets themselves are kept.
clean:
	rm -rf $(MEASURED)/ $(LOOT)/ policies/ zones/ data/flows/ loot-synth/
	rm -f def/networks.yml def/host_metadata.json def/services-observed.yml \
	    $(addprefix def/,$(STOCK_DEFS))
