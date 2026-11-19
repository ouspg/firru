# LSPR24 case study. Neither input is vendored: the flow parquet and the
# OSSEC archive are ~2.6 GB and ~4.7 GB, so point at your copies.
#
#   make fetch          download the two dataset files from the Zenodo record
#   make verify-inputs  the datasets you fetched are the ones this was built on
#   make all            everything committed here, from those two files
#   make ladder         the block-early counterfactual against red-team traffic
#   make enforced-diff  the synthesized policy against what the network did
#   make hourly         d2 an hour at a time against the night-tightened policy
#
# Committed, because regenerating them needs the 7 GB download and the point
# is that a reader who has not downloaded anything can inspect the output:
# def/ (inventory, read from the dataset), loot-ossec/ (real listening
# sockets, 59 hosts), loot-assumed/ (the same with assumptions.yml applied),
# policies/ and zones/ (the four variants).

# Point these at your copies, e.g. make LSPR24=~/Downloads/lspr24_v2.parquet
LSPR24 ?= lspr24_v2.parquet
OSSEC  ?= ossec-archive-host-logs.json
# loot-ossec/ is the measured record; loot-assumed/ is it with assumptions.yml
# applied, and everything downstream reads that.
MEASURED ?= loot-ossec
LOOT     ?= loot-assumed
# The window tightening learns from, one of firru.toml's.
LEARN  ?= night

.PHONY: all clean fetch verify-inputs defs stock-defs services identity assumptions flows tighten block-early enforced enforced-diff merged loot-ossec policies ladder listening-split hourly

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
	  echo "fetching $$f"; curl -fL --retry 3 -o "$$f.part" "$(ZENODO)/$$f/content" && mv "$$f.part" "$$f"; \
	done

# Everything committed is reproduced by this from the two dataset files plus
# the two hand-written ones, identity-assertions.yml and assumptions.yml.
all: defs loot-ossec identity assumptions services policies tighten block-early enforced merged


loot-ossec:
	ossec-to-loot $(OSSEC) --output $(MEASURED)/

# Everything the data does not record and the policies need: dynamic ranges,
# the Windows services syscollector never saw change, the blue team's own
# management sources. Each with its source and reasoning in assumptions.yml;
# --flows checks the Windows fill against what answered.
assumptions: flows
	python3 assumptions.py --loot $(MEASURED)/ --defs def/ \
	    --assumptions assumptions.yml --out $(LOOT)/ --flows flows/ --window $(LEARN)


# --overwrite because synth skips a host whose policy already exists, which
# makes a re-run after an inventory change silently a no-op.
policies: assumptions services identity
	firru synth --input $(LOOT)/ --defs def/ --overwrite \
	    --meta def/host_metadata.json --output policies/r1-synthesized/

# All of the dataset's flows as the store firru.toml names: 20M flows, 0.4 GB,
# about 20 seconds to rebuild, not committed. Commands then read one window of
# it, so the window is chosen where it is used, not when the file is written.
flows: flows/.complete
flows/.complete: $(LSPR24)
	rm -rf flows
	python lspr24_to_flows.py $(LSPR24) --store flows
	touch $@

# Narrow each term's sources to what the learn window shows, and report what
# that would have blocked and which rules never matched. The window is
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
	python3 block_early.py --flows flows/ --window $(LEARN) --loot $(LOOT)/ --defs def/ \
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

# The check before a deploy, an hour at a time: what the policy tightened on
# the night would have done to each hour of d2, for one host. A narrowing the
# hour's traffic contradicts would have cut those flows.
HOST ?= dc1_int_beg_05_berylia_org
hourly: flows
	@for h in 08 09 10 11 12 13 14 15 16 17; do \
	  next=$$(printf %02d $$((10#$$h + 1))); \
	  echo "d2 $$h:00-$$next:00"; \
	  firru diff policies/r1-synthesized/$(HOST).yml policies/r2-tightened/$(HOST).yml \
	      --defs def/ --direction in --since "d2 $$h:00" --until "d2 $$next:00" \
	    | sed -nE 's/^ *> ([^ ]+) .*  (observed \([0-9]+ flows\)|unexercised|!! CONTRADICTED: cuts [0-9]+ observed flow\(s\)).*/    \1  \2/p'; \
	done


# Everything `make all` writes, so that `make clean all` followed by
# `git status` shows nothing: the committed outputs are exactly what the two
# dataset files and the hand-written inputs (assumptions.yml,
# identity-assertions.yml, def/services-site.yml) produce. The datasets
# themselves are kept.
clean:
	rm -rf $(MEASURED)/ $(LOOT)/ policies/ zones/ flows/ loot-synth/
	rm -f def/networks.yml def/host_metadata.json def/services-observed.yml \
	    $(addprefix def/,$(STOCK_DEFS))
