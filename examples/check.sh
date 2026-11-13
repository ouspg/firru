#!/bin/bash
# Rebuild each example in an empty directory and compare what it produces
# with the copy committed under examples/<name>/expected/. A difference is a
# change in firru's output: review it, then refresh the copy with --update.
#   BASELINES=~/firru-os-baselines examples/check.sh [--update] [EXAMPLE ...]
set -euo pipefail
: "${BASELINES:?a clone of firru-os-baselines}"
FIRRU=$(cd "$(dirname "$0")/.." && pwd)
UPDATE=
[ "${1:-}" = --update ] && { UPDATE=1; shift; }
[ $# -eq 0 ] && set -- fleet fleet-zones

# What each example keeps: its outputs, not its inputs (loot stays in
# firru-os-baselines, flows are generated).
declare -A KEEP=(
  [fleet]="review.sh policies/staged policies/tightened policies/pol policies/block-early out"
  [fleet-zones]="policies/pol zones/pol out"
)

status=0
for ex in "$@"; do
  work=$(mktemp -d)
  trap 'rm -rf -- "$work"' EXIT
  (cd "$work" && BASELINES=$BASELINES FIRRU=$FIRRU bash "$FIRRU/examples/$ex/run.sh" > run.log 2>&1) \
    || { echo "$ex: run.sh failed"; tail -20 "$work/run.log"; exit 1; }
  got=$work/expected
  mkdir -p "$got"
  for p in ${KEEP[$ex]}; do
    mkdir -p "$got/$(dirname "$p")"
    cp -r "$work/$p" "$got/$p"
  done
  # The transcript, with this machine's paths taken out. A regular install
  # carries the stock def/ inside the package; an editable one reads $FIRRU/def.
  sed -e "s#$work#.#g" -e "s#$FIRRU#\$FIRRU#g" -e "s#$BASELINES#\$BASELINES#g" \
      -e "s#[^ ]*/firru/_stock_def#\$FIRRU/def#g" \
    "$work/run.log" > "$got/transcript.txt"
  want=$FIRRU/examples/$ex/expected
  if [ -n "$UPDATE" ]; then
    rm -rf -- "$want" && cp -r "$got" "$want"
    echo "$ex: expected/ refreshed"
  elif diff -r "$want" "$got" > "$work/diff.txt"; then
    echo "$ex: as expected"
  else
    echo "$ex: differs from expected/"; head -40 "$work/diff.txt"; status=1
  fi
  rm -rf -- "$work"; trap - EXIT
done
exit $status
