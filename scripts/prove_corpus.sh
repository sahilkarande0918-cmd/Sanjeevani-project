#!/bin/bash
# Phase 2 acceptance: run the prover over the whole corpus and print a table.
#
# eq-bytes must be small enough that the ORIGINAL is still well-defined.
# safety-bytes must be large enough to actually trigger the bug.
# They differ per program because the bugs need different input sizes.
cd /home/sahil/Sanjeevani || exit 1
mkdir -p proofs

# name : eq-bytes : safety-bytes
CASES=(
  "stack_overflow:4:24"
  "off_by_one:4:32"
  "format_string:2:8"
)

printf '%-16s %-12s %-16s %-14s %s\n' BINARY VERDICT SAFETY EQUIVALENCE ADDRESS
printf '%s\n' "--------------------------------------------------------------------------------"
for c in "${CASES[@]}"; do
  IFS=: read -r name eq safe <<<"$c"
  .venv/bin/python prover/differential_se.py \
      "corpus/out/$name.broken" "corpus/out/$name.fixed" \
      --eq-bytes "$eq" --safety-bytes "$safe" -t 180 \
      -o "proofs/$name.json" >/dev/null 2>&1
  .venv/bin/python -c "
import json
r=json.load(open('proofs/$name.json'))
print('%-16s %-12s %-16s %-14s %s' % (
  '$name', r['verdict'], r['safety']['result'],
  r['equivalence']['result'], r['safety']['address'] or '-'))
" 2>/dev/null || printf '%-16s %s\n' "$name" "FAILED TO RUN"
done
