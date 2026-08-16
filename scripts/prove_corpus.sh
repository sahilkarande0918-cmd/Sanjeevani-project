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

# ---------------------------------------------------------------------------
# NEGATIVE TESTS. A prover that only ever says yes is worthless, so these
# deliberately-wrong patches MUST come out anything other than PROVEN.
echo
echo "negative tests (must NOT be PROVEN)"
printf '%s\n' "--------------------------------------------------------------------------------"
fail=0
for c in "stack_overflow:4:24" "off_by_one:4:32"; do
  IFS=: read -r name eq safe <<<"$c"
  [ -f "corpus/out/$name.wrong" ] || { echo "  missing $name.wrong - run: make corpus"; fail=1; continue; }
  .venv/bin/python prover/differential_se.py \
      "corpus/out/$name.broken" "corpus/out/$name.wrong" \
      --eq-bytes "$eq" --safety-bytes "$safe" -t 180 \
      -o "proofs/$name.wrong.json" >/dev/null 2>&1
  .venv/bin/python -c "
import json,sys
r=json.load(open('proofs/$name.wrong.json'))
v=r['verdict']
ok = v != 'PROVEN'
print('%-16s %-12s %-16s %-14s %s' % ('$name.wrong', v, r['safety']['result'],
      r['equivalence']['result'], 'caught' if ok else 'MISSED - PROVER IS BROKEN'))
sys.exit(0 if ok else 1)
" || fail=1
done

echo
[ "$fail" = 0 ] && echo "negative tests OK - every bad patch was caught" \
                || { echo "NEGATIVE TESTS FAILED"; exit 1; }
