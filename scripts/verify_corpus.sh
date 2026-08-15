#!/bin/bash
# Acceptance check for Phase 1.
#
# Three things must hold for every corpus program:
#   1. the .broken binary CRASHES on the trigger input   (else Phase 3 has nothing to find)
#   2. the .fixed  binary SURVIVES the same input        (else the ground-truth fix is wrong)
#   3. both binaries agree on a harmless input           (else the fix changed normal behaviour,
#                                                         and Phase 2 would rightly reject it)

set -u
OUT=corpus/out
fail=0

# name : trigger input : benign input
CASES=(
  "stack_overflow:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:hi"
  "off_by_one:BBBBBBBBBBBBBBBBBBBBBBBB:hi"
  "format_string:%n%n%n%n:hi"
)

run() {  # run BINARY INPUT -> prints output, returns exit code
  printf '%s\n' "$2" | timeout 5 "$1" 2>/dev/null
}

for c in "${CASES[@]}"; do
  IFS=: read -r name trigger benign <<<"$c"
  b="$OUT/$name.broken"
  f="$OUT/$name.fixed"

  if [ ! -x "$b" ] || [ ! -x "$f" ]; then
    echo "MISSING  $name  (run: make corpus)"; fail=1; continue
  fi

  run "$b" "$trigger" >/dev/null; bc=$?
  run "$f" "$trigger" >/dev/null; fc=$?
  bo=$(run "$b" "$benign"); bbc=$?
  fo=$(run "$f" "$benign"); ffc=$?

  ok=1
  [ "$bc" -lt 128 ] && { echo "  [1] $name.broken did NOT crash on trigger (exit $bc)"; ok=0; }
  [ "$fc" -ge 128 ] && { echo "  [2] $name.fixed  DID crash on trigger (exit $fc)";     ok=0; }
  { [ "$bo" != "$fo" ] || [ "$bbc" -ne "$ffc" ]; } && {
      echo "  [3] $name behaviour differs on benign input: '$bo'($bbc) vs '$fo'($ffc)"; ok=0; }

  if [ "$ok" = 1 ]; then
    echo "PASS  $name   (broken exit $bc = signal $((bc-128)), fixed exit $fc)"
  else
    echo "FAIL  $name"; fail=1
  fi
done

echo
[ "$fail" = 0 ] && echo "corpus OK - all 3 programs crash when broken, survive when fixed" \
                || echo "corpus NOT ready"
exit $fail
