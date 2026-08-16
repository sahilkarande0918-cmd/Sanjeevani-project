#!/bin/bash
# Sanjeevani demo: repair three broken stripped binaries, offline, and prove it.
#
#   ./demo.sh          fuzz for real (takes seconds - the bugs are shallow)
#   ./demo.sh --safe   use pre-recorded crash inputs, skipping the fuzzer
#
# --safe exists for demo day. Fuzzing is random: it finds these crashes in
# well under a second every time we have run it, but "usually fast" is not a
# promise worth making in front of judges. Everything after FIND is identical
# either way, so the demonstration is not weakened by using it.
#
# Deliberately NOT using the LLM by default. Templates are instant and
# deterministic; the model takes ~60s per attempt on CPU and can still be
# wrong. Run ./demo.sh --model to show the model route instead.
set -u
cd "$(dirname "$0")" || exit 1

PY=.venv/bin/python
SAFE=0
MODEL="--no-model"
for a in "$@"; do
  case "$a" in
    --safe)  SAFE=1 ;;
    --model) MODEL="" ;;
    *) echo "usage: $0 [--safe] [--model]"; exit 2 ;;
  esac
done

# name : equivalence bytes : safety bytes
# Two bounds because the theorem has two halves. Equivalence must stay small
# enough that the ORIGINAL is still well-defined; safety must be large enough
# to actually trigger the bug.
CASES=(
  "stack_overflow:4:32"
  "off_by_one:4:32"
  "format_string:2:8"
)

[ -x "$PY" ] || { echo "no venv - run: make setup"; exit 1; }
for n in stack_overflow off_by_one format_string; do
  [ -f "corpus/out/$n.broken" ] || { echo "no corpus - run: make corpus"; exit 1; }
done

pass=0; total=0
t_all=$(date +%s)
for c in "${CASES[@]}"; do
  IFS=: read -r name eq safe <<<"$c"
  total=$((total + 1))

  seed=""
  if [ "$SAFE" = 1 ]; then
    s=$(ls demo/seeds/"$name"_*.json 2>/dev/null | head -1)
    [ -n "$s" ] && seed="--crash-seed $s"
  fi

  # shellcheck disable=SC2086
  $PY sanjeevani.py "corpus/out/$name.broken" \
      --eq-bytes "$eq" --safety-bytes "$safe" $MODEL $seed
  [ $? -eq 0 ] && pass=$((pass + 1))
done
t_all=$(( $(date +%s) - t_all ))

echo
echo "=================================================================="
echo "  $pass of $total binaries repaired and PROVEN, in ${t_all}s total"
echo "=================================================================="
[ "$pass" -ge 2 ] || exit 1
