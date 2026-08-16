#!/bin/bash
# Smoke test: can Ghidra analyse a stripped binary from the command line,
# with no GUI? Phase 3 needs this to turn machine code back into C.
set -u
cd /home/sahil/Sanjeevani || exit 1

HEADLESS=tools/ghidra/support/analyzeHeadless
BIN=corpus/out/stack_overflow.broken
PROJ=$(mktemp -d)

[ -x "$HEADLESS" ] || { echo "MISSING $HEADLESS - run scripts/setup_downloads.sh"; exit 1; }
[ -f "$BIN" ]      || { echo "MISSING $BIN - run: make corpus"; exit 1; }

echo "java: $(java -version 2>&1 | head -1)"
echo "analysing $BIN (first run is the slow one)..."

t0=$(date +%s)
"$HEADLESS" "$PROJ" smoke -import "$BIN" -deleteProject 2>&1 \
  | grep -Ei 'INFO  (REPORT|Using)|ERROR|Exception|analysis succeeded|functions' \
  | head -20
rc=${PIPESTATUS[0]}
t1=$(date +%s)

rm -rf "$PROJ"
echo
echo "exit=$rc, took $((t1-t0))s"
[ "$rc" = 0 ] && echo "OK: Ghidra headless analyses a stripped binary" \
              || echo "FAILED"
exit "$rc"
