#!/bin/bash
# Smoke test: does AFL++'s QEMU mode actually run our stripped binary?
#
# afl-qemu-trace is the piece that matters. It emulates the CPU and records
# which code paths an input reaches, WITHOUT needing the source to have been
# recompiled with instrumentation. That is the only reason we can fuzz a
# binary a vendor handed us with no source.
set -u
cd /home/sahil/Sanjeevani || exit 1

AFL=tools/AFLplusplus
BIN=corpus/out/stack_overflow.broken

[ -x "$AFL/afl-fuzz" ]       || { echo "MISSING $AFL/afl-fuzz";       exit 1; }
[ -x "$AFL/afl-qemu-trace" ] || { echo "MISSING $AFL/afl-qemu-trace"; exit 1; }
[ -f "$BIN" ]                || { echo "MISSING $BIN - run: make corpus"; exit 1; }

echo "afl-fuzz: $("$AFL/afl-fuzz" -h 2>&1 | head -1)"
echo

echo "--- benign input through the emulator (expect: prints, exit 0) ---"
echo "hi" | "$AFL/afl-qemu-trace" "$BIN"; echo "exit=$?"

echo
echo "--- crashing input through the emulator (expect: exit 139 = SIGSEGV) ---"
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' | "$AFL/afl-qemu-trace" "$BIN" >/dev/null 2>&1
rc=$?
echo "exit=$rc"

echo
if [ "$rc" -ge 128 ]; then
  echo "OK: QEMU mode runs the stripped binary and sees the crash"
else
  echo "FAILED: emulator did not reproduce the crash (got $rc)"
  exit 1
fi

# Fuzzing proper needs the kernel to hand core dumps straight to the process
# instead of piping them to a crash handler, or AFL++ refuses to start.
# Needs root, so it is a Phase 3 concern, not a Phase 1 one.
cp=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
case "$cp" in
  core*) echo "core_pattern OK ($cp)";;
  *)     echo "NOTE for Phase 3: core_pattern is '$cp'; afl-fuzz will want"
         echo "  echo core > /proc/sys/kernel/core_pattern   (needs root)";;
esac
