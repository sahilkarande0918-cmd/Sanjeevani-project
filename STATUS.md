# STATUS

## Phase 3 — FIND + LOCALISE  🟢 ACCEPTANCE MET

```
BINARY             TIME     EXECS    FAULT  BLAMED       FUNCTION
format_string      6.16s    7543     libc   0x4011ae     FUN_00401156
off_by_one         0.27s    14       libc   0x401228     FUN_00401156
stack_overflow     0.28s    22       own    0x4011eb     FUN_00401193 (+callee FUN_00401156)
```
All three crash and localise well under the 5-minute budget. `finder/fuzz.py`
runs AFL++ QEMU mode → gdb → Ghidra and writes `crashes/<name>_<hash>.json`
with the crashing input (base64), the blamed address, and decompiled C.

### Three problems found and fixed
1. **The fault is usually not in our code.** `off_by_one` dies inside `puts()` and
   `format_string` inside `printf()`, both deep in libc, because that is where the
   corrupted pointer is finally dereferenced. Handing Ghidra a libc address is
   useless — it only analysed our binary. Now we walk back up the stack to the
   first frame inside our own image, read from the ELF's PT_LOAD segments.
2. **A smashed stack defeats the backtrace.** On the worst `stack_overflow` inputs
   gdb reports garbage like `0x286686868` (literally our input bytes) and *no*
   frame lands in our binary. The bug class that destroys the stack destroys the
   evidence. Fallback added: angr replays the same concrete input and reports the
   last basic block that belonged to us. Real hardware first, symbolic execution
   as backup.
3. **The blamed function often contains no bug.** A stack overflow in `greet()`
   only faults once `greet` RETURNS, so blame lands on `main`, whose body is just
   a call to `greet`. Phase 4 would have been asked to fix correct code. Ghidra
   now decompiles the blamed function **and its callees**, so the `strcpy` is
   visible where it matters.

## Phase 2 — PROVE  🟢 ACCEPTANCE MET (2 of 3 green, negative tests pass)

```
BINARY               VERDICT      SAFETY           EQUIVALENCE    ADDRESS
stack_overflow       PROVEN       BUG_REMOVED      IDENTICAL      0x401190
off_by_one           PROVEN       BUG_REMOVED      IDENTICAL      0x401228
format_string        INCONCLUSIVE NO_BUG_FOUND     IDENTICAL      -

negative tests (must NOT be PROVEN)
stack_overflow.wrong REJECTED     BUG_REMOVED      DIFFERENT      caught
off_by_one.wrong     REJECTED     STILL_VULNERABLE IDENTICAL      caught
```

**The negative tests prove why the verdict needs both halves.** Each bad patch is
caught by exactly the half the other one would have missed:
- `stack_overflow.wrong` genuinely fixes the memory bug but changes the greeting
  from "hi" to "hello". Safety says BUG_REMOVED. Only **equivalence** catches it.
  A fuzzer would run for a week and call it clean.
- `off_by_one.wrong` adds a reassuring-looking bounds check but leaves `<=` intact.
  Behaviour is identical, so equivalence is happy. Only **safety** catches it.

Either half alone certifies one of these bad patches as good.

`prover/differential_se.py` works end to end on `stack_overflow` and prints the
green panel: **PROVEN EQUIVALENT EXCEPT AT ADDRESS 0x401190**.

### The design that emerged, and why
One bound could not express the theorem, so the prover now proves **two** things
at **two different input sizes**:
- **SAFETY** (large input, 24–32 bytes): the original loses control at a reported
  address; the patched binary never does.
- **EQUIVALENCE** (small input, 2–4 bytes): for every input where the original is
  still well-defined, Z3 proves both binaries print identical output.

They cannot share a bound. Past the overflow the original is undefined behaviour,
and comparing there produces a real-but-useless complaint (see below).

### Four bugs found in the prover itself
1. **Vacuous proof.** When the original had no surviving normal path, zero paths
   were compared and the tool reported PROVEN. "All 0 paths matched" is a vacuous
   truth. Now INCONCLUSIVE.
2. **Uninitialised memory.** angr invents a fresh unknown for every byte read
   before written, and *different* unknowns per binary, so they compared unequal.
   `strcpy` leaves the buffer untouched where `strncpy` zero-fills it — real
   hardware prints the same thing since printf stops at the first NUL. Fixed by
   zero-filling so both start identical. Declared as an assumption in the JSON.
3. **Crashes discarded as errors.** angr reports "ran into unmapped memory" as an
   analysis error. That is not a failure, it is the bug reproducing. Now counted
   as a crash, and its address is used for the green panel.
4. **Zero-fill masked the very bug being hunted.** Reads of unmapped memory
   silently returned zeros, so dereferencing a corrupted pointer looked harmless.
   Safety mode now uses angr's defaults instead. `STRICT_PAGE_ACCESS` was tried
   and rejected — it flags normal stack access, reporting *both* binaries as
   crashing at `0x500020`, angr's own simulated stack.

### The finding worth showing judges
At an 8-byte input the prover **rejected our own hand-written textbook fix**, and
it was right. `strcpy` copies all 8 bytes; `strncpy(buf, name, sizeof buf - 1)`
truncates to 7. The original did not crash on that input — it overflowed by one
byte into padding and survived — so the standard bounds-check fix **silently
truncates data on an input the original handled**. No fuzzer would ever find that.

### Two more prover bugs found and fixed (6 total)
5. **`strcspn` had no model, and silence made it dangerous.** With
   `auto_load_libs=False`, any library function angr cannot model is replaced by a
   stub returning a **completely unconstrained value**. `strcspn` hit that stub, so
   the solver was free to decide a 4-byte input had length 24 — enough to run the
   loop far enough to corrupt a pointer and "prove" a difference no real execution
   can produce. An unmodelled function does not fail loudly; it quietly makes the
   proof meaningless. Fixed with a real `SimStrcspn`, plus the verdict now **lists
   unmodelled functions** so this can never be silent again.
6. **`NO_BUG_FOUND` was passing as PROVEN** — the same vacuous trap as bug #1. We
   would have certified a bug removed without ever having seen the bug. PROVEN now
   requires safety to demonstrate the bug *and* equivalence to prove preservation.

### Why safety needed its own detector
Waiting for angr to crash is not good enough: it happily reads through a corrupted
pointer and invents data, so `puts(tail)` after `tail` was overwritten looked
harmless and the bug vanished from the analysis. Safety now asks the question
directly — on every memory access, if the address depends on the input **and** Z3
can steer it into the unmapped null page, an attacker controls where the program
reads or writes. That is a violation whether or not this run happens to fault.
(`STRICT_PAGE_ACCESS` was tried first and rejected: it flags ordinary stack access,
reporting *both* binaries as crashing inside angr's own simulated stack.)

### Open ✗
- **format_string — INCONCLUSIVE.** Equivalence proves IDENTICAL, but safety finds
  no bug: angr's `printf` model does not emulate `%n` writes or `%s` dereferences,
  which is precisely what this bug is. Likely genuinely out of reach for symbolic
  execution. This is the one that takes the plan's documented kill switch —
  `differential_fuzz.py`, labelled "bounded verification", not "proof". The
  Definition of Done requires 2 of 3 green, which is met without it.

### Next →
1. **Phase 3 — FIND** (AFL++ QEMU mode + Ghidra localisation)
2. `differential_fuzz.py` fallback for format_string
3. llama.cpp still unverified (needed for Phase 4, not before)

### llama.cpp — 4 attempts, current hypothesis
Never produced output. But it is NOT hung: earlier runs showed 100% CPU and a
healthy 5.3 GB RSS, which is real work. Ruled out so far: default 32k context
ballooning to 14 GB and thrashing (fixed with `-c 2048`), and blocking on stdin
(no change with `</dev/null`).

**Next hypothesis to test in Phase 4:** stdout is block-buffered when piped, and
`timeout` kills the process with SIGTERM, so the buffered tokens are discarded
before they are ever flushed. Every attempt so far both piped the output AND
killed it on a timer, which would produce exactly the empty output we saw.
Test with `stdbuf -o0`, redirect straight to a file instead of a pipe, and let it
run to completion without a timer.

## Phase 1 — Setup + test corpus  🟢 mostly done, 2 background jobs running

### Done ✓
- WSL memory 11 GB → **15 GB usable**; project at `~/Sanjeevani` (WSL native)
- `git init`, 2 commits, `origin` wired to your GitHub repo (**not pushed yet**)
- **System toolchain installed** — gcc, make, cmake, ninja, clang, JDK 21.0.11, strace, qemu deps
- **Corpus builds and passes all 3 acceptance checks:**
  ```
  PASS  stack_overflow   (broken exit 139 = SIGSEGV, fixed exit 0)
  PASS  off_by_one       (broken exit 139 = SIGSEGV, fixed exit 0)
  PASS  format_string    (broken exit 139 = SIGSEGV, fixed exit 0)
  ```
  6 stripped binaries, 14 KB each — small is what makes Phase 2 tractable
- **angr 9.3.2 + Z3 4.13 installed on Python 3.14**, every native dep had a `cp314` wheel
- **`scripts/smoke_angr.sh` passes** — angr loads a stripped binary, recovers `main`
  at `0x401193` by reading the address `_start` passes to `__libc_start_main`,
  builds a 29-function CFG in <0.1 s, and executes symbolically in 1.1 s

- **Ghidra 12.1.2 installed**, `smoke_ghidra.sh` passes — headless analysis of a
  stripped ELF in **8 seconds** (I had budgeted 30–90 s; risk R7 is much smaller)
- **AFL++ 5.03a built from source**, `smoke_afl.sh` passes — `afl-qemu-trace` runs the
  stripped binary, prints correctly on benign input, and reports exit 139 on the
  crashing one. `core_pattern` is already `core`, so Phase 3 will not need root.
- **llama.cpp built** (`tools/llama.cpp/build/bin/llama-cli`)
- `make setup` / `make model` / `make smoke` / `make deps` targets added

### Running in background ⏳
- `fetch_model.sh` — Qwen Q4_K_M (~4.7 GB). First attempt died at
  `curl: (56) Connection reset by peer`; `--retry` restarts the *request* but not the
  *file*, so a reset meant starting from zero. Rewritten with `-C -` so each retry
  resumes from the bytes already on disk. Verifies against the SHA-256 Hugging Face
  publishes: `509287f7…94d3c`.

### Fixed along the way
- **off_by_one.c did not crash and had to be redesigned.** Flagged as the shaky one
  in the last status, and it duly failed. Two measured reasons: `malloc(24)` returns
  exactly 24 usable bytes, so byte 25 lands in glibc's spare `prev_size` field where
  nothing checks it; and a single stray byte only nudges a neighbouring pointer within
  its own mapped page, so nothing faults. It now overflows an array of **pointers**, so
  the stray iteration overwrites a whole 8-byte pointer with input bytes. The crash now
  depends only on input **length** (≥24 chars), never on byte values — it reproduces
  every run, which matters more on demo day than elegance.

### Known, not blocking
- angr's `unicorn` accelerator failed to load (`unicornlib.so`). Only affects speed of
  concrete execution, not correctness. Revisit only if Phase 2 proves too slow.

### Next →
1. **Phase 2 — PROVE.** Unblocked; needs only angr + Z3, both working.
   `prover/differential_se.py`, GREEN on the 3 correct patches, RED on wrong ones.
2. Smoke tests for Ghidra / AFL++ / llama.cpp once the background jobs land
3. `make setup` + `make model` targets to wrap the setup scripts
