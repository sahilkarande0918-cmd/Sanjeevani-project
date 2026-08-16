# STATUS

## Phase 2 — PROVE  🟡 1 of 3 green (need 2 of 3)

```
BINARY           VERDICT      SAFETY           EQUIVALENCE    ADDRESS
stack_overflow   PROVEN       BUG_REMOVED      IDENTICAL      0x401190
off_by_one       REJECTED     NO_BUG_FOUND     DIFFERENT      -
format_string    INCONCLUSIVE NO_BUG_FOUND     INCONCLUSIVE   -
```

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

### Open ✗
- **off_by_one — SAFETY: NO_BUG_FOUND.** The real binary segfaults on ≥24 chars via
  `puts()` on a pointer overwritten with input. angr's default memory model does
  not fault on that; it invents symbolic data instead. Needs a detector for
  "dereferencing an attacker-controlled pointer".
- **off_by_one — EQUIVALENCE: DIFFERENT**, output lengths 8 vs 32 bits (1 byte vs
  4). Not yet root-caused. Both should print `end\n`. Do not assume it is an
  artifact — bug #2 also looked like one and was real.
- **format_string — INCONCLUSIVE.** The original has no normal exit even at 2
  bytes. Suspected root cause: angr cannot execute `printf` with a *symbolic
  format string*, which is precisely what this bug is. May be genuinely out of
  reach for symbolic execution, in which case this is the one that falls back to
  `differential_fuzz.py` (bounded verification) — the plan's kill switch, and the
  Definition of Done only requires 2 of 3 green.

### Next →
1. Root-cause the off_by_one equivalence length mismatch
2. Detect corrupted-pointer dereference for off_by_one safety
3. Decide format_string: symbolic-format workaround, or the fuzzing fallback
4. Negative tests — deliberately wrong patches must come out RED

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
