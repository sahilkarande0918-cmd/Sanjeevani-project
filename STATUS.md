# STATUS

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

### Running in background ⏳
- `setup_downloads.sh` — Ghidra 12.1.2 (573 MB) + Qwen Q4_K_M (~4.7 GB), checksum-verified
- `setup_build.sh` — AFL++ from source (no 26.04 package) + llama.cpp

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
