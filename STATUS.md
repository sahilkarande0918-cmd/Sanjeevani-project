# STATUS

## Phase 1 — Setup + test corpus  🟡 BLOCKED on one command from you

### Done ✓
- WSL memory raised 11 GB → **15 GB usable** (`C:\Users\Sahil\.wslconfig`, applied after `wsl --shutdown`)
- Project root created at `~/Sanjeevani` (WSL native, not OneDrive — AFL++ needs a fast filesystem)
- `git init` + first commit + `origin` wired to your GitHub repo (**not pushed yet**)
- `.gitignore` — keeps the 4.7 GB model, compiled binaries and fuzzer output out of the repo
- 3 buggy C programs written: `stack_overflow.c`, `off_by_one.c`, `format_string.c`
- 3 hand-written ground-truth fixes in `corpus/fixed/` (Phase 2 proves against these)
- `Makefile` — `make corpus` builds stripped `-O0 -no-pie` binaries
- `scripts/verify_corpus.sh` — Phase 1 acceptance check
- Verified on PyPI: **angr 9.3.2 supports Python 3.14**, the only Python on this box

### Blocked ✗
- **`sudo` needs a password.** I can't type passwords, so every `apt` install is stuck.
  Root cause of everything below. One command from you clears it:
  ```
  sudo bash ~/Sanjeevani/scripts/install_deps.sh
  ```
- Nothing is compiled yet — no `gcc`, so `make corpus` cannot run
- Not installed: gcc, make, cmake, JDK, AFL++, Ghidra, llama.cpp, angr, Z3, Patcherex2, qemu, strace
- Model not downloaded (`make model` target not written yet)

### Unverified assumptions (will test the moment gcc exists)
- `stack_overflow.broken` should segfault on a ~30-char input (return address overwritten)
- `off_by_one.broken` relies on glibc aborting in `free()` after the 1-byte heap overflow.
  **This is the shakiest of the three** — glibc may absorb the overwrite silently.
  If it doesn't crash, I'll adjust `N` or the trigger mechanism and say so.
- `format_string.broken` should fault on `%n` (needs `-U_FORTIFY_SOURCE`, which is set)

### Next →
1. You run `install_deps.sh`
2. I run `make corpus` + `verify-corpus` and fix whatever doesn't actually crash
3. Userspace installs, no root needed: Ghidra, llama.cpp, angr/Z3/Patcherex2 venv, model
4. `scripts/smoke_*.sh` — one per tool
5. Then **Phase 2 (PROVE)** — the hard one, built before FIND/WRITE/SPLICE
