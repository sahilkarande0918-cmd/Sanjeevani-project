# Sanjeevani

**Repair a broken program you have no source code for — and prove the repair didn't break anything.**

Fully offline. One laptop. Ethernet cable unplugged.

Built for the Indian Army **Terrier Cyber Quest 2026** hackathon, AI Kavach track.

---

## The problem

Indian defence laptops run air-gapped BOSS Linux with vendor-supplied binaries — and the
vendor never ships the source. When one of those binaries turns out to have a memory-safety
bug, or gets attacked (as in the August 2025 APT36 campaign that dropped ELF payloads on
BOSS Linux), nothing on that machine can fix it:

| Tool | Why it can't help |
|---|---|
| ChatGPT / Claude / Cursor | need internet — the machine is air-gapped |
| IDE tooling, linters, sanitizers | need source code — you have a stripped binary |
| Antivirus | tells you something is wrong, cannot repair it |

Sanjeevani fills that gap. It takes a stripped ELF binary and nothing else.

---

## What it does

```
FIND    fuzz the binary until an input crashes it            AFL++ (QEMU mode)
READ    find the faulting function and turn it back into C   gdb + Ghidra
WRITE   produce a fix                                        templates / Qwen2.5-Coder
SPLICE  write the fix back into the compiled program         Patcherex2
PROVE   prove the bug is gone and nothing else changed       angr + Z3
```

No source code. No internet. No cooperation from whoever shipped the binary.

---

## Results

Measured on WSL2 Ubuntu 26.04, 16 cores, 15 GB RAM, **no GPU**.

| Binary | Bug | Verdict | Address |
|---|---|---|---|
| `stack_overflow` | unbounded `strcpy` (CWE-121) | 🟢 **PROVEN** | `0x401190` |
| `off_by_one` | `i <= n` loop bound (CWE-193) | 🟢 **PROVEN** | `0x401228` |
| `format_string` | `printf(user_input)` (CWE-134) | 🟡 **BOUNDED VERIFICATION** | — |

```
+==========================================================+
|  PROVEN EQUIVALENT EXCEPT AT ADDRESS 0x401190            |
|                                                          |
|  bug removed        32 symbolic input bytes              |
|  behaviour preserved 1 path(s) proved identical          |
|  original  sha256   625d35c183a21547ee38d9056be6daaf...  |
|  patched   sha256   66b9da9201a3539263eb16374d2e67fa...  |
+==========================================================+
```

**Per binary, end to end:**

```
FIND+READ 13.9s   WRITE 0.1s   SPLICE 3.2s   PROVE 2.9s   TOTAL 20.2s
```

| Constraint | Target | Actual |
|---|---|---|
| Runtime per binary | < 3 min | **~24 s** |
| Disk footprint (tools + model) | < 10 GB | **8.6 GB** |
| Connections to any remote host | 0 | **0** — `strace`-verified |
| Binaries verified | ≥ 2 of 3 | **3 of 3** (2 proven, 1 bounded) |

---

## Quick start

```bash
sudo bash scripts/install_deps.sh   # the only step needing root
make setup                          # angr, Z3, AFL++, Ghidra, llama.cpp
make model                          # the 4.4 GB Qwen model (one-time, needs internet)
make corpus                         # build the demo binaries
./demo.sh                           # repair and verify all three
```

After `make model`, **nothing else ever touches the network.** Verify it yourself:

```bash
bash scripts/check_offline.sh
```

Repair a single binary:

```bash
.venv/bin/python sanjeevani.py corpus/out/stack_overflow.broken
```

---

## What makes it novel

Anyone can generate a patch with an LLM. Almost nobody can **prove the patch didn't break
anything else** — and that is the part that decides whether you dare deploy it.

### The proof has two halves, and both are necessary

A patch must do two things that pull in opposite directions:

- **SAFETY** — the bug is gone
- **EQUIVALENCE** — nothing else changed

They are proved separately, at different input sizes, because they cannot share one bound.
Safety needs a *large* input to trigger the bug; equivalence needs a *small* one, because
once the original overflows its buffer it is undefined behaviour and nothing sensible is
owed to it.

**Our negative tests show why one half alone is worthless.** Each deliberately-broken patch
is caught by exactly the half the other would wave through:

| Bad patch | What it does | Safety | Equivalence |
|---|---|---|---|
| `stack_overflow.wrong` | genuinely fixes the overflow, but changes `"hi"` → `"hello"` | ✅ BUG_REMOVED | ❌ **caught** |
| `off_by_one.wrong` | adds a reassuring bounds check, leaves `<=` intact | ❌ **caught** | ✅ IDENTICAL |

A fuzzer would run the first one for a week and call it clean.

### The proof runs on the real output

Sanjeevani proves the **actually-spliced binary**, not a hand-written reference fix.
The thing it produced is the thing it proved.

### It refuses to overclaim

`format_string` is reported as **bounded verification, not proof** — the panel is yellow and
says `NOT A PROOF` on the first line. angr's `printf` model doesn't emulate `%n` writes,
which *is* that bug, so we measure instead: 1000 concrete inputs, 221 crashes fixed, 604
outputs matched exactly, **0 regressions**. The gap between *"we tried 1000 inputs"* and
*"no input exists"* is the entire value of the PROVE step. Blurring it would cost more than
it gains.

---

## Tech stack

| Tool | Job | Why this one |
|---|---|---|
| **AFL++** | finds the crashing input | **QEMU mode** instruments the CPU at runtime, so it fuzzes stripped binaries with no source. Most fuzzers can't. |
| **Ghidra** | machine code → readable C | NSA-built, free, and `analyzeHeadless` is scriptable. 8 s per binary. |
| **gdb** | where did it actually die | ground truth from real hardware, not a model |
| **Qwen2.5-Coder-7B** (Q4_K_M) | writes the fix | ~4.4 GB — fits in laptop RAM, strong at code, and it's a *file on disk* |
| **llama.cpp** | runs the model on CPU | no GPU, no CUDA, no cloud. Built for air-gapped machines. |
| **Patcherex2** | splices the fix into the ELF | the one open tool that reliably rewrites compiled binaries |
| **angr** | symbolic execution | explores every path at once instead of one input at a time |
| **Z3** | the proof checker | answers *"does an input exist where these differ?"* definitively |

---

## Three things we learned that aren't obvious

**1. A patch may only call functions the binary already imports.**
Replacing `strcpy` with `strncpy` is the textbook fix taught everywhere — and it does not
link. A program that called `strcpy` has no PLT entry for `strncpy`, and you cannot bolt a
new library dependency onto a compiled ELF. Bounded copies are therefore emitted as **inline
loops that call nothing**.

**2. The bug that smashes the stack also destroys the evidence.**
On the worst overflow inputs, gdb's backtrace is garbage — it reported `0x286686868`,
literally our own input bytes sitting where a return address should be, with no frame inside
our binary. Localisation falls back to angr, which replays the same concrete input and
reports the last basic block that genuinely belonged to us.

**3. The blamed function often contains no bug.**
An overflow in `greet()` only faults once `greet` **returns**, so blame lands on `main` —
whose body is just a call to `greet`. Ghidra therefore decompiles the blamed function *and
its callees*, so the actual `strcpy` is visible to the patch step.

---

## Repository layout

```
sanjeevani.py          the orchestrator: FIND → READ → WRITE → SPLICE → PROVE
demo.sh                repairs and verifies all three binaries
finder/fuzz.py         AFL++ → gdb → Ghidra, writes a crash report
  ghidra_scripts/      DecompileAt.java — decompiles a function and its callees
synth/patch.py         template matching, then the local model with retry-on-compiler-error
templates/*.tmpl       known-good rewrites, as data rather than code
splicer/rewrite.py     Patcherex2 splicing + verification
prover/
  differential_se.py   the proof: angr + Z3, two bounds
  differential_fuzz.py the honest fallback when a proof is out of reach
corpus/                3 buggy C programs, ground-truth fixes, deliberately-wrong patches
scripts/               setup, smoke tests, acceptance runs, offline audit
PLAN.md  STATUS.md     the plan, and an honest running log of what broke
```

---

## Honest limitations

- **x86-64 Linux ELF only.** Not Windows PE, not Mach-O, not ARM.
- **Three bug classes.** Stack overflow, off-by-one, format string.
- **Proofs are bounded.** Verdicts state the input size they hold for. Exceeding the limit
  returns `INCONCLUSIVE` — never `PROVEN`.
- **Format-string bugs can't be proved symbolically** with angr's current `printf` model.
  They get bounded verification, clearly labelled.
- **The model is slow on CPU** (~3 tokens/sec). Templates run first because they're instant
  and deterministic; the model handles what no template covers.

---

## Verifying the offline claim

```bash
$ bash scripts/check_offline.sh

  NETWORK SYSCALL AUDIT
  network-related syscalls traced: 6
  --- connect() to a REMOTE address (must be none) ---
    none. No process contacted a remote host.
  CLEAN: zero connections to any remote host
```

Local IPC (`AF_UNIX`, netlink) is reported **separately rather than filtered out**. A claim
of zero network calls should show its working rather than quietly redefine the words.
