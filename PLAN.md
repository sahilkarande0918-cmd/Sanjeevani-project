# PLAN.md — Sanjeevani

**Status:** Awaiting your approval. No code will be written until you say "go."

---

## 1. What Sanjeevani is (in 3 sentences)

Sanjeevani takes a **stripped ELF binary** — a compiled Linux program with no source code and no function names — finds the input that crashes it, reads the machine code back into something human-readable, asks a small offline AI to write a fix, splices that fix directly into the compiled program, and then **mathematically proves** the repaired program behaves identically to the original everywhere except at the exact spot the bug was.

Everything runs on one laptop with the network cable unplugged. No cloud, no source code, no internet.

**Why it matters:** Indian defence laptops run air-gapped BOSS Linux with vendor binaries whose source the vendor never ships. When one of those has a bug, ChatGPT/Claude/Cursor can't help (no internet) and IDE tools can't help (no source). Sanjeevani is built for exactly that gap.

---

## 2. Your environment — what I actually found

I probed your machine before planning. Several things differ from the prompt's assumptions:

| | Prompt assumed | Reality | Impact |
|---|---|---|---|
| OS | Ubuntu 22.04 | WSL2 **Ubuntu 26.04 LTS** | Newer than expected — some tools may need building from source instead of `apt install` |
| CPU | ~8 cores | **16 cores** | Better. Fuzzing scales with cores |
| RAM | 16 GB | **11 GB** → raising to 16 GB | You approved a `.wslconfig` bump (host has 23 GB) |
| Disk | — | **955 GB free** | No concern |
| Python | — | **3.14.4 only** | ✅ Verified on PyPI: angr 9.3.2 officially supports 3.14 |
| Tools | — | **None installed** | gcc, make, pip, java, cmake, AFL++, Ghidra, llama.cpp, z3, qemu, strace all missing |
| Model | `~/models/*.gguf` | **Not downloaded** | Adding a `make model` target |
| Project dir | — | Empty, not a git repo | Will `git init` in Phase 1 |

### Decisions you made

1. **Project lives at `~/Sanjeevani` inside WSL** (not the OneDrive folder). Reason: AFL++ hammers the filesystem with millions of tiny reads/writes. Across the Windows `/mnt/c` bridge that runs 10–100× slower, and OneDrive can lock or corrupt an ELF file mid-build. GitHub is the sync/backup point instead.
2. **WSL RAM raised to 16 GB** via `C:\Users\Sahil\.wslconfig`. Needs one `wsl --shutdown` at the start of Phase 1.
3. **`make model`** downloads the Qwen GGUF once during setup. Setup uses internet; **runtime never does** — that's the claim judges will test.

### Your GitHub repo

`https://github.com/sahilkarande0918-cmd/Sanjeevani-project.git` — I'll wire this as `origin` in Phase 1 and commit after every working sub-task. **I will not push without asking you first.**

---

## 3. Working discipline — the ponytail rule

You pointed me at [ponytail](https://github.com/DietrichGebert/ponytail). It isn't a binary-analysis tool — it's a *code-minimalism discipline*. I'm adopting it as the house rule for this project. Before writing anything, I climb this ladder and stop at the first rung that works:

1. Does this need to be built at all?
2. Does it already exist in this codebase? Reuse it.
3. Does the standard library do it? Use it.
4. Does a native platform feature cover it? Use it.
5. Does an already-installed dependency solve it? Use it.
6. Can it be one line? Make it one line.
7. Only then: write the minimum code that works.

Core rules I'll follow: *deletion over addition; boring over clever; fewest files possible; no abstractions you didn't ask for; no new dependency if avoidable; bug fix = root cause, not symptom.*

**What ponytail explicitly says never to strip, and I won't:** understanding the problem before coding, input validation at trust boundaries, error handling that prevents data loss, and one runnable check for any non-trivial logic. Deliberate shortcuts get a `# ponytail:` comment naming the ceiling and the upgrade path.

This matters for the hackathon too — "lightweight design" and "resource efficiency" are two of the five judging criteria.

---

## 4. The tech stack — what each tool does and why it's right

### AFL++ — the FIND step
**What it does:** Throws millions of mutated inputs at the program and watches for the one that makes it crash. Think of it as a robot that mashes every key combination on a keyboard until the program falls over — but smart: it notices which inputs reach *new code* and breeds more like those.

**Why this one:** Most fuzzers need source code to insert their tracking instrumentation at compile time. We don't have source. AFL++'s **QEMU mode** (`-Q`) emulates the CPU and inserts tracking at runtime, so it works on a stripped binary you were handed as-is. That's the whole reason it's in the stack. It's also the best-maintained free fuzzer as of 2026.

### Ghidra (headless) — the READ step
**What it does:** Takes machine code and reconstructs readable C-like code. Like getting a cake back into a recipe — imperfect, but close enough to understand what happened.

**Why this one:** Built by the NSA and released free. The paid alternative (IDA Pro) costs thousands. Critically, `analyzeHeadless` is a **command-line mode** — no GUI clicking — so our pipeline can script it. The AI needs readable C to reason about, and this is what produces it.

### Qwen2.5-Coder-7B (GGUF Q4_K_M) — the WRITE step
**What it does:** Reads the decompiled C and proposes a patch.

**Why this one:** "7B" = 7 billion parameters. "Q4" = compressed to 4 bits per parameter, shrinking it from ~15 GB to **~4.7 GB** — small enough for laptop RAM. Among models that small, Qwen2.5-Coder is the strongest at code. And it's a **file on disk**, so it runs with the network unplugged. A cloud model would break the entire thesis of the project.

### llama.cpp — the engine under the model
**What it does:** Actually runs the model on your CPU.

**Why this one:** Single self-contained binary. No CUDA, no GPU, no Python ML stack, no cloud calls. It was built specifically to run models on ordinary hardware, and it's the reason we can promise "works air-gapped on a laptop."

### Patcherex2 — the SPLICE step
**What it does:** The surgery. Inserts new machine instructions into an already-compiled binary without breaking it.

**Why this one:** This is genuinely hard — a binary is a rigid structure where everything points at fixed addresses, so inserting even one instruction can shift addresses and shatter every reference. Patcherex2 handles the relocation bookkeeping. It's the one open-source tool that does this reliably for ELF, and it's the maintained successor to the original Patcherex.

### angr — the exploration engine
**What it does:** **Symbolic execution.** Instead of running the program with one concrete input like `"AAAA"`, it runs it with a placeholder meaning *"any possible input"* and tracks the mathematical conditions along every branch. One run explores every path at once.

**Why this one:** The standard research-grade symbolic execution engine, with a mature Python API. Our demo binaries are small, which is exactly where angr is fast enough to be practical.

### Z3 — the proof checker
**What it does:** An **SMT solver** — it answers questions like *"is there any value of X where these two programs disagree?"* with a definitive yes (plus the exact value) or no.

**Why this one:** Microsoft Research's solver, the industry standard, ships with Python bindings, and angr already uses it internally via claripy. Using it directly costs us no new dependency — **ponytail rung 5**.

### angr + Z3 together — the PROVE step, and our novelty
**What it does:** **Differential symbolic execution.** Runs the broken binary and the patched binary side by side on the *same* symbolic input, then asks Z3: *"can these two ever produce different output, anywhere outside the one basic block we patched?"* If Z3 says no such input exists, we have a proof — not a test, a proof.

**Why this is the differentiator:** Anyone can generate a patch with an LLM. Almost nobody can *prove* the patch didn't break anything else. That combination, end-to-end and fully offline, is what nothing else does. This is the green panel on demo day, and I won't cut corners on it.

**A note on honesty:** symbolic execution on real programs is bounded — loops and huge state spaces force limits. If we bound the exploration, the output will say **"bounded verification"**, not "proof." Overclaiming to judges who know this field would cost us more than it gains.

---

## 5. The six phases

**Important distinction:** build order ≠ run order.

- **Build order:** 1 → **2 (PROVE)** → 3 → 4 → 5 → 6. We build the hardest, most novel part second, so we learn early if it works.
- **Run order at demo time:** 3 (FIND) → 4 (WRITE) → 5 (SPLICE) → 2 (PROVE).

---

### Phase 1 — Setup + test corpus
**Produces:** a working toolchain and 3 broken + 3 known-good stripped binaries.

- `wsl --shutdown` to apply the 16 GB memory bump.
- `git init`, wire up your GitHub remote, add `.gitignore` (never commit the 4.7 GB model or fuzzer output).
- Install: gcc, make, cmake, JDK, AFL++, Ghidra, llama.cpp, Patcherex2, angr, Z3, qemu, strace.
- One smoke test per tool in `scripts/smoke_*.sh` — each proves the tool actually runs, not just that it's on disk.
- `make model` downloads the Qwen GGUF with checksum verification.
- Build `corpus/`: `stack_overflow.c` (unchecked `strcpy`), `off_by_one.c` (`i <= N`), `format_string.c` (`printf(user_input)`).
- For each: compile `gcc -O0 -no-pie`, then `strip`. Also hand-write the **correct** patch and build a known-good binary — this is Phase 2's ground truth.

**Done when:** `make setup && make corpus` produces 3 broken + 3 patched stripped binaries in `corpus/out/`, and every smoke test passes.

---

### Phase 2 — PROVE (the hard one, built first)
**Produces:** `prover/differential_se.py`, emitting `proof.json` or `rejected.json`.

- Load broken + hand-patched binaries as two `angr.Project`s.
- Symbolically execute both from `main` with the same symbolic input.
- At each pair of end states, ask Z3: are outputs equal? Is all reachable memory equal, except inside the patched basic block?
- **GREEN** → `proof.json` with the diverging block address, the SMT model, and SHA-256 of both binaries.
- **RED** → `rejected.json` explaining *why* they differ.

**Two-sided testing** — a prover that only ever says yes is worthless:
- 3 corpus binaries with correct hand-patches → **must be GREEN**
- Deliberately wrong patches (e.g. one that just swallows the crash) → **must be RED**

**Kill switch:** if angr exceeds 10 minutes on `stack_overflow.c`, **I stop and tell you.** We fall back to `differential_fuzz.py` — 1000 fuzzer seeds through both binaries, all outputs compared — and label it honestly as *"bounded verification."* The demo still works.

**Done when:** GREEN on all 3 correct patches, RED on all wrong patches.

---

### Phase 3 — FIND + LOCALISE
**Produces:** `finder/fuzz.py` and `crashes/<hash>.json`.

- Wrap AFL++ in QEMU mode; run until first crash (demo timeout: 5 min).
- Feed the crashing input through Ghidra `analyzeHeadless` to identify the crashing function.
- Save: crashing input (base64), function name, decompiled C of that function.

**Done when:** all 3 binaries produce a crash report with correct function localisation, under 5 min each.

---

### Phase 4 — WRITE a fix
**Produces:** `synth/patch.py` + `templates/`.

- Prompt Qwen with the decompiled C; get back a small C patch.
- **I will show you the prompt template and get your approval before locking it in** (you asked for this).
- Doesn't compile? Retry up to 3× with the compiler error fed back in.
- Still failing → fall back to 4b.

**Phase 4b — template library** (kill switch, but built as a first-class feature regardless):
- `stack_overflow.tmpl` → `strcpy` becomes `strncpy(dst, src, sizeof(dst)-1)`
- `off_by_one.tmpl` → `<=` becomes `<`
- `format_string.tmpl` → `printf(x)` becomes `printf("%s", x)`

In fallback mode the model's job shrinks to "pick the right template and fill in the variable names" — less impressive-sounding, far more reliable, still novel. Having both paths means the demo cannot hard-fail here.

**Done when:** all 3 binaries yield a C patch snippet that compiles.

---

### Phase 5 — SPLICE
**Produces:** `splicer/rewrite.py` and `corpus/out/<name>.patched`.

- Compile the Phase 4 snippet to an object file.
- Splice it into the broken binary at the Phase 3 function using Patcherex2.
- Emit a new stripped ELF.

**Done when:** the patched binary (a) does not crash on the original crashing input, and (b) still passes the Phase 1 regression test — proving we fixed the bug *without* breaking normal behaviour.

---

### Phase 6 — INTEGRATE + DEMO
**Produces:** `sanjeevani.py` and `demo.sh`.

- One CLI running FIND → WRITE → SPLICE → PROVE with coloured progress ticks.
- Final money shot: `PROVEN EQUIVALENT EXCEPT AT ADDRESS 0x<hex>` in a big green box.
- `demo.sh` with fallbacks pre-loaded (pre-recorded crashing input in case fuzzing is slow on the day).

**Done when:** `demo.sh` runs end-to-end **with the network unplugged**, broken binary → green panel, under 5 minutes.

---

## 6. Risks — where this could break

Ordered by how likely they are to hurt us.

**R1 — angr path explosion (HIGH likelihood, HIGH impact).**
Symbolic execution branches on every `if`. A loop over a 64-byte buffer can explode into billions of states. This is the single most likely thing to sink Phase 2.
*Mitigation:* keep corpus binaries tiny; bound input length; use angr's veritesting/state-merging; hard 10-min timeout. **Fallback already designed** (`differential_fuzz.py`), relabelled honestly as bounded verification.
🛑 **I will stop and ask you** if the timeout trips.

**R2 — Ubuntu 26.04 is brand new (HIGH likelihood, MEDIUM impact).**
AFL++, Ghidra, and Patcherex2 may have no ready package for a release this recent. Some may need building from source, which eats Phase 1 time.
🛑 **I will stop and ask you** if any single tool needs a source build likely to exceed ~30 minutes.

**R3 — Conflicting time budgets in the spec (CERTAIN, MEDIUM impact).**
Your spec says Phase 3 may fuzz for up to 5 minutes, but the Definition of Done says total runtime per binary must be under **3 minutes**. Those can't both hold.
*My assumption, flag it if wrong:* the 3-minute budget is the target for the **demo path**, where `demo.sh` uses a pre-recorded crashing seed (which your spec already permits). The 5-minute fuzz is the cold-start path we quote for honesty. These bugs are so shallow AFL++ should find them in seconds anyway.

**R4 — Patcherex2 splicing produces a subtly broken binary (MEDIUM/HIGH).**
Inserting code into a compiled program can break alignment or relocations in ways that don't show up immediately.
*Mitigation:* Phase 5 is not "done" until the patched binary passes the regression test — and Phase 2 will independently catch it, which is exactly the point of having a prover.

**R5 — Memory pressure (MEDIUM).**
Ghidra (JVM), angr, and llama.cpp are each multi-GB. At 16 GB, running them concurrently risks the OOM killer.
*Mitigation:* the pipeline runs phases **strictly one at a time**, releasing memory between. This costs a little wall-clock and buys reliability.

**R6 — Qwen too slow on CPU (MEDIUM/LOW).**
A 7B Q4 model on 16 CPU cores runs roughly 5–15 tokens/sec, so a 200-token patch takes 15–40s.
*Mitigation:* keep prompts short, cap output tokens, cache results for the demo. Template fallback (4b) is near-instant.

**R7 — Ghidra headless is slow (MEDIUM/LOW).**
First-time analysis of a binary takes 30–90s, which is a big slice of a 3-minute budget.
*Mitigation:* cache decompilation output keyed by binary SHA-256. Analyse once, reuse.

**R8 — Model download (LOW, but blocking).**
4.7 GB over your connection. Do this early, not on demo day.

### I will stop and ask you before:
- Swapping any tool for a different one
- Changing the phase order or expanding scope
- **Any** cloud/network call at runtime (this kills the project's thesis — if I ever feel tempted, I'll explain why instead of doing it)
- Locking in the Qwen prompt template (Phase 4)
- Pushing to your GitHub repo
- Any step that has failed **3 times** — I won't sit there guessing

---

## 7. Definition of Done for the whole project

- [ ] `demo.sh` runs end-to-end offline on all 3 corpus binaries
- [ ] Green PROVE panel for at least **2 of 3**
- [ ] Total disk footprint (model + tools + code) under **10 GB**
- [ ] **Zero network calls at runtime** — demonstrated with `strace -f -e trace=network ./demo.sh`, output shown to you
- [ ] Runtime per binary under **3 minutes** (see R3)

---

## 8. Files I'll create

```
~/Sanjeevani/
├── PLAN.md              ← this file
├── STATUS.md            ← updated at the end of every phase: done ✓ / broken ✗ / next →
├── Makefile             ← setup, corpus, model
├── demo.sh
├── sanjeevani.py        ← the one CLI orchestrator
├── corpus/              ← 3 buggy C programs + hand-written correct patches
│   └── out/             ← stripped binaries (gitignored)
├── scripts/smoke_*.sh   ← one per tool
├── prover/              ← differential_se.py  (+ differential_fuzz.py fallback)
├── finder/              ← fuzz.py
├── synth/               ← patch.py
├── templates/           ← the 3 .tmpl patch templates
└── splicer/             ← rewrite.py
```

Nine small modules, one job each. No framework, no plugin system, no abstraction layer — ponytail rung 1 says don't build what nobody asked for.

---

## 🛑 STOP — awaiting your approval

Reply **"go"** and I'll start Phase 1. If anything above is wrong, tell me now — it's far cheaper to fix a plan than a build.
