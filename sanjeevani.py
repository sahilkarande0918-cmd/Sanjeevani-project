#!/usr/bin/env python3
"""Sanjeevani - repair a stripped ELF binary, offline, and prove the repair.

    FIND    AFL++ fuzzes the binary until an input crashes it
    READ    gdb says where it died, Ghidra turns that function back into C
    WRITE   a template or the local Qwen model produces a fix
    SPLICE  Patcherex2 writes the fix back into the compiled program
    PROVE   angr and Z3 prove the bug is gone and nothing else changed

No source code, no internet, no cooperation from whoever shipped the binary.

Phases run STRICTLY ONE AT A TIME and each releases its memory before the next
starts. Ghidra (a JVM), angr and llama.cpp are each multiple gigabytes; holding
two at once on a 15 GB box sends the machine into swap. That is not a
theoretical worry - it is how we lost an afternoon to what looked like a hung
model but was two processes starving each other.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

G, R, Y, B, DIM, OFF = ("\033[92m", "\033[91m", "\033[93m",
                        "\033[1m", "\033[2m", "\033[0m")


def rule(char: str = "-", n: int = 66) -> str:
    return char * n


def step(name: str, detail: str = "") -> None:
    print(f"{B}[{name:<6}]{OFF} {detail}")


def ok(name: str, detail: str) -> None:
    print(f"{G}[{name:<6}] ok{OFF} {detail}")


def bad(name: str, detail: str) -> None:
    print(f"{R}[{name:<6}] !!{OFF} {detail}")


def panel(res: dict) -> str:
    """The demo money shot."""
    v = res["verdict"]
    if v == "PROVEN":
        addr = res["safety"].get("address")
        lines = ["PROVEN EQUIVALENT" + (f" EXCEPT AT ADDRESS {addr}" if addr else ""),
                 "",
                 f"bug removed        {res['safety']['symbolic_input_bytes']} symbolic input bytes",
                 f"behaviour preserved {res['equivalence']['paths_compared']} path(s) proved identical",
                 f"original  sha256   {res['binaries']['original']['sha256'][:32]}...",
                 f"patched   sha256   {res['binaries']['patched']['sha256'][:32]}..."]
        colour = G
    elif v == "REJECTED":
        eq, sf = res["equivalence"], res["safety"]
        blame = eq if eq["result"] == "DIFFERENT" else sf
        lines = ["PATCH REJECTED", "", blame.get("why", "")]
        colour = R
    else:
        eq, sf = res["equivalence"], res["safety"]
        blame = eq if eq["result"] == "INCONCLUSIVE" else sf
        lines = ["NOT PROVED (bounded verification only)", "", blame.get("why", "")]
        colour = Y

    width = max(len(x) for x in lines) + 6
    top = "+" + "=" * (width - 2) + "+"
    body = "\n".join(f"|  {x.ljust(width - 6)}  |" for x in lines)
    return f"\n{colour}{B}{top}\n{body}\n{top}{OFF}\n"


def repair(binary: Path, fuzz_seconds: int, eq_bytes: int, safety_bytes: int,
           use_model: bool, crash_seed: Path | None) -> dict:
    t_start = time.time()
    print(f"\n{B}Sanjeevani{OFF}  repairing {binary}\n{rule('=')}")

    # ---------------------------------------------------------- FIND + READ
    from finder.fuzz import find, localise, decompile, image_range  # noqa: E402
    t0 = time.time()

    if crash_seed and crash_seed.exists():
        # Demo safety net: a pre-recorded crashing input, so a slow fuzzing run
        # on the day cannot derail the demonstration. Everything after this
        # point is identical either way.
        step("FIND", f"{DIM}using pre-recorded crash input {crash_seed.name}{OFF}")
        report = json.loads(crash_seed.read_text())
    else:
        report = find(binary, fuzz_seconds, ROOT / "crashes")
    if not report.get("crash_found"):
        bad("FIND", "no crash found")
        return {"failed": "FIND"}

    fn = report.get("function", {})
    ok("FIND", f"crash in {report['fuzz_seconds']}s after "
               f"{report.get('executions','?')} executions")
    ok("READ", f"{fn.get('function','?')} @ {fn.get('entry','?')} "
               f"({len(fn.get('callees', []))} callee(s) decompiled)")
    t_find = time.time() - t0

    # ---------------------------------------------------------------- WRITE
    from synth.patch import patch_from_report  # noqa: E402
    t0 = time.time()
    tmp_report = ROOT / "crashes" / "_current.json"
    tmp_report.parent.mkdir(exist_ok=True)
    tmp_report.write_text(json.dumps(report))
    patch = patch_from_report(tmp_report, use_model=use_model)
    if not patch.get("compiles"):
        bad("WRITE", patch.get("error", "patch does not compile"))
        return {"failed": "WRITE"}
    ok("WRITE", f"{patch['route']} -> {patch.get('bug', patch.get('bug_guess',''))}")
    t_write = time.time() - t0

    # --------------------------------------------------------------- SPLICE
    from splicer.rewrite import splice_from_patch  # noqa: E402
    t0 = time.time()
    patch["binary"] = str(binary)
    patch_file = ROOT / "patches" / "_current.json"
    patch_file.parent.mkdir(exist_ok=True)
    patch_file.write_text(json.dumps(patch))
    spliced = splice_from_patch(patch_file)
    v = spliced["verification"]
    if not v["ok"]:
        bad("SPLICE", f"crash_fixed={v['crash_fixed']} "
                      f"benign_preserved={v['benign_output_matches']}")
        return {"failed": "SPLICE"}
    ok("SPLICE", f"{Path(spliced['output']).name} - crash fixed, benign output preserved")
    t_splice = time.time() - t0

    # ---------------------------------------------------------------- PROVE
    from prover.differential_se import prove  # noqa: E402
    t0 = time.time()
    step("PROVE", f"{DIM}symbolic execution + Z3...{OFF}")
    proof = prove(str(binary), spliced["output"], eq_bytes, safety_bytes,
                  timeout=180.0, max_states=200)
    t_prove = time.time() - t0
    (ok if proof["verdict"] == "PROVEN" else bad)(
        "PROVE", f"{proof['verdict']}  safety={proof['safety']['result']}  "
                 f"equivalence={proof['equivalence']['result']}")

    proofs = ROOT / "proofs"
    proofs.mkdir(exist_ok=True)
    name = "proof" if proof["verdict"] == "PROVEN" else "rejected"
    dest = proofs / f"{binary.stem}.{name}.json"
    dest.write_text(json.dumps(proof, indent=2))

    total = time.time() - t_start
    print(rule())
    print(f"{DIM}FIND+READ {t_find:5.1f}s   WRITE {t_write:5.1f}s   "
          f"SPLICE {t_splice:5.1f}s   PROVE {t_prove:5.1f}s   "
          f"TOTAL {total:5.1f}s{OFF}")
    print(panel(proof))
    print(f"{DIM}proof written to {dest}{OFF}")
    return {"proof": proof, "seconds": total, "patched": spliced["output"]}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("binary")
    ap.add_argument("-s", "--fuzz-seconds", type=int, default=300)
    ap.add_argument("--eq-bytes", type=int, default=4)
    ap.add_argument("--safety-bytes", type=int, default=32)
    ap.add_argument("--no-model", action="store_true",
                    help="templates only - faster and deterministic, used by demo.sh")
    ap.add_argument("--crash-seed", help="pre-recorded crash report, skips fuzzing")
    args = ap.parse_args()

    r = repair(Path(args.binary).resolve(), args.fuzz_seconds, args.eq_bytes,
               args.safety_bytes, not args.no_model,
               Path(args.crash_seed) if args.crash_seed else None)
    raise SystemExit(0 if r.get("proof", {}).get("verdict") == "PROVEN" else 1)
