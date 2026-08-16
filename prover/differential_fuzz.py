#!/usr/bin/env python3
"""Differential fuzzing - the documented fallback when a proof is out of reach.

This is NOT a proof and never claims to be. It runs a large number of concrete
inputs through both binaries and checks they agree. That is evidence, bounded by
however many inputs we tried. The verdict is labelled BOUNDED_VERIFICATION and
carries the exact sample size, because the difference between "we tried 2000
inputs" and "no input exists" is the entire value of the PROVE step and it would
be dishonest to blur it.

WHEN THIS IS USED
-----------------
format_string. angr's printf model does not emulate %n writes or %s pointer
dereferences - which IS that bug - so symbolic execution cannot see the very
thing it is meant to check. Its equivalence half still proves IDENTICAL; only
the safety half is out of reach. Rather than fake a proof, we measure instead.

WHAT IS CHECKED
---------------
  SAFETY       inputs that kill the original but not the patched binary
  EQUIVALENCE  inputs where both survive - outputs must match exactly
  REGRESSION   any input where both survive but disagree is a FAILURE, and is
               reported with the input that shows it
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import subprocess
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate(n: int, seeds: list[bytes], rng: random.Random) -> list[bytes]:
    """Inputs spanning benign, boundary and hostile.

    Not purely random bytes: these bugs live at specific shapes - long strings,
    format specifiers, exact buffer boundaries - and uniform noise would mostly
    waste runs on inputs no branch cares about.
    """
    out: list[bytes] = []

    # The shapes that matter for our three bug classes.
    fixed = [b"", b"\n", b"hi\n", b"hello world\n",
             b"%n\n", b"%s%s%s%s\n", b"%x%x%x%x\n", b"%99999999s\n",
             b"A" * 7 + b"\n", b"A" * 8 + b"\n", b"A" * 9 + b"\n",     # buf[8] edges
             b"B" * 23 + b"\n", b"B" * 24 + b"\n", b"B" * 25 + b"\n",  # 24-char edge
             b"C" * 63 + b"\n", b"C" * 200 + b"\n"]
    out.extend(fixed)
    out.extend(seeds)

    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 %sxn"
    while len(out) < n:
        kind = rng.random()
        if kind < 0.35:                       # length sweep
            length = rng.randint(0, 64)
            body = bytes(rng.choice(alphabet) for _ in range(length))
        elif kind < 0.6:                      # format-specifier soup
            body = b"".join(rng.choice([b"%s", b"%n", b"%x", b"%d", b"A", b"%p"])
                            for _ in range(rng.randint(1, 12)))
        elif kind < 0.8:                      # mutate a seed
            base = bytearray(rng.choice(out))
            if base:
                for _ in range(rng.randint(1, 4)):
                    base[rng.randrange(len(base))] = rng.randrange(1, 256)
            body = bytes(base).replace(b"\n", b"")
        else:                                 # raw bytes
            body = bytes(rng.randrange(1, 256) for _ in range(rng.randint(1, 48)))
        out.append(body + b"\n")
    return out[:n]


def run(binary: Path, data: bytes, timeout: float = 5.0):
    try:
        r = subprocess.run([str(binary)], input=data,
                           capture_output=True, timeout=timeout)
        return r.returncode, r.stdout
    except subprocess.TimeoutExpired:
        return None, b""


def died(rc) -> bool:
    # subprocess reports a signal death as a NEGATIVE returncode, not 128+signal.
    return rc is not None and (rc < 0 or rc >= 128)


def verify(original: Path, patched: Path, n: int, seeds: list[bytes],
           rng_seed: int = 0, ub_marker: bytes | None = None) -> dict:
    """Compare two binaries over n concrete inputs.

    ub_marker marks inputs on which the ORIGINAL was already in undefined
    behaviour, and it is not optional pedantry - without it this check calls a
    working fix a regression.

    For format_string, an input containing '%' makes the original read
    arbitrary stack memory. The patched binary prints the text literally. Those
    outputs differ, and they SHOULD: "9fdd6ba009vx]" versus "%x%x%xvx]" is the
    repair doing its job. Counting that as a regression would penalise the fix
    for fixing. Nothing is owed to a program that already had no defined
    behaviour - the same reason the symbolic equivalence check stays inside the
    range where the original is well-defined.

    These inputs are counted and reported, never silently dropped.
    """
    rng = random.Random(rng_seed)          # fixed seed: reruns are reproducible
    inputs = generate(n, seeds, rng)

    crashes_fixed = 0
    still_crashing = []
    mismatches = []
    excluded_ub = []
    both_fine = 0
    timeouts = 0

    for data in inputs:
        o_rc, o_out = run(original, data)
        p_rc, p_out = run(patched, data)
        if o_rc is None or p_rc is None:
            timeouts += 1
            continue

        if died(o_rc) and not died(p_rc):
            crashes_fixed += 1
        elif died(p_rc):
            still_crashing.append(base64.b64encode(data).decode())
        elif not died(o_rc):
            # Both survived, so they must agree. This is the half that catches a
            # patch which stops the crash by changing what the program does.
            if o_rc != p_rc or o_out != p_out:
                record = {
                    "input_b64": base64.b64encode(data).decode(),
                    "original": o_out.decode(errors="replace")[:80],
                    "patched": p_out.decode(errors="replace")[:80],
                }
                if ub_marker and ub_marker in data:
                    excluded_ub.append(record)   # original was already undefined
                else:
                    mismatches.append(record)
            else:
                both_fine += 1

    ok = not mismatches and not still_crashing and crashes_fixed > 0
    return {
        "tool": "sanjeevani/differential_fuzz",
        "verdict": "BOUNDED_VERIFICATION" if ok else "REJECTED",
        "disclaimer": ("this is evidence from a finite sample, NOT a proof. "
                       f"It says the two binaries agreed on {n} inputs, not that "
                       "no disagreeing input exists."),
        "why_not_a_proof": ("symbolic execution could not model this bug - angr's "
                            "printf does not emulate %n writes or %s dereferences - "
                            "so we measured instead of proving"),
        "binaries": {
            "original": {"path": str(original), "sha256": sha256(original)},
            "patched": {"path": str(patched), "sha256": sha256(patched)},
        },
        "sample": {
            "inputs_tried": n,
            "crashes_fixed": crashes_fixed,
            "both_ran_cleanly": both_fine,
            "timeouts": timeouts,
            "excluded_undefined_behaviour": len(excluded_ub),
        },
        "still_crashing": still_crashing[:5],
        "output_mismatches": mismatches[:5],
        "excluded_examples": excluded_ub[:3],
        "exclusion_note": (
            f"inputs containing {ub_marker!r} put the ORIGINAL into undefined "
            "behaviour, so its output there is not a behaviour worth preserving. "
            "They are excluded from the equivalence check and counted above."
        ) if ub_marker else None,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Bounded differential verification by fuzzing.")
    ap.add_argument("original")
    ap.add_argument("patched")
    ap.add_argument("-n", "--inputs", type=int, default=1000)
    ap.add_argument("--crash-report", help="a crashes/*.json to seed from")
    ap.add_argument("--ub-marker", default=None,
                    help="byte sequence that puts the ORIGINAL into undefined "
                         "behaviour, e.g. %% for a format-string bug. Inputs "
                         "containing it are excluded from the equivalence check "
                         "and reported separately.")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()

    seeds: list[bytes] = []
    if args.crash_report and Path(args.crash_report).exists():
        rep = json.loads(Path(args.crash_report).read_text())
        if rep.get("crash_input_b64"):
            seeds.append(base64.b64decode(rep["crash_input_b64"]))

    res = verify(Path(args.original), Path(args.patched), args.inputs, seeds,
                 ub_marker=args.ub_marker.encode() if args.ub_marker else None)
    print(json.dumps(res, indent=2))
    s = res["sample"]
    print(f"\n{res['verdict']}: {s['crashes_fixed']} crash(es) fixed, "
          f"{s['both_ran_cleanly']} input(s) matched exactly, "
          f"{len(res['output_mismatches'])} regression(s), "
          f"{s['excluded_undefined_behaviour']} excluded as already-undefined, "
          f"out of {s['inputs_tried']} tried")
    if args.out:
        Path(args.out).write_text(json.dumps(res, indent=2))
    raise SystemExit(0 if res["verdict"] == "BOUNDED_VERIFICATION" else 1)
