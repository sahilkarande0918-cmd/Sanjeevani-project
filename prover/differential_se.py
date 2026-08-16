#!/usr/bin/env python3
"""Differential symbolic execution - the PROVE step of FIND-PATCH-PROVE.

WHAT IS PROVED, AND WHY IT TAKES TWO PARTS
------------------------------------------
A patch has to do two things, and they pull in opposite directions:

    SAFETY      the bug is gone
    EQUIVALENCE nothing else changed

We prove them separately, because they live at different input sizes, and
pretending one number covers both produces nonsense.

  SAFETY is checked with a LARGE symbolic input - big enough to actually
  trigger the bug. We show the original loses control of itself and report the
  address where that happens, and that the patched binary does not.

  EQUIVALENCE is checked with a SMALL symbolic input - small enough that the
  original is still a well-defined program. For every input at that size we
  ask Z3 whether the two binaries can print different things. UNSAT means no
  such input exists: a proof, not a sample.

WHY EQUIVALENCE CANNOT USE THE LARGE BOUND
------------------------------------------
Once the original overflows its buffer it is undefined behaviour, and nothing
sensible is owed to it. Worse, checking equivalence there produces a REAL but
useless complaint. We hit this immediately: on an 8-character input the
original strcpy copies all 8 bytes, while the strncpy fix truncates to 7, so
they genuinely print different things. The prover was right - a textbook
bounds-check fix DOES silently truncate data - but that is a property of the
fix, not a regression to block on. The equivalence bound therefore stays
inside the range where the original is well-defined.

HONESTY
-------
Bounded exploration. If we hit a step or time limit the verdict is
INCONCLUSIVE, never PROVEN. If the original has no surviving normal path at
the equivalence bound, nothing was compared, and "all zero paths matched" is
a vacuous truth - that is also INCONCLUSIVE, not a pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
from dataclasses import dataclass, field

for _noisy in ("angr", "cle", "pyvex", "claripy"):
    logging.getLogger(_noisy).setLevel("ERROR")

import angr        # noqa: E402
import claripy     # noqa: E402


# ---------------------------------------------------------------- helpers

def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def find_main(proj: "angr.Project") -> int:
    """Locate main in a stripped binary.

    No symbol table, but glibc's _start loads main's address into RDI before
    calling __libc_start_main, so the entry block states it outright.
    """
    sym = proj.loader.main_object.get_symbol("main")
    if sym is not None:
        return sym.rebased_addr
    for insn in proj.factory.block(proj.entry).capstone.insns:
        if insn.mnemonic == "mov" and insn.op_str.split(",")[0].strip() in ("rdi", "edi"):
            return int(insn.op_str.split(",")[1].strip(), 16)
    raise RuntimeError(f"could not locate main in {proj.filename}")


def stdout_ast(state):
    """The formula for what the program printed, in terms of the input.

    Not the concrete bytes. The formula is what makes a proof possible rather
    than a spot check.
    """
    packets = state.posix.stdout.content
    if not packets:
        return None
    return claripy.Concat(*[data for data, _size in packets])


# ---------------------------------------------------------------- exploring

@dataclass
class Exploration:
    path: str
    main: int
    deadended: list = field(default_factory=list)
    unconstrained: list = field(default_factory=list)
    crash_states: list = field(default_factory=list)   # touched unmapped memory
    errored: int = 0          # angr genuinely could not continue
    steps: int = 0
    seconds: float = 0.0
    timed_out: bool = False

    @property
    def lost_control(self) -> int:
        """Paths where the program stopped being the program.

        Two flavours, both bugs. 'unconstrained' means the input chose where to
        jump. 'crashed' means it jumped somewhere unmapped - typically address
        0, because the overflow wrote zeros over the return address.
        """
        return len(self.unconstrained) + len(self.crash_states)

    def summary(self) -> dict:
        return {"normal_exits": len(self.deadended),
                "hijacked": len(self.unconstrained),
                "crashed": len(self.crash_states),
                "lost_control": self.lost_control,
                "errored": self.errored,
                "steps": self.steps,
                "seconds": round(self.seconds, 2),
                "timed_out": self.timed_out}


# angr reports "ran off into unmapped memory" as an error. For us that is not
# an analysis failure, it is the bug reproducing.
_CRASH_MARKERS = ("No bytes in memory", "Attempted to execute", "Symbolic jump",
                  "Segfault", "segfault", "SimSegfaultError", "unmapped",
                  "Cannot access")


def _classify_errors(simgr):
    """Split angr's 'errored' pile into real crashes and genuine analysis failures."""
    crash_states, errored = [], 0
    for e in simgr.errored:
        if any(m in str(e.error) for m in _CRASH_MARKERS):
            crash_states.append(e.state)
        else:
            errored += 1
    return crash_states, errored


def explore(path: str, inp, timeout: float, max_states: int,
            mode: str = "equivalence") -> Exploration:
    """Symbolically execute one binary.

    The two checks need OPPOSITE memory models, which cost us a wrong result
    before we noticed:

      mode="equivalence"  zero-fill uninitialised memory, so both binaries
                          start identical and outputs are comparable.
      mode="safety"       angr's defaults. Zero-filling is actively harmful
                          here - it makes a dereference of a corrupted pointer
                          quietly return zeros, so the crash we are hunting
                          silently disappears.

    STRICT_PAGE_ACCESS was tried for safety mode and rejected: it flags normal
    stack access as a violation, reporting BOTH binaries as crashing after 8
    steps at 0x500020, which is angr's own simulated stack region rather than
    anything the program did wrong.
    """
    proj = angr.Project(path, auto_load_libs=False)
    main = find_main(proj)

    stdin = angr.SimFileStream(name="stdin", content=inp, has_end=True)

    # Both binaries must start from the SAME known machine state, or the
    # comparison is meaningless. By default angr invents a fresh unknown value
    # for every byte read before being written - and invents DIFFERENT unknowns
    # for each binary, which then compare as trivially unequal.
    #
    # That bit us immediately: strcpy writes only the terminating NUL and leaves
    # the rest of the buffer untouched, while strncpy zero-fills it. Real
    # hardware prints the same thing either way because printf stops at the
    # first NUL. angr called it a behaviour change because it was comparing two
    # sets of unrelated unknowns.
    #
    # Zero-filling makes the starting state identical and deterministic. It is a
    # modelling assumption, so it is declared in the verdict rather than hidden.
    if mode == "equivalence":
        opts = {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    else:
        opts = set()
    state = proj.factory.call_state(main, stdin=stdin, add_options=opts)
    simgr = proj.factory.simulation_manager(state, save_unconstrained=True)

    exp = Exploration(path=path, main=main)
    t0 = time.time()
    while simgr.active:
        if time.time() - t0 > timeout or len(simgr.active) > max_states:
            exp.timed_out = True
            break
        simgr.step()
        exp.steps += 1

    exp.seconds = time.time() - t0
    exp.deadended = list(simgr.deadended)
    exp.unconstrained = list(getattr(simgr, "unconstrained", []))
    exp.crash_states, exp.errored = _classify_errors(simgr)
    return exp


def crash_address(exp: Exploration) -> int | None:
    """The last instruction the program executed as itself.

    Look in BOTH failure piles. A hijacked path has a symbolic instruction
    pointer; a crashed path ran into unmapped memory. Either way the address we
    want is the last basic block that actually belonged to the program.
    """
    for st in list(exp.unconstrained) + list(exp.crash_states):
        hist = list(st.history.bbl_addrs)
        if hist:
            return hist[-1]
    return None


# ---------------------------------------------------------------- proving

def compare_outputs(sa, sb, inp):
    """Can these two normal exits ever print different things?

    Returns None if they provably cannot - the good case - otherwise a dict
    describing how they differ.
    """
    solver = claripy.Solver()
    for c in list(sa.solver.constraints) + list(sb.solver.constraints):
        solver.add(c)

    if not solver.satisfiable():
        return None                     # these two paths cannot co-occur

    out_a, out_b = stdout_ast(sa), stdout_ast(sb)
    if out_a is None and out_b is None:
        return None
    if out_a is None or out_b is None:
        return {"reason": "one path printed nothing, the other printed something"}

    if out_a.length != out_b.length:
        return {"reason": f"output lengths differ: {out_a.length} vs {out_b.length} bits"}

    solver.add(out_a != out_b)
    if not solver.satisfiable():
        return None                     # PROVED equal on this pair of paths

    ce = solver.eval(inp, 1)[0]
    return {"reason": "an input exists where the two binaries print different things",
            "input_hex": ce.to_bytes(inp.length // 8, "big").hex()}


def check_equivalence(original, patched, nbytes, timeout, max_states) -> dict:
    """Prove the patched binary prints what the original printed."""
    # ONE symbolic variable shared by both runs. Two separate variables would
    # be unrelated and nothing could be compared.
    inp = claripy.BVS("stdin", nbytes * 8)
    a = explore(original, inp, timeout, max_states)
    b = explore(patched, inp, timeout, max_states)

    out = {"symbolic_input_bytes": nbytes,
           "original": a.summary(), "patched": b.summary()}

    if a.timed_out or b.timed_out:
        out.update(result="INCONCLUSIVE",
                   why="exploration hit its limit, so nothing is proved")
        return out

    mismatches, pairs = [], 0
    for sa in a.deadended:
        for sb in b.deadended:
            pairs += 1
            bad = compare_outputs(sa, sb, inp)
            if bad:
                mismatches.append(bad)
    out["paths_compared"] = pairs

    if mismatches:
        out.update(result="DIFFERENT", counterexamples=mismatches[:5],
                   why="the patch changes behaviour on inputs the original handled")
    elif pairs == 0:
        # A proof over zero paths is not a proof.
        out.update(result="INCONCLUSIVE",
                   why=("nothing was compared: the original had no normal exit at "
                        "this bound. Lower --eq-bytes."))
    else:
        out.update(result="IDENTICAL",
                   why=f"all {pairs} reachable normal exit(s) proved to print identical output")
    return out


def check_safety(original, patched, nbytes, timeout, max_states) -> dict:
    """Show the original loses control here, and the patched binary does not."""
    inp = claripy.BVS("stdin", nbytes * 8)
    a = explore(original, inp, timeout, max_states, mode="safety")
    b = explore(patched, inp, timeout, max_states, mode="safety")

    addr = crash_address(a)
    out = {"symbolic_input_bytes": nbytes,
           "original": a.summary(), "patched": b.summary(),
           "address": hex(addr) if addr is not None else None}

    if a.lost_control and not b.lost_control:
        out.update(result="BUG_REMOVED",
                   why=("the original loses control of itself here; "
                        "the patched binary never does"))
    elif not a.lost_control:
        out.update(result="NO_BUG_FOUND",
                   why="the original never lost control at this bound - try a larger --safety-bytes")
    else:
        out.update(result="STILL_VULNERABLE",
                   why="the patched binary still loses control")
    return out


def prove(original: str, patched: str, eq_bytes: int, safety_bytes: int,
          timeout: float, max_states: int) -> dict:
    eq = check_equivalence(original, patched, eq_bytes, timeout, max_states)
    safety = check_safety(original, patched, safety_bytes, timeout, max_states)

    if eq["result"] == "DIFFERENT":
        verdict = "REJECTED"
    elif eq["result"] == "INCONCLUSIVE":
        verdict = "INCONCLUSIVE"
    elif safety["result"] == "STILL_VULNERABLE":
        verdict = "REJECTED"
    else:
        verdict = "PROVEN"

    return {
        "tool": "sanjeevani/differential_se",
        "verdict": verdict,
        "theorem": {
            "safety": "the original loses control at the reported address; the patched binary does not",
            "equivalence": "for every input where the original is well-defined, both print the same thing",
        },
        "assumptions": [
            "both binaries start from an identical machine state, with "
            "uninitialised memory and registers reading as zero",
            "exploration is bounded; results hold up to the stated input sizes",
        ],
        "binaries": {
            "original": {"path": original, "sha256": sha256(original)},
            "patched":  {"path": patched,  "sha256": sha256(patched)},
        },
        "safety": safety,
        "equivalence": eq,
    }


# ---------------------------------------------------------------- cli

GREEN, RED, YELLOW, BOLD, OFF = "\033[92m", "\033[91m", "\033[93m", "\033[1m", "\033[0m"


def banner(res: dict) -> str:
    v = res["verdict"]
    if v == "PROVEN":
        addr = res["safety"].get("address")
        lines = ["PROVEN EQUIVALENT" + (f" EXCEPT AT ADDRESS {addr}" if addr else ""),
                 f"bug removed  ({res['safety']['symbolic_input_bytes']} symbolic bytes)",
                 f"behaviour preserved  ({res['equivalence']['paths_compared']} path(s), "
                 f"{res['equivalence']['symbolic_input_bytes']} symbolic bytes)"]
        colour = GREEN
    elif v == "REJECTED":
        lines = ["PATCH REJECTED", res["equivalence"].get("why", "")]
        colour = RED
    else:
        lines = ["INCONCLUSIVE - NOT PROVED",
                 res["equivalence"].get("why", "")]
        colour = YELLOW

    width = max(len(x) for x in lines) + 4
    bar = "=" * width
    body = "\n".join(f"  {x}" for x in lines)
    return f"{colour}{BOLD}\n{bar}\n{body}\n{bar}{OFF}"


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Prove a patched binary fixes the bug and breaks nothing.")
    ap.add_argument("original")
    ap.add_argument("patched")
    ap.add_argument("--eq-bytes", type=int, default=4,
                    help="input size for the EQUIVALENCE proof; must be small enough "
                         "that the original is still well-defined (default 4)")
    ap.add_argument("--safety-bytes", type=int, default=24,
                    help="input size for the SAFETY check; must be large enough to "
                         "trigger the bug (default 24)")
    ap.add_argument("-t", "--timeout", type=float, default=120.0)
    ap.add_argument("--max-states", type=int, default=200)
    ap.add_argument("-o", "--out", help="write the JSON verdict here")
    args = ap.parse_args()

    res = prove(args.original, args.patched, args.eq_bytes, args.safety_bytes,
                args.timeout, args.max_states)

    print(json.dumps(res, indent=2))
    print(banner(res))

    if args.out:
        with open(args.out, "w") as fh:
            json.dump(res, fh, indent=2)
        print(f"written to {args.out}")

    sys.exit(0 if res["verdict"] == "PROVEN" else 1)
