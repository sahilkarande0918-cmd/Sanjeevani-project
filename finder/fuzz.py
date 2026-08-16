#!/usr/bin/env python3
"""FIND + LOCALISE - Phase 3.

Three stages, each using the tool that is actually good at its job:

  1. FUZZ      AFL++ in QEMU mode throws inputs at the binary until one
               crashes it. QEMU mode is the whole reason this works on a
               stripped binary: it instruments the CPU at runtime instead of
               needing the source recompiled.
  2. LOCALISE  gdb runs the binary on that exact input and reports the
               address where it actually faulted. Ground truth from real
               hardware, not a model.
  3. READ      Ghidra maps that address to the function containing it and
               decompiles it back to C.

The output is everything Phase 4 needs to write a patch: the crashing input,
the faulting address, and readable source for the function to fix.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AFL = ROOT / "tools" / "AFLplusplus" / "afl-fuzz"
GHIDRA = ROOT / "tools" / "ghidra" / "support" / "analyzeHeadless"
GHIDRA_SCRIPTS = ROOT / "finder" / "ghidra_scripts"


# ---------------------------------------------------------------- 1. fuzz

def fuzz(binary: Path, seconds: int, seed: bytes = b"hi\n") -> tuple[bytes | None, float, int]:
    """Run AFL++ until it finds a crash. Returns (crashing_input, elapsed, execs)."""
    workdir = Path(tempfile.mkdtemp(prefix="sanjeevani_afl_"))
    indir, outdir = workdir / "in", workdir / "out"
    indir.mkdir()
    (indir / "seed").write_bytes(seed)

    env = dict(os.environ)
    env.update({
        "AFL_SKIP_CPUFREQ": "1",     # do not nag about CPU governor
        "AFL_NO_UI": "1",            # no curses UI, we are not watching
        "AFL_NO_AFFINITY": "1",      # do not pin cores
        "AFL_BENCH_UNTIL_CRASH": "1",  # stop the instant we find one
    })

    t0 = time.time()
    try:
        subprocess.run(
            [str(AFL), "-Q", "-m", "none", "-i", str(indir), "-o", str(outdir),
             "--", str(binary)],
            env=env, capture_output=True, timeout=seconds,
        )
    except subprocess.TimeoutExpired:
        pass
    elapsed = time.time() - t0

    crashes = sorted((outdir / "default" / "crashes").glob("id:*")) \
        if (outdir / "default" / "crashes").exists() else []
    data = crashes[0].read_bytes() if crashes else None

    execs = 0
    if crashes:
        m = re.search(r"execs:(\d+)", crashes[0].name)
        execs = int(m.group(1)) if m else 0

    shutil.rmtree(workdir, ignore_errors=True)
    return data, elapsed, execs


# ---------------------------------------------------------------- 2. localise

_RIP = re.compile(r"^rip\s+(0x[0-9a-f]+)", re.M)
_FRAME = re.compile(r"^#\d+\s+(?:0x([0-9a-f]+)\s+in\s+)?(\S+)", re.M)


def image_range(binary: Path) -> tuple[int, int]:
    """The address range the binary itself occupies when loaded.

    Needed to tell OUR code apart from libc. Read from the ELF's PT_LOAD
    segments rather than assumed, so it stays correct if the layout changes.
    """
    from elftools.elf.elffile import ELFFile
    lo = hi = None
    with open(binary, "rb") as fh:
        for seg in ELFFile(fh).iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            start, end = seg["p_vaddr"], seg["p_vaddr"] + seg["p_memsz"]
            lo = start if lo is None else min(lo, start)
            hi = end if hi is None else max(hi, end)
    return lo or 0, hi or 0


def localise(binary: Path, crash_input: bytes) -> dict:
    """Run the binary for real under gdb and find OUR function that is to blame.

    The faulting instruction is frequently not in our code at all. off_by_one
    dies inside puts() and format_string inside printf(), both deep in libc,
    because that is where the corrupted pointer finally gets dereferenced.
    Handing Ghidra a libc address is useless - it only analysed our binary.

    So we do what an analyst does: walk back up the stack to the first frame
    that lies inside our own image. That is the code that has to be patched.
    """
    with tempfile.NamedTemporaryFile(delete=False) as fh:
        fh.write(crash_input)
        inp = fh.name
    try:
        out = subprocess.run(
            ["gdb", "--batch",
             "-ex", f"run < {inp}",
             "-ex", "info registers rip",
             "-ex", "bt",
             str(binary)],
            capture_output=True, text=True, timeout=60,
        ).stdout
    finally:
        os.unlink(inp)

    m = _RIP.search(out)
    fault = int(m.group(1), 16) if m else None

    lo, hi = image_range(binary)
    frames = [int(a, 16) for a, _ in _FRAME.findall(out) if a]

    # Prefer the faulting address when it is already ours, else the first
    # stack frame that is.
    if fault is not None and lo <= fault < hi:
        app_addr, where = fault, "fault"
    else:
        app_addr, where = None, None
        for f in frames:
            if lo <= f < hi:
                app_addr, where = f, "caller"
                break

    return {
        "faulting_address": hex(fault) if fault is not None else None,
        "in_our_code": fault is not None and lo <= fault < hi,
        "blamed_address": hex(app_addr) if app_addr is not None else None,
        "blamed_from": where,
        "image_range": [hex(lo), hex(hi)],
        "frames": [hex(f) for f in frames[:8]],
        "_app_addr": app_addr,
    }


# ---------------------------------------------------------------- 3. read

def localise_symbolic(binary: Path, crash_input: bytes) -> int | None:
    """Fallback when the stack is too smashed for gdb to walk.

    A stack overflow destroys the very frames a backtrace needs, so on the worst
    inputs gdb reports garbage like 0x286686868 - literally our input bytes -
    and not one frame lands inside our binary.

    angr does not care. It replays the same concrete input tracking every basic
    block it executes, so we can just take the last block that belonged to us
    before control was lost. Real hardware first, symbolic execution as backup.
    """
    import logging
    for noisy in ("angr", "cle", "pyvex", "claripy"):
        logging.getLogger(noisy).setLevel("ERROR")
    import angr

    try:
        proj = angr.Project(str(binary), auto_load_libs=False)
        state = proj.factory.full_init_state(
            stdin=crash_input,
            add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                         angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )
        simgr = proj.factory.simulation_manager(state, save_unconstrained=True)
        simgr.run(n=3000)
    except Exception:
        return None

    lo, hi = image_range(binary)
    candidates = (list(simgr.unconstrained)
                  + [e.state for e in simgr.errored]
                  + list(simgr.deadended))
    for st in candidates:
        for a in reversed(list(st.history.bbl_addrs)):
            if lo <= a < hi:
                return a
    return None


def decompile(binary: Path, addr: int) -> dict:
    """Ask Ghidra for the function containing addr, as C."""
    proj = Path(tempfile.mkdtemp(prefix="sanjeevani_ghidra_"))
    outfile = proj / "loc.json"
    try:
        subprocess.run(
            [str(GHIDRA), str(proj), "loc", "-import", str(binary),
             "-scriptPath", str(GHIDRA_SCRIPTS),
             "-postScript", "DecompileAt.java", hex(addr), str(outfile),
             "-deleteProject"],
            capture_output=True, text=True, timeout=600,
        )
        if outfile.exists():
            return json.loads(outfile.read_text())
        return {"found": False, "error": "ghidra produced no output"}
    except subprocess.TimeoutExpired:
        return {"found": False, "error": "ghidra timed out"}
    finally:
        shutil.rmtree(proj, ignore_errors=True)


# ---------------------------------------------------------------- pipeline

def find(binary: Path, seconds: int, outdir: Path) -> dict:
    print(f"[FIND]     fuzzing {binary.name} (max {seconds}s)...")
    crash, elapsed, execs = fuzz(binary, seconds)
    if crash is None:
        print(f"[FIND]     no crash in {elapsed:.1f}s")
        return {"binary": str(binary), "crash_found": False, "fuzz_seconds": round(elapsed, 2)}
    print(f"[FIND]  ok crash in {elapsed:.1f}s after {execs} executions, "
          f"{len(crash)} bytes")

    print("[LOCALISE] running it under gdb...")
    loc = localise(binary, crash)
    app_addr = loc.pop("_app_addr")
    if app_addr is None:
        print(f"[LOCALISE] stack too smashed for gdb ({loc['faulting_address']}); "
              f"falling back to angr...")
        app_addr = localise_symbolic(binary, crash)
        loc["blamed_address"] = hex(app_addr) if app_addr else None
        loc["blamed_from"] = "angr"
        if app_addr is None:
            print("[LOCALISE] angr could not blame our code either")
            return {"binary": str(binary), "crash_found": True,
                    "crash_input_b64": base64.b64encode(crash).decode(),
                    "localisation": loc, "error": "could not blame our code"}
        print(f"[LOCALISE] ok angr blames {loc['blamed_address']}")
    elif loc["in_our_code"]:
        print(f"[LOCALISE] ok faulted in our code at {loc['blamed_address']}")
    else:
        print(f"[LOCALISE] ok faulted inside a library at {loc['faulting_address']}; "
              f"blaming our caller at {loc['blamed_address']}")

    print("[READ]     decompiling with Ghidra...")
    fn = decompile(binary, app_addr)
    if fn.get("found"):
        print(f"[READ]  ok {fn['function']} @ {fn['entry']} ({fn['size']} bytes)")
    else:
        print(f"[READ]     could not decompile: {fn.get('error', 'no function there')}")

    report = {
        "binary": str(binary),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "crash_found": True,
        "fuzz_seconds": round(elapsed, 2),
        "executions": execs,
        "crash_input_b64": base64.b64encode(crash).decode(),
        "crash_input_len": len(crash),
        "localisation": loc,
        "function": fn,
    }

    outdir.mkdir(parents=True, exist_ok=True)
    dest = outdir / f"{binary.stem}_{hashlib.sha256(crash).hexdigest()[:12]}.json"
    dest.write_text(json.dumps(report, indent=2))
    print(f"[SAVED]    {dest}")
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Find a crash and localise it to a function.")
    ap.add_argument("binary")
    ap.add_argument("-s", "--seconds", type=int, default=300,
                    help="fuzzing budget before giving up (default 300)")
    ap.add_argument("-o", "--outdir", default=str(ROOT / "crashes"))
    args = ap.parse_args()

    r = find(Path(args.binary).resolve(), args.seconds, Path(args.outdir))
    raise SystemExit(0 if r.get("crash_found") else 1)
