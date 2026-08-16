#!/usr/bin/env python3
"""SPLICE the fix into the binary - Phase 5.

Takes the patched C from Phase 4 and writes it back into the compiled program,
replacing the buggy function in place. The output is a new stripped ELF that
runs on the same machine, with no source, no recompilation of the original,
and no cooperation from whoever shipped it.

TWO CONSTRAINTS THAT DO NOT EXIST WHEN PATCHING SOURCE
------------------------------------------------------
1. A patch may only call functions the binary ALREADY IMPORTS. Replacing
   strcpy with strncpy is the textbook source fix and it simply does not link
   here: a program that called strcpy has no PLT entry for strncpy, and you
   cannot bolt a new library dependency onto a compiled ELF. Bounded copies
   are therefore written out as inline loops that call nothing.
2. Ghidra's decompiled C is not valid C. It uses pseudo-types like undefined8
   for values whose real type it could not recover, so a prelude declaring
   them has to be prepended before anything will compile.
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import tempfile
from pathlib import Path

for _noisy in ("angr", "cle", "pyvex", "claripy", "patcherex2"):
    logging.getLogger(_noisy).setLevel("ERROR")

ROOT = Path(__file__).resolve().parent.parent

# Prepended to every patch before compiling. The typedefs make Ghidra's
# pseudo-types real; the declarations let the patch call libc functions the
# target already imports.
PRELUDE = """\
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

typedef unsigned long  undefined8;
typedef unsigned int   undefined4;
typedef unsigned short undefined2;
typedef unsigned char  undefined1;
typedef unsigned char  undefined;
typedef unsigned char  byte;
typedef unsigned int   uint;
typedef unsigned long  ulong;
"""


def imported_functions(binary: Path) -> set[str]:
    """What the target already links against - the only calls a patch may make."""
    from elftools.elf.elffile import ELFFile
    names = set()
    with open(binary, "rb") as fh:
        elf = ELFFile(fh)
        for section in elf.iter_sections():
            if section.name in (".dynsym", ".symtab"):
                for sym in section.iter_symbols():
                    if sym.name:
                        names.add(sym.name)
    return names


def splice(binary: Path, entry: int, code: str, out: Path,
           clang_version: int = 21) -> dict:
    from patcherex2 import Patcherex, ModifyFunctionPatch
    from patcherex2.components.compilers.clang import Clang

    p = Patcherex(str(binary))
    # Patcherex2 defaults to clang-15, which Ubuntu 26.04 does not package.
    p.compiler = Clang(p, clang_version=clang_version,
                       compiler_flags=["-target", "x86_64-linux-gnu"])
    p.patches.append(ModifyFunctionPatch(entry, PRELUDE + code))
    try:
        p.apply_patches()
    except subprocess.CalledProcessError as e:
        # Patcherex2 runs the compiler with capture_output and lets the raw
        # CalledProcessError escape, so the actual diagnostic is invisible.
        # Surface it - a compiler message is the whole point of the failure.
        raise RuntimeError(
            "patch failed to compile:\n"
            + (e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes)
               else str(e.stderr))
        ) from None
    p.binfmt_tool.save_binary(str(out))
    out.chmod(0o755)
    return {"spliced": True, "output": str(out), "entry": hex(entry)}


def run(binary: Path, data: bytes, timeout: int = 5) -> tuple[int, bytes]:
    r = subprocess.run([str(binary)], input=data, capture_output=True, timeout=timeout)
    return r.returncode, r.stdout


def died_by_signal(rc: int) -> bool:
    """Did this process get killed rather than exit?

    Python's subprocess reports a signal death as a NEGATIVE returncode (-11 for
    SIGSEGV), whereas a shell reports 128+signal. Checking only for >= 128 reads
    every real crash as a clean exit - which briefly made a working patch look
    like a failure here.
    """
    return rc < 0 or rc >= 128


def verify(original: Path, patched: Path, crash_input: bytes,
           benign: bytes = b"hi\n") -> dict:
    """Phase 5 is not done until BOTH of these hold.

    Fixing the crash is easy - `return 0` fixes every crash. What makes a patch
    real is that normal behaviour survives it, so we check the original and the
    patched binary still agree on an input neither of them chokes on.
    """
    o_crash_rc, _ = run(original, crash_input)
    p_crash_rc, p_crash_out = run(patched, crash_input)
    o_ok_rc, o_ok_out = run(original, benign)
    p_ok_rc, p_ok_out = run(patched, benign)

    fixed = died_by_signal(o_crash_rc) and not died_by_signal(p_crash_rc)
    preserved = (o_ok_rc == p_ok_rc) and (o_ok_out == p_ok_out)
    return {
        "original_crashes": died_by_signal(o_crash_rc),
        "original_exit": o_crash_rc,
        "patched_exit_on_crash_input": p_crash_rc,
        "patched_output_on_crash_input": p_crash_out.decode(errors="replace").strip(),
        "crash_fixed": fixed,
        "benign_output_matches": preserved,
        "benign_original": o_ok_out.decode(errors="replace").strip(),
        "benign_patched": p_ok_out.decode(errors="replace").strip(),
        "ok": fixed and preserved,
    }


def splice_from_patch(patch_path: Path, outdir: Path | None = None) -> dict:
    import base64
    patch = json.loads(patch_path.read_text())

    binary = Path(patch["binary"])
    entry = int(str(patch["target_entry"]), 16)
    code = patch["patched_c"]
    out = (outdir or binary.parent) / (binary.stem + ".patched")

    print(f"[SPLICE]   {binary.name}: replacing {patch['target_function']} @ {hex(entry)}")

    # Guard the constraint that bit us, with a clear message rather than a
    # confusing UndefinedSymbolError out of the linker.
    available = imported_functions(binary)
    for risky in ("strncpy", "snprintf", "strlcpy", "memmove_s"):
        if risky + "(" in code.replace(" ", "") and risky not in available:
            print(f"[SPLICE]     WARNING: patch calls {risky}(), which this binary "
                  f"does not import. It will not link.")

    res = splice(binary, entry, code, out)
    print(f"[SPLICE] ok wrote {out}")

    # Find the crashing input that started all this.
    crash_reports = sorted((ROOT / "crashes").glob(f"{binary.stem}_*.json"))
    crash_input = b"A" * 40 + b"\n"
    if crash_reports:
        rep = json.loads(crash_reports[-1].read_text())
        if rep.get("crash_input_b64"):
            crash_input = base64.b64decode(rep["crash_input_b64"])

    v = verify(binary, out, crash_input)
    res["verification"] = v
    print(f"[VERIFY]   crash fixed: {v['crash_fixed']}   "
          f"benign behaviour preserved: {v['benign_output_matches']}")
    if not v["ok"]:
        print(f"[VERIFY]     original benign: {v['benign_original']!r}")
        print(f"[VERIFY]     patched  benign: {v['benign_patched']!r}")
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Splice a patch into a stripped binary.")
    ap.add_argument("patch", help="a patches/*.json file from Phase 4")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()

    r = splice_from_patch(Path(args.patch))
    print(json.dumps(r, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(r, indent=2))
    raise SystemExit(0 if r["verification"]["ok"] else 1)
