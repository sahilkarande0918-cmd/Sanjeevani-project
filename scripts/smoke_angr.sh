#!/bin/bash
# Smoke test: can angr load a STRIPPED binary, locate main without symbols,
# and symbolically execute? Everything in Phase 2 depends on yes.
cd /home/sahil/Sanjeevani || exit 1
exec .venv/bin/python - <<'PY'
import logging, time
logging.getLogger("angr").setLevel("ERROR")
logging.getLogger("cle").setLevel("ERROR")
logging.getLogger("pyvex").setLevel("ERROR")

import angr, claripy, z3

BIN = "corpus/out/stack_overflow.broken"
proj = angr.Project(BIN, auto_load_libs=False)

print(f"angr {angr.__version__}   z3 {z3.get_version_string()}")
print(f"binary   {BIN}")
print(f"arch     {proj.arch.name}")
print(f"entry    {proj.entry:#x}")
print(f"pie      {proj.loader.main_object.pic}")
print(f"'main' symbol present: {proj.loader.main_object.get_symbol('main') is not None}  (stripped, so expected False)")

# A stripped binary has no 'main' symbol. But glibc's _start always hands
# main's address to __libc_start_main in RDI, so the entry block spells it out.
main_addr = None
for insn in proj.factory.block(proj.entry).capstone.insns:
    if insn.mnemonic == "mov" and insn.op_str.split(",")[0].strip() in ("rdi", "edi"):
        main_addr = int(insn.op_str.split(",")[1].strip(), 16)
        break
print(f"main recovered from _start: {main_addr:#x}" if main_addr else "COULD NOT FIND main")

t0 = time.time()
cfg = proj.analyses.CFGFast()
print(f"CFG      {len(cfg.functions)} functions in {time.time()-t0:.1f}s")

# Symbolically execute main with 16 unknown input bytes.
t0 = time.time()
inp = claripy.BVS("stdin", 16 * 8)
st = proj.factory.call_state(main_addr, stdin=angr.SimFileStream(name="stdin", content=inp, has_end=True))
simgr = proj.factory.simulation_manager(st)
simgr.run(n=60)          # 60 steps is plenty to prove the machinery turns over
print(f"stepped  {time.time()-t0:.1f}s -> {simgr}")
print("OK: angr loads a stripped binary, finds main, and executes symbolically")
PY
