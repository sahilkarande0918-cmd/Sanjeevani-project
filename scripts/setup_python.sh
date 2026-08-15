#!/bin/bash
# Python side of setup: angr (symbolic execution) + Z3 (proof checker).
# No root needed - everything lands in ./.venv
#
# This is the moment of truth for Python 3.14: angr's release notes claim
# support, but angr depends on several compiled packages (pyvex, unicorn,
# claripy, cle). If any of them lack a 3.14 wheel, pip has to build from
# source, which is slow and can fail outright.
set -u
cd /home/sahil/Sanjeevani || exit 1

if [ ! -d .venv ]; then
  python3 -m venv .venv || { echo "FAILED: could not create venv"; exit 1; }
fi

.venv/bin/python -m pip install --upgrade pip -q
echo "pip: $(.venv/bin/pip --version)"
echo
echo "=== installing angr (this pulls Z3 in as a dependency) ==="
.venv/bin/pip install angr || { echo "FAILED: angr did not install"; exit 1; }

echo
echo "=== versions ==="
.venv/bin/python - <<'PY'
import importlib.metadata as md
for p in ("angr", "z3-solver", "claripy", "pyvex", "cle", "archinfo", "unicorn"):
    try:
        print(f"  {p:12s} {md.version(p)}")
    except Exception:
        print(f"  {p:12s} NOT INSTALLED")
PY
