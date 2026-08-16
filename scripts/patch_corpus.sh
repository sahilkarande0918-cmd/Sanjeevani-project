#!/bin/bash
# Phase 4 acceptance: every crash report must yield a patch that COMPILES.
# Pass --no-model to test the template route alone (instant, deterministic).
cd /home/sahil/Sanjeevani || exit 1
mkdir -p patches
fail=0
for f in crashes/*.json; do
  name=$(basename "$f" .json)
  echo "################################ $name"
  .venv/bin/python synth/patch.py "$f" "$@" -o "patches/$name.json" 2>&1 | tail -24 || fail=1
  echo
done
echo "================================================================"
.venv/bin/python - <<'PY'
import json, pathlib
print("%-34s %-10s %-22s %s" % ("REPORT","ROUTE","BUG","COMPILES"))
print("-"*78)
for f in sorted(pathlib.Path("patches").glob("*.json")):
    r = json.load(open(f))
    print("%-34s %-10s %-22s %s" % (f.stem[:33], r.get("route","-"),
          (r.get("bug") or r.get("bug_guess","-"))[:21], r.get("compiles")))
PY
exit $fail
