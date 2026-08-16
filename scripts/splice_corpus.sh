#!/bin/bash
# Phase 5 acceptance: every patched binary must (a) not crash on the input that
# crashed the original, and (b) still behave identically on a benign input.
#
# Both halves matter. Fixing the crash alone is trivial - `return 0` fixes every
# crash ever written. What makes a patch real is that normal behaviour survives.
cd /home/sahil/Sanjeevani || exit 1
mkdir -p spliced
fail=0
for f in patches/*.json; do
  base=$(basename "$f" .json)
  echo "################################ $base"
  .venv/bin/python splicer/rewrite.py "$f" -o "spliced/$base.json" 2>&1 \
    | grep -E '^\[SPLICE\]|^\[VERIFY\]|RuntimeError|error:' | head -10
  echo
done
echo "================================================================"
.venv/bin/python - <<'PY'
import json, pathlib
print("%-18s %-13s %-13s %s" % ("BINARY","CRASH_FIXED","BENIGN_SAME","RESULT"))
print("-"*60)
bad = 0
for f in sorted(pathlib.Path("spliced").glob("*.json")):
    r = json.load(open(f))
    v = r.get("verification", {})
    name = pathlib.Path(r.get("output","?")).stem
    ok = v.get("ok")
    bad += 0 if ok else 1
    print("%-18s %-13s %-13s %s" % (name, v.get("crash_fixed"),
          v.get("benign_output_matches"), "PASS" if ok else "FAIL"))
raise SystemExit(1 if bad else 0)
PY
