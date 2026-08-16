#!/bin/bash
# Phase 3 acceptance: every corpus binary must produce a crash report with
# correct function localisation, in under 5 minutes each.
cd /home/sahil/Sanjeevani || exit 1
rm -rf crashes
fail=0
for n in stack_overflow off_by_one format_string; do
  echo "############################## $n"
  .venv/bin/python finder/fuzz.py "corpus/out/$n.broken" -s 300 || fail=1
  echo
done
echo "=============================================="
.venv/bin/python - <<'PY'
import json, pathlib
rows = []
for f in sorted(pathlib.Path("crashes").glob("*.json")):
    r = json.load(open(f))
    fn = r.get("function", {})
    loc = r.get("localisation", {})
    rows.append((pathlib.Path(r["binary"]).stem, f"{r['fuzz_seconds']}s",
                 str(r.get("executions", "-")),
                 ("own" if loc.get("in_our_code") else "libc"),
                 loc.get("blamed_address", "-"),
                 fn.get("function", "NOT FOUND")))
print("%-18s %-8s %-8s %-6s %-12s %s" % ("BINARY","TIME","EXECS","FAULT","BLAMED","FUNCTION"))
print("-" * 78)
for r in rows:
    print("%-18s %-8s %-8s %-6s %-12s %s" % r)
PY
exit $fail
