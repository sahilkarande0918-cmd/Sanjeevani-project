#!/usr/bin/env python3
"""WRITE a fix - Phase 4.

Two routes to a patch, tried in order:

  1. TEMPLATE   Match the decompiled C against templates/*.tmpl and apply a
                known-good rewrite. Deterministic, instant, always compiles.
  2. MODEL      Ask Qwen2.5-Coder, running offline on the CPU, and retry with
                the compiler's error message fed back in.

Templates go FIRST, which is the opposite of what sounds impressive. The
reason is that a 7B model on a laptop CPU produces about 3 tokens a second, so
every model call costs ~20 seconds and can still come back wrong - the smoke
test asked it to fix a strcpy and it echoed the strcpy straight back. A
template that matches is right every time and takes a millisecond. The model
earns its place on the cases no template covers.

Whatever comes out, Phase 2 has to prove it. Neither route is trusted.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = ROOT / "templates"
LLAMA = ROOT / "tools" / "llama.cpp" / "build" / "bin" / "llama-completion"
MODEL = Path.home() / "models" / "qwen2.5-coder-7b-instruct-q4_k_m.gguf"


# ---------------------------------------------------------------- templates

@dataclass
class Template:
    path: Path
    name: str
    cwe: str
    detect: str
    find: str
    replace: str
    explain: str
    caveat: str

    def matches(self, code: str) -> bool:
        return re.search(self.detect, code) is not None

    def apply(self, code: str) -> tuple[str, int]:
        # \0 in the .tmpl means a NUL character in C source, but Python's re
        # would read it as group 0. Protect it before substituting.
        repl = self.replace.replace(r"\0", "\\\\0")
        patched, n = re.subn(self.find, repl, code)
        return patched, n


def _parse_template(path: Path) -> Template:
    fields: dict[str, str] = {}
    key = None
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith(" ") and key:          # continuation line
            fields[key] += " " + line.strip()
        elif ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            fields[key] = val.strip()
    return Template(
        path=path,
        name=fields.get("name", path.stem),
        cwe=fields.get("cwe", ""),
        detect=fields.get("detect", "$^"),
        find=fields.get("find", "$^"),
        replace=fields.get("replace", ""),
        explain=fields.get("explain", ""),
        caveat=fields.get("caveat", ""),
    )


def load_templates() -> list[Template]:
    return [_parse_template(p) for p in sorted(TEMPLATE_DIR.glob("*.tmpl"))]


def try_templates(code: str) -> dict | None:
    for t in load_templates():
        if not t.matches(code):
            continue
        patched, n = t.apply(code)
        if n == 0 or patched == code:
            continue
        return {"route": "template", "template": t.path.name, "bug": t.name,
                "cwe": t.cwe, "replacements": n, "patched_c": patched,
                "explain": t.explain, "caveat": t.caveat}
    return None


# ---------------------------------------------------------------- the model

PROMPT = """\
You are repairing a memory-safety bug in C code recovered from a binary.

Here is the function:

{code}

The bug is a {bug}.

Rewrite the function so the bug is fixed. Obey these rules exactly:
- Change as little as possible. Fix the bug and nothing else.
- Keep the same function name, parameters and return type.
- Keep every printed string byte-for-byte identical.
- Output only C code. No explanation, no markdown fences.

Corrected function:
"""


def ask_model(code: str, bug: str, feedback: str = "", tokens: int = 320) -> str:
    prompt = PROMPT.format(code=code.strip(), bug=bug)
    if feedback:
        prompt += (f"\nYour previous attempt did not compile. The compiler said:\n"
                   f"{feedback}\nFix that and output the corrected function only.\n")
    out = subprocess.run(
        [str(LLAMA), "-m", str(MODEL), "-n", str(tokens), "-c", "2048",
         "-t", "8", "--temp", "0", "-p", prompt],
        capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL,
    ).stdout
    return extract_c(out)


def extract_c(text: str) -> str:
    """Pull C source out of whatever the model wrapped it in."""
    if "```" in text:
        parts = text.split("```")
        if len(parts) >= 2:
            body = parts[1]
            body = re.sub(r"^(c|cpp)\n", "", body)
            return body.strip()
    # Otherwise take from the first line that looks like a function signature.
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.match(r"^\s*(void|int|char|bool|undefined\d*|size_t|unsigned)\b.*\(", line):
            return "\n".join(lines[i:]).strip()
    return text.strip()


# ---------------------------------------------------------------- compiling

CFLAGS = ["-O0", "-no-pie", "-fno-stack-protector", "-U_FORTIFY_SOURCE",
          "-fcf-protection=none", "-g0", "-c"]

# Ghidra's decompiler emits its own pseudo-types for values whose real type it
# could not recover - undefined8, uint, byte and friends. They are not C, so
# decompiled output does not compile as-is. Declaring them is what turns
# "readable C-like text" into something a compiler will actually accept.
PRELUDE = """\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long  undefined8;
typedef unsigned int   undefined4;
typedef unsigned short undefined2;
typedef unsigned char  undefined1;
typedef unsigned char  undefined;
typedef unsigned char  byte;
typedef unsigned int   uint;
typedef unsigned long  ulong;
typedef unsigned long  code;
"""


def compiles(code: str) -> tuple[bool, str]:
    """Does this C actually build? Returns (ok, compiler_error)."""
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "patch.c"
        src.write_text(PRELUDE + code + "\n")
        r = subprocess.run(["gcc", *CFLAGS, str(src), "-o", str(Path(d) / "patch.o")],
                           capture_output=True, text=True)
        return r.returncode == 0, r.stderr.strip()


# ---------------------------------------------------------------- pipeline

def guess_bug(code: str) -> str:
    if re.search(r"\bstrcpy\s*\(", code):
        return "buffer overflow from an unbounded strcpy"
    if re.search(r"<=", code) and "for" in code:
        return "off-by-one loop bound that writes past the end of an array"
    if re.search(r"\bprintf\s*\(\s*\w+\s*\)", code):
        return "format string vulnerability: user input used as a printf format"
    return "memory-safety bug"


def synth(code: str, use_model: bool = True, retries: int = 3,
          model_only: bool = False) -> dict:
    bug = guess_bug(code)

    hit = None if model_only else try_templates(code)
    if hit:
        ok, err = compiles(hit["patched_c"])
        hit.update(compiles=ok, compiler_error=err, bug_guess=bug)
        if ok:
            print(f"[WRITE]  ok template '{hit['template']}' matched "
                  f"({hit['replacements']} replacement(s))")
            return hit
        print(f"[WRITE]     template matched but did not compile: {err.splitlines()[:1]}")

    if not use_model:
        return hit or {"route": "none", "compiles": False,
                       "error": "no template matched and the model was disabled"}

    feedback = ""
    for attempt in range(1, retries + 1):
        print(f"[WRITE]     asking the model (attempt {attempt}/{retries})...")
        try:
            cand = ask_model(code, bug, feedback)
        except subprocess.TimeoutExpired:
            return {"route": "model", "compiles": False, "error": "model timed out"}
        ok, err = compiles(cand)
        if ok:
            print(f"[WRITE]  ok model produced compiling C on attempt {attempt}")
            return {"route": "model", "attempt": attempt, "patched_c": cand,
                    "compiles": True, "bug_guess": bug}
        feedback = err[:400]
        print(f"[WRITE]     did not compile: {(err.splitlines() or [''])[0]}")

    return {"route": "model", "compiles": False, "bug_guess": bug,
            "error": f"model output failed to compile after {retries} attempts"}


def patch_from_report(report_path: Path, use_model: bool = True) -> dict:
    report = json.loads(report_path.read_text())
    fn = report.get("function", {})

    # The blamed function is not always the buggy one - an overflow in greet()
    # faults only once greet RETURNS, so blame lands on main. Phase 3 therefore
    # decompiles callees too. Pick whichever body a template recognises.
    bodies = [(fn.get("function", "?"), fn.get("decompiled", ""))]
    bodies += [(c["function"], c["decompiled"]) for c in fn.get("callees", [])]

    for name, body in bodies:
        if body and try_templates(body):
            print(f"[WRITE]     bug found in {name}")
            out = synth(body, use_model)
            out["target_function"] = name
            out["original_c"] = body
            return out

    name, body = bodies[0]
    print(f"[WRITE]     no template matched; using blamed function {name}")
    out = synth(body, use_model)
    out["target_function"] = name
    out["original_c"] = body
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Write a patch for a crash report.")
    ap.add_argument("report", help="a crashes/*.json file from Phase 3")
    ap.add_argument("--no-model", action="store_true",
                    help="templates only, skip the LLM")
    ap.add_argument("--model-only", action="store_true",
                    help="skip templates, exercise the LLM route")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()

    if args.model_only:
        rep = json.loads(Path(args.report).read_text())
        fn = rep.get("function", {})
        bodies = [fn.get("decompiled", "")] + [c["decompiled"] for c in fn.get("callees", [])]
        body = next((b for b in bodies if b and try_templates(b)), bodies[0])
        res = synth(body, use_model=True, model_only=True)
        res["target_function"] = fn.get("function")
    else:
        res = patch_from_report(Path(args.report), use_model=not args.no_model)
    print(json.dumps({k: v for k, v in res.items() if k != "original_c"}, indent=2))
    if res.get("patched_c"):
        print("--- patched C ---")
        print(res["patched_c"])
    if args.out:
        Path(args.out).write_text(json.dumps(res, indent=2))
    raise SystemExit(0 if res.get("compiles") else 1)
