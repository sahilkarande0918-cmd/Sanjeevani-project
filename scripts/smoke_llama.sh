#!/bin/bash
# Smoke test: does the Qwen model run offline on CPU, and how fast?
#
# Uses llama-completion, NOT llama-cli. That distinction cost us hours:
# llama-cli in this build loads the model, blocks in accept() waiting for an
# HTTP connection, and prints nothing to stdout OR stderr. It is
# indistinguishable from a hang. llama-completion is the plain
# prompt-in/tokens-out tool.
#
# -c 512 is also load-bearing: left at its default llama.cpp sizes the KV cache
# for the model's full 32768-token context and the process balloons to ~14 GB
# on a 15 GB box, then thrashes swap instead of computing.
set -u
cd /home/sahil/Sanjeevani || exit 1

LLAMA=tools/llama.cpp/build/bin/llama-completion
MODEL="$HOME/models/qwen2.5-coder-7b-instruct-q4_k_m.gguf"

[ -x "$LLAMA" ] || { echo "MISSING $LLAMA - run scripts/setup_build.sh"; exit 1; }
[ -f "$MODEL" ] || { echo "MISSING $MODEL - run: make model"; exit 1; }
echo "model: $(du -h "$MODEL" | cut -f1)"

t0=$(date +%s)
out=$(timeout 300 "$LLAMA" -m "$MODEL" -n 48 -c 512 -t "$(nproc)" --temp 0 \
        -p 'Fix this C bug. Reply with only the corrected line: strcpy(buf, name);' \
        </dev/null 2>/tmp/llama_smoke.err)
rc=$?
t1=$(date +%s)

echo "--- model said ---"
echo "$out" | head -12
echo "--- speed ---"
grep -E 'prompt eval time|eval time|load time' /tmp/llama_smoke.err | head -4
echo "wall $((t1-t0))s, exit=$rc"

[ "$rc" = 0 ] && [ -n "$out" ] && echo "OK: model runs offline on CPU" \
  || { echo "FAILED (exit $rc)"; tail -15 /tmp/llama_smoke.err; exit 1; }
