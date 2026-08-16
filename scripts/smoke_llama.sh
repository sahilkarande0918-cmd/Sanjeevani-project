#!/bin/bash
# Smoke test: does the Qwen model run offline on CPU, and is it fast enough?
#
# Two things are being checked. First that it loads and answers at all, with
# no network. Second - the real question - how many tokens per second we get,
# because Phase 4 has to produce a patch inside the 3-minute budget. Risk R6
# in PLAN.md estimated 5-15 tok/s; this replaces the estimate with a number.
set -u
cd /home/sahil/Sanjeevani || exit 1

LLAMA=tools/llama.cpp/build/bin/llama-cli
MODEL="$HOME/models/qwen2.5-coder-7b-instruct-q4_k_m.gguf"

[ -x "$LLAMA" ]  || { echo "MISSING $LLAMA - run scripts/setup_build.sh"; exit 1; }
[ -f "$MODEL" ]  || { echo "MISSING $MODEL - run: make model"; exit 1; }
echo "model: $(du -h "$MODEL" | cut -f1)"

# A miniature of the real Phase 4 job: show it a bug, ask for the fix.
read -r -d '' PROMPT <<'EOF'
Fix the buffer overflow in this C function. Reply with the corrected line only.

void greet(const char *name) {
    char buf[8];
    strcpy(buf, name);
    printf("hi %s\n", buf);
}
EOF

# -c 2048 is load-bearing, not a tuning knob. Left at its default, llama.cpp
# sizes the KV cache for the model's full 32768-token context and the process
# balloons to ~14 GB RSS on a 15 GB box - it then thrashes swap at 26% CPU and
# never finishes. Our prompts are a decompiled function, a few hundred tokens.
# 2048 is generous for that and keeps the whole thing near the model's own size.
echo "--- generating (first run loads 4.5 GB from disk, so it is the slow one) ---"
t0=$(date +%s)
"$LLAMA" -m "$MODEL" -p "$PROMPT" -n 64 -c 2048 -t "$(nproc)" \
         -no-cnv --temp 0 --no-warmup 2>/tmp/llama.err
rc=$?
t1=$(date +%s)

echo
echo "--- speed ---"
grep -E 'eval time|tokens per second|load time' /tmp/llama.err | head -5
echo "wall clock: $((t1-t0))s, exit=$rc"
[ "$rc" = 0 ] && echo "OK: model runs offline on CPU" || { echo "FAILED"; tail -20 /tmp/llama.err; exit 1; }
