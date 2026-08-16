#!/bin/bash
# CPU-bound half of setup: build AFL++ and llama.cpp from source.
# AFL++ has no Ubuntu 26.04 package, and llama.cpp is source-only by design.
set -u
cd /home/sahil/Sanjeevani || exit 1
mkdir -p tools
J=$(nproc)

echo "=== 1/2  AFL++ (with QEMU mode - the part that fuzzes stripped binaries) ==="
if [ -x tools/AFLplusplus/afl-fuzz ]; then
  echo "already built, skipping"
else
  [ -d tools/AFLplusplus ] || git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus tools/AFLplusplus
  cd tools/AFLplusplus || exit 1
  # 'binary-only' = the tools for fuzzing programs we have no source for.
  make binary-only -j"$J" 2>&1 | tail -25
  cd /home/sahil/Sanjeevani || exit 1
fi
echo "afl-fuzz:        $(ls tools/AFLplusplus/afl-fuzz 2>/dev/null || echo MISSING)"
echo "afl-qemu-trace:  $(ls tools/AFLplusplus/afl-qemu-trace 2>/dev/null || echo MISSING)"

echo
echo "=== 2/2  llama.cpp (CPU inference engine for the Qwen model) ==="
# Build llama-completion, NOT llama-cli. In current llama.cpp, llama-cli is
# built around chat/server flows: headless it loads the 4.5 GB model, blocks in
# accept() waiting for a connection that never comes, and prints nothing at all
# on stdout or stderr. It looks exactly like a hang. llama-completion is the
# plain prompt-in/tokens-out tool we actually want.
if [ -x tools/llama.cpp/build/bin/llama-completion ]; then
  echo "already built, skipping"
else
  [ -d tools/llama.cpp ] || git clone --depth 1 https://github.com/ggml-org/llama.cpp tools/llama.cpp
  cd tools/llama.cpp || exit 1
  cmake -B build -DGGML_NATIVE=ON -DLLAMA_CURL=OFF -DCMAKE_BUILD_TYPE=Release > /dev/null
  cmake --build build -j"$J" --target llama-completion 2>&1 | tail -15
  cd /home/sahil/Sanjeevani || exit 1
fi
echo "llama-completion: $(ls tools/llama.cpp/build/bin/llama-completion 2>/dev/null || echo MISSING)"
