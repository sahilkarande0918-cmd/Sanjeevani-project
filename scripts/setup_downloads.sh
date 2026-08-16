#!/bin/bash
# Network-bound half of setup: Ghidra (573 MB) + the Qwen model (~4.7 GB).
# This is the ONLY part of the project that touches the internet. Once these
# two files are on disk, everything runs air-gapped.
set -u
cd /home/sahil/Sanjeevani || exit 1
mkdir -p tools "$HOME/models"

GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip"
GHIDRA_ZIP="tools/ghidra.zip"
MODEL_REPO="Qwen/Qwen2.5-Coder-7B-Instruct-GGUF"
MODEL_FILE="qwen2.5-coder-7b-instruct-q4_k_m.gguf"
MODEL_DST="$HOME/models/$MODEL_FILE"

echo "=== 1/2  Ghidra 12.1.2 (573 MB) ==="
if [ -d tools/ghidra ]; then
  echo "already present, skipping"
else
  curl -L --fail --retry 3 -o "$GHIDRA_ZIP" "$GHIDRA_URL" \
       -w 'downloaded %{size_download} bytes in %{time_total}s\n' || { echo "GHIDRA DOWNLOAD FAILED"; exit 1; }
  unzip -q "$GHIDRA_ZIP" -d tools/ && rm -f "$GHIDRA_ZIP"
  mv tools/ghidra_*_PUBLIC tools/ghidra
  echo "analyzeHeadless: $(ls tools/ghidra/support/analyzeHeadless 2>/dev/null || echo MISSING)"
fi

echo
echo "=== 2/2  Qwen2.5-Coder-7B Q4_K_M (~4.7 GB) ==="
# Delegated: a download this size needs resume-on-failure, which is fiddly
# enough to deserve its own script.
bash scripts/fetch_model.sh || exit 1

echo
echo "=== disk used ==="
du -sh tools/ghidra "$HOME/models" 2>/dev/null
