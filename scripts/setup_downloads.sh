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
if [ -f "$MODEL_DST" ]; then
  echo "already present, skipping"
else
  # Hugging Face stores the file's real SHA-256 as the LFS object id.
  # Fetch it FIRST so we can prove the download arrived intact.
  echo "fetching expected checksum..."
  EXPECTED=$(curl -sL "https://huggingface.co/api/models/$MODEL_REPO/tree/main?recursive=1" \
    | .venv/bin/python -c "
import json,sys
for e in json.load(sys.stdin):
    if e.get('path')=='$MODEL_FILE':
        print((e.get('lfs') or {}).get('oid',''))
        break
")
  echo "expected sha256: ${EXPECTED:-<unavailable>}"

  curl -L --fail --retry 3 -o "$MODEL_DST" \
       "https://huggingface.co/$MODEL_REPO/resolve/main/$MODEL_FILE" \
       -w 'downloaded %{size_download} bytes in %{time_total}s\n' || { echo "MODEL DOWNLOAD FAILED"; exit 1; }

  ACTUAL=$(sha256sum "$MODEL_DST" | cut -d' ' -f1)
  echo "actual   sha256: $ACTUAL"
  if [ -n "$EXPECTED" ] && [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "CHECKSUM MISMATCH - deleting corrupt download"
    rm -f "$MODEL_DST"; exit 1
  fi
  echo "checksum OK"
fi

echo
echo "=== disk used ==="
du -sh tools/ghidra "$HOME/models" 2>/dev/null
