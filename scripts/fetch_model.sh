#!/bin/bash
# Download the Qwen model, resumably.
#
# A 4.7 GB download over a home connection WILL get interrupted. The first
# attempt died with "Connection reset by peer" after a few hundred MB.
# curl's --retry restarts the request but not the file, so a reset meant
# starting from zero. -C - resumes from whatever bytes are already on disk,
# so each retry makes progress instead of repeating work.
set -u
cd /home/sahil/Sanjeevani || exit 1
mkdir -p "$HOME/models"

REPO="Qwen/Qwen2.5-Coder-7B-Instruct-GGUF"
FILE="qwen2.5-coder-7b-instruct-q4_k_m.gguf"
DST="$HOME/models/$FILE"
URL="https://huggingface.co/$REPO/resolve/main/$FILE"
EXPECTED="509287f78cb4d4cf6b3843734733b914b2c158e43e22a7f4bf5e963800894d3c"

verify() {  # returns 0 if the file on disk matches the published hash
  [ -f "$DST" ] || return 1
  [ "$(sha256sum "$DST" | cut -d' ' -f1)" = "$EXPECTED" ]
}

if verify; then echo "model already present and verified"; exit 0; fi

[ -f "$DST" ] && echo "resuming from $(du -h "$DST" | cut -f1)"

for attempt in $(seq 1 40); do
  echo "--- attempt $attempt ---"
  curl -L --fail --silent --show-error -C - -o "$DST" "$URL" \
       --connect-timeout 30 --retry 5 --retry-delay 5 --retry-all-errors
  rc=$?
  have=$( [ -f "$DST" ] && stat -c%s "$DST" || echo 0 )
  echo "curl rc=$rc, have $((have/1024/1024)) MB"

  # rc 33 = server refused a range request; 416 = already complete.
  if [ "$rc" = 0 ] || [ "$rc" = 33 ] || [ "$rc" = 416 ]; then
    if verify; then echo "checksum OK ($((have/1024/1024)) MB)"; exit 0; fi
    echo "download finished but checksum did NOT match - restarting clean"
    rm -f "$DST"
  fi
  sleep 5
done

echo "GAVE UP after 40 attempts"
exit 1
