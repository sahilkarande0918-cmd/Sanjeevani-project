#!/bin/bash
# Sanjeevani Phase 1 - the ONLY step that needs root.
# Run once:  sudo bash ~/Sanjeevani/scripts/install_deps.sh
# Everything else in this project runs as your normal user.

set -u

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run with sudo:  sudo bash $0"
  exit 1
fi

echo "=== 1/3  Refreshing package index (this is what was missing) ==="
apt-get update || { echo "apt-get update FAILED - check network"; exit 1; }

# Pick the first package name that actually has a candidate version.
# Ubuntu 26.04 renamed some of these, so we probe instead of guessing.
pick() {
  for p in "$@"; do
    if apt-cache policy "$p" 2>/dev/null | grep -q 'Candidate: [0-9]'; then
      echo "$p"; return 0
    fi
  done
  return 1
}

echo "=== 2/3  Installing build toolchain, Java, and fuzzer dependencies ==="

CORE="build-essential gcc make cmake ninja-build pkg-config git curl wget unzip file binutils ca-certificates strace"
PYTHON="$(pick python3-dev python3.14-dev) $(pick python3-venv python3.14-venv)"
JAVA="$(pick openjdk-21-jdk-headless openjdk-25-jdk-headless openjdk-24-jdk-headless default-jdk-headless)"
# AFL++ QEMU mode is what lets us fuzz a stripped binary with no source.
# These are its build dependencies.
AFLDEPS="clang llvm llvm-dev libglib2.0-dev libpixman-1-dev automake libtool bison flex meson"

for group in "$CORE" "$PYTHON" "$JAVA" "$AFLDEPS"; do
  # shellcheck disable=SC2086
  [ -n "${group// /}" ] && apt-get install -y $group
done

# AFL++ may or may not be packaged on 26.04. Try it; if absent we build from
# source later as a normal user, which needs no root.
echo "--- optional: AFL++ from apt (we build from source if this is unavailable) ---"
apt-get install -y afl++ afl++-clang 2>/dev/null || echo "afl++ not in apt - will build from source"

echo "=== 3/3  Report ==="
for t in gcc make cmake ninja git curl unzip strace java python3 clang afl-fuzz afl-qemu-trace; do
  loc=$(command -v "$t" 2>/dev/null)
  printf '%-18s %s\n' "$t" "${loc:-MISSING}"
done
echo
echo "Java version:"; java -version 2>&1 | head -1
echo
echo "Done. Tell Claude 'deps installed' and it will take over from here."
