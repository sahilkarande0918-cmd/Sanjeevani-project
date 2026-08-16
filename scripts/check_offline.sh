#!/bin/bash
# Definition of Done: zero network calls at runtime.
#
# Traces every network syscall made by the entire demo, across every child
# process - AFL++, QEMU, gdb, the Ghidra JVM, angr, Z3, Patcherex2, clang.
# Then reports anything that actually talks to a remote host.
#
# Loopback and AF_UNIX are reported separately rather than hidden. Local IPC is
# not "phoning home", but a claim of zero network calls should show its working
# rather than quietly redefine the words.
set -u
cd "$(dirname "$0")/.." || exit 1

LOG=/tmp/sanjeevani_net.log
echo "tracing demo.sh --safe (this is slower than normal under strace)..."
strace -f -e trace=network -o "$LOG" ./demo.sh --safe >/tmp/sanjeevani_demo.log 2>&1
demo_rc=$?

echo
echo "=================================================================="
echo "  NETWORK SYSCALL AUDIT"
echo "=================================================================="
total=$(grep -cE 'socket\(|connect\(|sendto\(|recvfrom\(|bind\(' "$LOG" 2>/dev/null || echo 0)
echo "network-related syscalls traced: $total"

echo
echo "--- connect() to a REMOTE address (must be none) ---"
remote=$(grep 'connect(' "$LOG" 2>/dev/null \
         | grep -vE 'AF_UNIX|AF_LOCAL|127\.0\.0\.1|::1|AF_NETLINK' || true)
if [ -z "$remote" ]; then
  echo "  none. No process contacted a remote host."
else
  echo "$remote" | head -20
fi

echo
echo "--- local IPC (AF_UNIX / loopback / netlink), shown for honesty ---"
grep -E 'AF_UNIX|AF_LOCAL|127\.0\.0\.1|::1|AF_NETLINK' "$LOG" 2>/dev/null \
  | sed 's/^\([0-9]*\).*\(socket\|connect\|bind\)(\([^,)]*\).*/  \2 \3/' \
  | sort | uniq -c | sort -rn | head -10
[ -s "$LOG" ] || echo "  (none)"

echo
echo "=================================================================="
if [ -z "$remote" ]; then
  echo "  CLEAN: zero connections to any remote host"
  echo "  demo exit code: $demo_rc   full trace: $LOG"
  exit 0
else
  echo "  FAILED: something contacted the network"
  exit 1
fi
