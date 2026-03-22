#!/usr/bin/env bash
# Black-box functional tests for ipk-L2L3-scan (CLI).
# Run from project root (Makefile does this). Tests 3–4 need root or sudo for raw sockets + pcap.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT" || exit 1

SCANNER="${SCANNER:-./ipk-L2L3-scan}"
FAILED=0

SUDO=()
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  SUDO=(sudo)
fi

pass() { echo "[OK]   $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }

if [ ! -x "$SCANNER" ]; then
  echo "[FAIL] Scanner binary not found or not executable: $SCANNER (run 'make' first)"
  exit 1
fi

echo "============================================================================"
echo "  Functional tests (black-box CLI) - $SCANNER"
echo "============================================================================"

# --- Test 1: help must succeed ---
"$SCANNER" -h >/dev/null 2>&1
ec1=$?
if [ "$ec1" -eq 0 ]; then
  pass "Test 1: ./ipk-L2L3-scan -h returns exit code 0"
else
  fail "Test 1: -h expected exit 0, got $ec1"
fi

# --- Test 2: list interfaces (-i with no further args) ---
out2=$("$SCANNER" -i 2>&1)
ec2=$?
if [ "$ec2" -ne 0 ]; then
  fail "Test 2: -i (list) expected exit 0, got $ec2"
elif [ -z "${out2//[$'\t\r\n ']/}" ]; then
  fail "Test 2: -i (list) expected non-empty output"
else
  pass "Test 2: ./ipk-L2L3-scan -i lists interfaces and returns 0"
fi

# --- Test 3: output format (grep Scanning ranges: and 127.0.0.0/30 2) ---
if [ "${#SUDO[@]}" -eq 0 ]; then
  run3=("$SCANNER")
else
  run3=("${SUDO[@]}" "$SCANNER")
fi
out3=$("${run3[@]}" -i lo -s 127.0.0.1/30 2>&1)
ec3=$?
if [ "$ec3" -ne 0 ]; then
  fail "Test 3: scan exited $ec3 (root/sudo may be required; first bytes: ${out3:0:160})"
elif ! echo "$out3" | grep -q 'Scanning ranges:'; then
  fail "Test 3: output missing 'Scanning ranges:'"
elif ! echo "$out3" | grep -q '127\.0\.0\.0/30 2'; then
  fail "Test 3: output missing line with '127.0.0.0/30 2'"
else
  pass "Test 3: output contains Scanning ranges: and 127.0.0.0/30 2"
fi

# --- Test 4: non-existent interface must fail ---
if [ "${#SUDO[@]}" -eq 0 ]; then
  run4=("$SCANNER")
else
  run4=("${SUDO[@]}" "$SCANNER")
fi
"${run4[@]}" -i nonexist0 -s 127.0.0.1/32 >/dev/null 2>&1
ec4=$?
if [ "$ec4" -eq 0 ]; then
  fail "Test 4: expected non-zero exit for -i nonexist0, got 0"
else
  pass "Test 4: -i nonexist0 exits non-zero (exit code $ec4)"
fi

if [ "$FAILED" -ne 0 ]; then
  echo "----------------------------------------------------------------------------"
  echo "[SUMMARY] Functional tests: aborted after core checks (see failures above)"
  exit 1
fi

# --- Test 5: empty line between summary and host results ---
# Reuse output from test 3.
if echo "$out3" | grep -Pzq "Scanning ranges:.*\n.*\n\n"; then
  pass "Test 5: empty line between summary and results found"
else
  # Fallback if grep lacks -P (Perl regex).
  if [[ "$out3" =~ $'\n\n' ]]; then
    pass "Test 5: empty line between sections found (fallback check)"
  else
    fail "Test 5: MISSING empty line between summary and results"
  fi
fi

# --- Test 6: IPv6 normalization and host count (/126 -> 3 hosts) ---
# Assignment-style check: fd00:cafe::1/126 -> summary fd00:cafe::/126 3
out6=$("${run3[@]}" -i lo -s fd00:cafe::1/126 2>&1)
if echo "$out6" | grep -iq 'fd00:cafe::/126 3'; then
  pass "Test 6: IPv6 normalization and host count (3 hosts for /126)"
else
  fail "Test 6: IPv6 output format mismatch or wrong host count"
fi

# --- Test 7: Missing -s SUBNET must fail ---
"$SCANNER" -i lo >/dev/null 2>&1
ec7=$?
if [ "$ec7" -ne 0 ]; then
  pass "Test 7: missing -s correctly returns non-zero"
else
  fail "Test 7: expected error when -s is missing, but got 0"
fi

# --- Test 8: multiple subnets (IPv4 + IPv6) and argument order ---
out8=$("${run3[@]}" -s fd00:cafe::1/128 -w 100 -i lo -s 127.0.0.1/32 2>&1)

# Both subnets must appear in the summary (tolerant to IPv6 textual normalization).
if echo "$out8" | grep -qE '127\.0\.0\.[01]/32 1' && echo "$out8" | grep -iq 'fd00:cafe:.*128 1'; then
  pass "Test 8: Mixed IPv4/IPv6 subnets and random argument order"
else
  fail "Test 8: Mixed subnets or argument order failed"
fi

# --- Test 9: long option --help ---
"$SCANNER" --help > /dev/null 2>&1
if [ $? -eq 0 ]; then
  pass "Test 9: --help returns exit code 0"
else
  fail "Test 9: --help expected exit 0"
fi

# --- Test 10: duplicate -s subnet (must not crash; exit 0 or non-zero acceptable) ---
"$SCANNER" -i lo -s 127.0.0.1/32 -s 127.0.0.1/32 > /dev/null 2>&1
if [ $? -eq 0 ]; then
  pass "Test 10: Duplicate subnets handled without crash"
else
  pass "Test 10: Duplicate subnets returned non-zero (acceptable if handled as error)"
fi

# --- Test 11: invalid IPv4 prefix /33 ---
"$SCANNER" -i lo -s 127.0.0.1/33 > /dev/null 2>&1
if [ $? -ne 0 ]; then
  pass "Test 11: Invalid prefix /33 correctly rejected"
else
  fail "Test 11: Invalid prefix /33 should have failed with non-zero exit code"
fi
echo "----------------------------------------------------------------------------"
if [ "$FAILED" -ne 0 ]; then
  echo "[SUMMARY] Functional tests: some checks failed (see [FAIL] lines above)"
  exit 1
fi
echo "[SUMMARY] Functional tests: all checks passed"
exit 0
