#!/usr/bin/env bash
#
# Manual live smoke-test suite for f5_ssl_scan.py.
#
# Requires a reachable lab BIG-IP (self-signed management cert assumed) with
# credentials exported in the environment:
#
#   export F5_HOST=<mgmt-ip> F5_USERNAME=admin F5_PASSWORD='<password>'
#   bash scripts/smoke.sh
#
# This is NOT run in CI: it needs a real device. It checks each invocation's
# exit code and output, then prints a pass/fail summary.

set -u
S="$(dirname "$0")/../f5_ssl_scan.py"
pass=0; fail=0

run() { # run "<desc>" <want_exit> "<grep|->" -- cmd...
  local d=$1 e=$2 p=$3; shift 3; [ "$1" = "--" ] && shift
  local out rc ok=1
  out=$("$@" 2>&1); rc=$?
  [ "$rc" = "$e" ] || ok=0
  [ "$p" = "-" ] || echo "$out" | grep -qiE -e "$p" || ok=0
  if [ $ok = 1 ]; then echo "PASS [$rc] $d"; pass=$((pass + 1))
  else echo "FAIL [exit $rc want $e] $d"; echo "$out" | sed 's/^/     | /' | head -4; fail=$((fail + 1)); fi
}

echo "## args / credentials (no network) ##"
run "--version"             0 "1\.1\.0"              -- python3 "$S" --version
run "--help lists flags"    0 "--fullciphers"        -- python3 "$S" --help
run "--password rejected"   2 "not supported"        -- python3 "$S" --password x
run "missing host"          2 "host is required"     -- env -u F5_HOST python3 "$S" --insecure
run "missing username"      2 "username is required" -- env -u F5_USERNAME python3 "$S" --insecure

echo "## error paths (need reachable BIG-IP) ##"
run "wrong password (401)"  2 "aborting|401"         -- env F5_PASSWORD=definitelywrong python3 "$S" --insecure
run "default TLS verify"    2 "certificate_verify_failed|aborting" -- python3 "$S"
run "timeout/unreachable"   2 "aborting"             -- python3 "$S" --insecure --host 192.0.2.1 --timeout 3
run "bad CSV path"          2 "no such file|aborting" -- python3 "$S" --insecure --csv /nope/dir/x.csv

echo "## success / output ##"
run "normal run"            0 "report complete"      -- python3 "$S" --insecure
run "verbose"               0 "found .* ssl profile" -- python3 "$S" --insecure --verbose
run "fullciphers"           0 "suite|complete cipher list" -- python3 "$S" --insecure --fullciphers
run "csv output"            0 "report complete"      -- python3 "$S" --insecure --csv /tmp/suite.csv
if [ -s /tmp/suite.csv ] && head -1 /tmp/suite.csv | grep -q "Virtual Server Path"; then
  echo "PASS csv header written"; pass=$((pass + 1))
else echo "FAIL csv header"; fail=$((fail + 1)); fi

rm -f /tmp/suite_ciphers.csv
run "csv + fullciphers"     0 "per-profile cipher list" -- python3 "$S" --insecure --csv /tmp/suite.csv --fullciphers
if [ -s /tmp/suite_ciphers.csv ] && head -1 /tmp/suite_ciphers.csv | grep -q "SSL PROFILE"; then
  echo "PASS cipher csv written"; pass=$((pass + 1))
else echo "FAIL cipher csv"; fail=$((fail + 1)); fi

echo
echo "## RESULT: $pass passed, $fail failed ##"
[ "$fail" = 0 ]
