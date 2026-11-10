#!/usr/bin/env bash
#
# mayhem/test.sh — runs upstream's gtest suite (test-srt, built by mayhem/build.sh with normal flags):
# SRT handshakes, encryption (HaiCrypt KM exchange and data), FEC rebuilding, buffers, sockopts, bonding.
# Each test asserts values; a test that fails is retried once, since several open real loopback sockets.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


RUNNER="$SRC/_build_test/test-srt"
if [ ! -x "$RUNNER" ]; then
  echo "test-srt missing: mayhem/build.sh did not produce $RUNNER" >&2
  emit_ctrf "gtest" 0 1 0
  exit 1
fi

JSON1=$(mktemp) ; JSON2=$(mktemp)
(cd "$SRC/_build_test" && "$RUNNER" --gtest_output="json:$JSON1" >/tmp/test-srt.log 2>&1)
tail -n 5 /tmp/test-srt.log

# Prints "<tests> <passed> <failed> <skipped> <names of failed tests...>" from a gtest JSON report.
summarize() {
  python3 - "$1" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("0 0 0 0"); sys.exit(0)
tests = passed = failed = skipped = 0
names = []
for s in d.get("testsuites", []):
    for t in s.get("testsuite", []):
        if t.get("status") != "RUN":
            continue
        tests += 1
        if t.get("result") == "SKIPPED":
            skipped += 1
        elif t.get("failures"):
            failed += 1
            names.append("%s.%s" % (s["name"], t["name"]))
        else:
            passed += 1
print(tests, passed, failed, skipped, " ".join(names))
PY
}

read -r T1 P1 F1 S1 FAILED1 <<<"$(summarize "$JSON1")"
if [ "${F1:-0}" -gt 0 ]; then
  echo "retrying failed tests once: $FAILED1" >&2
  (cd "$SRC/_build_test" && "$RUNNER" --gtest_filter="$(echo "$FAILED1" | tr ' ' ':')" --gtest_output="json:$JSON2" >/tmp/test-srt-retry.log 2>&1)
  read -r T2 P2 F2 S2 _ <<<"$(summarize "$JSON2")"
  P1=$(( P1 + P2 )) ; F1=$F2 ; S1=$(( S1 + S2 ))
fi
rm -f "$JSON1" "$JSON2"

emit_ctrf "gtest" "${P1:-0}" "$(( ${F1:-0} + (${T1:-0} == 0 ? 1 : 0) ))" "${S1:-0}"
