#!/usr/bin/env bash
#
# mayhem/build.sh — builds the sanitized libsrt (+ HaiCrypt), the three fuzz harnesses and their
# -standalone reproducers, and the upstream gtest suite with normal flags. Offline and re-runnable.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
GTEST_PREFIX=/opt/toolchains/deps/googletest-1.12.1
TARGETS="fuzz_srt_haicrypt fuzz_srt_sockopt fuzz_srt_fec"

# 1) Sanitized library. Debug type keeps the asserts (_DEBUG enables SRT_ASSERT); -O1 keeps fuzzing fast.
#    -fsanitize=fuzzer-no-link puts SanCov edge counters on the library itself.
FUZZ_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
cmake -G Ninja -S . -B _build_fuzz \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_BUILD_TYPE=Debug -DENABLE_DEBUG=ON -DENABLE_HEAVY_LOGGING=OFF \
    -DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS" \
    -DCMAKE_C_FLAGS_DEBUG="-O1" -DCMAKE_CXX_FLAGS_DEBUG="-O1" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DUSE_ENCLIB=openssl-evp -DENABLE_SHARED=OFF -DENABLE_STATIC=ON -DENABLE_APPS=OFF \
    -DENABLE_UNITTESTS=OFF -DENABLE_TESTING=OFF -DENABLE_BONDING=ON
cmake --build _build_fuzz -j"$MAYHEM_JOBS" --target srt_static

# The harnesses include internal headers: reuse the library's own include dirs and defines.
mapfile -t HARNESS_FLAGS < <(python3 - <<'PY'
import json, shlex
cmds = json.load(open("_build_fuzz/compile_commands.json"))
c = next(e for e in cmds if e["file"].endswith("srtcore/fec.cpp"))
keep = []
toks = shlex.split(c["command"])
for i, t in enumerate(toks):
    if t.startswith(("-D", "-I", "-std=")):
        keep.append(t)
    elif t == "-isystem":
        keep += ["-isystem", toks[i + 1]]
print("\n".join(keep))
PY
)
INCS="-I$SRC/srtcore -I$SRC/haicrypt -I$SRC/common -I$SRC/_build_fuzz"
LIBS="$SRC/_build_fuzz/libsrt.a -lssl -lcrypto -lpthread"

# 2) Fuzzers and standalone reproducers. LSan is switched off at build time by lsan_off.cc.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o /tmp/lsan_off.o
for t in $TARGETS; do
    $CXX $SANITIZER_FLAGS $FUZZ_FLAGS -O1 "${HARNESS_FLAGS[@]}" $INCS $LIB_FUZZING_ENGINE \
        "mayhem/$t.cpp" /tmp/lsan_off.o $LIBS -o "/mayhem/$t"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -O1 "${HARNESS_FLAGS[@]}" $INCS \
        "mayhem/$t.cpp" /tmp/standalone_main.o /tmp/lsan_off.o $LIBS -o "/mayhem/$t-standalone"
done

# 3) Upstream's gtest suite with normal flags (no sanitizers), run by mayhem/test.sh.
cmake -G Ninja -S . -B _build_test \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
    -DCMAKE_PREFIX_PATH="$GTEST_PREFIX" \
    -DUSE_ENCLIB=openssl-evp -DENABLE_SHARED=OFF -DENABLE_STATIC=ON -DENABLE_APPS=OFF \
    -DENABLE_BONDING=ON -DENABLE_UNITTESTS=ON -DENABLE_UNITTESTS_DISCOVERY=OFF
cmake --build _build_test -j"$MAYHEM_JOBS" --target test-srt
