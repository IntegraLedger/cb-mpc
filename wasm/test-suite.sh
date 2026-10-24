#!/bin/bash
# Build cb-mpc's full unit-test suite for wasm32 and run it under node.
#
# Usage: wasm/test-suite.sh <openssl-wasm-threads-prefix>
#   the prefix from scripts/openssl/build-static-openssl-wasm.sh --threads
#
# This is the check that the browser build computes what the native build does: the same 1,400+ upstream
# tests, on the platform upstream does not support. It is how the ILP32 addx/subx truncation was found.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <openssl-wasm-threads-prefix>" >&2
  exit 2
fi
OSSL="$1"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build/wasm-tests"

grep -q '^# *define OPENSSL_THREADS' "$OSSL/include/openssl/configuration.h" || {
  echo "$OSSL is not a threaded build (use build-static-openssl-wasm.sh --threads)" >&2
  exit 1
}

emcmake cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON \
  -DCBMPC_PLATFORM_DEP_OUTPUT_DIR=ON -DCBMPC_OPENSSL_ROOT="$OSSL" \
  -DCMAKE_CXX_FLAGS="-pthread -fwasm-exceptions" \
  -DCMAKE_EXE_LINKER_FLAGS="-pthread -fwasm-exceptions -Wno-pthreads-mem-growth -sPTHREAD_POOL_SIZE=32 -sALLOW_MEMORY_GROWTH=1 -sINITIAL_MEMORY=268435456 -sMAXIMUM_MEMORY=4GB -sSTACK_SIZE=8MB -sDEFAULT_PTHREAD_STACK_SIZE=8MB -sNODERAWFS=1 -sEXIT_RUNTIME=1"
cmake --build "$BUILD" -- -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"

cd "$ROOT"
node "$BUILD/bin/Release/JS-wasm32/cbmpc_test_unit.js" --gtest_brief=1
