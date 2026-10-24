#!/bin/bash
# Build the browser module: wasm/dist/cbmpc.mjs + cbmpc.wasm.
#
# Usage: wasm/build.sh <openssl-wasm-prefix>
#   <openssl-wasm-prefix> from scripts/openssl/build-static-openssl-wasm.sh (single-threaded, 64-bit words).
# Requires emcc on PATH.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <openssl-wasm-prefix>" >&2
  exit 2
fi
OSSL="$1"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build/wasm"
OUT="$ROOT/wasm/dist"

emcmake cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF \
  -DCBMPC_PLATFORM_DEP_OUTPUT_DIR=ON -DCBMPC_OPENSSL_ROOT="$OSSL" -DCMAKE_CXX_FLAGS="-fwasm-exceptions"
cmake --build "$BUILD" -- -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"

LIB="$ROOT/lib/Release/JS-wasm32/libcbmpc.a"
[ -f "$LIB" ] || { echo "missing $LIB" >&2; exit 1; }

mkdir -p "$OUT"
emcc -O3 -std=c++17 -fwasm-exceptions \
  -I "$ROOT/include" -I "$OSSL/include" \
  "$ROOT/wasm/integra_wasm.cpp" "$LIB" "$OSSL/lib/libcrypto.a" \
  -o "$OUT/cbmpc.mjs" \
  -sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORT_NAME=createCbmpc -sENVIRONMENT=worker,node \
  -sALLOW_MEMORY_GROWTH=1 -sSTACK_SIZE=4MB -sFILESYSTEM=0 \
  -sEXPORTED_FUNCTIONS=_integra_rand_status,_integra_dkg_p2,_integra_sign_p2,_integra_public_key,_integra_derive_child,_integra_free_output,_cbmpc_malloc,_cbmpc_free,_malloc,_free \
  -sEXPORTED_RUNTIME_METHODS=HEAPU8,getValue,setValue

shasum -a 256 "$OUT/cbmpc.wasm" "$OUT/cbmpc.mjs"
