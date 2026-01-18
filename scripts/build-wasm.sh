#!/bin/bash
# Build cb-mpc for WebAssembly
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build-wasm"
OUTPUT_DIR="$ROOT_DIR/dist-wasm"
OPENSSL_WASM_ROOT="${CBMPC_OPENSSL_WASM_ROOT:-/tmp/openssl-wasm}"

# Check for Emscripten
if [ -z "$EMSDK" ]; then
  echo "Error: EMSDK not set. Please source emsdk_env.sh first."
  echo "  source /path/to/emsdk/emsdk_env.sh"
  exit 1
fi

# Check for OpenSSL WASM
if [ ! -f "$OPENSSL_WASM_ROOT/lib/libcrypto.a" ]; then
  echo "Error: OpenSSL WASM not found at $OPENSSL_WASM_ROOT"
  echo "Please build it first with scripts/openssl/build-static-openssl-wasm.sh"
  exit 1
fi

echo "Building cb-mpc for WebAssembly..."
echo "  Build dir: $BUILD_DIR"
echo "  Output dir: $OUTPUT_DIR"
echo "  OpenSSL: $OPENSSL_WASM_ROOT"

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR"

# Configure with Emscripten
cd "$BUILD_DIR"
emcmake cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTS=OFF \
  -DBUILD_DUDECT=OFF \
  -DCBMPC_OPENSSL_ROOT="$OPENSSL_WASM_ROOT" \
  -DCMAKE_CXX_FLAGS="-fexceptions -s DISABLE_EXCEPTION_CATCHING=0" \
  "$ROOT_DIR"

# Build the static library and WASM bindings
emmake make -j$(sysctl -n hw.ncpu 2>/dev/null || nproc)

echo ""
echo "Static library built: $BUILD_DIR/lib/Release/libcbmpc.a"

# Link everything into a WASM module
echo ""
echo "Linking WASM module..."

# Exported functions for JavaScript
EXPORTED_FUNCTIONS='["_wasm_alloc", "_wasm_free", "_wasm_init", "_wasm_get_last_error", "_wasm_key_serialize", "_wasm_key_deserialize", "_wasm_key_free", "_wasm_key_get_public_key", "_wasm_key_get_address", "_wasm_key_derive", "_wasm_keygen_p1_start", "_wasm_keygen_p1_process", "_wasm_keygen_p1_get_key", "_wasm_keygen_session_free", "_wasm_sign_p1_start", "_wasm_sign_p1_process", "_wasm_sign_p1_get_signature", "_wasm_sign_session_free", "_malloc", "_free"]'

# Link with Emscripten to produce .wasm + .js
emcc \
  -O3 \
  -fexceptions \
  -s WASM=1 \
  -s MODULARIZE=1 \
  -s EXPORT_ES6=1 \
  -s EXPORT_NAME="createCBMPCModule" \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s EXPORTED_FUNCTIONS="$EXPORTED_FUNCTIONS" \
  -s EXPORTED_RUNTIME_METHODS='["ccall", "cwrap", "getValue", "setValue", "UTF8ToString", "stringToUTF8", "lengthBytesUTF8"]' \
  -s NO_EXIT_RUNTIME=1 \
  -s FILESYSTEM=0 \
  -s ENVIRONMENT='web,worker' \
  -s DISABLE_EXCEPTION_CATCHING=0 \
  "$BUILD_DIR/src/cbmpc/wasm/CMakeFiles/cbmpc_wasm.dir/wasm_ecdsa2p.cpp.o" \
  "$ROOT_DIR/lib/Release/libcbmpc.a" \
  "$OPENSSL_WASM_ROOT/lib/libcrypto.a" \
  -o "$OUTPUT_DIR/cbmpc.js"

echo ""
echo "Build complete!"
echo "  WASM module: $OUTPUT_DIR/cbmpc.wasm"
echo "  JS loader: $OUTPUT_DIR/cbmpc.js"
ls -la "$OUTPUT_DIR/"
