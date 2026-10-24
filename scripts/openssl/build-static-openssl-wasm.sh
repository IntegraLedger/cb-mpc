#!/bin/bash
# Build OpenSSL 3.6.4 for WebAssembly (Emscripten) with 64-bit bignum words.
#
# Usage: build-static-openssl-wasm.sh <install-prefix>
#
# The target is defined in wasm32-bn64.conf next to this script: wasm32 pointers, SIXTY_FOUR_BIT
# bignum words, so cb-mpc's 64-bit-word assumptions hold in the browser build.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <install-prefix>" >&2
  exit 2
fi
INSTALL_PREFIX="$1"

if ! command -v emcc >/dev/null 2>&1; then
  echo "emcc not found: source emsdk_env.sh first" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT
cd "$BUILD_DIR"

curl -fsSL https://github.com/openssl/openssl/releases/download/openssl-3.6.4/openssl-3.6.4.tar.gz \
  --output openssl-3.6.4.tar.gz

expectedHash='9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef'
fileHash=$(shasum -a 256 openssl-3.6.4.tar.gz | cut -d " " -f 1)
if [ "$expectedHash" != "$fileHash" ]; then
  echo "sha256 mismatch: expected $expectedHash, got $fileHash" >&2
  exit 1
fi

tar -xzf openssl-3.6.4.tar.gz
cd openssl-3.6.4

# Same patch as the native recipes.
sed -i.bak 's/^static//' crypto/ec/curve25519.c

CC=emcc AR=emar RANLIB=emranlib ./Configure \
  --config="$SCRIPT_DIR/wasm32-bn64.conf" \
  no-asm no-threads no-shared \
  no-afalgeng no-apps no-aria no-autoload-config no-bf no-camellia no-cast \
  no-chacha no-cmac no-cms no-crypto-mdebug no-comp no-cmp no-ct no-des \
  no-dh no-dgram no-dsa no-dso no-dtls no-dynamic-engine no-ec2m no-egd \
  no-engine no-external-tests no-gost no-http no-idea no-mdc2 no-md2 no-md4 \
  no-module no-nextprotoneg no-ocb no-ocsp no-psk no-padlockeng no-poly1305 \
  no-quic no-rc2 no-rc4 no-rc5 no-rfc3779 no-scrypt no-sctp no-seed \
  no-siphash no-sm2 no-sm3 no-sm4 no-sock no-srtp no-srp no-ssl-trace \
  no-ssl3 no-stdio no-tests no-tls no-ts no-unit-test no-uplink \
  no-whirlpool no-zlib \
  --prefix="$INSTALL_PREFIX" \
  wasm32-bn64

if ! grep -q '^# *define SIXTY_FOUR_BIT$' include/openssl/configuration.h; then
  echo "configuration.h does not define SIXTY_FOUR_BIT: the custom target did not apply" >&2
  exit 1
fi

make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" CC=emcc AR=emar RANLIB=emranlib build_libs
make install_sw CC=emcc AR=emar RANLIB=emranlib

echo "OpenSSL 3.6.4 (wasm32-bn64) installed to $INSTALL_PREFIX"
