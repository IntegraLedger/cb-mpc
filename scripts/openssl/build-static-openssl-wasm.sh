#!/bin/bash
# Build OpenSSL 3.2.0 for WebAssembly (Emscripten)
set -e

# Ensure Emscripten is activated
if [ -z "$EMSDK" ]; then
  echo "Error: EMSDK not set. Please source emsdk_env.sh first."
  echo "  source /path/to/emsdk/emsdk_env.sh"
  exit 1
fi

INSTALL_PREFIX="${CBMPC_OPENSSL_WASM_ROOT:-/tmp/openssl-wasm}"

cd /tmp
if [ ! -f openssl-3.2.0.tar.gz ]; then
  curl -L https://github.com/openssl/openssl/releases/download/openssl-3.2.0/openssl-3.2.0.tar.gz --output openssl-3.2.0.tar.gz
fi

expectedHash='14c826f07c7e433706fb5c69fa9e25dab95684844b4c962a2cf1bf183eb4690e'
fileHash=$(sha256sum openssl-3.2.0.tar.gz | cut -d " " -f 1)

if [ "$expectedHash" != "$fileHash" ]; then
  echo 'ERROR: SHA256 DOES NOT MATCH!'
  echo 'expected: ' $expectedHash
  echo 'file:     ' $fileHash
  exit 1
fi

rm -rf openssl-3.2.0
tar -xzf openssl-3.2.0.tar.gz
cd openssl-3.2.0

# Apply the same patch as native builds
sed -i '' 's/^static//' crypto/ec/curve25519.c 2>/dev/null || sed -i 's/^static//' crypto/ec/curve25519.c

# Set CC and AR to Emscripten tools directly
export CC="emcc"
export AR="emar"
export RANLIB="emranlib"

# Configure for WASM with minimal features (matching the native config)
./Configure \
  no-asm \
  no-threads \
  no-shared \
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
  linux-generic32

# Build with Emscripten - explicit make variables
make -j$(sysctl -n hw.ncpu 2>/dev/null || nproc) \
  CC=emcc AR=emar RANLIB=emranlib \
  build_libs

# Install just the libraries and headers
make install_sw \
  CC=emcc AR=emar RANLIB=emranlib

echo "OpenSSL WASM build complete at: $INSTALL_PREFIX"
echo "libcrypto.a: $INSTALL_PREFIX/lib/libcrypto.a"
