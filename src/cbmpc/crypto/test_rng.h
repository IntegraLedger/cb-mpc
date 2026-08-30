#pragma once

// Test-only deterministic RNG shim (Integra remediation plan step 0.4).
//
// ⛔ This file exists so protocol transcripts can be byte-compared between the
// native and WASM builds. A deterministic RNG in a custody service is the single
// worst thing that could reach production, so it is defended three ways:
//
//   1. The implementation compiles ONLY when CBMPC_TEST_RNG is defined, which is
//      off by default (cmake option CBMPC_TEST_RNG).
//   2. Even when compiled, it does nothing until cbmpc_test_rng_install() is
//      called explicitly. There is deliberately NO static initializer, so it can
//      never activate as a side effect of linking.
//   3. CI asserts the symbol is absent from every shipped artifact AND that
//      RAND_bytes output differs across two production-build runs.
//
// Why RAND_METHOD and not seed_random(): crypto/base.cpp:103's seed_random() is
// RAND_seed(), i.e. RAND_add() — it MIXES entropy into an already-seeded DRBG
// rather than resetting it, so it yields no reproducibility at all. Verified by
// execution: three processes, identical 32-byte seed, three different outputs.
//
// This shim reaches bn_t::rand() because base_bn.cpp:432/439 call BN_rand()/
// BN_rand_range(), which route through RAND_bytes_ex(), which delegates to a
// custom legacy RAND_METHOD under #ifndef OPENSSL_NO_DEPRECATED_3_0. No OpenSSL
// build in this tree passes no-deprecated, so that path is live. Verified by
// execution on OpenSSL 3.2.0, 3.6.1 and 3.6.4.

#ifdef CBMPC_TEST_RNG

#include <stddef.h>
#include <stdint.h>

extern "C" {

// Install the deterministic RNG, seeded from `seed`. Returns 1 on success.
// Every subsequent RAND_bytes / BN_rand / bn_t::rand draw becomes a pure
// function of (seed, call sequence).
int cbmpc_test_rng_install(const uint8_t* seed, size_t seed_len);

// Restore OpenSSL's real RNG. Returns 1 on success.
int cbmpc_test_rng_uninstall(void);

// 1 if the deterministic shim is currently installed.
int cbmpc_test_rng_is_installed(void);

}  // extern "C"

#endif  // CBMPC_TEST_RNG
