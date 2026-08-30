#include <cbmpc/crypto/test_rng.h>

#ifdef CBMPC_TEST_RNG

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

namespace {

// SHA-256 in counter mode: output_i = SHA256(seed || LE64(counter++)).
// Deterministic, reproducible across platforms, and independent of any OpenSSL
// DRBG state — which is the whole point, since the DRBG cannot be reset.
struct det_state_t {
  uint8_t seed[64];
  size_t seed_len = 0;
  uint64_t counter = 0;
  uint8_t block[32];
  size_t block_used = 32;  // force a refill on first use
  bool installed = false;
};

det_state_t g_state;
const RAND_METHOD* g_saved = nullptr;

void refill() {
  uint8_t ctr[8];
  for (int i = 0; i < 8; i++) ctr[i] = (uint8_t)((g_state.counter >> (8 * i)) & 0xff);
  g_state.counter++;

  unsigned int out_len = 0;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(ctx, g_state.seed, g_state.seed_len);
  EVP_DigestUpdate(ctx, ctr, sizeof(ctr));
  EVP_DigestFinal_ex(ctx, g_state.block, &out_len);
  EVP_MD_CTX_free(ctx);
  g_state.block_used = 0;
}

int det_bytes(unsigned char* buf, int num) {
  if (num < 0) return 0;
  for (int i = 0; i < num; i++) {
    if (g_state.block_used >= sizeof(g_state.block)) refill();
    buf[i] = g_state.block[g_state.block_used++];
  }
  return 1;
}

int det_status(void) { return 1; }
int det_seed(const void*, int) { return 1; }         // ignored: the seed is fixed at install
int det_add(const void*, int, double) { return 1; }  // ignored, deliberately

RAND_METHOD g_method = {
    det_seed,   // seed
    det_bytes,  // bytes
    nullptr,    // cleanup
    det_add,    // add
    det_bytes,  // pseudorand
    det_status  // status
};

}  // namespace

extern "C" {

int cbmpc_test_rng_install(const uint8_t* seed, size_t seed_len) {
  if (seed == nullptr || seed_len == 0 || seed_len > sizeof(g_state.seed)) return 0;
  memcpy(g_state.seed, seed, seed_len);
  g_state.seed_len = seed_len;
  g_state.counter = 0;
  g_state.block_used = sizeof(g_state.block);
  if (!g_state.installed) g_saved = RAND_get_rand_method();
  if (RAND_set_rand_method(&g_method) != 1) return 0;
  g_state.installed = true;
  return 1;
}

int cbmpc_test_rng_uninstall(void) {
  if (!g_state.installed) return 1;
  if (g_saved != nullptr && RAND_set_rand_method(g_saved) != 1) return 0;
  memset(g_state.seed, 0, sizeof(g_state.seed));
  g_state.seed_len = 0;
  g_state.counter = 0;
  g_state.installed = false;
  return 1;
}

int cbmpc_test_rng_is_installed(void) { return g_state.installed ? 1 : 0; }

}  // extern "C"

#endif  // CBMPC_TEST_RNG
