// Keygen transcript recorder driving the WASM ENTRY POINTS (plan 0.5, WASM half;
// unblocked by 1.1).
//
// ⚠️ Read this before trusting a comparison made with it. This exercises the
// WASM *source* compiled natively -- `WASM_EXPORT` is empty off Emscripten
// (wasm_ecdsa2p.cpp:16), so wasm_keygen_p1_* / p2_* link and run like ordinary
// C functions. It therefore tests the same LOGIC as the browser, but NOT the
// same artifact or toolchain. A byte-identical result here does not license any
// claim about the shipped cbmpc.wasm; that needs the Emscripten build running
// under node, which is the remaining half of 0.5.
//
// Both parties run in their own thread, exactly as native_keygen_transcript.cpp
// does, because the deterministic RNG shim's state is THREAD-LOCAL. Driving the
// two roles sequentially on one thread would force a re-install between calls,
// which resets the (seed, call-sequence) stream and silently destroys the
// correspondence with a real run where each party draws continuously.
//
// ⛔ wasm_seed_random() is NOT a determinism hook: it is RAND_add(), which mixes
// into an already-seeded DRBG rather than resetting it. Step 0.4 measured three
// processes with an identical 32-byte seed producing three different outputs.

#include <openssl/sha.h>

#include <cbmpc/crypto/base.h>
#include <cbmpc/crypto/test_rng.h>

#include "../../src/cbmpc/wasm/wasm_ecdsa2p.h"

#include <unistd.h>

#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// ⚠️ The P2 role and the curve-code helper are defined in wasm_ecdsa2p.cpp and
// listed in EXPORTED_FUNCTIONS (scripts/build-wasm.sh:65), but they are NOT
// declared in wasm_ecdsa2p.h. JavaScript reaches them by name through
// ccall/cwrap so the omission is invisible there; any C consumer has to
// redeclare them, as here. Worth closing when 2.2 rewrites that file.
extern "C" {
int wasm_get_secp256k1_curve_code(void);
int wasm_keygen_p2_start(int curve, const uint8_t* msg1_in, size_t msg1_len, wasm_keygen_session* out_session);
int wasm_keygen_p2_process(wasm_keygen_session* session, const uint8_t* msg_in, size_t msg_in_len,
                           uint8_t** msg_out, size_t* msg_out_len, int* is_complete);
int wasm_keygen_p2_get_key(wasm_keygen_session* session, wasm_key_handle* out_key);
void wasm_keygen_p2_session_free(wasm_keygen_session* session);
}

namespace {

struct message_t {
  int from, to;
  std::vector<uint8_t> bytes;
};

// Records every message in send order and hands it to the other party.
class channel_t {
 public:
  void send(int from, int to, const uint8_t* data, size_t len) {
    std::unique_lock<std::mutex> lk(m_);
    std::vector<uint8_t> v(data, data + len);
    transcript_.push_back({from, to, v});
    q_[to - 1].push_back(std::move(v));
    cv_.notify_all();
  }

  std::vector<uint8_t> recv(int me) {
    std::unique_lock<std::mutex> lk(m_);
    cv_.wait(lk, [&] { return !q_[me - 1].empty(); });
    auto v = q_[me - 1].front();
    q_[me - 1].pop_front();
    return v;
  }

  std::vector<message_t> transcript_;

 private:
  std::mutex m_;
  std::condition_variable cv_;
  std::deque<std::vector<uint8_t>> q_[2];
};

std::string hex(const std::vector<uint8_t>& v) {
  static const char* d = "0123456789abcdef";
  std::string s;
  s.reserve(v.size() * 2);
  for (uint8_t b : v) { s.push_back(d[b >> 4]); s.push_back(d[b & 15]); }
  return s;
}

std::string sha256_hex(const std::vector<uint8_t>& v) {
  std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
  SHA256(v.data(), v.size(), out.data());
  return hex(out);
}

std::vector<uint8_t> pubkey_of(wasm_key_handle* k) {
  uint8_t* out = nullptr;
  size_t len = 0;
  if (wasm_key_get_public_key(k, &out, &len) != WASM_MPC_SUCCESS || !out) return {};
  std::vector<uint8_t> v(out, out + len);
  wasm_free(out);
  return v;
}

}  // namespace

int main(int argc, char** argv) {
  // usage: wasm_api_keygen_transcript [p1_seed_byte_hex] [p2_seed_byte_hex]
  uint8_t b1 = 0x11, b2 = 0x22;
  if (argc > 1) b1 = (uint8_t)strtol(argv[1], nullptr, 16);
  if (argc > 2) b2 = (uint8_t)strtol(argv[2], nullptr, 16);
  uint8_t seed_p1[32], seed_p2[32];
  memset(seed_p1, b1, sizeof(seed_p1));
  memset(seed_p2, b2, sizeof(seed_p2));
  fprintf(stderr, "seeds p1=0x%02x p2=0x%02x\n", b1, b2);

  if (wasm_init() != WASM_MPC_SUCCESS) { fprintf(stderr, "wasm_init failed\n"); return 2; }
  const int curve = wasm_get_secp256k1_curve_code();

  channel_t ch;
  int rv1 = 0, rv2 = 0;
  std::vector<uint8_t> q1, q2;

  // ⛔ wasm_ecdsa2p.cpp still contains 148 debug printfs (plan 0.7 left them to
  // 2.2, which rewrites that file). They go to stdout and would corrupt the
  // JSON below. A `grep -v "[WASM DEBUG]"` filter is NOT safe -- some of those
  // printfs emit continuation fragments with no prefix at all -- so stdout is
  // redirected to stderr for the duration of the protocol and restored before
  // the transcript is written.
  fflush(stdout);
  int saved_stdout = dup(STDOUT_FILENO);
  if (saved_stdout < 0 || dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
    fprintf(stderr, "could not redirect stdout; refusing to emit a transcript that debug output may corrupt\n");
    return 2;
  }

  // P1: start -> msg1 -> (recv msg2) -> msg3 -> complete
  auto run_p1 = [&] {
    if (!cbmpc_test_rng_install(seed_p1, 32)) { rv1 = -100; return; }
    wasm_keygen_session s{};
    if ((rv1 = wasm_keygen_p1_start(curve, &s))) { fprintf(stderr, "p1_start: %s\n", wasm_get_last_error()); return; }

    uint8_t* out = nullptr; size_t out_len = 0; int done = 0;
    if ((rv1 = wasm_keygen_p1_process(&s, nullptr, 0, &out, &out_len, &done))) {
      fprintf(stderr, "p1 round0: %s\n", wasm_get_last_error()); return;
    }
    ch.send(1, 2, out, out_len); wasm_free(out);

    auto msg2 = ch.recv(1);
    out = nullptr; out_len = 0;
    if ((rv1 = wasm_keygen_p1_process(&s, msg2.data(), msg2.size(), &out, &out_len, &done))) {
      fprintf(stderr, "p1 round1: %s\n", wasm_get_last_error()); return;
    }
    ch.send(1, 2, out, out_len); wasm_free(out);

    out = nullptr; out_len = 0;
    if ((rv1 = wasm_keygen_p1_process(&s, nullptr, 0, &out, &out_len, &done))) {
      fprintf(stderr, "p1 round2: %s\n", wasm_get_last_error()); return;
    }
    if (out) wasm_free(out);

    wasm_key_handle k{};
    if ((rv1 = wasm_keygen_p1_get_key(&s, &k))) { fprintf(stderr, "p1 get_key: %s\n", wasm_get_last_error()); return; }
    q1 = pubkey_of(&k);
    wasm_key_free(&k);
    wasm_keygen_session_free(&s);
    cbmpc_test_rng_uninstall();
  };

  // P2: (recv msg1) -> start -> msg2 -> (recv msg3) -> complete
  auto run_p2 = [&] {
    if (!cbmpc_test_rng_install(seed_p2, 32)) { rv2 = -100; return; }
    auto msg1 = ch.recv(2);
    wasm_keygen_session s{};
    if ((rv2 = wasm_keygen_p2_start(curve, msg1.data(), msg1.size(), &s))) {
      fprintf(stderr, "p2_start: %s\n", wasm_get_last_error()); return;
    }

    uint8_t* out = nullptr; size_t out_len = 0; int done = 0;
    if ((rv2 = wasm_keygen_p2_process(&s, nullptr, 0, &out, &out_len, &done))) {
      fprintf(stderr, "p2 round0: %s\n", wasm_get_last_error()); return;
    }
    ch.send(2, 1, out, out_len); wasm_free(out);

    auto msg3 = ch.recv(2);
    out = nullptr; out_len = 0;
    if ((rv2 = wasm_keygen_p2_process(&s, msg3.data(), msg3.size(), &out, &out_len, &done))) {
      fprintf(stderr, "p2 round1: %s\n", wasm_get_last_error()); return;
    }
    if (out) wasm_free(out);

    wasm_key_handle k{};
    if ((rv2 = wasm_keygen_p2_get_key(&s, &k))) { fprintf(stderr, "p2 get_key: %s\n", wasm_get_last_error()); return; }
    q2 = pubkey_of(&k);
    wasm_key_free(&k);
    wasm_keygen_p2_session_free(&s);
    cbmpc_test_rng_uninstall();
  };

  std::thread t1(run_p1), t2(run_p2);
  t1.join();
  t2.join();

  if (rv1 || rv2) {
    // Still emit what was captured: a partial transcript is exactly what the
    // bisector needs in order to name the round where the run stopped.
    fprintf(stderr, "keygen failed: p1=%d p2=%d after %zu message(s)\n", rv1, rv2, ch.transcript_.size());
  }

  // Restore stdout before the transcript is written.
  fflush(stdout);
  if (dup2(saved_stdout, STDOUT_FILENO) < 0) {
    fprintf(stderr, "could not restore stdout\n");
    return 2;
  }
  close(saved_stdout);

  printf("{\n");
  printf("  \"protocol\": \"ecdsa2pc.dkg\",\n");
  printf("  \"seeds\": {\"p1\": \"%02x\", \"p2\": \"%02x\"},\n", b1, b2);
  printf("  \"messages\": [\n");
  for (size_t i = 0; i < ch.transcript_.size(); i++) {
    const auto& m = ch.transcript_[i];
    printf("    {\"index\": %zu, \"from\": %d, \"to\": %d, \"len\": %zu, \"sha256\": \"%s\", \"hex\": \"%s\"}%s\n",
           i, m.from, m.to, m.bytes.size(), sha256_hex(m.bytes).c_str(), hex(m.bytes).c_str(),
           i + 1 == ch.transcript_.size() ? "" : ",");
  }
  printf("  ],\n");
  printf("  \"result\": {\"q_p1\": \"%s\", \"q_p2\": \"%s\", \"q_agree\": %s}\n",
         hex(q1).c_str(), hex(q2).c_str(), (!q1.empty() && q1 == q2) ? "true" : "false");
  printf("}\n");

  if (rv1 || rv2) return 1;
  return (!q1.empty() && q1 == q2) ? 0 : 1;
}
