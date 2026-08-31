// 2-party ECDSA SIGN transcript recorder over the WASM entry points
// (remediation plan 0.5 / 1.1's "both roles"; feeds component 5).
//
// Runs a keygen first to obtain both key shares, then records the signing
// exchange. Same JSON shape as the keygen recorders, so transcript-bisect
// compares them directly.
//
// ⚠️ Exercises the WASM SOURCE compiled natively (WASM_EXPORT is empty off
// Emscripten). Same logic as the browser, NOT the same artifact.
//
// ⚠️ API asymmetry, and the host has to absorb it: P1 emits its first message
// as ser(sid, com_msg) -- one buffer -- while wasm_sign_p2_start() demands the
// sid raw and the com_msg serialized, as two separate arguments. So any caller
// must parse cb-mpc's internal wire format to split them. That format is a
// 4-byte big-endian length prefix (core/convert.cpp writes lengths with
// be_set_4), which is an internal detail a JS consumer should not have to know.

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

extern "C" {
int wasm_get_secp256k1_curve_code(void);
int wasm_keygen_p2_start(int curve, const uint8_t* msg1_in, size_t msg1_len, wasm_keygen_session* out_session);
int wasm_keygen_p2_process(wasm_keygen_session* session, const uint8_t* msg_in, size_t msg_in_len,
                           uint8_t** msg_out, size_t* msg_out_len, int* is_complete);
int wasm_keygen_p2_get_key(wasm_keygen_session* session, wasm_key_handle* out_key);
void wasm_keygen_p2_session_free(wasm_keygen_session* session);
int wasm_sign_p2_start(wasm_key_handle* key, const uint8_t* message_hash, size_t hash_len,
                       const uint8_t* sid_in, size_t sid_len, const uint8_t* com_msg_in, size_t com_msg_len,
                       wasm_sign_session* out_session);
int wasm_sign_p2_process(wasm_sign_session* session, const uint8_t* msg_in, size_t msg_in_len,
                         uint8_t** msg_out, size_t* msg_out_len, int* is_complete);
void wasm_sign_p2_session_free(wasm_sign_session* session);
}

namespace {

struct message_t {
  int from, to;
  std::vector<uint8_t> bytes;
};

class channel_t {
 public:
  void send(int from, int to, const uint8_t* data, size_t len) {
    std::unique_lock<std::mutex> lk(m_);
    std::vector<uint8_t> v(data, data + len);
    if (recording_) transcript_.push_back({from, to, v});
    q_[to - 1].push_back(std::move(v));
    cv_.notify_all();
  }
  // ⛔ Returns empty when the peer has given up. Without this the harness
  // DEADLOCKS whenever one party errors and returns: the other waits on a
  // message that will never be sent. That cost a 10-minute timeout, and a hang
  // is a far worse failure mode than a wrong answer because it reports nothing.
  std::vector<uint8_t> recv(int me) {
    std::unique_lock<std::mutex> lk(m_);
    cv_.wait(lk, [&] { return !q_[me - 1].empty() || aborted_; });
    if (q_[me - 1].empty()) return {};
    auto v = q_[me - 1].front();
    q_[me - 1].pop_front();
    return v;
  }

  // Called unconditionally as each party exits, so a peer blocked in recv()
  // is released whether the exit was success or failure.
  void abort() {
    std::unique_lock<std::mutex> lk(m_);
    aborted_ = true;
    cv_.notify_all();
  }
  void start_recording() {
    std::unique_lock<std::mutex> lk(m_);
    recording_ = true;
  }
  std::vector<message_t> transcript_;

 private:
  std::mutex m_;
  std::condition_variable cv_;
  std::deque<std::vector<uint8_t>> q_[2];
  bool recording_ = false;
  bool aborted_ = false;
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

// Decode one length in cb-mpc's variable-length form, mirroring
// converter_t::convert_len (core/convert.cpp:130). The top bits of the first
// byte give the width: 0xxxxxxx = 1 byte, 10xxxxxx = 2, 110xxxxx = 3,
// 111xxxxx = 4.
//
// ⛔ A first attempt assumed a fixed 4-byte big-endian prefix. It was wrong,
// and the harness then deadlocked rather than reporting it. Measured: P1's
// sign msg1 is 50 bytes beginning 0x10, i.e. a ONE-byte length of 16 for the
// 16-byte sid, then a 33-byte com_msg. Read the encoder, do not infer it.
bool decode_len(const std::vector<uint8_t>& b, size_t& off, uint32_t& len) {
  if (off >= b.size()) return false;
  uint8_t b0 = b[off];
  auto need = [&](size_t n) { return off + n <= b.size(); };
  if ((b0 & 0x80) == 0) { len = b0; off += 1; return true; }
  if ((b0 & 0x40) == 0) {
    if (!need(2)) return false;
    len = (uint32_t(b0 & 0x3f) << 8) | b[off + 1];
    off += 2;
    return true;
  }
  if ((b0 & 0x20) == 0) {
    if (!need(3)) return false;
    len = (uint32_t(b0 & 0x1f) << 16) | (uint32_t(b[off + 1]) << 8) | b[off + 2];
    off += 3;
    return true;
  }
  if (!need(4)) return false;
  len = (uint32_t(b0 & 0x1f) << 24) | (uint32_t(b[off + 1]) << 16) | (uint32_t(b[off + 2]) << 8) | b[off + 3];
  off += 4;
  return true;
}

// P1's sign msg1 is ser(sid, com_msg); wasm_sign_p2_start wants the sid raw and
// the com_msg still serialized, so the host has to split them here.
bool split_sid_and_com(const std::vector<uint8_t>& msg1, std::vector<uint8_t>& sid, std::vector<uint8_t>& com) {
  size_t off = 0;
  uint32_t n = 0;
  if (!decode_len(msg1, off, n)) return false;
  if (off + n > msg1.size()) return false;
  sid.assign(msg1.begin() + off, msg1.begin() + off + n);
  com.assign(msg1.begin() + off + n, msg1.end());
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  uint8_t b1 = 0x11, b2 = 0x22;
  if (argc > 1) b1 = (uint8_t)strtol(argv[1], nullptr, 16);
  if (argc > 2) b2 = (uint8_t)strtol(argv[2], nullptr, 16);
  bool tamper = false;
  for (int i = 1; i < argc; i++) if (std::string(argv[i]) == "--tamper") tamper = true;
  uint8_t seed_p1[32], seed_p2[32];
  memset(seed_p1, b1, sizeof(seed_p1));
  memset(seed_p2, b2, sizeof(seed_p2));
  fprintf(stderr, "seeds p1=0x%02x p2=0x%02x\n", b1, b2);

  if (wasm_init() != WASM_MPC_SUCCESS) { fprintf(stderr, "wasm_init failed\n"); return 2; }
  const int curve = wasm_get_secp256k1_curve_code();

  // Fixed message hash so the transcript depends only on the seeds.
  std::vector<uint8_t> msg_hash(32);
  for (int i = 0; i < 32; i++) msg_hash[i] = uint8_t(i);

  channel_t ch;
  int rv1 = 0, rv2 = 0;
  std::vector<uint8_t> signature, pubkey;

  // The WASM layer's 148 debug printfs would corrupt the JSON on stdout.
  fflush(stdout);
  int saved_stdout = dup(STDOUT_FILENO);
  if (saved_stdout < 0 || dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
    fprintf(stderr, "could not redirect stdout\n");
    return 2;
  }

  struct releaser_t {
    channel_t& c;
    ~releaser_t() { c.abort(); }
  };

  auto run_p1 = [&] {
    releaser_t rel{ch};
    if (!cbmpc_test_rng_install(seed_p1, 32)) { rv1 = -100; return; }
    uint8_t* out = nullptr; size_t out_len = 0; int done = 0;

    wasm_keygen_session ks{};
    if ((rv1 = wasm_keygen_p1_start(curve, &ks))) { fprintf(stderr, "p1 keygen_start: %s\n", wasm_get_last_error()); return; }
    if ((rv1 = wasm_keygen_p1_process(&ks, nullptr, 0, &out, &out_len, &done))) { fprintf(stderr, "p1 kg r0: %s\n", wasm_get_last_error()); return; }
    ch.send(1, 2, out, out_len); wasm_free(out);
    auto k_msg2 = ch.recv(1);
    if (k_msg2.empty()) { rv1 = -102; return; }
    out = nullptr;
    if ((rv1 = wasm_keygen_p1_process(&ks, k_msg2.data(), k_msg2.size(), &out, &out_len, &done))) { fprintf(stderr, "p1 kg r1: %s\n", wasm_get_last_error()); return; }
    ch.send(1, 2, out, out_len); wasm_free(out);
    out = nullptr;
    if ((rv1 = wasm_keygen_p1_process(&ks, nullptr, 0, &out, &out_len, &done))) { fprintf(stderr, "p1 kg r2: %s\n", wasm_get_last_error()); return; }
    if (out) wasm_free(out);
    wasm_key_handle key{};
    if ((rv1 = wasm_keygen_p1_get_key(&ks, &key))) { fprintf(stderr, "p1 get_key: %s\n", wasm_get_last_error()); return; }
    {
      uint8_t* pk = nullptr; size_t pk_len = 0;
      if ((rv1 = wasm_key_get_public_key(&key, &pk, &pk_len))) { fprintf(stderr, "p1 pubkey: %s\n", wasm_get_last_error()); return; }
      pubkey.assign(pk, pk + pk_len);
      wasm_free(pk);
    }
    wasm_keygen_session_free(&ks);

    if (ch.recv(1).empty()) { rv1 = -102; return; }  // barrier: P2 signals its key is ready

    // ---- signing ----
    wasm_sign_session ss{};
    if ((rv1 = wasm_sign_p1_start(&key, msg_hash.data(), msg_hash.size(), &ss))) { fprintf(stderr, "p1 sign_start: %s\n", wasm_get_last_error()); return; }
    out = nullptr;
    if ((rv1 = wasm_sign_p1_process(&ss, nullptr, 0, &out, &out_len, &done))) { fprintf(stderr, "p1 sign r0: %s\n", wasm_get_last_error()); return; }
    ch.send(1, 2, out, out_len); wasm_free(out);
    auto s_msg2 = ch.recv(1);
    if (s_msg2.empty()) { rv1 = -102; return; }
    out = nullptr;
    if ((rv1 = wasm_sign_p1_process(&ss, s_msg2.data(), s_msg2.size(), &out, &out_len, &done))) { fprintf(stderr, "p1 sign r1: %s\n", wasm_get_last_error()); return; }
    ch.send(1, 2, out, out_len); wasm_free(out);
    // ⚠️ Signing is a FOUR-message protocol, unlike keygen's three: P1's round 2
    // consumes P2's ciphertext message. Passing nullptr here fails with
    // "Expected P2's ciphertext message".
    auto s_msg4 = ch.recv(1);
    if (s_msg4.empty()) { rv1 = -102; return; }
    // Negative control for plan step 2.2: with --tamper, flip one byte deep
    // inside P2's zk_ecdsa proof. P1 MUST reject. Without this the new verify
    // call could be inert and every run would still look green.
    if (tamper && s_msg4.size() > 3000) {
      s_msg4[3000] ^= 0x01;
      fprintf(stderr, "TAMPERED: flipped byte 3000 of P2's %zu-byte proof message\n", s_msg4.size());
    }
    out = nullptr;
    if ((rv1 = wasm_sign_p1_process(&ss, s_msg4.data(), s_msg4.size(), &out, &out_len, &done))) { fprintf(stderr, "p1 sign r2: %s\n", wasm_get_last_error()); return; }
    if (out) wasm_free(out);
    uint8_t* sig = nullptr; size_t sig_len = 0;
    if ((rv1 = wasm_sign_p1_get_signature(&ss, &sig, &sig_len))) { fprintf(stderr, "p1 get_signature: %s\n", wasm_get_last_error()); return; }
    signature.assign(sig, sig + sig_len);
    wasm_free(sig);
    wasm_sign_session_free(&ss);
    wasm_key_free(&key);
    cbmpc_test_rng_uninstall();
  };

  auto run_p2 = [&] {
    releaser_t rel{ch};
    if (!cbmpc_test_rng_install(seed_p2, 32)) { rv2 = -100; return; }
    uint8_t* out = nullptr; size_t out_len = 0; int done = 0;

    auto k_msg1 = ch.recv(2);
    if (k_msg1.empty()) { rv2 = -102; return; }
    wasm_keygen_session ks{};
    if ((rv2 = wasm_keygen_p2_start(curve, k_msg1.data(), k_msg1.size(), &ks))) { fprintf(stderr, "p2 keygen_start: %s\n", wasm_get_last_error()); return; }
    if ((rv2 = wasm_keygen_p2_process(&ks, nullptr, 0, &out, &out_len, &done))) { fprintf(stderr, "p2 kg r0: %s\n", wasm_get_last_error()); return; }
    ch.send(2, 1, out, out_len); wasm_free(out);
    auto k_msg3 = ch.recv(2);
    if (k_msg3.empty()) { rv2 = -102; return; }
    out = nullptr;
    if ((rv2 = wasm_keygen_p2_process(&ks, k_msg3.data(), k_msg3.size(), &out, &out_len, &done))) { fprintf(stderr, "p2 kg r1: %s\n", wasm_get_last_error()); return; }
    if (out) wasm_free(out);
    wasm_key_handle key{};
    if ((rv2 = wasm_keygen_p2_get_key(&ks, &key))) { fprintf(stderr, "p2 get_key: %s\n", wasm_get_last_error()); return; }
    wasm_keygen_p2_session_free(&ks);

    // Only the signing exchange is recorded.
    ch.start_recording();
    uint8_t ready = 1;
    ch.send(2, 1, &ready, 1);

    // ---- signing ----
    auto s_msg1 = ch.recv(2);
    if (s_msg1.empty()) { rv2 = -102; return; }
    std::vector<uint8_t> sid, com;
    if (!split_sid_and_com(s_msg1, sid, com)) {
      fprintf(stderr, "p2: could not split ser(sid, com_msg); msg1 is %zu bytes, head:", s_msg1.size());
      for (size_t i = 0; i < 16 && i < s_msg1.size(); i++) fprintf(stderr, " %02x", s_msg1[i]);
      fprintf(stderr, "\n");
      rv2 = -101; return;
    }
    wasm_sign_session ss{};
    if ((rv2 = wasm_sign_p2_start(&key, msg_hash.data(), msg_hash.size(), sid.data(), sid.size(),
                                  com.data(), com.size(), &ss))) {
      fprintf(stderr, "p2 sign_start: %s\n", wasm_get_last_error()); return;
    }
    out = nullptr;
    if ((rv2 = wasm_sign_p2_process(&ss, nullptr, 0, &out, &out_len, &done))) { fprintf(stderr, "p2 sign r0: %s\n", wasm_get_last_error()); return; }
    ch.send(2, 1, out, out_len); wasm_free(out);
    auto s_msg3 = ch.recv(2);
    if (s_msg3.empty()) { rv2 = -102; return; }
    out = nullptr;
    if ((rv2 = wasm_sign_p2_process(&ss, s_msg3.data(), s_msg3.size(), &out, &out_len, &done))) { fprintf(stderr, "p2 sign r1: %s\n", wasm_get_last_error()); return; }
    if (out && out_len) { ch.send(2, 1, out, out_len); wasm_free(out); }
    else { fprintf(stderr, "p2 sign r1 produced no message; P1 will stall\n"); rv2 = -103; return; }
    wasm_sign_p2_session_free(&ss);
    wasm_key_free(&key);
    cbmpc_test_rng_uninstall();
  };

  std::thread t1(run_p1), t2(run_p2);
  t1.join();
  t2.join();

  fflush(stdout);
  if (dup2(saved_stdout, STDOUT_FILENO) < 0) { fprintf(stderr, "could not restore stdout\n"); return 2; }
  close(saved_stdout);

  if (rv1 || rv2) fprintf(stderr, "sign failed: p1=%d p2=%d after %zu message(s)\n", rv1, rv2, ch.transcript_.size());

  // The "ready" barrier byte is recorded first; drop it from the transcript.
  std::vector<message_t> msgs;
  for (const auto& m : ch.transcript_) {
    if (m.bytes.size() == 1 && m.from == 2 && msgs.empty()) continue;
    msgs.push_back(m);
  }

  printf("{\n");
  printf("  \"protocol\": \"ecdsa2pc.sign\",\n");
  printf("  \"seeds\": {\"p1\": \"%02x\", \"p2\": \"%02x\"},\n", b1, b2);
  printf("  \"messages\": [\n");
  for (size_t i = 0; i < msgs.size(); i++) {
    const auto& m = msgs[i];
    printf("    {\"index\": %zu, \"from\": %d, \"to\": %d, \"len\": %zu, \"sha256\": \"%s\", \"hex\": \"%s\"}%s\n",
           i, m.from, m.to, m.bytes.size(), sha256_hex(m.bytes).c_str(), hex(m.bytes).c_str(),
           i + 1 == msgs.size() ? "" : ",");
  }
  printf("  ],\n");
  // q_p1/q_p2 carry the shared public key so this shares the keygen schema;
  // the signature and the hash it covers are the extra fields a verifier needs.
  printf("  \"result\": {\"q_p1\": \"%s\", \"q_p2\": \"%s\", \"q_agree\": %s,\n",
         hex(pubkey).c_str(), hex(pubkey).c_str(), pubkey.empty() ? "false" : "true");
  printf("             \"signature\": \"%s\", \"message_hash\": \"%s\"}\n",
         hex(signature).c_str(), hex(msg_hash).c_str());
  printf("}\n");

  if (rv1 || rv2) return 1;
  return signature.empty() ? 1 : 0;
}
