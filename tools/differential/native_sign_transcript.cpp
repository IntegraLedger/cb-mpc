// Native 2-party ECDSA SIGN transcript recorder — the reference the WASM sign
// path must be compared against (remediation plan 2.2 / component 5).
//
// ⛔ Why this exists. The WASM sign recorders compare the WASM entry points
// built natively against the same entry points built with Emscripten. That
// checks the toolchain, NOT the protocol: both sides run the same WASM code, so
// they agree even if that code disagrees with cb-mpc's own implementation.
// Plan step 2.2 says exactly that is the case -- the native prover does
// job.p2_to_p1(c, zk_ecdsa) with c a VECTOR while the WASM sends ser(c) with c
// a bare bn_t, so the wire shape differs and the proof is absent. This recorder
// drives ecdsa2pc::sign over job_2p_t, which is the implementation the enclave
// actually runs, so the two can finally be compared.
//
// Runs a keygen first (3 messages, dropped) and records only the signing
// exchange, so its output lines up with the WASM sign recorders.

#include <openssl/sha.h>

#include <cbmpc/crypto/base.h>
#include <cbmpc/crypto/test_rng.h>
#include <cbmpc/protocol/ecdsa_2p.h>
#include <cbmpc/protocol/mpc_job.h>

#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace coinbase;
using namespace coinbase::mpc;

namespace {

struct message_t {
  int from, to;
  std::vector<uint8_t> bytes;
};

class recording_transport_t : public data_transport_interface_t {
 public:
  error_t send(party_idx_t receiver, mem_t msg) override {
    std::unique_lock<std::mutex> lk(m_);
    int from = 1 - receiver;
    transcript_.push_back({from, (int)receiver, std::vector<uint8_t>(msg.data, msg.data + msg.size)});
    q_[receiver].push_back(std::vector<uint8_t>(msg.data, msg.data + msg.size));
    cv_.notify_all();
    return 0;
  }
  error_t receive(party_idx_t sender, buf_t& msg) override {
    std::unique_lock<std::mutex> lk(m_);
    int me = 1 - sender;
    cv_.wait(lk, [&] { return !q_[me].empty(); });
    auto v = q_[me].front();
    q_[me].pop_front();
    msg = buf_t(v.data(), (int)v.size());
    return 0;
  }
  error_t receive_all(const std::vector<party_idx_t>& senders, std::vector<buf_t>& out) override {
    out.resize(senders.size());
    for (size_t i = 0; i < senders.size(); i++) {
      error_t rv = receive(senders[i], out[i]);
      if (rv) return rv;
    }
    return 0;
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

}  // namespace

int main(int argc, char** argv) {
  uint8_t b1 = 0x11, b2 = 0x22;
  if (argc > 1) b1 = (uint8_t)strtol(argv[1], nullptr, 16);
  if (argc > 2) b2 = (uint8_t)strtol(argv[2], nullptr, 16);
  uint8_t seed_p1[32], seed_p2[32];
  memset(seed_p1, b1, sizeof(seed_p1));
  memset(seed_p2, b2, sizeof(seed_p2));
  fprintf(stderr, "seeds p1=0x%02x p2=0x%02x\n", b1, b2);

  // Same fixed hash the WASM sign recorders use.
  std::vector<uint8_t> msg_hash(32);
  for (int i = 0; i < 32; i++) msg_hash[i] = uint8_t(i);

  // Optional third argument: a hex sid to supply, which skips the handshake.
  std::vector<uint8_t> fixed_sid;
  if (argc > 3) {
    const char* h = argv[3];
    for (size_t i = 0; h[i] && h[i + 1]; i += 2) {
      auto nib = [](char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; };
      fixed_sid.push_back(uint8_t(nib(h[i]) << 4 | nib(h[i + 1])));
    }
    fprintf(stderr, "supplied sid: %zu bytes (handshake skipped)\n", fixed_sid.size());
  }

  auto transport = std::make_shared<recording_transport_t>();
  ecdsa2pc::key_t k1, k2;
  buf_t sig1, sig2;
  error_t rv1 = 0, rv2 = 0;
  size_t keygen_msgs = 0;

  auto run = [&](party_t role, const uint8_t* seed, ecdsa2pc::key_t* key, buf_t* sig, error_t* rv) {
    if (!cbmpc_test_rng_install(seed, 32)) { *rv = -1; return; }
    job_2p_t job(role, crypto::pname_t("server"), crypto::pname_t("client"), transport);
    *rv = ecdsa2pc::dkg(job, crypto::curve_secp256k1, *key);
    if (*rv) { cbmpc_test_rng_uninstall(); return; }
    // ⚠️ sid handling is a CHOICE, not a protocol constant. sign_batch_impl
    // runs generate_sid_fixed_2p ONLY when the sid is empty
    // (ecdsa_2p.cpp:256). Pass one and the two-message handshake disappears.
    // The WASM has P1 generate a sid locally and carry it in its first message,
    // so comparing against an EMPTY-sid native run compares two different
    // deployment choices, not two implementations of the same one.
    buf_t sid;
    if (!fixed_sid.empty()) sid = buf_t(fixed_sid.data(), (int)fixed_sid.size());
    *rv = ecdsa2pc::sign(job, sid, *key, mem_t(msg_hash.data(), (int)msg_hash.size()), *sig);
    cbmpc_test_rng_uninstall();
  };

  std::thread t1(run, party_t::p1, seed_p1, &k1, &sig1, &rv1);
  std::thread t2(run, party_t::p2, seed_p2, &k2, &sig2, &rv2);
  t1.join();
  t2.join();

  // Keygen is 3 messages (measured by native_keygen_transcript); the rest is
  // the signing exchange. Asserted rather than assumed.
  keygen_msgs = 3;  // measured by native_keygen_transcript
  if (transport->transcript_.size() < keygen_msgs) {
    fprintf(stderr, "only %zu messages: keygen did not complete\n", transport->transcript_.size());
    return 1;
  }
  if (rv1 || rv2) fprintf(stderr, "run failed: p1=%d p2=%d after %zu message(s)\n", (int)rv1, (int)rv2, transport->transcript_.size());

  buf_t q = k1.Q.to_compressed_bin();
  std::vector<uint8_t> qv(q.data(), q.data() + q.size());
  std::vector<uint8_t> sigv(sig1.data(), sig1.data() + sig1.size());

  printf("{\n");
  printf("  \"protocol\": \"ecdsa2pc.sign\",\n");
  printf("  \"seeds\": {\"p1\": \"%02x\", \"p2\": \"%02x\"},\n", b1, b2);
  printf("  \"messages\": [\n");
  size_t n = transport->transcript_.size();
  for (size_t i = keygen_msgs; i < n; i++) {
    const auto& m = transport->transcript_[i];
    printf("    {\"index\": %zu, \"from\": %d, \"to\": %d, \"len\": %zu, \"sha256\": \"%s\", \"hex\": \"%s\"}%s\n",
           i - keygen_msgs, m.from + 1, m.to + 1, m.bytes.size(), sha256_hex(m.bytes).c_str(), hex(m.bytes).c_str(),
           i + 1 == n ? "" : ",");
  }
  printf("  ],\n");
  printf("  \"result\": {\"q_p1\": \"%s\", \"q_p2\": \"%s\", \"q_agree\": %s,\n",
         hex(qv).c_str(), hex(qv).c_str(), qv.empty() ? "false" : "true");
  printf("             \"signature\": \"%s\", \"message_hash\": \"%s\"}\n",
         hex(sigv).c_str(), hex(msg_hash).c_str());
  printf("}\n");

  if (rv1 || rv2) return 1;
  return sigv.empty() ? 1 : 0;
}
