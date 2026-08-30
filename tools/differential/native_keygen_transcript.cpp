// Native 2-party ECDSA keygen transcript recorder (Integra remediation plan 0.5).
//
// Produces a byte-exact transcript of every protocol message under the
// deterministic test RNG, so the native and WASM implementations can be
// compared message-for-message rather than only on their final output.
//
// ⚠️ Drives job_2p_t directly with pnames {"server","client"} — deliberately NOT
// the fork's own wasm_keygen_p1_* entry points, whose DEFAULT_P1_PID is
// pid_from_name("client") where every real counterparty computes
// pid_from_name("server"). Those fail at commitment_t::open in round 2. That
// defect is step 1.1; this harness routes around it so 0.5 does not depend on it.

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

// In-process transport that records every message in send order.
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

}  // namespace

int main(int argc, char** argv) {
  // Distinct per-party seeds: each party has its own RNG in the real protocol,
  // and the shim's state is thread-local so the streams do not interleave.
  // Seeds are settable so the harness can be used as a control (different seed
  // must give a different transcript) and by the round-divergence bisector (0.7).
  //   usage: native_keygen_transcript [p1_seed_byte_hex] [p2_seed_byte_hex]
  uint8_t b1 = 0x11, b2 = 0x22;
  if (argc > 1) b1 = (uint8_t)strtol(argv[1], nullptr, 16);
  if (argc > 2) b2 = (uint8_t)strtol(argv[2], nullptr, 16);
  uint8_t seed_p1[32], seed_p2[32];
  memset(seed_p1, b1, sizeof(seed_p1));
  memset(seed_p2, b2, sizeof(seed_p2));
  fprintf(stderr, "seeds p1=0x%02x p2=0x%02x\n", b1, b2);

  auto transport = std::make_shared<recording_transport_t>();
  ecdsa2pc::key_t k1, k2;
  error_t rv1 = 0, rv2 = 0;

  auto run = [&](party_t role, const uint8_t* seed, ecdsa2pc::key_t* key, error_t* rv) {
    if (!cbmpc_test_rng_install(seed, 32)) { *rv = -1; return; }
    job_2p_t job(role, crypto::pname_t("server"), crypto::pname_t("client"), transport);
    *rv = ecdsa2pc::dkg(job, crypto::curve_secp256k1, *key);
    cbmpc_test_rng_uninstall();
  };

  std::thread t1(run, party_t::p1, seed_p1, &k1, &rv1);
  std::thread t2(run, party_t::p2, seed_p2, &k2, &rv2);
  t1.join();
  t2.join();

  if (rv1 || rv2) { fprintf(stderr, "keygen failed: p1=%d p2=%d\n", (int)rv1, (int)rv2); return 1; }

  printf("messages %zu\n", transport->transcript_.size());
  for (size_t i = 0; i < transport->transcript_.size(); i++) {
    const auto& m = transport->transcript_[i];
    printf("msg %02zu p%d->p%d len %zu sha_prefix %s\n", i, m.from + 1, m.to + 1, m.bytes.size(),
           hex(m.bytes).substr(0, 32).c_str());
  }

  // Public key is the shared output both parties must agree on.
  buf_t q1 = k1.Q.to_compressed_bin(), q2 = k2.Q.to_compressed_bin();
  std::vector<uint8_t> v1(q1.data(), q1.data() + q1.size()), v2(q2.data(), q2.data() + q2.size());
  printf("Q_p1 %s\n", hex(v1).c_str());
  printf("Q_p2 %s\n", hex(v2).c_str());
  printf("Q_agree %s\n", v1 == v2 ? "yes" : "NO");
  return v1 == v2 ? 0 : 1;
}
