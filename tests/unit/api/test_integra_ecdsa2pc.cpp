// Integra extension tests: document-hash derivation over ECDSA-2PC key blobs.
//
// The derived public key and every signature are checked with OpenSSL's own EC and ECDSA code, not cb-mpc's,
// so a defect shared by cb-mpc's curve arithmetic and its verifier cannot pass.

#include <gtest/gtest.h>
#include <memory>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <vector>

#include <cbmpc/api/ecdsa_2p.h>
#include <cbmpc/api/integra_ecdsa_2p.h>
#include <cbmpc/c_api/integra_ecdsa_2p.h>

#include "test_transport_harness.h"
#include "utils/local_network/network_context.h"

namespace {

using coinbase::buf_t;
using coinbase::error_t;
using coinbase::mem_t;
using coinbase::api::curve_id;
using coinbase::api::ecdsa_2p::party_t;
using coinbase::testutils::mpc_net_context_t;
using coinbase::testutils::api_harness::local_api_transport_t;
using coinbase::testutils::api_harness::run_2pc;

// secp256k1 group order n, big-endian.
const uint8_t kOrder[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
                            0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

buf_t zeros(int n) {
  buf_t b(n);
  for (int i = 0; i < n; i++) b[i] = 0;
  return b;
}

buf_t tweak_of(uint8_t fill) {
  buf_t t(32);
  for (int i = 0; i < 32; i++) t[i] = static_cast<uint8_t>(fill + i);
  return t;
}

// Q + t*G computed by OpenSSL, compressed.
buf_t openssl_add_tweak(const buf_t& Q_compressed, const buf_t& tweak) {
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
  EC_POINT* Q = EC_POINT_new(group);
  EC_POINT* R = EC_POINT_new(group);
  BIGNUM* t = BN_bin2bn(tweak.data(), tweak.size(), nullptr);
  BIGNUM* one = BN_new();
  BN_one(one);
  EXPECT_EQ(EC_POINT_oct2point(group, Q, Q_compressed.data(), Q_compressed.size(), nullptr), 1);
  EXPECT_EQ(EC_POINT_mul(group, R, t, Q, one, nullptr), 1);
  buf_t out(33);
  EXPECT_EQ(EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, out.data(), out.size(), nullptr), 33u);
  BN_free(one);
  BN_free(t);
  EC_POINT_free(R);
  EC_POINT_free(Q);
  EC_GROUP_free(group);
  return out;
}

// ECDSA verification of a DER signature over a 32-byte prehash, by OpenSSL.
bool openssl_verify(const buf_t& pub_compressed, const buf_t& hash, const buf_t& sig_der) {
  OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
  OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "secp256k1", 0);
  OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_compressed.data(), pub_compressed.size());
  OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
  EVP_PKEY_CTX* fctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY* pkey = nullptr;
  EXPECT_EQ(EVP_PKEY_fromdata_init(fctx), 1);
  EXPECT_EQ(EVP_PKEY_fromdata(fctx, &pkey, EVP_PKEY_PUBLIC_KEY, params), 1);
  EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new(pkey, nullptr);
  EXPECT_EQ(EVP_PKEY_verify_init(vctx), 1);
  const int ok = EVP_PKEY_verify(vctx, sig_der.data(), sig_der.size(), hash.data(), hash.size());
  EVP_PKEY_CTX_free(vctx);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(fctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(bld);
  return ok == 1;
}

class IntegraDeriveChild : public ::testing::Test {
 protected:
  void SetUp() override {
    c1 = std::make_shared<mpc_net_context_t>(0);
    c2 = std::make_shared<mpc_net_context_t>(1);
    std::vector<std::shared_ptr<mpc_net_context_t>> peers = {c1, c2};
    c1->init_with_peers(peers);
    c2->init_with_peers(peers);
    t1 = std::make_unique<local_api_transport_t>(c1);
    t2 = std::make_unique<local_api_transport_t>(c2);
    job1 = std::make_unique<coinbase::api::job_2p_t>(coinbase::api::job_2p_t{party_t::p1, "p1", "p2", *t1});
    job2 = std::make_unique<coinbase::api::job_2p_t>(coinbase::api::job_2p_t{party_t::p2, "p1", "p2", *t2});

    error_t rv1 = UNINITIALIZED_ERROR, rv2 = UNINITIALIZED_ERROR;
    run_2pc(
        c1, c2, [&] { return coinbase::api::ecdsa_2p::dkg(*job1, curve_id::secp256k1, blob1); },
        [&] { return coinbase::api::ecdsa_2p::dkg(*job2, curve_id::secp256k1, blob2); }, rv1, rv2);
    ASSERT_EQ(rv1, SUCCESS);
    ASSERT_EQ(rv2, SUCCESS);
    ASSERT_EQ(coinbase::api::ecdsa_2p::get_public_key_compressed(blob1, master_pub), SUCCESS);
  }

  // Signs `hash` with the two blobs; returns P1's DER signature.
  buf_t sign(const buf_t& b1, const buf_t& b2, const buf_t& hash) {
    buf_t sid1, sid2, sig1, sig2;
    error_t rv1 = UNINITIALIZED_ERROR, rv2 = UNINITIALIZED_ERROR;
    run_2pc(
        c1, c2, [&] { return coinbase::api::ecdsa_2p::sign(*job1, b1, hash, sid1, sig1); },
        [&] { return coinbase::api::ecdsa_2p::sign(*job2, b2, hash, sid2, sig2); }, rv1, rv2);
    EXPECT_EQ(rv1, SUCCESS);
    EXPECT_EQ(rv2, SUCCESS);
    return sig1;
  }

  std::shared_ptr<mpc_net_context_t> c1, c2;
  std::unique_ptr<local_api_transport_t> t1, t2;
  std::unique_ptr<coinbase::api::job_2p_t> job1, job2;
  buf_t blob1, blob2, master_pub;
};

TEST_F(IntegraDeriveChild, ChildKeyIsMasterPlusTweakAndSigns) {
  buf_t hash(32);
  for (int i = 0; i < 32; i++) hash[i] = static_cast<uint8_t>(0xA0 + i);

  for (uint8_t fill : {uint8_t(1), uint8_t(0x40)}) {
    const buf_t tweak = tweak_of(fill);
    buf_t child1, child2, pub1, pub2;
    ASSERT_EQ(coinbase::api::ecdsa_2p::integra_derive_child(blob1, tweak, child1), SUCCESS);
    ASSERT_EQ(coinbase::api::ecdsa_2p::integra_derive_child(blob2, tweak, child2), SUCCESS);
    ASSERT_EQ(coinbase::api::ecdsa_2p::get_public_key_compressed(child1, pub1), SUCCESS);
    ASSERT_EQ(coinbase::api::ecdsa_2p::get_public_key_compressed(child2, pub2), SUCCESS);

    EXPECT_EQ(pub1, pub2);
    EXPECT_EQ(pub1, openssl_add_tweak(master_pub, tweak));
    EXPECT_NE(pub1, master_pub);

    const buf_t sig = sign(child1, child2, hash);
    ASSERT_GT(sig.size(), 0);
    EXPECT_TRUE(openssl_verify(pub1, hash, sig));
    // Control: the verifier can fail — the child signature does not verify under the master key.
    EXPECT_FALSE(openssl_verify(master_pub, hash, sig));
  }
}

TEST_F(IntegraDeriveChild, DerivationIsDeterministic) {
  const buf_t tweak = tweak_of(7);
  for (const buf_t* blob : {&blob1, &blob2}) {
    buf_t a, b;
    ASSERT_EQ(coinbase::api::ecdsa_2p::integra_derive_child(*blob, tweak, a), SUCCESS);
    ASSERT_EQ(coinbase::api::ecdsa_2p::integra_derive_child(*blob, tweak, b), SUCCESS);
    EXPECT_EQ(a, b);
  }
}

TEST_F(IntegraDeriveChild, OnlyP2ShareMoves) {
  const buf_t tweak = tweak_of(3);
  buf_t child1, child2;
  ASSERT_EQ(coinbase::api::ecdsa_2p::integra_derive_child(blob1, tweak, child1), SUCCESS);
  ASSERT_EQ(coinbase::api::ecdsa_2p::integra_derive_child(blob2, tweak, child2), SUCCESS);

  buf_t detached, x1_parent, x1_child, x2_parent, x2_child;
  ASSERT_EQ(coinbase::api::ecdsa_2p::detach_private_scalar(blob1, detached, x1_parent), SUCCESS);
  ASSERT_EQ(coinbase::api::ecdsa_2p::detach_private_scalar(child1, detached, x1_child), SUCCESS);
  ASSERT_EQ(coinbase::api::ecdsa_2p::detach_private_scalar(blob2, detached, x2_parent), SUCCESS);
  ASSERT_EQ(coinbase::api::ecdsa_2p::detach_private_scalar(child2, detached, x2_child), SUCCESS);

  EXPECT_EQ(x1_parent, x1_child);  // P1's share and its Paillier encryption are untouched
  EXPECT_NE(x2_parent, x2_child);
}

TEST_F(IntegraDeriveChild, RejectsOutOfRangeTweaks) {
  const buf_t zero = zeros(32);
  buf_t order(32);
  for (int i = 0; i < 32; i++) order[i] = kOrder[i];
  buf_t above(32);
  for (int i = 0; i < 32; i++) above[i] = 0xFF;

  for (const buf_t* blob : {&blob1, &blob2}) {
    buf_t out;
    EXPECT_EQ(coinbase::api::ecdsa_2p::integra_derive_child(*blob, zero, out), E_BADARG);
    EXPECT_EQ(coinbase::api::ecdsa_2p::integra_derive_child(*blob, order, out), E_RANGE);
    EXPECT_EQ(coinbase::api::ecdsa_2p::integra_derive_child(*blob, above, out), E_RANGE);
    EXPECT_EQ(coinbase::api::ecdsa_2p::integra_derive_child(*blob, zeros(31), out), E_BADARG);
    EXPECT_EQ(coinbase::api::ecdsa_2p::integra_derive_child(*blob, zeros(33), out), E_BADARG);
    EXPECT_TRUE(out.empty());
  }
}

TEST_F(IntegraDeriveChild, RejectsMalformedBlob) {
  const buf_t truncated(blob2.data(), blob2.size() - 1);
  buf_t out;
  EXPECT_NE(coinbase::api::ecdsa_2p::integra_derive_child(truncated, tweak_of(1), out), SUCCESS);
}

TEST_F(IntegraDeriveChild, CApiMatchesCppApi) {
  const buf_t tweak = tweak_of(9);
  buf_t expected;
  ASSERT_EQ(coinbase::api::ecdsa_2p::integra_derive_child(blob2, tweak, expected), SUCCESS);

  cmem_t out{nullptr, 0};
  ASSERT_EQ(cbmpc_ecdsa_2p_integra_derive_child(cmem_t{blob2.data(), blob2.size()}, cmem_t{tweak.data(), tweak.size()},
                                                &out),
            CBMPC_SUCCESS);
  EXPECT_EQ(buf_t(out.data, out.size), expected);
  cbmpc_cmem_free(out);

  const buf_t zero = zeros(32);
  cmem_t none{reinterpret_cast<uint8_t*>(1), 1};
  EXPECT_EQ(cbmpc_ecdsa_2p_integra_derive_child(cmem_t{blob2.data(), blob2.size()}, cmem_t{zero.data(), zero.size()},
                                                &none),
            CBMPC_E_BADARG);
  EXPECT_EQ(none.data, nullptr);
  EXPECT_EQ(none.size, 0);
}

}  // namespace
