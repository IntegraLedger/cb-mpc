/**
 * Test: Take WASM-serialized proof bytes and verify in native
 *
 * This tests whether WASM serialization is compatible with native deserialization.
 *
 * From WASM debug output (b22a357.output):
 * - Q2: 02ca03469345c3923c71481d4bf8a541... (includes curve code)
 * - sid: sha256(sid1, sid2) = 28bb11fe2341f477567ea5c22f5dd0e8...
 * - pi_2: 2315 bytes starting with 00000020000000042002ca...
 */

#include <cbmpc/crypto/base.h>
#include <cbmpc/crypto/base_ecc.h>
#include <cbmpc/zk/zk_ec.h>
#include <cbmpc/core/convert.h>
#include <cstdio>
#include <vector>

using namespace coinbase;
using namespace coinbase::crypto;
using namespace coinbase::zk;

// Helper to convert hex string to bytes
std::vector<uint8_t> hex_to_bytes(const char* hex) {
    std::vector<uint8_t> bytes;
    while (*hex && *(hex+1)) {
        uint8_t byte = 0;
        for (int i = 0; i < 2; i++) {
            char c = *hex++;
            byte <<= 4;
            if (c >= '0' && c <= '9') byte |= c - '0';
            else if (c >= 'a' && c <= 'f') byte |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') byte |= c - 'A' + 10;
        }
        bytes.push_back(byte);
    }
    return bytes;
}

int main() {
    printf("=== Test: Verify WASM proof in native ===\n\n");

    // Initialize crypto
    initializer_t init;
    ecurve_t curve = curve_secp256k1;

    // Step 1: Generate a proof natively and print its serialized form
    printf("1. Generate native proof for comparison...\n");

    bn_t x = bn_t::rand(curve.order());
    ecc_point_t Q = x * curve.generator();
    buf_t sid = gen_random_bitlen(128);

    uc_dl_t proof;
    proof.prove(Q, x, sid, 2);

    // Serialize Q and proof
    buf_t Q_ser = ser(Q);
    buf_t proof_ser = ser(proof);

    printf("   Q serialized: %d bytes, first 16: ", Q_ser.size());
    for (int i = 0; i < 16 && i < Q_ser.size(); i++) printf("%02x", Q_ser.data()[i]);
    printf("\n");

    printf("   proof serialized: %d bytes, first 16: ", proof_ser.size());
    for (int i = 0; i < 16 && i < proof_ser.size(); i++) printf("%02x", proof_ser.data()[i]);
    printf("\n");

    // Verify original
    error_t rv = proof.verify(Q, sid, 2);
    printf("   Native verify: %s\n\n", rv ? "FAILED" : "PASSED");

    // Step 2: Test serialization consistency
    printf("2. Test that deserialized proof still verifies...\n");

    uc_dl_t proof2;
    ecc_point_t Q2;

    rv = deser(proof_ser, proof2);
    if (rv) {
        printf("   Proof deserialization FAILED: %d\n", rv);
        return 1;
    }

    rv = deser(Q_ser, Q2);
    if (rv) {
        printf("   Q deserialization FAILED: %d\n", rv);
        return 1;
    }

    rv = proof2.verify(Q2, sid, 2);
    printf("   Deserialized verify: %s\n\n", rv ? "FAILED" : "PASSED");

    // Step 3: Test with known e values
    printf("3. Analyze proof structure...\n");
    printf("   params.rho=%d, params.b=%d\n", proof.params.rho, proof.params.b);
    printf("   e values (first 5): ");
    for (int i = 0; i < 5 && i < proof.e.size(); i++) {
        printf("%d ", proof.e[i]);
    }
    printf("\n");

    // Check the math: for each i, A[i] should equal z[i]*G - e[i]*Q
    printf("\n4. Manual verification of proof equation A = z*G - e*Q...\n");
    const auto& G = curve.generator();
    for (int i = 0; i < 3; i++) {
        ecc_point_t expected = proof.z[i] * G - bn_t(proof.e[i]) * Q;
        bool match = (expected == proof.A[i]);
        printf("   Round %d: A[%d] %s z[%d]*G - e[%d]*Q\n",
               i, i, match ? "==" : "!=", i, i);
        if (!match) {
            printf("   *** PROOF EQUATION VIOLATED ***\n");
        }
    }

    printf("\n=== Test Complete ===\n");
    return 0;
}
