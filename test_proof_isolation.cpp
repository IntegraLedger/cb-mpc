/**
 * Isolation test: Verify that uc_dl_t proof generation and verification
 * work correctly in the same environment (native code).
 *
 * Build: g++ -std=c++17 -I src -I /opt/homebrew/opt/openssl@3/include \
 *        -L lib/Release -L /opt/homebrew/opt/openssl@3/lib \
 *        test_proof_isolation.cpp -lcbmpc -lssl -lcrypto -o test_proof_isolation
 *
 * Run: ./test_proof_isolation
 */

#include <cbmpc/crypto/base.h>
#include <cbmpc/crypto/base_ecc.h>
#include <cbmpc/zk/zk_ec.h>
#include <cstdio>

using namespace coinbase;
using namespace coinbase::crypto;
using namespace coinbase::zk;

int main() {
    printf("=== Proof Isolation Test ===\n\n");

    // Initialize crypto
    initializer_t init;

    // Use secp256k1 curve
    ecurve_t curve = curve_secp256k1;
    const auto& G = curve.generator();
    const mod_t& q = curve.order();

    printf("1. Setup:\n");
    printf("   Curve: secp256k1\n");

    // Generate random secret and public key
    bn_t x = bn_t::rand(q);  // secret
    ecc_point_t Q = x * G;    // public key

    printf("   Generated random secret x and Q = x*G\n");

    // Generate random session ID (like the protocol does)
    buf_t sid = gen_random_bitlen(128);
    printf("   Generated random session ID (%d bytes)\n", sid.size());

    // Create proof
    printf("\n2. Generating proof...\n");
    uc_dl_t proof;
    proof.prove(Q, x, sid, 2);  // aux=2 like P2 uses

    printf("   Proof generated:\n");
    printf("   - params.rho: %d\n", proof.params.rho);
    printf("   - params.b: %d\n", proof.params.b);
    printf("   - A.size(): %zu\n", proof.A.size());
    printf("   - e.size(): %zu\n", proof.e.size());
    printf("   - z.size(): %zu\n", proof.z.size());
    printf("   - e[0,1,2]: %d, %d, %d\n", proof.e[0], proof.e[1], proof.e[2]);

    // Verify proof immediately (no serialization)
    printf("\n3. Verifying proof (same environment, no serialization)...\n");
    error_t rv = proof.verify(Q, sid, 2);

    if (rv) {
        printf("   *** VERIFICATION FAILED: error %d ***\n", rv);
        printf("\n=== CONCLUSION: Proof generation is BROKEN ===\n");
        return 1;
    } else {
        printf("   VERIFICATION PASSED!\n");
        printf("\n=== CONCLUSION: Proof generation works correctly ===\n");
        printf("=== If server verification fails, it's a SERIALIZATION issue ===\n");
    }

    // Now test serialization round-trip
    printf("\n4. Testing serialization round-trip...\n");
    buf_t serialized = ser(proof);
    printf("   Serialized proof: %d bytes\n", serialized.size());
    printf("   First 64 bytes (hex):\n     ");
    for (int i = 0; i < 64 && i < serialized.size(); i++) {
        printf("%02x", serialized.data()[i]);
        if ((i + 1) % 32 == 0) printf("\n     ");
    }
    printf("\n");

    // Print e vector bytes specifically (at offset 8 + A_size)
    // params = 8 bytes, A vector = variable
    buf_t A_serialized = ser(proof.A);
    int e_offset = 8 + A_serialized.size();
    printf("   A vector size: %d bytes\n", A_serialized.size());
    printf("   e vector starts at offset: %d\n", e_offset);
    printf("   Bytes at e offset: ");
    for (int i = e_offset; i < e_offset + 24 && i < serialized.size(); i++) {
        printf("%02x ", serialized.data()[i]);
    }
    printf("\n");

    uc_dl_t proof2;
    error_t deser_rv = deser(serialized, proof2);
    if (deser_rv) {
        printf("   *** DESERIALIZATION FAILED: error %d ***\n", deser_rv);
        return 1;
    }
    printf("   Deserialized successfully\n");

    // Verify deserialized proof
    printf("\n5. Verifying deserialized proof...\n");
    rv = proof2.verify(Q, sid, 2);

    if (rv) {
        printf("   *** VERIFICATION OF DESERIALIZED PROOF FAILED: error %d ***\n", rv);
        printf("\n=== CONCLUSION: SERIALIZATION is BROKEN ===\n");
        return 1;
    } else {
        printf("   VERIFICATION PASSED!\n");
        printf("\n=== CONCLUSION: Both proof generation AND serialization work ===\n");
        printf("=== The issue must be in CROSS-PLATFORM serialization (WASM vs native) ===\n");
    }

    return 0;
}
