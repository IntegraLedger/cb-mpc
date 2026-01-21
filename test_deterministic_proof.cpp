/**
 * Deterministic proof test: Uses FIXED values for all inputs to enable
 * comparison between WASM and native.
 *
 * This test:
 * 1. Uses a known, fixed secret x (instead of random)
 * 2. Uses a known, fixed sid (instead of random)
 * 3. Generates a proof
 * 4. Outputs ALL intermediate values
 * 5. Verifies the proof
 *
 * Build: g++ -std=c++17 -I src -I /opt/homebrew/opt/openssl@3/include \
 *        -L lib/Release -L /opt/homebrew/opt/openssl@3/lib \
 *        test_deterministic_proof.cpp -lcbmpc -lssl -lcrypto -o test_deterministic_proof
 */

#include <cbmpc/crypto/base.h>
#include <cbmpc/crypto/base_ecc.h>
#include <cbmpc/zk/zk_ec.h>
#include <cbmpc/core/convert.h>
#include <cstdio>

using namespace coinbase;
using namespace coinbase::crypto;
using namespace coinbase::zk;

// Fixed test values (same as what we'll use in WASM)
const char* FIXED_SECRET_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const char* FIXED_SID_HEX = "deadbeefcafebabe0123456789abcdef";

buf_t hex_to_buf(const char* hex) {
    size_t len = strlen(hex) / 2;
    buf_t buf(len);
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + 2*i, "%02x", &byte);
        buf.data()[i] = byte;
    }
    return buf;
}

void print_hex(const char* label, mem_t data) {
    printf("%s (%d bytes): ", label, data.size);
    for (int i = 0; i < data.size; i++) {
        printf("%02x", data.data[i]);
    }
    printf("\n");
}

int main() {
    printf("=== Deterministic Proof Test ===\n\n");

    // Initialize crypto
    initializer_t init;
    ecurve_t curve = curve_secp256k1;
    const auto& G = curve.generator();
    const mod_t& q = curve.order();

    // Step 1: Check curve generator
    printf("1. Curve generator G:\n");
    buf_t G_ser = ser(G);
    print_hex("   G serialized", G_ser);

    // Step 2: Use fixed secret
    printf("\n2. Fixed secret x:\n");
    buf_t x_buf = hex_to_buf(FIXED_SECRET_HEX);
    print_hex("   x raw bytes", x_buf);
    bn_t x = bn_t::from_bin(x_buf);
    // Reduce modulo curve order
    x = x % q;
    buf_t x_reduced = x.to_bin(32);
    print_hex("   x reduced mod q", x_reduced);

    // Step 3: Compute Q = x * G
    printf("\n3. Compute Q = x * G:\n");
    ecc_point_t Q = x * G;
    buf_t Q_ser = ser(Q);
    print_hex("   Q serialized", Q_ser);

    // Step 4: Use fixed SID
    printf("\n4. Fixed SID:\n");
    buf_t sid = hex_to_buf(FIXED_SID_HEX);
    print_hex("   sid", sid);

    // Step 5: Generate proof
    printf("\n5. Generate proof with aux=2:\n");
    uc_dl_t proof;
    proof.prove(Q, x, sid, 2);

    printf("   Proof structure:\n");
    printf("     params.rho: %d\n", proof.params.rho);
    printf("     params.b: %d\n", proof.params.b);
    printf("     params.t: %d\n", proof.params.t);
    printf("     A.size(): %zu\n", proof.A.size());
    printf("     e.size(): %zu\n", proof.e.size());
    printf("     z.size(): %zu\n", proof.z.size());

    // Print e values
    printf("   e values: ");
    for (size_t i = 0; i < proof.e.size(); i++) {
        printf("%d ", proof.e[i]);
    }
    printf("\n");

    // Print first A point
    if (proof.A.size() > 0) {
        buf_t A0_ser = ser(proof.A[0]);
        print_hex("   A[0]", A0_ser);
    }

    // Print first z value
    if (proof.z.size() > 0) {
        buf_t z0_ser = ser(proof.z[0]);
        print_hex("   z[0]", z0_ser);
    }

    // Serialize full proof
    buf_t proof_ser = ser(proof);
    print_hex("\n6. Full proof serialized", proof_ser);

    // Print first 128 bytes hex dump
    printf("   First 128 bytes:\n     ");
    for (int i = 0; i < 128 && i < proof_ser.size(); i++) {
        printf("%02x", proof_ser.data()[i]);
        if ((i + 1) % 32 == 0) printf("\n     ");
    }
    printf("\n");

    // Step 6: Verify proof
    printf("\n7. Verify proof:\n");
    error_t rv = proof.verify(Q, sid, 2);
    if (rv) {
        printf("   VERIFICATION FAILED: error %d\n", rv);
        return 1;
    } else {
        printf("   VERIFICATION PASSED!\n");
    }

    // Step 7: Check manual equation for round 0
    printf("\n8. Manual check A[0] = z[0]*G - e[0]*Q:\n");
    ecc_point_t expected = proof.z[0] * G - bn_t(proof.e[0]) * Q;
    buf_t expected_ser = ser(expected);
    buf_t A0_ser = ser(proof.A[0]);
    print_hex("   Expected", expected_ser);
    print_hex("   A[0]    ", A0_ser);
    bool match = (expected == proof.A[0]);
    printf("   Match: %s\n", match ? "YES" : "NO");

    printf("\n=== Test Complete ===\n");
    printf("\nTo compare with WASM, use these EXACT values:\n");
    printf("  FIXED_SECRET_HEX = \"%s\"\n", FIXED_SECRET_HEX);
    printf("  FIXED_SID_HEX = \"%s\"\n", FIXED_SID_HEX);
    return 0;
}
