/**
 * WASM bindings implementation for 2-party ECDSA protocol
 *
 * Implements the P1 (client) side of the 2PC ECDSA protocol from cb-mpc.
 * Based on the Go CGO bindings pattern from demos-go/cb-mpc-go/internal/cgobinding/
 *
 * Protocol flow:
 * - Keygen: P1 generates commitment + Paillier key, exchanges with P2 over 3 rounds
 * - Signing: P1 and P2 collaboratively sign using threshold ECDSA
 */

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define WASM_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define WASM_EXPORT
#endif

#include "wasm_ecdsa2p.h"

#include <cbmpc/core/buf.h>
#include <cbmpc/core/convert.h>
#include <cbmpc/crypto/base.h>
#include <cbmpc/crypto/base_ecc.h>
#include <cbmpc/crypto/commitment.h>
#include <cbmpc/crypto/ro.h>
#include <cbmpc/protocol/ec_dkg.h>
#include <cbmpc/protocol/ecdsa_2p.h>
#include <cbmpc/zk/zk_ec.h>

#include <openssl/rand.h>

#include <cstring>
#include <memory>
#include <string>

using namespace coinbase;
using namespace coinbase::mpc;
using namespace coinbase::crypto;

// Thread-local error message
static std::string g_last_error;

static void set_error(const std::string& msg) {
    g_last_error = msg;
}

// PIDs for party identification
// Use lazy initialization to avoid static initialization order issues in WASM
// The hash functions used by pid_from_name may not work correctly at static init time

static const mpc_pid_t& get_p1_pid_as_client() {
    static mpc_pid_t pid;
    static bool initialized = false;
    if (!initialized) {
        pid = pid_from_name("client");
        initialized = true;
    }
    return pid;
}

static const mpc_pid_t& get_p1_pid_as_server() {
    static mpc_pid_t pid;
    static bool initialized = false;
    if (!initialized) {
        pid = pid_from_name("server");
        initialized = true;
    }
    return pid;
}

// Macros for convenience (acts like the old static constants)
#define P1_PID_AS_CLIENT get_p1_pid_as_client()
#define P1_PID_AS_SERVER get_p1_pid_as_server()
#define DEFAULT_P1_PID get_p1_pid_as_client()

// ============================================================================
// Internal State Types
// ============================================================================

/**
 * Keygen session state for P1 (client)
 * Holds all intermediate values needed across protocol rounds
 */
struct KeygenSessionState {
    ecurve_t curve;
    int round;
    ecdsa2pc::key_t key;
    bool complete;

    // Protocol objects
    std::unique_ptr<eckey::dkg_2p_t> ec_dkg;
    std::unique_ptr<ecdsa2pc::paillier_gen_interactive_t> paillier_gen;

    // Message buffers for protocol state
    buf_t last_sent_msg;

    KeygenSessionState() : curve(curve_secp256k1), round(0), complete(false) {}
};

/**
 * Sign session state for P1 (client)
 * Holds intermediate values for the signing protocol
 *
 * Note: This implementation uses "global abort" mode - it does not verify
 * the ZK proof (zk_ecdsa) from P2. Instead, it relies on signature verification
 * at the end. If P2 cheats, the signature will be invalid.
 */
struct SignSessionState {
    ecdsa2pc::key_t* key_ref;
    buf_t message_hash;
    buf_t sid;  // Session ID for signing
    int round;
    buf_t signature;
    bool complete;

    // Signing protocol state
    bn_t k1;           // P1's nonce share
    ecc_point_t R1;    // P1's R commitment
    ecc_point_t R;     // Combined R point
    bn_t r;            // r = R.x mod q

    // State that must persist across rounds
    std::unique_ptr<zk::uc_batch_dl_t> pi_1;  // ZK proof generated in round 0
    std::unique_ptr<coinbase::crypto::commitment_t> com;  // Commitment generated in round 0
    std::vector<ecc_point_t> R1_vec;  // R1 as vector for serialization

    SignSessionState() : key_ref(nullptr), round(0), complete(false) {}
};

/**
 * Keygen session state for P2 (responder/server-first protocol)
 * Holds all intermediate values needed across protocol rounds
 */
struct KeygenP2SessionState {
    ecurve_t curve;
    int round;
    ecdsa2pc::key_t key;
    bool complete;

    // Protocol objects - P2 uses P1's PID (server) for verification
    std::unique_ptr<eckey::dkg_2p_t> ec_dkg;
    std::unique_ptr<ecdsa2pc::paillier_gen_interactive_t> paillier_gen;

    // Store P1's encrypted key for later use
    bn_t c_key_from_p1;

    KeygenP2SessionState() : curve(curve_secp256k1), round(0), complete(false) {}
};

/**
 * Sign session state for P2 (responder/server-first protocol)
 * Holds intermediate values for the signing protocol
 *
 * Note: P2 computes and sends the Paillier ciphertext but does NOT
 * compute the final signature. This is the "global abort" mode where
 * P1 verifies the signature and aborts if it's invalid.
 */
struct SignP2SessionState {
    ecdsa2pc::key_t* key_ref;
    buf_t message_hash;
    buf_t sid;  // Session ID received from P1
    int round;
    bool complete;

    // Signing protocol state
    bn_t k2;           // P2's nonce share
    ecc_point_t R2;    // P2's R point
    std::vector<ecc_point_t> R2_vec;  // R2 as vector
    std::unique_ptr<zk::uc_batch_dl_t> pi_2;  // P2's ZK proof

    // State from P1's messages
    buf_t com_msg;     // P1's commitment message
    std::unique_ptr<coinbase::crypto::commitment_t> com;  // For verification
    std::vector<ecc_point_t> R1_vec;  // P1's R1 (received in opening)
    ecc_point_t R;     // Combined R point
    bn_t r;            // r = R.x mod q

    SignP2SessionState() : key_ref(nullptr), round(0), complete(false) {}
};

// ============================================================================
// Memory Management
// ============================================================================

extern "C" {

WASM_EXPORT
uint8_t* wasm_alloc(size_t size) {
    return static_cast<uint8_t*>(malloc(size));
}

WASM_EXPORT
void wasm_free(void* ptr) {
    free(ptr);
}

// ============================================================================
// Key Management
// ============================================================================

WASM_EXPORT
int wasm_key_serialize(wasm_key_handle* key, uint8_t** out_data, size_t* out_len) {
    if (!key || !key->opaque || !out_data || !out_len) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    try {
        ecdsa2pc::key_t* k = static_cast<ecdsa2pc::key_t*>(key->opaque);

        // Calculate size first
        converter_t sizer(true);
        k->convert(sizer);
        int size = sizer.get_size();

        // Allocate buffer
        uint8_t* buffer = static_cast<uint8_t*>(malloc(size));
        if (!buffer) {
            set_error("Memory allocation failed");
            return WASM_MPC_MEMORY_ERROR;
        }

        // Serialize
        converter_t writer(buffer);
        k->convert(writer);

        if (writer.is_error()) {
            free(buffer);
            set_error("Serialization failed");
            return WASM_MPC_ERROR;
        }

        *out_data = buffer;
        *out_len = static_cast<size_t>(size);
        return WASM_MPC_SUCCESS;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return WASM_MPC_ERROR;
    } catch (...) {
        set_error("Unknown exception");
        return WASM_MPC_ERROR;
    }
}

WASM_EXPORT
int wasm_key_deserialize(const uint8_t* data, size_t len, wasm_key_handle* out_key) {
    if (!data || len == 0 || !out_key) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    try {
        ecdsa2pc::key_t* k = new ecdsa2pc::key_t();

        mem_t mem(const_cast<uint8_t*>(data), static_cast<int>(len));
        converter_t reader(mem);
        k->convert(reader);

        if (reader.is_error()) {
            delete k;
            set_error("Deserialization failed");
            return WASM_MPC_ERROR;
        }

        out_key->opaque = k;
        return WASM_MPC_SUCCESS;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return WASM_MPC_ERROR;
    } catch (...) {
        set_error("Unknown exception");
        return WASM_MPC_ERROR;
    }
}

WASM_EXPORT
void wasm_key_free(wasm_key_handle* key) {
    if (key && key->opaque) {
        delete static_cast<ecdsa2pc::key_t*>(key->opaque);
        key->opaque = nullptr;
    }
}

WASM_EXPORT
int wasm_key_get_public_key(wasm_key_handle* key, uint8_t** out_data, size_t* out_len) {
    if (!key || !key->opaque || !out_data || !out_len) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    try {
        ecdsa2pc::key_t* k = static_cast<ecdsa2pc::key_t*>(key->opaque);

        // Get compressed public key (33 bytes for secp256k1)
        buf_t compressed = k->Q.to_compressed_bin();

        *out_len = compressed.size();
        *out_data = static_cast<uint8_t*>(malloc(*out_len));
        if (!*out_data) {
            set_error("Memory allocation failed");
            return WASM_MPC_MEMORY_ERROR;
        }
        memcpy(*out_data, compressed.data(), *out_len);
        return WASM_MPC_SUCCESS;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return WASM_MPC_ERROR;
    } catch (...) {
        set_error("Unknown exception");
        return WASM_MPC_ERROR;
    }
}

WASM_EXPORT
int wasm_key_get_uncompressed_public_key(wasm_key_handle* key, uint8_t** out_data, size_t* out_len) {
    if (!key || !key->opaque || !out_data || !out_len) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    try {
        ecdsa2pc::key_t* k = static_cast<ecdsa2pc::key_t*>(key->opaque);

        // Get uncompressed public key (65 bytes for secp256k1: 0x04 || x || y)
        buf_t uncompressed = k->Q.to_bin();

        *out_len = uncompressed.size();
        *out_data = static_cast<uint8_t*>(malloc(*out_len));
        if (!*out_data) {
            set_error("Memory allocation failed");
            return WASM_MPC_MEMORY_ERROR;
        }
        memcpy(*out_data, uncompressed.data(), *out_len);
        return WASM_MPC_SUCCESS;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return WASM_MPC_ERROR;
    } catch (...) {
        set_error("Unknown exception");
        return WASM_MPC_ERROR;
    }
}

WASM_EXPORT
int wasm_key_get_address(wasm_key_handle* key, uint8_t** out_data, size_t* out_len) {
    // Note: Ethereum address requires keccak256 which may not be available in cb-mpc
    // For now, return the uncompressed public key and let JavaScript compute the address
    // using ethers.js or a similar library
    set_error("Use wasm_key_get_uncompressed_public_key and compute address in JavaScript");
    return WASM_MPC_ERROR;
}

WASM_EXPORT
int wasm_key_derive(
    wasm_key_handle* base_key,
    const uint8_t* tweak,
    size_t tweak_len,
    wasm_key_handle* out_key
) {
    if (!base_key || !base_key->opaque || !tweak || !out_key) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }
    if (tweak_len != 32) {
        set_error("Tweak must be 32 bytes");
        return WASM_MPC_PARAM_ERROR;
    }

    try {
        ecdsa2pc::key_t* base = static_cast<ecdsa2pc::key_t*>(base_key->opaque);
        ecdsa2pc::key_t* derived = new ecdsa2pc::key_t();

        mem_t tweak_mem(const_cast<uint8_t*>(tweak), 32);
        error_t err = ecdsa2pc::derive_child_key(*base, tweak_mem, *derived);

        if (err) {
            delete derived;
            set_error("Key derivation failed");
            return WASM_MPC_ERROR;
        }

        out_key->opaque = derived;
        return WASM_MPC_SUCCESS;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return WASM_MPC_ERROR;
    } catch (...) {
        set_error("Unknown exception");
        return WASM_MPC_ERROR;
    }
}

WASM_EXPORT
int wasm_key_get_curve_code(wasm_key_handle* key) {
    if (!key || !key->opaque) {
        return -1;
    }
    ecdsa2pc::key_t* k = static_cast<ecdsa2pc::key_t*>(key->opaque);
    return k->curve.get_openssl_code();
}

WASM_EXPORT
int wasm_key_get_role(wasm_key_handle* key) {
    if (!key || !key->opaque) {
        return -1;
    }
    ecdsa2pc::key_t* k = static_cast<ecdsa2pc::key_t*>(key->opaque);
    return static_cast<int>(k->role);
}

// ============================================================================
// Key Generation Protocol
// Implements the P1 (client) side of the 2PC ECDSA keygen protocol
//
// Protocol rounds:
// - Round 0 (no input): Generate P1's first message (ec_dkg.msg1 + paillier_gen.msg1 + c_key)
// - Round 1 (P2's msg2): Process P2's response, generate P1's final message (msg3)
// - Round 2 (P2's final): Complete protocol, verify and extract key
// ============================================================================

WASM_EXPORT
int wasm_keygen_p1_start(int curve, wasm_keygen_session* out_session) {
    if (!out_session) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    try {
        auto* state = new KeygenSessionState();
        ecurve_t ec = ecurve_t::find(curve);
        if (!ec) {
            delete state;
            set_error("Invalid curve code");
            return WASM_MPC_PARAM_ERROR;
        }
        state->curve = ec;
        state->round = 0;
        state->complete = false;

        // Initialize key with curve and role
        state->key.curve = ec;
        state->key.role = party_t::p1;

        // Generate P1's private share
        const mod_t& q = ec.order();
        state->key.x_share = bn_t::rand(q);

        // Initialize protocol objects
        state->ec_dkg = std::make_unique<eckey::dkg_2p_t>(ec, DEFAULT_P1_PID);
        state->paillier_gen = std::make_unique<ecdsa2pc::paillier_gen_interactive_t>(DEFAULT_P1_PID);

        out_session->opaque = state;
        return WASM_MPC_SUCCESS;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return WASM_MPC_ERROR;
    }
}

WASM_EXPORT
int wasm_keygen_p1_process(
    wasm_keygen_session* session,
    const uint8_t* msg_in,
    size_t msg_in_len,
    uint8_t** msg_out,
    size_t* msg_out_len,
    int* is_complete
) {
    if (!session || !session->opaque || !msg_out || !msg_out_len || !is_complete) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    auto* state = static_cast<KeygenSessionState*>(session->opaque);

    try {
        *is_complete = 0;
        *msg_out = nullptr;
        *msg_out_len = 0;

        switch (state->round) {
            case 0: {
                // Round 0: Generate P1's first message
                // P1 generates commitment for Q1 and Paillier key setup

                // Step 1a: EC DKG step1 - generate commitment for Q1
                state->ec_dkg->step1_p1_to_p2(state->key.x_share);

                // Step 1b: Paillier keygen step1 - generate Paillier key and encrypt x1
                state->paillier_gen->step1_p1_to_p2(
                    state->key.paillier,
                    state->key.x_share,
                    state->curve.order(),
                    state->key.c_key
                );

                // Serialize P1's msg1: (ec_dkg.msg1, paillier_gen.msg1, c_key)
                // ec_dkg.msg1 = (sid1, com.msg)
                // paillier_gen.msg1 = (N, c_key, Com, equal.msg1, range.msg1)
                buf_t out_buf = ser(
                    state->ec_dkg->msg1,
                    state->paillier_gen->msg1,
                    state->key.c_key
                );

                *msg_out_len = out_buf.size();
                *msg_out = static_cast<uint8_t*>(malloc(*msg_out_len));
                if (!*msg_out) {
                    set_error("Memory allocation failed");
                    return WASM_MPC_MEMORY_ERROR;
                }
                memcpy(*msg_out, out_buf.data(), *msg_out_len);

                state->round = 1;
                break;
            }

            case 1: {
                // Round 1: Process P2's msg2 and generate P1's msg3
                if (!msg_in || msg_in_len == 0) {
                    set_error("Expected P2's msg2 input");
                    return WASM_MPC_PARAM_ERROR;
                }

                // Deserialize P2's msg2: (ec_dkg.msg2, paillier_gen.msg2)
                // ec_dkg.msg2 = (sid2, pi_2, Q2)
                // paillier_gen.msg2 = (equal.challenge, range.challenge, valid_m1)
                mem_t msg_mem(const_cast<uint8_t*>(msg_in), static_cast<int>(msg_in_len));
                error_t rv = deser(
                    msg_mem,
                    state->ec_dkg->msg2,
                    state->paillier_gen->msg2
                );
                if (rv) {
                    set_error("Failed to deserialize P2's msg2");
                    return WASM_MPC_ERROR;
                }

                // Step 3a: EC DKG step3 - verify P2's proof and generate P1's proof
                rv = state->ec_dkg->step3_p1_to_p2(state->key.Q);
                if (rv) {
                    set_error("EC DKG step3 failed: verification error");
                    return WASM_MPC_ERROR;
                }

                // Step 3b: Paillier keygen step3 - generate proofs
                state->paillier_gen->step3_p1_to_p2(
                    state->key.paillier,
                    state->key.x_share,
                    state->ec_dkg->Q1,
                    DEFAULT_P1_PID,
                    state->ec_dkg->sid
                );

                // Serialize P1's msg3: (ec_dkg.msg3, paillier_gen.msg3)
                // ec_dkg.msg3 = (com.rand, pi_1, Q1)
                // paillier_gen.msg3 = (pdl, equal.msg2, range.msg2, valid_m2)
                buf_t out_buf = ser(
                    state->ec_dkg->msg3,
                    state->paillier_gen->msg3
                );

                *msg_out_len = out_buf.size();
                *msg_out = static_cast<uint8_t*>(malloc(*msg_out_len));
                if (!*msg_out) {
                    set_error("Memory allocation failed");
                    return WASM_MPC_MEMORY_ERROR;
                }
                memcpy(*msg_out, out_buf.data(), *msg_out_len);

                state->round = 2;
                break;
            }

            case 2: {
                // Round 2: Protocol complete
                // P2 verifies P1's proofs on their side
                // P1 just needs to mark complete and return the key

                state->complete = true;
                *is_complete = 1;
                break;
            }

            default:
                set_error("Invalid round state");
                return WASM_MPC_INVALID_STATE;
        }

        return WASM_MPC_SUCCESS;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return WASM_MPC_ERROR;
    } catch (...) {
        set_error("Unknown exception");
        return WASM_MPC_ERROR;
    }
}

WASM_EXPORT
int wasm_keygen_p1_get_key(wasm_keygen_session* session, wasm_key_handle* out_key) {
    if (!session || !session->opaque || !out_key) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    auto* state = static_cast<KeygenSessionState*>(session->opaque);
    if (!state->complete) {
        set_error("Keygen not complete");
        return WASM_MPC_INVALID_STATE;
    }

    auto* key = new ecdsa2pc::key_t(state->key);
    out_key->opaque = key;
    return WASM_MPC_SUCCESS;
}

WASM_EXPORT
void wasm_keygen_session_free(wasm_keygen_session* session) {
    if (session && session->opaque) {
        delete static_cast<KeygenSessionState*>(session->opaque);
        session->opaque = nullptr;
    }
}

// ============================================================================
// Key Generation Protocol - P2 (Responder)
// Implements the P2 (responder) side of the 2PC ECDSA keygen protocol
// Used when WASM client acts as P2 (server-first protocol)
//
// Protocol rounds:
// - Start: Receive P1's msg1 (ec_dkg.msg1 + paillier_gen.msg1 + c_key)
// - Round 0: Generate P2's msg2 (ec_dkg.msg2 + paillier_gen.msg2)
// - Round 1: Receive P1's msg3, verify, complete
// ============================================================================

WASM_EXPORT
int wasm_keygen_p2_start(
    int curve,
    const uint8_t* msg1_in,
    size_t msg1_len,
    wasm_keygen_session* out_session
) {
    if (!msg1_in || msg1_len == 0 || !out_session) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    try {
        auto* state = new KeygenP2SessionState();
        ecurve_t ec = ecurve_t::find(curve);
        if (!ec) {
            delete state;
            set_error("Invalid curve code");
            return WASM_MPC_PARAM_ERROR;
        }
        state->curve = ec;
        state->round = 0;
        state->complete = false;

        // Initialize key with curve and role (P2)
        state->key.curve = ec;
        state->key.role = party_t::p2;

        // Generate P2's private share
        const mod_t& q = ec.order();
        state->key.x_share = bn_t::rand(q);

        // Initialize protocol objects with P1's PID (server)
        state->ec_dkg = std::make_unique<eckey::dkg_2p_t>(ec, P1_PID_AS_SERVER);
        state->paillier_gen = std::make_unique<ecdsa2pc::paillier_gen_interactive_t>(P1_PID_AS_SERVER);

        // Deserialize P1's msg1: (ec_dkg.msg1, paillier_gen.msg1, c_key)
        mem_t msg_mem(const_cast<uint8_t*>(msg1_in), static_cast<int>(msg1_len));
        error_t rv = deser(
            msg_mem,
            state->ec_dkg->msg1,
            state->paillier_gen->msg1,
            state->c_key_from_p1
        );
        if (rv) {
            delete state;
            set_error("Failed to deserialize P1's msg1");
            return WASM_MPC_ERROR;
        }

        // Debug: Log sid1 immediately after deserialization
        printf("[WASM DEBUG] wasm_keygen_p2_start: after deserializing msg1\n");
        printf("[WASM DEBUG]   sid1 size: %d bytes\n", state->ec_dkg->sid1.size());
        printf("[WASM DEBUG]   sid1 first 16 bytes: ");
        for (int i = 0; i < 16 && i < state->ec_dkg->sid1.size(); i++) {
            printf("%02x", state->ec_dkg->sid1.data()[i]);
        }
        printf("\n");
        printf("[WASM DEBUG]   com.msg size: %d bytes\n", state->ec_dkg->com.msg.size());

        // Store c_key for the key structure (needed for signing later)
        state->key.c_key = state->c_key_from_p1;

        out_session->opaque = state;
        return WASM_MPC_SUCCESS;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return WASM_MPC_ERROR;
    }
}

WASM_EXPORT
int wasm_keygen_p2_process(
    wasm_keygen_session* session,
    const uint8_t* msg_in,
    size_t msg_in_len,
    uint8_t** msg_out,
    size_t* msg_out_len,
    int* is_complete
) {
    if (!session || !session->opaque || !msg_out || !msg_out_len || !is_complete) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    auto* state = static_cast<KeygenP2SessionState*>(session->opaque);

    try {
        *is_complete = 0;
        *msg_out = nullptr;
        *msg_out_len = 0;

        switch (state->round) {
            case 0: {
                // Round 0: Generate P2's msg2 response
                // P2 processes P1's commitment and generates its own values

                // EC DKG step2: P2 generates Q2 and proof
                state->ec_dkg->step2_p2_to_p1(state->key.x_share);

                // Paillier gen step2: P2 generates challenge
                state->paillier_gen->step2_p2_to_p1();

                // Debug: Test byte order functions
                printf("[WASM DEBUG] Byte order test:\n");
                uint8_t test_buf[4] = {0};
                coinbase::be_set_4(test_buf, 21);  // 21 = 0x00000015
                printf("[WASM DEBUG]   be_set_4(21) = %02x %02x %02x %02x (expected: 00 00 00 15)\n",
                       test_buf[0], test_buf[1], test_buf[2], test_buf[3]);
                uint8_t test_buf2[4] = {0};
                coinbase::le_set_4(test_buf2, 21);
                printf("[WASM DEBUG]   le_set_4(21) = %02x %02x %02x %02x (expected: 15 00 00 00)\n",
                       test_buf2[0], test_buf2[1], test_buf2[2], test_buf2[3]);

                // Also check: is __x86_64__ defined?
#if defined(__x86_64__)
                printf("[WASM DEBUG]   __x86_64__ IS defined (using bswap path)\n");
#else
                printf("[WASM DEBUG]   __x86_64__ NOT defined (using portable path)\n");
#endif

                // ============================================================
                // ISOLATION TEST: Verify proof in same environment (WASM)
                // This tests if the proof is valid BEFORE any serialization
                // ============================================================
                printf("[WASM DEBUG] === ISOLATION TEST ===\n");
                {
                    error_t verify_rv = state->ec_dkg->pi_2.verify(
                        state->ec_dkg->Q2,
                        state->ec_dkg->sid,
                        2  // aux = party index
                    );
                    if (verify_rv) {
                        printf("[WASM DEBUG] ISOLATION TEST FAILED: error %d\n", verify_rv);
                        printf("[WASM DEBUG] The proof is INVALID even before serialization!\n");
                    } else {
                        printf("[WASM DEBUG] ISOLATION TEST PASSED: proof verified in WASM\n");
                    }
                }
                printf("[WASM DEBUG] === END ISOLATION TEST ===\n");

                // Debug: log component sizes
                buf_t ec_dkg_msg2_only = ser(state->ec_dkg->msg2);
                buf_t paillier_msg2_only = ser(state->paillier_gen->msg2);
                printf("[WASM DEBUG] ec_dkg.msg2 size: %d bytes\n", ec_dkg_msg2_only.size());
                printf("[WASM DEBUG] paillier_gen.msg2 size: %d bytes\n", paillier_msg2_only.size());

                // Log ec_dkg.msg2 sub-components
                buf_t sid2_only = ser(state->ec_dkg->sid2);
                buf_t pi2_only = ser(state->ec_dkg->pi_2);
                buf_t Q2_only = ser(state->ec_dkg->Q2);
                printf("[WASM DEBUG]   sid2 size: %d bytes\n", sid2_only.size());
                printf("[WASM DEBUG]   pi_2 size: %d bytes\n", pi2_only.size());
                printf("[WASM DEBUG]   Q2 size: %d bytes\n", Q2_only.size());

                // Log paillier_gen.msg2 sub-components
                buf_t equal_challenge = ser(state->paillier_gen->equal.challenge);
                buf_t range_challenge = ser(state->paillier_gen->range.challenge);
                buf_t valid_m1 = ser(state->paillier_gen->valid_m1);
                printf("[WASM DEBUG]   equal.challenge size: %d bytes\n", equal_challenge.size());
                printf("[WASM DEBUG]   range.challenge size: %d bytes\n", range_challenge.size());
                printf("[WASM DEBUG]   valid_m1 size: %d bytes\n", valid_m1.size());

                // Log Fischlin proof structure
                printf("[WASM DEBUG] pi_2 proof structure:\n");
                printf("[WASM DEBUG]   params.rho: %d, params.b: %d\n",
                       state->ec_dkg->pi_2.params.rho,
                       state->ec_dkg->pi_2.params.b);
                printf("[WASM DEBUG]   A.size(): %zu\n", state->ec_dkg->pi_2.A.size());
                printf("[WASM DEBUG]   e.size(): %zu\n", state->ec_dkg->pi_2.e.size());
                printf("[WASM DEBUG]   z.size(): %zu\n", state->ec_dkg->pi_2.z.size());

                // Log first few e values (these are small ints)
                if (state->ec_dkg->pi_2.e.size() >= 3) {
                    printf("[WASM DEBUG]   e[0,1,2]: %d, %d, %d\n",
                           state->ec_dkg->pi_2.e[0],
                           state->ec_dkg->pi_2.e[1],
                           state->ec_dkg->pi_2.e[2]);
                    // Log all e values to see the pattern
                    printf("[WASM DEBUG]   ALL e values: ");
                    for (size_t i = 0; i < state->ec_dkg->pi_2.e.size(); i++) {
                        printf("%d ", state->ec_dkg->pi_2.e[i]);
                    }
                    printf("\n");
                }

                // Serialize JUST pi_2 and dump raw bytes to trace serialization
                buf_t pi2_raw = ser(state->ec_dkg->pi_2);
                printf("[WASM DEBUG]   pi_2 raw serialized (%d bytes), first 64 bytes:\n[WASM DEBUG]     ", pi2_raw.size());
                for (int i = 0; i < 64 && i < pi2_raw.size(); i++) {
                    printf("%02x", pi2_raw.data()[i]);
                    if ((i + 1) % 32 == 0) printf("\n[WASM DEBUG]     ");
                }
                printf("\n");

                // Now find where e vector starts in the serialization
                // First, let's check how many bytes params actually uses
                buf_t params_only = ser(state->ec_dkg->pi_2.params);
                printf("[WASM DEBUG]   fischlin_params_t serialized size: %d bytes\n", params_only.size());
                printf("[WASM DEBUG]     params raw bytes: ");
                for (int i = 0; i < params_only.size(); i++) {
                    printf("%02x ", params_only.data()[i]);
                }
                printf("\n");
                printf("[WASM DEBUG]     params.rho=%d, params.b=%d, params.t=%d\n",
                       state->ec_dkg->pi_2.params.rho,
                       state->ec_dkg->pi_2.params.b,
                       state->ec_dkg->pi_2.params.t);

                // Calculate A vector size
                buf_t A_vec_only = ser(state->ec_dkg->pi_2.A);
                printf("[WASM DEBUG]     A vector serialized size: %d bytes\n", A_vec_only.size());

                // Calculate e vector size
                buf_t e_vec_only = ser(state->ec_dkg->pi_2.e);
                printf("[WASM DEBUG]     e vector serialized size: %d bytes\n", e_vec_only.size());
                printf("[WASM DEBUG]     e vector raw bytes (first 24): ");
                for (int i = 0; i < 24 && i < e_vec_only.size(); i++) {
                    printf("%02x ", e_vec_only.data()[i]);
                }
                printf("\n");

                int e_offset = params_only.size() + A_vec_only.size();
                printf("[WASM DEBUG]     e vector should start at offset %d in pi_2\n", e_offset);
                if (e_offset < pi2_raw.size()) {
                    printf("[WASM DEBUG]     bytes at e offset in pi_2: ");
                    for (int i = e_offset; i < e_offset + 24 && i < pi2_raw.size(); i++) {
                        printf("%02x ", pi2_raw.data()[i]);
                    }
                    printf("\n");
                }

                // Log first z value size
                if (state->ec_dkg->pi_2.z.size() > 0) {
                    buf_t z0_ser = ser(state->ec_dkg->pi_2.z[0]);
                    printf("[WASM DEBUG]   z[0] serialized size: %d bytes\n", z0_ser.size());
                }

                // Log sid1, sid2, and combined sid for debugging
                printf("[WASM DEBUG]   sid1 size: %d bytes, first 16 bytes: ", state->ec_dkg->sid1.size());
                for (int i = 0; i < 16 && i < state->ec_dkg->sid1.size(); i++) {
                    printf("%02x", state->ec_dkg->sid1.data()[i]);
                }
                printf("\n");
                printf("[WASM DEBUG]   sid2 size: %d bytes, first 16 bytes: ", state->ec_dkg->sid2.size());
                for (int i = 0; i < 16 && i < state->ec_dkg->sid2.size(); i++) {
                    printf("%02x", state->ec_dkg->sid2.data()[i]);
                }
                printf("\n");
                // Log the combined sid = sha256(sid1, sid2) used for proof
                printf("[WASM DEBUG]   combined sid first 16 bytes: ");
                for (int i = 0; i < 16 && i < state->ec_dkg->sid.size(); i++) {
                    printf("%02x", state->ec_dkg->sid.data()[i]);
                }
                printf("\n");
                // Log Q2 for verification
                buf_t Q2_ser = ser(state->ec_dkg->Q2);
                printf("[WASM DEBUG]   Q2 first 16 bytes: ");
                for (int i = 0; i < 16 && i < Q2_ser.size(); i++) {
                    printf("%02x", Q2_ser.data()[i]);
                }
                printf("\n");

                // Serialize P2's msg2: (ec_dkg.msg2, paillier_gen.msg2)
                buf_t out_buf = ser(
                    state->ec_dkg->msg2,
                    state->paillier_gen->msg2
                );
                printf("[WASM DEBUG] Total msg2 size: %d bytes\n", out_buf.size());

                *msg_out_len = out_buf.size();
                *msg_out = static_cast<uint8_t*>(malloc(*msg_out_len));
                if (!*msg_out) {
                    set_error("Memory allocation failed");
                    return WASM_MPC_MEMORY_ERROR;
                }
                memcpy(*msg_out, out_buf.data(), *msg_out_len);

                state->round = 1;
                break;
            }

            case 1: {
                // Round 1: Receive P1's msg3, verify proofs, complete protocol
                if (!msg_in || msg_in_len == 0) {
                    set_error("Expected P1's msg3 input");
                    return WASM_MPC_PARAM_ERROR;
                }

                printf("[WASM DEBUG] Round 1: Deserializing P1's msg3 (%zu bytes)...\n", msg_in_len);

                // Deserialize P1's msg3: (ec_dkg.msg3, paillier_gen.msg3)
                mem_t msg_mem(const_cast<uint8_t*>(msg_in), static_cast<int>(msg_in_len));
                error_t rv = deser(
                    msg_mem,
                    state->ec_dkg->msg3,
                    state->paillier_gen->msg3
                );
                if (rv) {
                    set_error("Failed to deserialize P1's msg3");
                    return WASM_MPC_ERROR;
                }

                // Debug: Log what we received in msg3
                printf("[WASM DEBUG] msg3 deserialized successfully\n");
                printf("[WASM DEBUG]   Q1 (from com opening): ");
                buf_t Q1_ser = ser(state->ec_dkg->Q1);
                for (int i = 0; i < Q1_ser.size() && i < 36; i++) {
                    printf("%02x", Q1_ser.data()[i]);
                }
                printf("\n");

                // Log sid1 and combined sid that will be used for verification
                printf("[WASM DEBUG]   sid1 (stored from msg1): %d bytes, first 16: ", state->ec_dkg->sid1.size());
                for (int i = 0; i < 16 && i < state->ec_dkg->sid1.size(); i++) {
                    printf("%02x", state->ec_dkg->sid1.data()[i]);
                }
                printf("\n");
                printf("[WASM DEBUG]   combined sid: %d bytes, first 16: ", state->ec_dkg->sid.size());
                for (int i = 0; i < 16 && i < state->ec_dkg->sid.size(); i++) {
                    printf("%02x", state->ec_dkg->sid.data()[i]);
                }
                printf("\n");

                // Log pi_1 structure
                printf("[WASM DEBUG]   pi_1.params: rho=%d, b=%d, t=%d\n",
                       state->ec_dkg->pi_1.params.rho,
                       state->ec_dkg->pi_1.params.b,
                       state->ec_dkg->pi_1.params.t);
                printf("[WASM DEBUG]   pi_1: A.size=%zu, e.size=%zu, z.size=%zu\n",
                       state->ec_dkg->pi_1.A.size(),
                       state->ec_dkg->pi_1.e.size(),
                       state->ec_dkg->pi_1.z.size());
                if (state->ec_dkg->pi_1.e.size() >= 3) {
                    printf("[WASM DEBUG]   pi_1.e[0,1,2]: %d, %d, %d\n",
                           state->ec_dkg->pi_1.e[0],
                           state->ec_dkg->pi_1.e[1],
                           state->ec_dkg->pi_1.e[2]);
                }

                // Try each verification step individually to find which fails
                printf("[WASM DEBUG] Testing step4_output_p2 sub-steps:\n");

                // Step 1: curve.check(Q1)
                rv = state->curve.check(state->ec_dkg->Q1);
                if (rv) {
                    printf("[WASM DEBUG]   [FAIL] curve.check(Q1) failed: %d\n", rv);
                    set_error("EC DKG step4 failed: Q1 curve check");
                    return WASM_MPC_ERROR;
                }
                printf("[WASM DEBUG]   [OK] curve.check(Q1) passed\n");

                // Step 2: com.id(sid1, p1_pid).open(Q1)
                // Print the actual PID bytes for debugging
                {
                    buf_t pid_bytes = P1_PID_AS_SERVER.to_bin();
                    printf("[WASM DEBUG]   P1_PID_AS_SERVER (%d bytes): ", pid_bytes.size());
                    for (int i = 0; i < pid_bytes.size() && i < 20; i++) {
                        printf("%02x", pid_bytes.data()[i]);
                    }
                    printf("\n");
                }
                printf("[WASM DEBUG]   com.msg size: %d bytes\n", state->ec_dkg->com.msg.size());
                // Print com.rand bytes (buf256_t has operator[] for access)
                printf("[WASM DEBUG]   com.rand (first 16 bytes): ");
                for (int i = 0; i < 16; i++) {
                    printf("%02x", state->ec_dkg->com.rand[i]);
                }
                printf("\n");
                rv = state->ec_dkg->com.id(state->ec_dkg->sid1, P1_PID_AS_SERVER).open(state->ec_dkg->Q1);
                if (rv) {
                    printf("[WASM DEBUG]   [FAIL] com.open(Q1) failed: %d\n", rv);
                    set_error("EC DKG step4 failed: commitment open");
                    return WASM_MPC_ERROR;
                }
                printf("[WASM DEBUG]   [OK] com.open(Q1) passed\n");

                // Step 3: pi_1.verify(Q1, sid, 1)
                printf("[WASM DEBUG]   Verifying pi_1 with aux=1\n");
                rv = state->ec_dkg->pi_1.verify(state->ec_dkg->Q1, state->ec_dkg->sid, 1);
                if (rv) {
                    printf("[WASM DEBUG]   [FAIL] pi_1.verify() failed: %d\n", rv);

                    // Try to understand why - check A[0] = z[0]*G - e[0]*Q verification
                    if (state->ec_dkg->pi_1.A.size() > 0 && state->ec_dkg->pi_1.z.size() > 0) {
                        const auto& G = state->curve.generator();
                        ecc_point_t expected_A0 = state->ec_dkg->pi_1.z[0] * G -
                            bn_t(state->ec_dkg->pi_1.e[0]) * state->ec_dkg->Q1;
                        printf("[WASM DEBUG]     Manual check: A[0] = z[0]*G - e[0]*Q1\n");
                        printf("[WASM DEBUG]     A[0] from proof: ");
                        buf_t A0_ser = ser(state->ec_dkg->pi_1.A[0]);
                        for (int i = 0; i < A0_ser.size(); i++) {
                            printf("%02x", A0_ser.data()[i]);
                        }
                        printf("\n");
                        printf("[WASM DEBUG]     Expected A[0]:   ");
                        buf_t exp_ser = ser(expected_A0);
                        for (int i = 0; i < exp_ser.size(); i++) {
                            printf("%02x", exp_ser.data()[i]);
                        }
                        printf("\n");
                        printf("[WASM DEBUG]     Match: %s\n", (expected_A0 == state->ec_dkg->pi_1.A[0]) ? "YES" : "NO");
                    }

                    set_error("EC DKG step4 failed: pi_1 verification");
                    return WASM_MPC_ERROR;
                }
                printf("[WASM DEBUG]   [OK] pi_1.verify() passed\n");

                // All checks passed - compute combined Q
                state->key.Q = state->ec_dkg->Q1 + state->ec_dkg->Q2;
                printf("[WASM DEBUG] EC DKG step4 complete, Q computed\n");

                // Paillier gen step4: P2 verifies P1's proofs and creates Paillier pub key
                rv = state->paillier_gen->step4_p2_output(
                    state->key.paillier,
                    state->ec_dkg->Q1,
                    state->c_key_from_p1,
                    P1_PID_AS_SERVER,
                    state->ec_dkg->sid
                );
                if (rv) {
                    set_error("Paillier gen step4 failed: verification error");
                    return WASM_MPC_ERROR;
                }

                state->complete = true;
                *is_complete = 1;
                break;
            }

            default:
                set_error("Invalid round state");
                return WASM_MPC_INVALID_STATE;
        }

        return WASM_MPC_SUCCESS;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return WASM_MPC_ERROR;
    } catch (...) {
        set_error("Unknown exception");
        return WASM_MPC_ERROR;
    }
}

WASM_EXPORT
int wasm_keygen_p2_get_key(wasm_keygen_session* session, wasm_key_handle* out_key) {
    if (!session || !session->opaque || !out_key) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    auto* state = static_cast<KeygenP2SessionState*>(session->opaque);
    if (!state->complete) {
        set_error("Keygen not complete");
        return WASM_MPC_INVALID_STATE;
    }

    auto* key = new ecdsa2pc::key_t(state->key);
    out_key->opaque = key;
    return WASM_MPC_SUCCESS;
}

WASM_EXPORT
void wasm_keygen_p2_session_free(wasm_keygen_session* session) {
    if (session && session->opaque) {
        delete static_cast<KeygenP2SessionState*>(session->opaque);
        session->opaque = nullptr;
    }
}

// ============================================================================
// Signing Protocol
// Implements the P1 (client) side of the 2PC ECDSA signing protocol
//
// Protocol rounds (based on sign_batch_impl in ecdsa_2p.cpp):
// - Round 0 (no input): Generate P1's commitment (R1) and ZK proof
// - Round 1 (P2's R2): Process P2's R2, verify, generate presignature
// - Round 2 (P2's ciphertext c): Decrypt and compute final signature
// ============================================================================

WASM_EXPORT
int wasm_sign_p1_start(
    wasm_key_handle* key,
    const uint8_t* message_hash,
    size_t hash_len,
    wasm_sign_session* out_session
) {
    if (!key || !key->opaque || !message_hash || hash_len != 32 || !out_session) {
        set_error("Invalid parameters (message_hash must be 32 bytes)");
        return WASM_MPC_PARAM_ERROR;
    }

    try {
        auto* state = new SignSessionState();
        state->key_ref = static_cast<ecdsa2pc::key_t*>(key->opaque);
        state->message_hash = buf_t(message_hash, 32);
        state->round = 0;
        state->complete = false;

        // Generate session ID for this signing operation
        state->sid = crypto::gen_random_bitlen(SEC_P_COM);

        out_session->opaque = state;
        return WASM_MPC_SUCCESS;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return WASM_MPC_ERROR;
    }
}

WASM_EXPORT
int wasm_sign_p1_process(
    wasm_sign_session* session,
    const uint8_t* msg_in,
    size_t msg_in_len,
    uint8_t** msg_out,
    size_t* msg_out_len,
    int* is_complete
) {
    if (!session || !session->opaque || !msg_out || !msg_out_len || !is_complete) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    auto* state = static_cast<SignSessionState*>(session->opaque);

    try {
        *is_complete = 0;
        *msg_out = nullptr;
        *msg_out_len = 0;

        ecurve_t curve = state->key_ref->curve;
        const auto& G = curve.generator();
        const mod_t& q = curve.order();

        switch (state->round) {
            case 0: {
                // Round 0: Generate P1's nonce share and commitment
                // k1 is P1's share of the nonce k
                state->k1 = curve.get_random_value();
                state->R1 = state->k1 * G;
                state->R1_vec = { state->R1 };

                // Generate ZK proof that we know k1 such that R1 = k1 * G
                // Store this proof - we'll need it in round 1 for the commitment opening
                state->pi_1 = std::make_unique<zk::uc_batch_dl_t>();
                std::vector<bn_t> k1_vec = { state->k1 };
                state->pi_1->prove(state->R1_vec, k1_vec, state->sid, 1);

                // Create commitment and store it
                // Adding msgs here serves as a way of checking the consistency of the input messages
                state->com = std::make_unique<coinbase::crypto::commitment_t>(state->sid, DEFAULT_P1_PID);
                std::vector<mem_t> msgs_vec = { state->message_hash };
                state->com->gen(msgs_vec, state->R1_vec, *state->pi_1);

                // Serialize P1's msg1: SID + commitment
                // P2 needs the SID to verify the commitment and ZK proofs
                buf_t out_buf = ser(state->sid, state->com->msg);

                *msg_out_len = out_buf.size();
                *msg_out = static_cast<uint8_t*>(malloc(*msg_out_len));
                if (!*msg_out) {
                    set_error("Memory allocation failed");
                    return WASM_MPC_MEMORY_ERROR;
                }
                memcpy(*msg_out, out_buf.data(), *msg_out_len);

                state->round = 1;
                break;
            }

            case 1: {
                // Round 1: Process P2's R2 and send commitment opening
                if (!msg_in || msg_in_len == 0) {
                    set_error("Expected P2's R2 message");
                    return WASM_MPC_PARAM_ERROR;
                }

                // Deserialize P2's msg: (R2, pi_2)
                std::vector<ecc_point_t> R2_vec(1);
                zk::uc_batch_dl_t pi_2;
                mem_t msg_mem(const_cast<uint8_t*>(msg_in), static_cast<int>(msg_in_len));
                error_t rv = deser(msg_mem, R2_vec, pi_2);
                if (rv) {
                    set_error("Failed to deserialize P2's R2 message");
                    return WASM_MPC_ERROR;
                }

                // Verify P2's ZK proof (checking that R2 values are valid)
                rv = pi_2.verify(R2_vec, state->sid, 2);
                if (rv) {
                    set_error("P2's ZK proof verification failed");
                    return WASM_MPC_ERROR;
                }

                // Compute combined R = k1 * R2
                state->R = state->k1 * R2_vec[0];
                state->r = state->R.get_x() % q;

                // Serialize P1's msg2: commitment opening (com.rand, R1, pi_1)
                // Using the SAME pi_1 and com from round 0!
                buf_t out_buf = ser(state->com->rand, state->R1_vec, *state->pi_1);

                *msg_out_len = out_buf.size();
                *msg_out = static_cast<uint8_t*>(malloc(*msg_out_len));
                if (!*msg_out) {
                    set_error("Memory allocation failed");
                    return WASM_MPC_MEMORY_ERROR;
                }
                memcpy(*msg_out, out_buf.data(), *msg_out_len);

                state->round = 2;
                break;
            }

            case 2: {
                // Round 2: Process P2's ciphertext and compute signature
                if (!msg_in || msg_in_len == 0) {
                    set_error("Expected P2's ciphertext message");
                    return WASM_MPC_PARAM_ERROR;
                }

                // Deserialize P2's msg: ciphertext c
                bn_t c;
                mem_t msg_mem(const_cast<uint8_t*>(msg_in), static_cast<int>(msg_in_len));
                error_t rv = deser(msg_mem, c);
                if (rv) {
                    set_error("Failed to deserialize P2's ciphertext");
                    return WASM_MPC_ERROR;
                }

                // Decrypt and compute s
                bn_t s = state->key_ref->paillier.decrypt(c);
                s = q.mod(s);

                // Divide by k1 to get final s
                MODULO(q) { s /= state->k1; }

                // Normalize s to lower half of range
                bn_t q_minus_s = q - s;
                if (q_minus_s < s) s = q_minus_s;

                // Create signature
                crypto::ecdsa_signature_t sig(curve, state->r, s);
                state->signature = sig.to_der();

                // Verify signature
                crypto::ecc_pub_key_t pub_key(state->key_ref->Q);
                rv = pub_key.verify(state->message_hash, state->signature);
                if (rv) {
                    set_error("Signature verification failed");
                    return WASM_MPC_ERROR;
                }

                state->complete = true;
                *is_complete = 1;
                break;
            }

            default:
                set_error("Invalid round state");
                return WASM_MPC_INVALID_STATE;
        }

        return WASM_MPC_SUCCESS;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return WASM_MPC_ERROR;
    } catch (...) {
        set_error("Unknown exception");
        return WASM_MPC_ERROR;
    }
}

WASM_EXPORT
int wasm_sign_p1_get_signature(wasm_sign_session* session, uint8_t** out_sig, size_t* out_len) {
    if (!session || !session->opaque || !out_sig || !out_len) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    auto* state = static_cast<SignSessionState*>(session->opaque);
    if (!state->complete) {
        set_error("Signing not complete");
        return WASM_MPC_INVALID_STATE;
    }

    *out_len = state->signature.size();
    *out_sig = static_cast<uint8_t*>(malloc(*out_len));
    if (!*out_sig) {
        set_error("Memory allocation failed");
        return WASM_MPC_MEMORY_ERROR;
    }
    memcpy(*out_sig, state->signature.data(), *out_len);
    return WASM_MPC_SUCCESS;
}

WASM_EXPORT
void wasm_sign_session_free(wasm_sign_session* session) {
    if (session && session->opaque) {
        delete static_cast<SignSessionState*>(session->opaque);
        session->opaque = nullptr;
    }
}

// ============================================================================
// Signing Protocol - P2 (Responder)
// Implements the P2 (responder) side of the 2PC ECDSA signing protocol
// Used when WASM client acts as P2 (server-first protocol)
//
// Protocol flow (P2 perspective, global abort mode):
// - Start: Receive P1's commitment (com.msg) and SID
// - Round 0: Generate k2, R2, pi_2, send to P1
// - Round 1: Receive P1's opening (com.rand, R1, pi_1), verify, compute c
// - Complete (P2 does NOT compute signature - only P1 does)
// ============================================================================

WASM_EXPORT
int wasm_sign_p2_start(
    wasm_key_handle* key,
    const uint8_t* message_hash,
    size_t hash_len,
    const uint8_t* sid_in,
    size_t sid_len,
    const uint8_t* com_msg_in,
    size_t com_msg_len,
    wasm_sign_session* out_session
) {
    if (!key || !key->opaque || !message_hash || hash_len != 32 ||
        !sid_in || sid_len == 0 || !com_msg_in || com_msg_len == 0 || !out_session) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    try {
        auto* state = new SignP2SessionState();
        state->key_ref = static_cast<ecdsa2pc::key_t*>(key->opaque);
        state->message_hash = buf_t(message_hash, 32);
        state->sid = buf_t(sid_in, static_cast<int>(sid_len));
        state->round = 0;
        state->complete = false;

        // Deserialize P1's commitment message
        mem_t com_mem(const_cast<uint8_t*>(com_msg_in), static_cast<int>(com_msg_len));
        error_t rv = deser(com_mem, state->com_msg);
        if (rv) {
            delete state;
            set_error("Failed to deserialize P1's commitment");
            return WASM_MPC_ERROR;
        }

        out_session->opaque = state;
        return WASM_MPC_SUCCESS;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return WASM_MPC_ERROR;
    }
}

WASM_EXPORT
int wasm_sign_p2_process(
    wasm_sign_session* session,
    const uint8_t* msg_in,
    size_t msg_in_len,
    uint8_t** msg_out,
    size_t* msg_out_len,
    int* is_complete
) {
    if (!session || !session->opaque || !msg_out || !msg_out_len || !is_complete) {
        set_error("Invalid parameters");
        return WASM_MPC_PARAM_ERROR;
    }

    auto* state = static_cast<SignP2SessionState*>(session->opaque);

    try {
        *is_complete = 0;
        *msg_out = nullptr;
        *msg_out_len = 0;

        ecurve_t curve = state->key_ref->curve;
        const auto& G = curve.generator();
        const mod_t& q = curve.order();

        switch (state->round) {
            case 0: {
                // Round 0: Generate P2's R2 and ZK proof
                state->k2 = curve.get_random_value();
                state->R2 = state->k2 * G;
                state->R2_vec = { state->R2 };

                // Generate ZK proof that we know k2 such that R2 = k2 * G
                state->pi_2 = std::make_unique<zk::uc_batch_dl_t>();
                std::vector<bn_t> k2_vec = { state->k2 };
                state->pi_2->prove(state->R2_vec, k2_vec, state->sid, 2);

                // Serialize P2's msg: (R2_vec, pi_2)
                buf_t out_buf = ser(state->R2_vec, *state->pi_2);

                *msg_out_len = out_buf.size();
                *msg_out = static_cast<uint8_t*>(malloc(*msg_out_len));
                if (!*msg_out) {
                    set_error("Memory allocation failed");
                    return WASM_MPC_MEMORY_ERROR;
                }
                memcpy(*msg_out, out_buf.data(), *msg_out_len);

                state->round = 1;
                break;
            }

            case 1: {
                // Round 1: Receive P1's opening, verify, compute Paillier ciphertext
                if (!msg_in || msg_in_len == 0) {
                    set_error("Expected P1's opening message");
                    return WASM_MPC_PARAM_ERROR;
                }

                // Deserialize P1's opening: (com.rand, R1_vec, pi_1)
                buf256_t com_rand;
                state->R1_vec.resize(1);
                zk::uc_batch_dl_t pi_1;
                mem_t msg_mem(const_cast<uint8_t*>(msg_in), static_cast<int>(msg_in_len));
                error_t rv = deser(msg_mem, com_rand, state->R1_vec, pi_1);
                if (rv) {
                    set_error("Failed to deserialize P1's opening");
                    return WASM_MPC_ERROR;
                }

                // Create commitment object and verify opening
                state->com = std::make_unique<coinbase::crypto::commitment_t>(state->sid, P1_PID_AS_SERVER);
                state->com->rand = com_rand;
                state->com->msg = state->com_msg;

                // Verify commitment opening: (msgs, R1, pi_1)
                std::vector<mem_t> msgs_vec = { state->message_hash };
                rv = state->com->open(msgs_vec, state->R1_vec, pi_1);
                if (rv) {
                    set_error("Commitment opening verification failed");
                    return WASM_MPC_ERROR;
                }

                // Verify P1's ZK proof
                rv = pi_1.verify(state->R1_vec, state->sid, 1);
                if (rv) {
                    set_error("P1's ZK proof verification failed");
                    return WASM_MPC_ERROR;
                }

                // Compute combined R = k2 * R1
                state->R = state->k2 * state->R1_vec[0];
                state->r = state->R.get_x() % q;

                // Compute Paillier ciphertext c
                // Following sign_batch_impl from ecdsa_2p.cpp
                const mod_t& N = state->key_ref->paillier.get_N();

                // Convert message hash to bn_t
                bn_t m = curve_msg_to_bn(state->message_hash, curve);

                // Generate random values
                bn_t rho = bn_t::rand((q * q) << (SEC_P_STAT * 2));
                bn_t rc = bn_t::rand(N);
                if (!mod_t::coprime(rc, N)) {
                    set_error("gcd(rc, N) != 1");
                    return WASM_MPC_ERROR;
                }

                bn_t k2_inv;
                bn_t temp;
                MODULO(q) {
                    k2_inv = state->k2.inv();
                    temp = k2_inv * state->key_ref->x_share;
                }
                temp = k2_inv * m + temp * state->r + rho * q;
                auto c_tag = state->key_ref->paillier.enc(temp, rc);

                // Compute final ciphertext using homomorphic operations
                crypto::paillier_t::rerand_scope_t paillier_rerand(crypto::paillier_t::rerand_e::off);
                crypto::paillier_t::elem_t c_key_tag = state->key_ref->paillier.elem(state->key_ref->c_key) + (q << SEC_P_STAT);
                crypto::paillier_t::elem_t pai_c = (c_key_tag * (k2_inv * state->r)) + c_tag;

                bn_t c = pai_c.to_bn();

                // Serialize ciphertext
                buf_t out_buf = ser(c);

                *msg_out_len = out_buf.size();
                *msg_out = static_cast<uint8_t*>(malloc(*msg_out_len));
                if (!*msg_out) {
                    set_error("Memory allocation failed");
                    return WASM_MPC_MEMORY_ERROR;
                }
                memcpy(*msg_out, out_buf.data(), *msg_out_len);

                // P2 is done - P1 computes the signature
                state->complete = true;
                *is_complete = 1;
                break;
            }

            default:
                set_error("Invalid round state");
                return WASM_MPC_INVALID_STATE;
        }

        return WASM_MPC_SUCCESS;
    } catch (const std::exception& e) {
        set_error(std::string("Exception: ") + e.what());
        return WASM_MPC_ERROR;
    } catch (...) {
        set_error("Unknown exception");
        return WASM_MPC_ERROR;
    }
}

WASM_EXPORT
void wasm_sign_p2_session_free(wasm_sign_session* session) {
    if (session && session->opaque) {
        delete static_cast<SignP2SessionState*>(session->opaque);
        session->opaque = nullptr;
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

WASM_EXPORT
const char* wasm_get_last_error(void) {
    return g_last_error.c_str();
}

WASM_EXPORT
int wasm_init(void) {
    // Crypto library initializes automatically via static constructors
    return WASM_MPC_SUCCESS;
}

/**
 * Seed the random number generator with entropy from JavaScript
 * MUST be called before any cryptographic operations in WASM
 *
 * JavaScript should call this with entropy from crypto.getRandomValues()
 *
 * Note: In OpenSSL 3.x with WASM, RAND_status() may return 0 even after
 * proper seeding because the DRBG provider model expects system entropy
 * sources that don't exist in WASM. Instead, we verify by actually
 * generating random bytes with RAND_bytes().
 */
WASM_EXPORT
int wasm_seed_random(const uint8_t* entropy, size_t entropy_len) {
    if (!entropy || entropy_len < 32) {
        set_error("Entropy must be at least 32 bytes");
        return WASM_MPC_PARAM_ERROR;
    }

    // Use RAND_add with full entropy credit (entropy_len * 8 bits)
    // This seeds the OpenSSL random pool with JavaScript-provided entropy
    RAND_add(entropy, static_cast<int>(entropy_len), static_cast<double>(entropy_len));

    // Verify seeding worked by actually generating random bytes
    // This is more reliable than RAND_status() which may return 0 in WASM
    // even when the RNG is properly functional
    uint8_t test_buf[32];
    if (RAND_bytes(test_buf, sizeof(test_buf)) != 1) {
        set_error("RAND_bytes failed after seeding - RNG not working");
        return WASM_MPC_ERROR;
    }

    // Additional verification: ensure we got non-zero bytes
    // (extremely unlikely to get all zeros with proper RNG)
    bool all_zero = true;
    for (size_t i = 0; i < sizeof(test_buf); i++) {
        if (test_buf[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        set_error("RNG appears broken - generated all zeros");
        return WASM_MPC_ERROR;
    }

    return WASM_MPC_SUCCESS;
}

WASM_EXPORT
int wasm_get_secp256k1_curve_code(void) {
    return curve_secp256k1.get_openssl_code();
}

/**
 * Deterministic proof test for debugging.
 * Uses fixed inputs to enable comparison between WASM and native.
 *
 * Expected outputs from native test:
 * - G: 02ca0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
 * - Q: 02ca034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff
 * - e[0-2]: 14 4 16
 * - A[0]: 02ca02e74bfedce2d3394538d13ee424feff1f73903fd2f66384296cfe553fae40f432
 */
WASM_EXPORT
int wasm_test_deterministic_proof(void) {
    using namespace coinbase::zk;

    printf("[WASM DETERMINISTIC TEST] === Starting ===\n");

    // Use secp256k1 curve
    ecurve_t curve = curve_secp256k1;
    const auto& G = curve.generator();
    const mod_t& q = curve.order();

    // Step 1: Print curve generator
    buf_t G_ser = ser(G);
    printf("[WASM DETERMINISTIC TEST] G (%d bytes): ", G_ser.size());
    for (int i = 0; i < G_ser.size(); i++) {
        printf("%02x", G_ser.data()[i]);
    }
    printf("\n");
    printf("[WASM DETERMINISTIC TEST] Expected G:  02ca0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\n");

    // Step 2: Use fixed secret (same as native test)
    // x = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    uint8_t x_bytes[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    bn_t x_raw = bn_t::from_bin(mem_t(x_bytes, 32));

    // Debug: print x BEFORE modular reduction
    printf("[WASM DETERMINISTIC TEST] x BEFORE mod q: ");
    buf_t x_raw_buf = x_raw.to_bin(32);
    for (int i = 0; i < 32; i++) {
        printf("%02x", x_raw_buf.data()[i]);
    }
    printf("\n");
    printf("[WASM DETERMINISTIC TEST] Expected:        0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n");

    // Debug: print comparison of x < q
    printf("[WASM DETERMINISTIC TEST] Since x < q, x %% q should equal x unchanged\n");

    bn_t x = x_raw % q;

    printf("[WASM DETERMINISTIC TEST] x (reduced mod q): ");
    buf_t x_buf = x.to_bin(32);
    for (int i = 0; i < 32; i++) {
        printf("%02x", x_buf.data()[i]);
    }
    printf("\n");
    printf("[WASM DETERMINISTIC TEST] Expected:          0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n");

    // Step 3: Compute Q = x * G
    ecc_point_t Q = x * G;
    buf_t Q_ser = ser(Q);
    printf("[WASM DETERMINISTIC TEST] Q (%d bytes): ", Q_ser.size());
    for (int i = 0; i < Q_ser.size(); i++) {
        printf("%02x", Q_ser.data()[i]);
    }
    printf("\n");
    printf("[WASM DETERMINISTIC TEST] Expected Q:  02ca034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff\n");

    // Step 4: Use fixed SID
    // sid = deadbeefcafebabe0123456789abcdef
    uint8_t sid_bytes[16] = {
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    buf_t sid(sid_bytes, 16);

    printf("[WASM DETERMINISTIC TEST] sid: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", sid_bytes[i]);
    }
    printf("\n");

    // Step 5: Generate proof
    printf("[WASM DETERMINISTIC TEST] Generating proof with aux=2...\n");
    uc_dl_t proof;
    proof.prove(Q, x, sid, 2);

    printf("[WASM DETERMINISTIC TEST] Proof generated:\n");
    printf("[WASM DETERMINISTIC TEST]   params.rho: %d, params.b: %d, params.t: %d\n",
           proof.params.rho, proof.params.b, proof.params.t);
    printf("[WASM DETERMINISTIC TEST]   A.size(): %zu, e.size(): %zu, z.size(): %zu\n",
           proof.A.size(), proof.e.size(), proof.z.size());

    // Print e values
    printf("[WASM DETERMINISTIC TEST]   e values: ");
    for (size_t i = 0; i < proof.e.size(); i++) {
        printf("%d ", proof.e[i]);
    }
    printf("\n");
    printf("[WASM DETERMINISTIC TEST]   Expected e: 14 4 16 24 9 7 0 0 3 32 1 1 6 3 9 23 25 7 1 13 16 6 0 10 20 6 10 13 15 3 12 7\n");

    // Print A[0]
    if (proof.A.size() > 0) {
        buf_t A0_ser = ser(proof.A[0]);
        printf("[WASM DETERMINISTIC TEST]   A[0] (%d bytes): ", A0_ser.size());
        for (int i = 0; i < A0_ser.size(); i++) {
            printf("%02x", A0_ser.data()[i]);
        }
        printf("\n");
        printf("[WASM DETERMINISTIC TEST]   Expected A[0]: 02ca02e74bfedce2d3394538d13ee424feff1f73903fd2f66384296cfe553fae40f432\n");
    }

    // Step 6: Verify proof
    printf("[WASM DETERMINISTIC TEST] Verifying proof...\n");
    error_t rv = proof.verify(Q, sid, 2);
    if (rv) {
        printf("[WASM DETERMINISTIC TEST] *** VERIFICATION FAILED: error %d ***\n", rv);
        return WASM_MPC_ERROR;
    } else {
        printf("[WASM DETERMINISTIC TEST] VERIFICATION PASSED!\n");
    }

    // Step 7: Manual check for A[0]
    printf("[WASM DETERMINISTIC TEST] Manual check A[0] = z[0]*G - e[0]*Q:\n");
    ecc_point_t expected = proof.z[0] * G - bn_t(proof.e[0]) * Q;
    buf_t expected_ser = ser(expected);
    buf_t A0_ser2 = ser(proof.A[0]);
    printf("[WASM DETERMINISTIC TEST]   Expected: ");
    for (int i = 0; i < expected_ser.size(); i++) {
        printf("%02x", expected_ser.data()[i]);
    }
    printf("\n");
    printf("[WASM DETERMINISTIC TEST]   A[0]:     ");
    for (int i = 0; i < A0_ser2.size(); i++) {
        printf("%02x", A0_ser2.data()[i]);
    }
    printf("\n");
    printf("[WASM DETERMINISTIC TEST]   Match: %s\n", (expected == proof.A[0]) ? "YES" : "NO");

    printf("[WASM DETERMINISTIC TEST] === Test Complete ===\n");
    return WASM_MPC_SUCCESS;
}

}  // extern "C"
