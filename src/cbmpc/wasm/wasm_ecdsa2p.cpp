/**
 * WASM bindings implementation for 2-party ECDSA protocol
 *
 * Based on the Go CGO bindings pattern from demos-go/cb-mpc-go/internal/cgobinding/
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
#include <cbmpc/protocol/ecdsa_2p.h>

#include <cstring>
#include <string>

using namespace coinbase;
using namespace coinbase::mpc;
using namespace coinbase::crypto;

// Thread-local error message
static std::string g_last_error;

static void set_error(const std::string& msg) {
    g_last_error = msg;
}

// ============================================================================
// Internal State Types
// ============================================================================

struct KeygenSessionState {
    ecurve_t curve;
    int round;
    ecdsa2pc::key_t key;
    bool complete;

    KeygenSessionState() : curve(curve_secp256k1), round(0), complete(false) {}
};

struct SignSessionState {
    ecdsa2pc::key_t* key_ref;
    buf_t message_hash;
    int round;
    buf_t signature;
    bool complete;

    SignSessionState() : key_ref(nullptr), round(0), complete(false) {}
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
// Note: Full 2PC keygen requires network I/O handled by wallet-service
// These functions are placeholders for future client-side protocol support
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
    // Full protocol not yet implemented in WASM
    // The keygen protocol requires job_2p_t which needs network callbacks
    set_error("Full keygen protocol requires wallet-service API");
    return WASM_MPC_ERROR;
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
// Signing Protocol
// Note: Full 2PC signing requires network I/O handled by wallet-service
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
    // Full protocol not yet implemented in WASM
    set_error("Full signing protocol requires wallet-service API");
    return WASM_MPC_ERROR;
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

WASM_EXPORT
int wasm_get_secp256k1_curve_code(void) {
    return curve_secp256k1.get_openssl_code();
}

}  // extern "C"
