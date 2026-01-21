#pragma once
/**
 * WASM bindings for 2-party ECDSA protocol
 *
 * This header provides C-compatible functions that can be exported to JavaScript
 * through Emscripten. The design is optimized for async JavaScript/TypeScript usage.
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define WASM_MPC_SUCCESS 0
#define WASM_MPC_ERROR -1
#define WASM_MPC_PARAM_ERROR -2
#define WASM_MPC_MEMORY_ERROR -3
#define WASM_MPC_INVALID_STATE -4
#define WASM_MPC_PROTOCOL_ERROR -5

// Curve identifiers (matching OpenSSL NIDs)
#define WASM_CURVE_SECP256K1 714

// Party roles
#define WASM_PARTY_P1 0
#define WASM_PARTY_P2 1

/**
 * Opaque handle for an ECDSA 2PC key share
 */
typedef struct wasm_key_handle {
    void* opaque;
} wasm_key_handle;

/**
 * Opaque handle for a keygen session
 */
typedef struct wasm_keygen_session {
    void* opaque;
} wasm_keygen_session;

/**
 * Opaque handle for a signing session
 */
typedef struct wasm_sign_session {
    void* opaque;
} wasm_sign_session;

// ============================================================================
// Memory Management
// ============================================================================

/**
 * Allocate memory in WASM heap (for JavaScript to write data)
 */
uint8_t* wasm_alloc(size_t size);

/**
 * Free memory allocated by wasm_alloc or returned by other functions
 */
void wasm_free(void* ptr);

// ============================================================================
// Key Management
// ============================================================================

/**
 * Serialize a key handle to bytes
 * @param key The key handle to serialize
 * @param out_data Pointer to receive allocated data (caller must free with wasm_free)
 * @param out_len Pointer to receive data length
 * @return 0 on success, negative error code on failure
 */
int wasm_key_serialize(wasm_key_handle* key, uint8_t** out_data, size_t* out_len);

/**
 * Deserialize a key from bytes
 * @param data Serialized key data
 * @param len Length of data
 * @param out_key Pointer to receive the key handle
 * @return 0 on success, negative error code on failure
 */
int wasm_key_deserialize(const uint8_t* data, size_t len, wasm_key_handle* out_key);

/**
 * Free a key handle
 */
void wasm_key_free(wasm_key_handle* key);

/**
 * Get the public key Q as compressed SEC1 bytes (33 bytes)
 * @param key The key handle
 * @param out_data Pointer to receive allocated data (caller must free with wasm_free)
 * @param out_len Pointer to receive data length
 * @return 0 on success, negative error code on failure
 */
int wasm_key_get_public_key(wasm_key_handle* key, uint8_t** out_data, size_t* out_len);

/**
 * Get the Ethereum address from the public key (20 bytes)
 * @param key The key handle
 * @param out_data Pointer to receive allocated address (caller must free with wasm_free)
 * @param out_len Pointer to receive data length (will be 20)
 * @return 0 on success, negative error code on failure
 */
int wasm_key_get_address(wasm_key_handle* key, uint8_t** out_data, size_t* out_len);

/**
 * Derive a child key by adding a tweak to the key share
 * Uses the formula: child_x = x_share + tweak (mod n)
 * @param base_key The base key handle
 * @param tweak 32-byte tweak value (e.g., keccak256(document_hash))
 * @param tweak_len Must be 32
 * @param out_key Pointer to receive the derived key handle
 * @return 0 on success, negative error code on failure
 */
int wasm_key_derive(
    wasm_key_handle* base_key,
    const uint8_t* tweak,
    size_t tweak_len,
    wasm_key_handle* out_key
);

// ============================================================================
// Key Generation Protocol (2-party DKG)
// ============================================================================

/**
 * Create a new keygen session for P1 (client party)
 * @param curve Curve identifier (use WASM_CURVE_SECP256K1)
 * @param out_session Pointer to receive session handle
 * @return 0 on success, negative error code on failure
 */
int wasm_keygen_p1_start(int curve, wasm_keygen_session* out_session);

/**
 * Process a message from P2 and generate response
 * @param session The keygen session
 * @param msg_in Message from P2 (NULL for first round)
 * @param msg_in_len Length of input message (0 for first round)
 * @param msg_out Pointer to receive output message (caller must free with wasm_free)
 * @param msg_out_len Pointer to receive output message length
 * @param is_complete Pointer to receive completion flag (1 if keygen complete)
 * @return 0 on success, negative error code on failure
 */
int wasm_keygen_p1_process(
    wasm_keygen_session* session,
    const uint8_t* msg_in,
    size_t msg_in_len,
    uint8_t** msg_out,
    size_t* msg_out_len,
    int* is_complete
);

/**
 * Get the key share after keygen completes
 * @param session The completed keygen session
 * @param out_key Pointer to receive the key handle
 * @return 0 on success, negative error code on failure
 */
int wasm_keygen_p1_get_key(wasm_keygen_session* session, wasm_key_handle* out_key);

/**
 * Free a keygen session
 */
void wasm_keygen_session_free(wasm_keygen_session* session);

// ============================================================================
// Signing Protocol (2-party ECDSA signing)
// ============================================================================

/**
 * Create a new signing session for P1 (client party)
 * @param key The key handle to sign with
 * @param message_hash 32-byte hash of the message to sign
 * @param hash_len Must be 32
 * @param out_session Pointer to receive session handle
 * @return 0 on success, negative error code on failure
 */
int wasm_sign_p1_start(
    wasm_key_handle* key,
    const uint8_t* message_hash,
    size_t hash_len,
    wasm_sign_session* out_session
);

/**
 * Process a message from P2 and generate response
 * @param session The signing session
 * @param msg_in Message from P2 (NULL for first round)
 * @param msg_in_len Length of input message (0 for first round)
 * @param msg_out Pointer to receive output message (caller must free with wasm_free)
 * @param msg_out_len Pointer to receive output message length
 * @param is_complete Pointer to receive completion flag (1 if signing complete)
 * @return 0 on success, negative error code on failure
 */
int wasm_sign_p1_process(
    wasm_sign_session* session,
    const uint8_t* msg_in,
    size_t msg_in_len,
    uint8_t** msg_out,
    size_t* msg_out_len,
    int* is_complete
);

/**
 * Get the signature after signing completes
 * Returns 65 bytes: r (32) + s (32) + v (1)
 * @param session The completed signing session
 * @param out_sig Pointer to receive signature data (caller must free with wasm_free)
 * @param out_len Pointer to receive signature length (will be 65)
 * @return 0 on success, negative error code on failure
 */
int wasm_sign_p1_get_signature(wasm_sign_session* session, uint8_t** out_sig, size_t* out_len);

/**
 * Free a signing session
 */
void wasm_sign_session_free(wasm_sign_session* session);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get the last error message (useful for debugging)
 * @return Pointer to static error message string
 */
const char* wasm_get_last_error(void);

/**
 * Initialize the WASM module (called automatically, but can be called explicitly)
 * @return 0 on success
 */
int wasm_init(void);

/**
 * Run deterministic proof test for debugging.
 * Uses fixed inputs to compare WASM vs native behavior.
 * @return 0 on success (proof verified), non-zero on failure
 */
int wasm_test_deterministic_proof(void);

#ifdef __cplusplus
}  // extern "C"
#endif
