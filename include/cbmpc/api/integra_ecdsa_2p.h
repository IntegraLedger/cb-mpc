#pragma once

// Integra extension to the ECDSA-2PC API: document-hash key derivation.
//
// Not BIP32 (upstream's hd_keyset_ecdsa_2p is a different model). A 32-byte tweak t — the document's
// content hash — derives the child key Q' = Q + t*G from either party's key blob, with no interaction:
//   - P1 (holds the Paillier private key): x_share and c_key are unchanged; only Q moves.
//   - P2: x_share' = x_share + t (mod q).
// The joint secret is therefore x1 + x2 + t, and c_key still encrypts P1's unchanged share, so the
// unmodified signing protocol runs on the two child blobs.
//
// t is interpreted big-endian and must satisfy 0 < t < q. It is rejected, never reduced: a reduced or zero
// tweak would silently make two different documents derive the same key.

#include <cbmpc/core/buf.h>
#include <cbmpc/core/error.h>

namespace coinbase::api::ecdsa_2p {

error_t integra_derive_child(mem_t key_blob, mem_t tweak, buf_t& child_key_blob);

}  // namespace coinbase::api::ecdsa_2p
