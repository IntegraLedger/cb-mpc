#pragma once

#include <cbmpc/c_api/common.h>

#ifdef __cplusplus
extern "C" {
#endif

// Integra extension: document-hash key derivation. Semantics in <cbmpc/api/integra_ecdsa_2p.h>.
//
// `tweak` must be exactly 32 bytes with 0 < tweak < q (big-endian); it is rejected, never reduced.
//
// Ownership:
// - On success, `out_child_key_blob->data` is allocated by the library and must be freed with
//   `cbmpc_cmem_free(*out_child_key_blob)`.
// - On failure, `*out_child_key_blob` is set to `{NULL, 0}`.
cbmpc_error_t cbmpc_ecdsa_2p_integra_derive_child(cmem_t key_blob, cmem_t tweak, cmem_t* out_child_key_blob);

#ifdef __cplusplus
}
#endif
