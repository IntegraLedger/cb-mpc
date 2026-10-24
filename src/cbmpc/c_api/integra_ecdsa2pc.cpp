#include <new>

#include <cbmpc/api/integra_ecdsa_2p.h>
#include <cbmpc/c_api/integra_ecdsa_2p.h>
#include <cbmpc/core/buf.h>
#include <cbmpc/core/error.h>

#include "util.h"

using namespace coinbase::capi::detail;

extern "C" {

cbmpc_error_t cbmpc_ecdsa_2p_integra_derive_child(cmem_t key_blob, cmem_t tweak, cmem_t* out_child_key_blob) {
  try {
    if (!out_child_key_blob) return E_BADARG;
    *out_child_key_blob = cmem_t{nullptr, 0};
    const auto vkb = validate_cmem(key_blob);
    if (vkb) return vkb;
    const auto vt = validate_cmem(tweak);
    if (vt) return vt;

    coinbase::buf_t child;
    const coinbase::error_t rv =
        coinbase::api::ecdsa_2p::integra_derive_child(view_cmem(key_blob), view_cmem(tweak), child);
    if (rv) return rv;

    return alloc_cmem_from_buf(child, out_child_key_blob);
  } catch (const std::bad_alloc&) {
    if (out_child_key_blob) *out_child_key_blob = cmem_t{nullptr, 0};
    return E_INSUFFICIENT;
  } catch (...) {
    if (out_child_key_blob) *out_child_key_blob = cmem_t{nullptr, 0};
    return E_GENERAL;
  }
}

}  // extern "C"
