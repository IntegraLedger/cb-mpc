#include "ecdsa2p.h"

#include <memory>

#include <cbmpc/core/buf.h>
#include <cbmpc/core/convert.h>
#include <cbmpc/crypto/base.h>
#include <cbmpc/protocol/ecdsa_2p.h>
#include <cbmpc/protocol/mpc_job_session.h>

#include "curve.h"
#include "network.h"

using namespace coinbase;
using namespace coinbase::mpc;

int mpc_ecdsa2p_dkg(job_2p_ref* j, int curve_code, mpc_ecdsa2pc_key_ref* k) {
  job_2p_t* job = static_cast<job_2p_t*>(j->opaque);
  ecurve_t curve = ecurve_t::find(curve_code);

  ecdsa2pc::key_t* key = new ecdsa2pc::key_t();

  error_t err = ecdsa2pc::dkg(*job, curve, *key);
  if (err) return err;
  *k = mpc_ecdsa2pc_key_ref{key};

  return 0;
}

int mpc_ecdsa2p_refresh(job_2p_ref* j, mpc_ecdsa2pc_key_ref* k, mpc_ecdsa2pc_key_ref* nk) {
  job_2p_t* job = static_cast<job_2p_t*>(j->opaque);

  ecdsa2pc::key_t* key = static_cast<ecdsa2pc::key_t*>(k->opaque);
  ecdsa2pc::key_t* new_key = new ecdsa2pc::key_t();

  error_t err = ecdsa2pc::refresh(*job, *key, *new_key);
  if (err) return err;
  *nk = mpc_ecdsa2pc_key_ref{new_key};

  return 0;
}

int mpc_ecdsa2p_sign(job_2p_ref* j, cmem_t sid_mem, mpc_ecdsa2pc_key_ref* k, cmems_t msgs, cmems_t* sigs) {
  job_2p_t* job = static_cast<job_2p_t*>(j->opaque);
  ecdsa2pc::key_t* key = static_cast<ecdsa2pc::key_t*>(k->opaque);
  buf_t sid = mem_t(sid_mem);
  // Reconstruct messages from cmems_t explicitly and copy into owned buffers
  int count = msgs.count;
  std::vector<buf_t> owned_msgs;
  owned_msgs.reserve(count);
  const uint8_t* p = msgs.data;
  for (int i = 0; i < count; i++) {
    int len = msgs.sizes ? msgs.sizes[i] : 0;
    buf_t b(len);
    if (len > 0) memcpy(b.data(), p, len);
    owned_msgs.emplace_back(std::move(b));
    p += len;
  }
  std::vector<mem_t> messages(owned_msgs.size());
  for (size_t i = 0; i < owned_msgs.size(); i++) messages[i] = owned_msgs[i];

  std::vector<buf_t> signatures;
  error_t err = ecdsa2pc::sign_batch(*job, sid, *key, messages, signatures);
  if (err) return err;
  *sigs = coinbase::mems_t(signatures).to_cmems();

  return 0;
}

// ============ Memory Management =================
void free_mpc_ecdsa2p_key(mpc_ecdsa2pc_key_ref ctx) {
  if (ctx.opaque) {
    delete static_cast<ecdsa2pc::key_t*>(ctx.opaque);
  }
}

// ============ Accessors =========================

int mpc_ecdsa2p_key_get_role_index(mpc_ecdsa2pc_key_ref* key) {
  if (key == NULL || key->opaque == NULL) {
    return -1;  // error: invalid key
  }
  ecdsa2pc::key_t* k = static_cast<ecdsa2pc::key_t*>(key->opaque);
  return static_cast<int>(k->role);
}

ecc_point_ref mpc_ecdsa2p_key_get_Q(mpc_ecdsa2pc_key_ref* key) {
  if (key == NULL || key->opaque == NULL) {
    return ecc_point_ref{nullptr};
  }
  ecdsa2pc::key_t* k = static_cast<ecdsa2pc::key_t*>(key->opaque);
  ecc_point_t* Q_copy = new ecc_point_t(k->Q);  // deep copy
  return ecc_point_ref{Q_copy};
}

cmem_t mpc_ecdsa2p_key_get_x_share(mpc_ecdsa2pc_key_ref* key) {
  if (key == NULL || key->opaque == NULL) {
    return cmem_t{nullptr, 0};
  }
  ecdsa2pc::key_t* k = static_cast<ecdsa2pc::key_t*>(key->opaque);
  // Serialize bn_t to bytes (minimal length) preserving order size
  int bin_size = std::max(k->x_share.get_bin_size(), k->curve.order().get_bin_size());
  buf_t x_buf = k->x_share.to_bin(bin_size);
  return x_buf.to_cmem();
}

int mpc_ecdsa2p_key_get_curve_code(mpc_ecdsa2pc_key_ref* key) {
  if (key == NULL || key->opaque == NULL) {
    return -1;
  }
  ecdsa2pc::key_t* k = static_cast<ecdsa2pc::key_t*>(key->opaque);
  return k->curve.get_openssl_code();
}

// ============ Serialization =========================

int mpc_ecdsa2p_key_serialize(
    mpc_ecdsa2pc_key_ref* key,
    uint8_t** out_data,
    size_t* out_len
) {
  if (key == NULL || key->opaque == NULL || out_data == NULL || out_len == NULL) {
    return -1;
  }

  try {
    ecdsa2pc::key_t* k = static_cast<ecdsa2pc::key_t*>(key->opaque);

    // Calculate size first
    converter_t sizer(true);
    k->convert(sizer);
    int size = sizer.get_size();

    // Allocate buffer
    uint8_t* buffer = static_cast<uint8_t*>(malloc(size));
    if (buffer == NULL) {
      return -2;
    }

    // Serialize
    converter_t writer(buffer);
    k->convert(writer);

    if (writer.is_error()) {
      free(buffer);
      return -3;
    }

    *out_data = buffer;
    *out_len = static_cast<size_t>(size);
    return 0;
  } catch (...) {
    return -4;
  }
}

int mpc_ecdsa2p_key_deserialize(
    const uint8_t* data,
    size_t len,
    mpc_ecdsa2pc_key_ref* out_key
) {
  if (data == NULL || len == 0 || out_key == NULL) {
    return -1;
  }

  try {
    ecdsa2pc::key_t* k = new ecdsa2pc::key_t();

    mem_t mem(const_cast<uint8_t*>(data), static_cast<int>(len));
    converter_t reader(mem);
    k->convert(reader);

    if (reader.is_error()) {
      delete k;
      return -2;
    }

    out_key->opaque = k;
    return 0;
  } catch (...) {
    return -3;
  }
}

// ============ Derivation =========================

int mpc_ecdsa2p_key_derive(
    mpc_ecdsa2pc_key_ref* base_key,
    const uint8_t* tweak,
    size_t tweak_len,
    mpc_ecdsa2pc_key_ref* derived_key
) {
  if (base_key == NULL || base_key->opaque == NULL || tweak == NULL || derived_key == NULL) {
    return -1;
  }
  if (tweak_len != 32) {
    return -2;
  }

  try {
    ecdsa2pc::key_t* base = static_cast<ecdsa2pc::key_t*>(base_key->opaque);
    ecdsa2pc::key_t* derived = new ecdsa2pc::key_t();

    mem_t tweak_mem(const_cast<uint8_t*>(tweak), 32);
    error_t err = ecdsa2pc::derive_child_key(*base, tweak_mem, *derived);

    if (err) {
      delete derived;
      return -3;
    }

    derived_key->opaque = derived;
    return 0;
  } catch (...) {
    return -4;
  }
}