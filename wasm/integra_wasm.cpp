// Integra's WebAssembly entry points: party P2 of ECDSA-2PC on secp256k1, running upstream's protocol code
// unmodified through the C API.
//
// The protocol blocks inside `receive` until the other party's next message arrives. The host runs this
// module in a dedicated Web Worker (or a node worker thread), where the transport can block too: the JS
// side installs `Module.integraTransport = { send(receiver, bytes), receive(sender) }`, implemented with
// synchronous XHR in the browser and Atomics.wait under node. `receive` returns a Uint8Array, or null to
// abort the protocol.

#include <emscripten/emscripten.h>
#include <openssl/rand.h>
#include <stdint.h>

#include <cbmpc/c_api/ecdsa_2p.h>
#include <cbmpc/c_api/integra_ecdsa_2p.h>
#include <cbmpc/c_api/job.h>

// clang-format off
EM_JS(int, integra_js_send, (int32_t receiver, const uint8_t* data, int size), {
  return Module.integraTransport.send(receiver, HEAPU8.slice(data, data + size)) ? 0 : 1;
});

EM_JS(int, integra_js_receive, (int32_t sender, uint8_t** out_data, int* out_size), {
  const msg = Module.integraTransport.receive(sender);
  if (!(msg instanceof Uint8Array)) return 1;
  const p = _cbmpc_malloc(msg.length + 1);
  if (p === 0) return 1;
  HEAPU8.set(msg, p);
  setValue(out_data, p, "*");
  setValue(out_size, msg.length, "i32");
  return 0;
});
// clang-format on

namespace {

constexpr char kP1Name[] = "integra-p1";  // must match go/cbmpc P1Name / P2Name
constexpr char kP2Name[] = "integra-p2";

cbmpc_error_t send_cb(void*, int32_t receiver, const uint8_t* data, int size) {
  return integra_js_send(receiver, data, size) == 0 ? CBMPC_SUCCESS : CBMPC_E_NET_GENERAL;
}

cbmpc_error_t receive_cb(void*, int32_t sender, cmem_t* out_msg) {
  uint8_t* data = nullptr;
  int size = 0;
  if (integra_js_receive(sender, &data, &size) != 0) return CBMPC_E_NET_GENERAL;
  out_msg->data = data;
  out_msg->size = size;
  return CBMPC_SUCCESS;
}

cbmpc_2pc_job_t p2_job(cbmpc_transport_t* t) {
  t->ctx = nullptr;
  t->send = send_cb;
  t->receive = receive_cb;
  t->receive_all = nullptr;
  t->free = nullptr;
  return cbmpc_2pc_job_t{CBMPC_2PC_P2, kP1Name, kP2Name, t};
}

}  // namespace

extern "C" {

// 1 when OpenSSL's RNG is seeded from the host's CSPRNG (crypto.getRandomValues via getentropy). The host
// must refuse to run any protocol otherwise.
EMSCRIPTEN_KEEPALIVE int integra_rand_status() { return RAND_status(); }

// Outputs are written to `out` as {data, size}; free them with integra_free_output.

EMSCRIPTEN_KEEPALIVE int integra_dkg_p2(cmem_t* out_key_blob) {
  cbmpc_transport_t t;
  const cbmpc_2pc_job_t job = p2_job(&t);
  return cbmpc_ecdsa_2p_dkg(&job, CBMPC_CURVE_SECP256K1, out_key_blob);
}

// P2 never receives the signature (upstream returns it to P1 only); the caller gets it from the server.
EMSCRIPTEN_KEEPALIVE int integra_sign_p2(const uint8_t* key_blob, int key_size, const uint8_t* hash32) {
  cbmpc_transport_t t;
  const cbmpc_2pc_job_t job = p2_job(&t);
  cmem_t sid{nullptr, 0};
  cmem_t sig{nullptr, 0};
  const cbmpc_error_t rv = cbmpc_ecdsa_2p_sign(&job, cmem_t{const_cast<uint8_t*>(key_blob), key_size},
                                               cmem_t{const_cast<uint8_t*>(hash32), 32}, cmem_t{nullptr, 0}, &sid, &sig);
  cbmpc_cmem_free(sid);
  cbmpc_cmem_free(sig);
  return rv;
}

EMSCRIPTEN_KEEPALIVE int integra_public_key(const uint8_t* key_blob, int key_size, cmem_t* out_pub) {
  return cbmpc_ecdsa_2p_get_public_key_compressed(cmem_t{const_cast<uint8_t*>(key_blob), key_size}, out_pub);
}

EMSCRIPTEN_KEEPALIVE int integra_derive_child(const uint8_t* key_blob, int key_size, const uint8_t* tweak32,
                                              cmem_t* out_child) {
  return cbmpc_ecdsa_2p_integra_derive_child(cmem_t{const_cast<uint8_t*>(key_blob), key_size},
                                             cmem_t{const_cast<uint8_t*>(tweak32), 32}, out_child);
}

// Zeroizes, then frees, a buffer the library returned in a cmem_t.
EMSCRIPTEN_KEEPALIVE void integra_free_output(cmem_t* out) {
  cbmpc_cmem_free(*out);
  out->data = nullptr;
  out->size = 0;
}

}  // extern "C"
