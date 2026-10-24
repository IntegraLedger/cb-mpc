// Package cbmpc is a thin cgo binding over cb-mpc's C API for two-party ECDSA on secp256k1
// (include/cbmpc/c_api/ecdsa_2p.h) and Integra's derivation extension
// (include/cbmpc/c_api/integra_ecdsa_2p.h).
//
// Keys cross the boundary only as opaque key blobs in upstream's own format; no native handle outlives a
// call, so there is nothing to free. Blobs hold a party's secret share: callers zero them with Zero when
// done.
//
// The consumer supplies absolute include and library paths through CGO_CFLAGS and CGO_LDFLAGS (cgo runs the
// compiler from each package directory, so relative paths resolve wrongly).
package cbmpc

/*
#cgo darwin LDFLAGS: -lcbmpc -lcrypto -lc++ -framework CoreServices -framework IOKit
#cgo linux LDFLAGS: -lcbmpc -lcrypto -lstdc++ -lm -ldl -lpthread

#include <stdlib.h>
#include <cbmpc/c_api/ecdsa_2p.h>
#include <cbmpc/c_api/integra_ecdsa_2p.h>
#include <cbmpc/c_api/job.h>

extern cbmpc_error_t cbmpcGoSend(void* ctx, int32_t receiver, uint8_t* data, int size);
extern cbmpc_error_t cbmpcGoReceive(void* ctx, int32_t sender, cmem_t* out_msg);

static cbmpc_error_t send_trampoline(void* ctx, int32_t receiver, const uint8_t* data, int size) {
  return cbmpcGoSend(ctx, receiver, (uint8_t*)data, size);
}

static cbmpc_error_t receive_trampoline(void* ctx, int32_t sender, cmem_t* out_msg) {
  return cbmpcGoReceive(ctx, sender, out_msg);
}

// The job and transport are built here, on the C stack, because Go memory handed to C must not contain
// Go pointers. `handle` is a runtime/cgo.Handle, an integer.
static const char integra_p1_name[] = "integra-p1";
static const char integra_p2_name[] = "integra-p2";

static cbmpc_2pc_job_t make_job(cbmpc_transport_t* t, uintptr_t handle, int32_t self) {
  t->ctx = (void*)handle;
  t->send = send_trampoline;
  t->receive = receive_trampoline;
  t->receive_all = NULL;
  t->free = NULL;
  cbmpc_2pc_job_t job;
  job.self = (cbmpc_2pc_party_t)self;
  job.p1_name = integra_p1_name;
  job.p2_name = integra_p2_name;
  job.transport = t;
  return job;
}

static cbmpc_error_t run_dkg(uintptr_t handle, int32_t self, cmem_t* out_key_blob) {
  cbmpc_transport_t t;
  cbmpc_2pc_job_t job = make_job(&t, handle, self);
  return cbmpc_ecdsa_2p_dkg(&job, CBMPC_CURVE_SECP256K1, out_key_blob);
}

static cbmpc_error_t run_sign(uintptr_t handle, int32_t self, cmem_t key_blob, cmem_t msg_hash, cmem_t* sid_out,
                              cmem_t* sig_der_out) {
  cbmpc_transport_t t;
  cbmpc_2pc_job_t job = make_job(&t, handle, self);
  cmem_t no_sid = {NULL, 0};
  return cbmpc_ecdsa_2p_sign(&job, key_blob, msg_hash, no_sid, sid_out, sig_der_out);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime/cgo"
	"unsafe"
)

// Party is a role in the two-party protocol. In Integra's deployment the enclave is P1 (it holds the
// Paillier private key) and the browser or the signer is P2.
type Party int32

const (
	P1 Party = C.CBMPC_2PC_P1
	P2 Party = C.CBMPC_2PC_P2
)

// Party names bind each party's identity into the protocol's proofs, so every implementation — the
// enclave, the signer and the browser WASM — must use exactly these strings. The C side passes them
// (integra_p1_name / integra_p2_name above); these constants exist for the other implementations to match.
const (
	P1Name = "integra-p1"
	P2Name = "integra-p2"
)

// Transport carries protocol messages to and from the other party. Receive blocks until the next message
// from the other party arrives or the exchange is abandoned; a returned error aborts the protocol.
type Transport interface {
	Send(receiver Party, msg []byte) error
	Receive(sender Party) ([]byte, error)
}

// Error is a non-success return from cb-mpc.
type Error struct {
	Op   string
	Code uint32
}

func (e *Error) Error() string { return fmt.Sprintf("cb-mpc %s: error 0x%08x", e.Op, e.Code) }

// ErrTransport wraps the error a Transport returned when cb-mpc aborts because of it.
var ErrTransport = errors.New("cb-mpc transport failed")

// KeyBlob is one party's ECDSA-2PC key in upstream's opaque blob format. It contains that party's secret
// share.
type KeyBlob []byte

// Zero overwrites the blob in place.
func (k KeyBlob) Zero() {
	for i := range k {
		k[i] = 0
	}
}

type session struct {
	t   Transport
	err error // first transport error, reported instead of cb-mpc's generic network code
}

func runJob(op string, t Transport, call func(handle C.uintptr_t) C.cbmpc_error_t) error {
	s := &session{t: t}
	h := cgo.NewHandle(s)
	defer h.Delete()

	rv := call(C.uintptr_t(h))
	if s.err != nil {
		return fmt.Errorf("cb-mpc %s: %w: %w", op, ErrTransport, s.err)
	}
	if rv != C.CBMPC_SUCCESS {
		return &Error{Op: op, Code: uint32(rv)}
	}
	return nil
}

//export cbmpcGoSend
func cbmpcGoSend(ctx unsafe.Pointer, receiver C.int32_t, data *C.uint8_t, size C.int) C.cbmpc_error_t {
	s := cgo.Handle(uintptr(ctx)).Value().(*session)
	msg := C.GoBytes(unsafe.Pointer(data), size)
	if err := s.t.Send(Party(receiver), msg); err != nil {
		if s.err == nil {
			s.err = err
		}
		return C.CBMPC_E_NET_GENERAL
	}
	return C.CBMPC_SUCCESS
}

//export cbmpcGoReceive
func cbmpcGoReceive(ctx unsafe.Pointer, sender C.int32_t, out *C.cmem_t) C.cbmpc_error_t {
	s := cgo.Handle(uintptr(ctx)).Value().(*session)
	msg, err := s.t.Receive(Party(sender))
	if err != nil {
		if s.err == nil {
			s.err = err
		}
		return C.CBMPC_E_NET_GENERAL
	}
	// cb-mpc frees received buffers with cbmpc_free, so they must come from its allocator.
	n := len(msg)
	buf := C.cbmpc_malloc(C.size_t(n + 1)) // +1 so an empty message still has a non-NULL buffer
	if buf == nil {
		return C.CBMPC_E_INSUFFICIENT
	}
	if n > 0 {
		copy(unsafe.Slice((*byte)(buf), n), msg)
	}
	out.data = (*C.uint8_t)(buf)
	out.size = C.int(n)
	return C.CBMPC_SUCCESS
}

// takeCmem copies a library-owned buffer into Go memory and frees the original (cbmpc_cmem_free zeroizes).
func takeCmem(m C.cmem_t) []byte {
	if m.data == nil {
		return nil
	}
	out := C.GoBytes(unsafe.Pointer(m.data), m.size)
	C.cbmpc_cmem_free(m)
	return out
}

// cmemView exposes Go bytes to C for the duration of one call. The C API only reads its cmem_t inputs.
func cmemView(b []byte) (C.cmem_t, *C.uint8_t) {
	if len(b) == 0 {
		return C.cmem_t{data: nil, size: 0}, nil
	}
	p := (*C.uint8_t)(C.CBytes(b))
	return C.cmem_t{data: p, size: C.int(len(b))}, p
}

func freeView(p *C.uint8_t, n int) {
	if p == nil {
		return
	}
	clear(unsafe.Slice((*byte)(unsafe.Pointer(p)), n))
	C.free(unsafe.Pointer(p))
}

// DKG runs interactive key generation on secp256k1 and returns this party's key blob.
func DKG(self Party, t Transport) (KeyBlob, error) {
	var out C.cmem_t
	err := runJob("dkg", t, func(h C.uintptr_t) C.cbmpc_error_t {
		return C.run_dkg(h, C.int32_t(self), &out)
	})
	blob := takeCmem(out)
	if err != nil {
		KeyBlob(blob).Zero()
		return nil, err
	}
	return blob, nil
}

// Sign runs interactive signing of a 32-byte message hash. The session id is always agreed jointly by the
// two parties (an empty sid makes cb-mpc run its coin-flip), so neither side can choose it. Only P1
// receives the DER signature; P2 gets nil on success.
func Sign(self Party, t Transport, key KeyBlob, hash [32]byte) ([]byte, error) {
	keyView, keyPtr := cmemView(key)
	defer freeView(keyPtr, len(key))
	hashView, hashPtr := cmemView(hash[:])
	defer freeView(hashPtr, len(hash))

	var sid, sig C.cmem_t
	err := runJob("sign", t, func(h C.uintptr_t) C.cbmpc_error_t {
		return C.run_sign(h, C.int32_t(self), keyView, hashView, &sid, &sig)
	})
	takeCmem(sid)
	der := takeCmem(sig)
	if err != nil {
		return nil, err
	}
	return der, nil
}

// PublicKey returns the joint public key of a key blob, SEC1 compressed (33 bytes).
func PublicKey(key KeyBlob) ([]byte, error) {
	keyView, keyPtr := cmemView(key)
	defer freeView(keyPtr, len(key))
	var out C.cmem_t
	if rv := C.cbmpc_ecdsa_2p_get_public_key_compressed(keyView, &out); rv != C.CBMPC_SUCCESS {
		return nil, &Error{Op: "get_public_key_compressed", Code: uint32(rv)}
	}
	return takeCmem(out), nil
}

// DeriveChild applies Integra's document-hash derivation: the child's public key is Q + tweak*G. The tweak
// must satisfy 0 < tweak < n; cb-mpc rejects anything else rather than reducing it.
func DeriveChild(key KeyBlob, tweak [32]byte) (KeyBlob, error) {
	keyView, keyPtr := cmemView(key)
	defer freeView(keyPtr, len(key))
	tweakView, tweakPtr := cmemView(tweak[:])
	defer freeView(tweakPtr, len(tweak))
	var out C.cmem_t
	if rv := C.cbmpc_ecdsa_2p_integra_derive_child(keyView, tweakView, &out); rv != C.CBMPC_SUCCESS {
		return nil, &Error{Op: "integra_derive_child", Code: uint32(rv)}
	}
	return takeCmem(out), nil
}
