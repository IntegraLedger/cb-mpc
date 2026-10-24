// Party P2 of Integra's MPC API, driving cb-mpc compiled to WebAssembly (cbmpc.mjs / cbmpc.wasm).
//
// cb-mpc's protocol blocks while it waits for the other party, so everything here is synchronous and must
// run where blocking is allowed: a dedicated Web Worker (the browser SDK steps with synchronous XHR) or a
// node worker thread (steps with Atomics.wait). The host supplies `step(messages)`, which POSTs the
// queued P2 messages to the session's continue route and returns the parsed JSON step response:
//   { message?: base64 } while the protocol runs, {} when P1 waits for P2, { done: true, ... } at the end.
//
// The step rule (the enclave's side is internal/mpc in integra-cb-mpc-service): queue what the protocol
// sends; when it receives, step with the queue; when it returns, step once more to collect the result.

const E_DKG = "dkg";
const E_SIGN = "sign";

export function fromBase64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toBase64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

// Instantiates the module and refuses to proceed unless OpenSSL's RNG is seeded from the host CSPRNG.
export async function loadCbmpc(createCbmpc, moduleOptions = {}) {
  const mod = await createCbmpc(moduleOptions);
  if (mod._integra_rand_status() !== 1) {
    throw new Error("cb-mpc: the RNG is not seeded from a CSPRNG; refusing to run");
  }
  return mod;
}

function copyIn(mod, bytes) {
  const p = mod._malloc(bytes.length || 1);
  if (p === 0) throw new Error("cb-mpc: out of memory");
  mod.HEAPU8.set(bytes, p);
  return p;
}

function release(mod, p, n) {
  mod.HEAPU8.fill(0, p, p + n);
  mod._free(p);
}

// Reads and frees a cmem_t {uint8_t* data; int size} the library wrote at `out`.
function takeOutput(mod, out) {
  const data = mod.getValue(out, "*");
  const size = mod.getValue(out + 4, "i32");
  const bytes = mod.HEAPU8.slice(data, data + size);
  mod._integra_free_output(out);
  return bytes;
}

function errorCode(rv) {
  return "0x" + (rv >>> 0).toString(16).padStart(8, "0");
}

function makeTransport(step, start) {
  if (start.done) throw new Error("cb-mpc: the server finished before P2 started");
  let pending = start.message ? fromBase64(start.message) : null;
  let queue = [];
  const t = {
    error: null,
    send(_receiver, bytes) {
      queue.push(bytes);
      return true;
    },
    receive(_sender) {
      if (pending) {
        const m = pending;
        pending = null;
        return m;
      }
      try {
        const r = step(queue.map(toBase64));
        queue = [];
        if (r.done) throw new Error("server finished while P2 expected a message");
        if (!r.message) throw new Error("stalled: P1 is waiting for P2 although P2 asked for a message");
        return fromBase64(r.message);
      } catch (e) {
        t.error = e;
        return null; // aborts the protocol; the error is reported by the caller
      }
    },
    finish() {
      const r = step(queue.map(toBase64));
      queue = [];
      if (!r.done) throw new Error("server sent a message after P2 finished");
      return r;
    },
  };
  return t;
}

function fail(what, rv, t) {
  const cause = t.error ? `: ${t.error.message}` : "";
  return new Error(`cb-mpc ${what} failed (${errorCode(rv)})${cause}`, { cause: t.error ?? undefined });
}

// Runs P2 of keygen. `start` is the parsed response of POST /v1/keygen/start. Returns P2's key blob (secret:
// the caller must protect and eventually zero it) and the server's final step response.
export function keygen(mod, step, start) {
  const t = makeTransport(step, start);
  mod.integraTransport = t;
  const out = mod._malloc(8);
  try {
    const rv = mod._integra_dkg_p2(out);
    if (rv !== 0) throw fail(E_DKG, rv, t);
    const keyBlob = takeOutput(mod, out);
    try {
      return { keyBlob, result: t.finish() };
    } catch (e) {
      keyBlob.fill(0); // the key never became a wallet; do not leave the share in memory
      throw e;
    }
  } finally {
    mod._free(out);
    mod.integraTransport = undefined;
  }
}

// Runs P2 of signing `hash32` with `keyBlob` (already derived, if the server was given a tweak). `start` is
// the parsed response of POST /v1/sign/start. Returns the server's final step response, which carries the
// signature: only P1 learns it from the protocol.
export function sign(mod, step, start, keyBlob, hash32) {
  if (hash32.length !== 32) throw new Error("cb-mpc sign: hash must be 32 bytes");
  const t = makeTransport(step, start);
  mod.integraTransport = t;
  const k = copyIn(mod, keyBlob);
  const h = copyIn(mod, hash32);
  try {
    const rv = mod._integra_sign_p2(k, keyBlob.length, h);
    if (rv !== 0) throw fail(E_SIGN, rv, t);
    return t.finish();
  } finally {
    release(mod, k, keyBlob.length);
    release(mod, h, 32);
    mod.integraTransport = undefined;
  }
}

// Integra's document-hash derivation of a P2 key blob: the child key is Q + tweak*G. 0 < tweak < n.
export function deriveChild(mod, keyBlob, tweak32) {
  if (tweak32.length !== 32) throw new Error("cb-mpc derive: tweak must be 32 bytes");
  const k = copyIn(mod, keyBlob);
  const tw = copyIn(mod, tweak32);
  const out = mod._malloc(8);
  try {
    const rv = mod._integra_derive_child(k, keyBlob.length, tw, out);
    if (rv !== 0) throw new Error(`cb-mpc derive failed (${errorCode(rv)})`);
    return takeOutput(mod, out);
  } finally {
    release(mod, k, keyBlob.length);
    release(mod, tw, 32);
    mod._free(out);
  }
}

// The joint public key of a key blob, SEC1 compressed.
export function publicKey(mod, keyBlob) {
  const k = copyIn(mod, keyBlob);
  const out = mod._malloc(8);
  try {
    const rv = mod._integra_public_key(k, keyBlob.length, out);
    if (rv !== 0) throw new Error(`cb-mpc public key failed (${errorCode(rv)})`);
    return takeOutput(mod, out);
  } finally {
    release(mod, k, keyBlob.length);
    mod._free(out);
  }
}
