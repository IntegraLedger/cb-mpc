// Keygen transcript recorder driving the ACTUAL WASM ARTIFACT under node
// (remediation plan 0.5, WASM half).
//
// This is the half that makes 0.5 a differential: it runs the Emscripten-built
// module, not the C++ source compiled natively, so it exercises the same
// toolchain the browser does. Its output is byte-comparable with
// native_keygen_transcript (job_2p_t) and wasm_api_keygen_transcript (the same
// entry points built natively).
//
// ⛔ Each party gets its OWN module instance. The deterministic RNG shim keeps
// thread-local state, and node runs the whole protocol on one thread; sharing
// an instance would force a re-install between the two parties and reset each
// (seed, call-sequence) stream. Two instances means two linear memories and
// therefore two independent streams -- the same reason the native harness runs
// each party in its own thread.
//
// ⛔ Requires a module linked with CBMPC_TEST_RNG=ON and the shim exported.
// That artifact must never ship; it is built outside dist-wasm/ deliberately.
//
// usage: node wasm_node_keygen_transcript.cjs <module.js> [p1_seed_hex] [p2_seed_hex]

const path = require('path');
const crypto = require('crypto');

const modulePath = process.argv[2];
if (!modulePath) {
  console.error('usage: node wasm_node_keygen_transcript.cjs <module.js> [p1_seed_hex] [p2_seed_hex]');
  process.exit(2);
}
const b1 = parseInt(process.argv[3] || '11', 16);
const b2 = parseInt(process.argv[4] || '22', 16);

const WASM_MPC_SUCCESS = 0;
const PTR = 4; // wasm32

function api(mod) {
  const c = (name, ret, args) => mod.cwrap(name, ret, args);
  return {
    mod,
    rngInstall: c('cbmpc_test_rng_install', 'number', ['number', 'number']),
    init: c('wasm_init', 'number', []),
    curveCode: c('wasm_get_secp256k1_curve_code', 'number', []),
    lastError: c('wasm_get_last_error', 'string', []),
    p1Start: c('wasm_keygen_p1_start', 'number', ['number', 'number']),
    p1Process: c('wasm_keygen_p1_process', 'number', ['number', 'number', 'number', 'number', 'number', 'number']),
    p1GetKey: c('wasm_keygen_p1_get_key', 'number', ['number', 'number']),
    p2Start: c('wasm_keygen_p2_start', 'number', ['number', 'number', 'number', 'number']),
    p2Process: c('wasm_keygen_p2_process', 'number', ['number', 'number', 'number', 'number', 'number', 'number']),
    p2GetKey: c('wasm_keygen_p2_get_key', 'number', ['number', 'number']),
    pubKey: c('wasm_key_get_public_key', 'number', ['number', 'number', 'number']),
  };
}

function putBytes(mod, bytes) {
  const p = mod._malloc(bytes.length || 1);
  mod.HEAPU8.set(bytes, p);
  return p;
}
function readI32(mod, p) { return mod.getValue(p, 'i32'); }
function takeBytes(mod, ptrPtr, lenPtr) {
  const p = readI32(mod, ptrPtr);
  const n = readI32(mod, lenPtr);
  if (!p || n <= 0) return Buffer.alloc(0);
  return Buffer.from(mod.HEAPU8.subarray(p, p + n)); // copy before free
}

// Runs one keygen step and returns the produced message.
function step(a, fn, session, msgIn) {
  const m = a.mod;
  const inPtr = msgIn && msgIn.length ? putBytes(m, msgIn) : 0;
  const outPtrPtr = m._malloc(PTR), outLenPtr = m._malloc(PTR), donePtr = m._malloc(PTR);
  m.setValue(outPtrPtr, 0, 'i32'); m.setValue(outLenPtr, 0, 'i32'); m.setValue(donePtr, 0, 'i32');
  const rv = fn(session, inPtr, msgIn ? msgIn.length : 0, outPtrPtr, outLenPtr, donePtr);
  if (rv !== WASM_MPC_SUCCESS) {
    throw new Error(`step failed rv=${rv}: ${a.lastError()}`);
  }
  const out = takeBytes(m, outPtrPtr, outLenPtr);
  const outP = readI32(m, outPtrPtr);
  if (outP) m._free(outP);
  if (inPtr) m._free(inPtr);
  m._free(outPtrPtr); m._free(outLenPtr); m._free(donePtr);
  return out;
}

function publicKey(a, session, getKey) {
  const m = a.mod;
  const keyPtr = m._malloc(PTR); m.setValue(keyPtr, 0, 'i32');
  if (getKey(session, keyPtr) !== WASM_MPC_SUCCESS) throw new Error(`get_key: ${a.lastError()}`);
  const outPtrPtr = m._malloc(PTR), outLenPtr = m._malloc(PTR);
  m.setValue(outPtrPtr, 0, 'i32'); m.setValue(outLenPtr, 0, 'i32');
  if (a.pubKey(keyPtr, outPtrPtr, outLenPtr) !== WASM_MPC_SUCCESS) throw new Error(`pubkey: ${a.lastError()}`);
  const pk = takeBytes(m, outPtrPtr, outLenPtr);
  const p = readI32(m, outPtrPtr); if (p) m._free(p);
  m._free(outPtrPtr); m._free(outLenPtr); m._free(keyPtr);
  return pk;
}

function installSeed(a, byte) {
  const seed = Buffer.alloc(32, byte);
  const p = putBytes(a.mod, seed);
  const ok = a.rngInstall(p, 32);
  a.mod._free(p);
  if (ok !== 1) throw new Error(`cbmpc_test_rng_install returned ${ok}`);
}

(async () => {
  const createModule = require(path.resolve(modulePath));
  // ⛔ wasm_ecdsa2p.cpp still has 148 debug printfs. Under node they arrive on
  // process.stdout and corrupt the JSON transcript. Emscripten routes them
  // through Module.print, so redirect that to stderr rather than filtering --
  // 79 of the 148 carry no "[WASM DEBUG]" prefix, so a text filter would drop
  // some and silently produce a malformed transcript.
  const toStderr = { print: (t) => process.stderr.write(t + '\n'), printErr: (t) => process.stderr.write(t + '\n') };
  // Two instances: two linear memories, two independent RNG streams.
  const a1 = api(await createModule({ ...toStderr }));
  const a2 = api(await createModule({ ...toStderr }));
  process.stderr.write(`seeds p1=0x${b1.toString(16).padStart(2, '0')} p2=0x${b2.toString(16).padStart(2, '0')}\n`);

  a1.init(); a2.init();
  // Pass "none" as the p1 seed to run on REAL randomness with the shim left
  // uninstalled. This is the control that distinguishes "the artifact is
  // broken" from "the shim breaks the artifact": the shim is inert until
  // installed, by design, so skipping the install exercises the production
  // code path. Transcripts from a no-shim run are NOT comparable across runs.
  const useShim = (process.argv[3] || '') !== 'none';
  if (useShim) { installSeed(a1, b1); installSeed(a2, b2); }
  else process.stderr.write('shim NOT installed: running on real randomness\n');
  const curve = a1.curveCode();

  const transcript = [];
  const record = (from, to, bytes) => transcript.push({ from, to, bytes });

  let failure = null;
  let q1 = Buffer.alloc(0), q2 = Buffer.alloc(0);
  try {
    const s1 = a1.mod._malloc(PTR); a1.mod.setValue(s1, 0, 'i32');
    if (a1.p1Start(curve, s1) !== WASM_MPC_SUCCESS) throw new Error(`p1_start: ${a1.lastError()}`);

    const msg1 = step(a1, a1.p1Process, s1, null);
    record(1, 2, msg1);

    const s2 = a2.mod._malloc(PTR); a2.mod.setValue(s2, 0, 'i32');
    const m1p = putBytes(a2.mod, msg1);
    if (a2.p2Start(curve, m1p, msg1.length, s2) !== WASM_MPC_SUCCESS) throw new Error(`p2_start: ${a2.lastError()}`);
    a2.mod._free(m1p);

    const msg2 = step(a2, a2.p2Process, s2, null);
    record(2, 1, msg2);

    const msg3 = step(a1, a1.p1Process, s1, msg2);
    record(1, 2, msg3);

    step(a2, a2.p2Process, s2, msg3);   // P2 verifies and completes
    step(a1, a1.p1Process, s1, null);   // P1 completes

    q1 = publicKey(a1, s1, a1.p1GetKey);
    q2 = publicKey(a2, s2, a2.p2GetKey);
  } catch (e) {
    // Emit the partial transcript anyway: it is exactly what the bisector needs
    // in order to name the round where the run stopped.
    failure = e.message;
    process.stderr.write(`keygen failed after ${transcript.length} message(s): ${e.message}\n`);
  }

  const msgs = transcript.map((m, i) => {
    const hex = m.bytes.toString('hex');
    const sha = crypto.createHash('sha256').update(m.bytes).digest('hex');
    return `    {"index": ${i}, "from": ${m.from}, "to": ${m.to}, "len": ${m.bytes.length}, "sha256": "${sha}", "hex": "${hex}"}`;
  });
  const agree = q1.length > 0 && q1.equals(q2);
  process.stdout.write(
    '{\n' +
    '  "protocol": "ecdsa2pc.dkg",\n' +
    `  "seeds": {"p1": "${b1.toString(16).padStart(2, '0')}", "p2": "${b2.toString(16).padStart(2, '0')}"},\n` +
    '  "messages": [\n' + msgs.join(',\n') + '\n  ],\n' +
    `  "result": {"q_p1": "${q1.toString('hex')}", "q_p2": "${q2.toString('hex')}", "q_agree": ${agree}}\n` +
    '}\n'
  );
  process.exit(failure || !agree ? 1 : 0);
})();
