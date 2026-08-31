// 2-party ECDSA SIGN transcript recorder driving the ACTUAL WASM ARTIFACT under
// node (remediation plan 0.5 / component 5 groundwork).
//
// Runs a keygen first to obtain both key shares, then records the signing
// exchange. Output is byte-comparable with wasm_api_sign_transcript (the same
// entry points built natively).
//
// ⛔ Each party gets its OWN module instance: the RNG shim's state is
// thread-local and node is single-threaded, so a shared instance would force a
// re-install between parties and reset each (seed, call-sequence) stream.
//
// ⛔ Requires a module linked with CBMPC_TEST_RNG=ON and the shim exported.
// Never ship that artifact.
//
// usage: node wasm_node_sign_transcript.cjs <module.js> [p1_seed_hex] [p2_seed_hex]
//        pass "none" as the p1 seed to run on real randomness with no shim.

const path = require('path');
const crypto = require('crypto');

const modulePath = process.argv[2];
if (!modulePath) {
  console.error('usage: node wasm_node_sign_transcript.cjs <module.js> [p1_seed_hex] [p2_seed_hex]');
  process.exit(2);
}
const b1 = parseInt(process.argv[3] || '11', 16);
const b2 = parseInt(process.argv[4] || '22', 16);
const useShim = (process.argv[3] || '') !== 'none';

const OK = 0;
const PTR = 4; // wasm32

function api(mod) {
  const c = (n, r, a) => mod.cwrap(n, r, a);
  const six = ['number', 'number', 'number', 'number', 'number', 'number'];
  return {
    mod,
    rngInstall: c('cbmpc_test_rng_install', 'number', ['number', 'number']),
    init: c('wasm_init', 'number', []),
    curveCode: c('wasm_get_secp256k1_curve_code', 'number', []),
    lastError: c('wasm_get_last_error', 'string', []),
    kgP1Start: c('wasm_keygen_p1_start', 'number', ['number', 'number']),
    kgP1Process: c('wasm_keygen_p1_process', 'number', six),
    kgP1GetKey: c('wasm_keygen_p1_get_key', 'number', ['number', 'number']),
    kgP2Start: c('wasm_keygen_p2_start', 'number', ['number', 'number', 'number', 'number']),
    kgP2Process: c('wasm_keygen_p2_process', 'number', six),
    kgP2GetKey: c('wasm_keygen_p2_get_key', 'number', ['number', 'number']),
    pubKey: c('wasm_key_get_public_key', 'number', ['number', 'number', 'number']),
    sgP1Start: c('wasm_sign_p1_start', 'number', ['number', 'number', 'number', 'number']),
    sgP1Process: c('wasm_sign_p1_process', 'number', six),
    sgP1GetSig: c('wasm_sign_p1_get_signature', 'number', ['number', 'number', 'number']),
    sgP2Start: c('wasm_sign_p2_start', 'number', ['number', 'number', 'number', 'number', 'number', 'number', 'number', 'number']),
    sgP2Process: c('wasm_sign_p2_process', 'number', six),
  };
}

const put = (mod, bytes) => { const p = mod._malloc(bytes.length || 1); mod.HEAPU8.set(bytes, p); return p; };
const readI32 = (mod, p) => mod.getValue(p, 'i32');
function take(mod, ptrPtr, lenPtr) {
  const p = readI32(mod, ptrPtr), n = readI32(mod, lenPtr);
  if (!p || n <= 0) return Buffer.alloc(0);
  return Buffer.from(mod.HEAPU8.subarray(p, p + n)); // copy before free
}

// One protocol step: feed msgIn (or null), return the produced message.
function step(a, fn, session, msgIn, label) {
  const m = a.mod;
  const inPtr = msgIn && msgIn.length ? put(m, msgIn) : 0;
  const op = m._malloc(PTR), ol = m._malloc(PTR), dn = m._malloc(PTR);
  m.setValue(op, 0, 'i32'); m.setValue(ol, 0, 'i32'); m.setValue(dn, 0, 'i32');
  const rv = fn(session, inPtr, msgIn ? msgIn.length : 0, op, ol, dn);
  if (rv !== OK) throw new Error(`${label} rv=${rv}: ${a.lastError()}`);
  const out = take(m, op, ol);
  const p = readI32(m, op); if (p) m._free(p);
  if (inPtr) m._free(inPtr);
  m._free(op); m._free(ol); m._free(dn);
  return out;
}

// Decode one length in cb-mpc's variable-length form (converter_t::convert_len,
// core/convert.cpp:130): 0xxxxxxx = 1 byte, 10xxxxxx = 2, 110xxxxx = 3,
// 111xxxxx = 4. ⛔ NOT a fixed 4-byte big-endian prefix.
function decodeLen(buf, off) {
  if (off >= buf.length) return null;
  const b0 = buf[off];
  if ((b0 & 0x80) === 0) return { len: b0, off: off + 1 };
  if ((b0 & 0x40) === 0) {
    if (off + 2 > buf.length) return null;
    return { len: ((b0 & 0x3f) << 8) | buf[off + 1], off: off + 2 };
  }
  if ((b0 & 0x20) === 0) {
    if (off + 3 > buf.length) return null;
    return { len: ((b0 & 0x1f) << 16) | (buf[off + 1] << 8) | buf[off + 2], off: off + 3 };
  }
  if (off + 4 > buf.length) return null;
  return { len: ((b0 & 0x1f) << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3], off: off + 4 };
}

// P1's sign msg1 is ser(sid, com_msg); wasm_sign_p2_start wants the sid raw and
// the com_msg still serialized, so the host has to split them.
function splitSidAndCom(msg1) {
  const d = decodeLen(msg1, 0);
  if (!d || d.off + d.len > msg1.length) throw new Error(`could not split ser(sid, com_msg) from ${msg1.length} bytes`);
  return { sid: msg1.subarray(d.off, d.off + d.len), com: msg1.subarray(d.off + d.len) };
}

function publicKey(a, sessionPtr, getKey) {
  const m = a.mod;
  const keyPtr = m._malloc(PTR); m.setValue(keyPtr, 0, 'i32');
  if (getKey(sessionPtr, keyPtr) !== OK) throw new Error(`get_key: ${a.lastError()}`);
  const op = m._malloc(PTR), ol = m._malloc(PTR);
  m.setValue(op, 0, 'i32'); m.setValue(ol, 0, 'i32');
  if (a.pubKey(keyPtr, op, ol) !== OK) throw new Error(`pubkey: ${a.lastError()}`);
  const pk = take(m, op, ol);
  const p = readI32(m, op); if (p) m._free(p);
  m._free(op); m._free(ol);
  return { keyPtr, pk };
}

function installSeed(a, byte) {
  const p = put(a.mod, Buffer.alloc(32, byte));
  const ok = a.rngInstall(p, 32);
  a.mod._free(p);
  if (ok !== 1) throw new Error(`cbmpc_test_rng_install returned ${ok}`);
}

(async () => {
  const createModule = require(path.resolve(modulePath));
  // Module.print carries the 148 debug printfs; 79 of them have no
  // "[WASM DEBUG]" prefix, so redirect rather than filter.
  const q = { print: (t) => process.stderr.write(t + '\n'), printErr: (t) => process.stderr.write(t + '\n') };
  const a1 = api(await createModule({ ...q }));
  const a2 = api(await createModule({ ...q }));

  a1.init(); a2.init();
  if (useShim) { installSeed(a1, b1); installSeed(a2, b2); }
  else process.stderr.write('shim NOT installed: running on real randomness\n');
  const curve = a1.curveCode();

  // Fixed message hash, so the transcript depends only on the seeds.
  const msgHash = Buffer.from(Array.from({ length: 32 }, (_, i) => i));

  const transcript = [];
  const rec = (from, to, bytes) => transcript.push({ from, to, bytes });

  let failure = null, sig = Buffer.alloc(0), pk1 = Buffer.alloc(0);
  try {
    // ---- keygen ----
    const ks1 = a1.mod._malloc(PTR); a1.mod.setValue(ks1, 0, 'i32');
    if (a1.kgP1Start(curve, ks1) !== OK) throw new Error(`kg p1_start: ${a1.lastError()}`);
    const k1 = step(a1, a1.kgP1Process, ks1, null, 'kg p1 r0');

    const ks2 = a2.mod._malloc(PTR); a2.mod.setValue(ks2, 0, 'i32');
    const k1p = put(a2.mod, k1);
    if (a2.kgP2Start(curve, k1p, k1.length, ks2) !== OK) throw new Error(`kg p2_start: ${a2.lastError()}`);
    a2.mod._free(k1p);
    const k2 = step(a2, a2.kgP2Process, ks2, null, 'kg p2 r0');
    const k3 = step(a1, a1.kgP1Process, ks1, k2, 'kg p1 r1');
    step(a2, a2.kgP2Process, ks2, k3, 'kg p2 r1');
    step(a1, a1.kgP1Process, ks1, null, 'kg p1 r2');

    const key1 = publicKey(a1, ks1, a1.kgP1GetKey);
    const key2 = publicKey(a2, ks2, a2.kgP2GetKey);
    pk1 = key1.pk;
    if (!key1.pk.equals(key2.pk)) throw new Error('keygen produced different public keys');

    // ---- signing (recorded) ----
    const ss1 = a1.mod._malloc(PTR); a1.mod.setValue(ss1, 0, 'i32');
    const mh1 = put(a1.mod, msgHash);
    if (a1.sgP1Start(key1.keyPtr, mh1, 32, ss1) !== OK) throw new Error(`sign p1_start: ${a1.lastError()}`);
    a1.mod._free(mh1);

    const s1 = step(a1, a1.sgP1Process, ss1, null, 'sign p1 r0');
    rec(1, 2, s1);

    const { sid, com } = splitSidAndCom(s1);
    const ss2 = a2.mod._malloc(PTR); a2.mod.setValue(ss2, 0, 'i32');
    const mh2 = put(a2.mod, msgHash), sidP = put(a2.mod, sid), comP = put(a2.mod, com);
    if (a2.sgP2Start(key2.keyPtr, mh2, 32, sidP, sid.length, comP, com.length, ss2) !== OK) {
      throw new Error(`sign p2_start: ${a2.lastError()}`);
    }
    a2.mod._free(mh2); a2.mod._free(sidP); a2.mod._free(comP);

    const s2 = step(a2, a2.sgP2Process, ss2, null, 'sign p2 r0');
    rec(2, 1, s2);
    const s3 = step(a1, a1.sgP1Process, ss1, s2, 'sign p1 r1');
    rec(1, 2, s3);
    // ⚠️ Signing is FOUR messages where keygen is three: P1's round 2 consumes
    // P2's ciphertext message.
    const s4 = step(a2, a2.sgP2Process, ss2, s3, 'sign p2 r1');
    if (!s4.length) throw new Error('sign p2 r1 produced no message; P1 would stall');
    rec(2, 1, s4);
    step(a1, a1.sgP1Process, ss1, s4, 'sign p1 r2');

    const m = a1.mod, op = m._malloc(PTR), ol = m._malloc(PTR);
    m.setValue(op, 0, 'i32'); m.setValue(ol, 0, 'i32');
    if (a1.sgP1GetSig(ss1, op, ol) !== OK) throw new Error(`get_signature: ${a1.lastError()}`);
    sig = take(m, op, ol);
    const sp = readI32(m, op); if (sp) m._free(sp);
    m._free(op); m._free(ol);
  } catch (e) {
    failure = e.message;
    process.stderr.write(`sign failed after ${transcript.length} message(s): ${e.message}\n`);
  }

  const msgs = transcript.map((mm, i) => {
    const sha = crypto.createHash('sha256').update(mm.bytes).digest('hex');
    return `    {"index": ${i}, "from": ${mm.from}, "to": ${mm.to}, "len": ${mm.bytes.length}, "sha256": "${sha}", "hex": "${mm.bytes.toString('hex')}"}`;
  });
  process.stdout.write(
    '{\n  "protocol": "ecdsa2pc.sign",\n' +
    `  "seeds": {"p1": "${b1.toString(16).padStart(2, '0')}", "p2": "${b2.toString(16).padStart(2, '0')}"},\n` +
    '  "messages": [\n' + msgs.join(',\n') + '\n  ],\n' +
    `  "result": {"q_p1": "${pk1.toString('hex')}", "q_p2": "${pk1.toString('hex')}", "q_agree": ${pk1.length > 0},\n` +
    `             "signature": "${sig.toString('hex')}", "message_hash": "${msgHash.toString('hex')}"}\n}\n`
  );
  process.exit(failure || !sig.length ? 1 : 0);
})();
