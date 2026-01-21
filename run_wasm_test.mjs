/**
 * Run the deterministic proof test in WASM
 *
 * This script loads the WASM module and runs the deterministic test,
 * then compares the output with native test results.
 *
 * Usage: node run_wasm_test.mjs
 */

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync } from 'fs';
import crypto from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load the WASM module
const wasmPath = join(__dirname, 'dist-wasm', 'cbmpc.js');
const wasmBinaryPath = join(__dirname, 'dist-wasm', 'cbmpc.wasm');

async function main() {
    console.log('=== WASM Deterministic Proof Test ===\n');
    console.log('Loading WASM module...');

    // Read the WASM binary directly
    const wasmBinary = readFileSync(wasmBinaryPath);

    // Dynamic import of the ES module
    const { default: createCBMPCModule } = await import(wasmPath);

    // Create the module instance with the binary provided
    const Module = await createCBMPCModule({
        print: (text) => console.log(text),
        printErr: (text) => console.error(text),
        wasmBinary: wasmBinary.buffer,
    });

    console.log('WASM module loaded.\n');

    // Debug: show what's available
    console.log('Available methods:', Object.keys(Module).filter(k => typeof Module[k] === 'function').slice(0, 30));
    console.log('Has HEAPU8:', !!Module.HEAPU8);
    console.log('Has HEAP8:', !!Module.HEAP8);

    // Use setValue for writing bytes
    const setValue = Module.setValue || Module._setValue;
    const getValue = Module.getValue || Module._getValue;

    // Seed the random number generator
    console.log('\nSeeding RNG...');
    const entropy = new Uint8Array(64);
    crypto.getRandomValues(entropy);
    const entropyPtr = Module._malloc(entropy.length);

    // Write entropy bytes manually
    for (let i = 0; i < entropy.length; i++) {
        setValue(entropyPtr + i, entropy[i], 'i8');
    }

    const seedResult = Module._wasm_seed_random(entropyPtr, entropy.length);
    Module._free(entropyPtr);

    if (seedResult !== 0) {
        console.error('Failed to seed RNG');
        process.exit(1);
    }
    console.log('RNG seeded.\n');

    // Run the deterministic test
    console.log('Running deterministic proof test...\n');
    console.log('--- WASM Output ---');
    const result = Module._wasm_test_deterministic_proof();
    console.log('--- End WASM Output ---\n');

    if (result === 0) {
        console.log('TEST PASSED: WASM proof generation and verification works!');
    } else {
        console.log('TEST FAILED: See output above for details');
        process.exit(1);
    }

    // Print expected values from native test for comparison
    console.log('\n=== Expected Values from Native Test ===');
    console.log('G: 02ca0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
    console.log('Q: 02ca034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff');
    console.log('e[0-2]: 14 4 16');
    console.log('A[0]: 02ca02e74bfedce2d3394538d13ee424feff1f73903fd2f66384296cfe553fae40f432');
}

main().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
