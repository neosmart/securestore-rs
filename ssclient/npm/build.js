#!/usr/bin/env node

// @ts-check

import path from 'node:path';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const cargoRoot = path.resolve(__dirname, '..', '..');
const srcWasm = path.resolve(cargoRoot, 'target/wasm32-wasip1/release/ssclient.wasm');
const dstDir = path.resolve(__dirname, 'bin');
const dstWasm = path.resolve(dstDir, 'ssclient.wasm');
const ssclient = path.resolve(__dirname, 'ssclient.js');

/**
 * Helper to exit with a non-zero status code
 * @param {string} message
 */
const die = (message) => {
    console.error(`[BUILD ERROR] ${message}`);
    process.exit(1);
};

console.log(`> cd ${cargoRoot}`);

/** @type {import('node:child_process').SpawnSyncOptions} */
const spawnOptions = {
    cwd: cargoRoot,
    stdio: 'inherit',
    env: {
        ...process.env,
        RUSTFLAGS: '', // Explicitly clear RUSTFLAGS
    },
    shell: false
};

const cargoArgs = [
    'build',
    '--no-default-features',
    '--features', 'rustls',
    '--target', 'wasm32-wasip1',
    '--release'
];

console.log(`> cargo ${cargoArgs.join(' ')}`);

const result = spawnSync('cargo', cargoArgs, spawnOptions);

if (result.error) {
    die(`Failed to execute cargo: ${result.error.message}`);
}

if (result.status !== 0) {
    die(`Cargo build failed with exit code ${result.status}`);
}

try {
    if (!fs.existsSync(dstDir)) {
        console.log(`Creating directory: ${dstDir}`);
        fs.mkdirSync(dstDir, { recursive: true });
    }

    console.log(`Copying build artifact:\n From: ${srcWasm}\n To:   ${dstWasm}`);

    if (!fs.existsSync(srcWasm)) {
        die(`Source file not found at ${srcWasm}`);
    }

    fs.copyFileSync(srcWasm, dstWasm);
    console.log('Build and copy successful.');
} catch (err) {
    /** @type {Error} */
    // @ts-ignore
    const error = err;
    die(`File operation failed: ${error.message}`);
}

// Ensure ssclient.js runs ok
const wasmResult = spawnSync('node', [ssclient, "--version"]);
if (wasmResult.error) {
    die(`Failed to execute ssclient.wasm (via ssclient.js): ${wasmResult.error.message}`);
} else if (wasmResult.status !== 0) {
    die(`ssclient.wasm failed with exit code ${wasmResult.status}`);
}
