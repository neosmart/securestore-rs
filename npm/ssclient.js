#!/usr/bin/env -S node --experimental-wasi-unstable-preview1

import { join, dirname } from "node:path";
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// const WASM_FILE = "../target/wasm32-wasip1/debug/ssclient.wasm";
const WASM_FILE = join(__dirname, "../target/wasm32-wasip1/release/ssclient.wasm");

// Silence node warnings about WASI being in preview, as we test functionality ourselves
if (process && process.emitWarning) {
    const emitWarning = process.emitWarning;
    process.emitWarning = (warning, type) => {
        if (type === "ExperimentalWarning") {
            if (warning.toString().includes("WASI")) {
                return false;
            }
        }
        // @ts-ignore
        return emitWarning(arguments);
    };
}

// Import WASI dynamically to ensure our ExperimentalWarning intercept takes place first
const { WASI } = await import("node:wasi");
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

/**
 * @param {string} payload - Path to the WASM binary
 */
async function runWasm(payload) {
    // Extract node-specific values
    const args = process.argv.slice(2);
    const cwd = process.cwd();
    const env = process.env;

    const wasi = new WASI({
        version: "preview1",
        args: ["ssclient", ...args],
        env: env,
        // Map paths we need into the sandbox
        preopens: {
            [cwd]: cwd,
            ".": ".",
        },
    });

    // wasi.getImportObject() isn't yet supported by bun
    // Reported upstream at https://github.com/oven-sh/bun/issues/28534
    /** @type {any} */
    const wasiImportObject = wasi.getImportObject ? wasi.getImportObject()
        : { wasi_snapshot_preview1: wasi.wasiImport };

    try {
        const wasmPath = resolve(payload);
        const wasmBuffer = await readFile(wasmPath);
        const wasmModule = await WebAssembly.compile(wasmBuffer);
        const instance = await WebAssembly.instantiate(
            wasmModule,
            wasiImportObject,
        );

        wasi.start(instance);
    } catch (err) {
        const msg = err instanceof Error ? err.message : err?.toString();
        console.error(`Error executing ${payload}: `, msg);
        process.exit(1);
    }
}

await runWasm(WASM_FILE);
