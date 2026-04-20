#!/usr/bin/env node

import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from 'node:url';
import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const WASM_FILE = join(__dirname, "bin/ssclient.wasm");

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
// Also figure out if we need to relaunch with a flag for compatibility with older node versions.

/** @type {typeof import("node:wasi").WASI} */
let WASI;
try {
    const wasiModule = await import("node:wasi");
    WASI = wasiModule.WASI;
} catch (e) {
    // If we can't import it, we need the --experimental-wasi-unstable-preview1 flag.
    const scriptPath = fileURLToPath(import.meta.url);

    if (process.argv.find(arg => arg === "--experimental-wasi-unstable-preview1")) {
        // Already tried launching with this flag and it didn't work
        console.error(`Unable to load WASI module: ${e}`);
        process.exit(1);
    }

    // Re-spawn the current process with the flag enabled
    const child = spawn(
        process.execPath,
        ["--experimental-wasi-unstable-preview1", scriptPath, ...process.argv.slice(2)],
        { stdio: "inherit" }
    );

    child.on("exit", (code) => process.exit(code ?? 0));
    // Block indefinitely until child has exited
    await new Promise(() => { });
}

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
