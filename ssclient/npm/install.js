#!/usr/bin/env node

// @ts-check
"use strict";

import { mkdir, rm, rename, unlink, symlink, copyFile, chmod, readdir, readFile, writeFile } from "node:fs/promises";
import { createWriteStream, existsSync } from "node:fs";
import { finished } from 'node:stream/promises';
import { join, relative, basename, dirname } from "node:path";
import { execSync } from "node:child_process";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from 'node:url';
import pkg from "./package.json" with { type: "json" };

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * @typedef {Object} BuildEntry
 * @property {string | string[]} url - One or more URLs to try
 * @property {string} [bin_path] - Override default bin_path
 */

/**
 * @typedef {Object} Manifest
 * @property {string} bin_path - Default path to entrypoint within archives
 * @property {Record<string, string | string[] | BuildEntry>} precompiled - Mapping of os-arch to builds
 */

const VERSION = pkg.version.replace(/\+.*/, "");
const MANIFEST_URLS = [
  `${__dirname}/manifest.json`,
  `https://raw.githubusercontent.com/neosmart/securestore-rs/refs/heads/master/ssclient/npm/manifests/v${VERSION}.json`,
  `https://neosmart.net/SecureStore/ssclient/npm/manifests/v${VERSION}.json`,
];
const BIN_NAME = "ssclient";
const PKG_ROOT = __dirname;
const FALLBACK_JS = join(PKG_ROOT, "ssclient.js");
const BASE_BIN_DIR = join(PKG_ROOT, "bin");
const VERSIONED_DIR = join(BASE_BIN_DIR, `v${VERSION}`);
const ENTRY_POINT = join(__dirname, pkg.bin[BIN_NAME]);

/** @returns {string} */
function getPlatformTuple() {
  return `${process.platform}-${process.arch}`;
}

/** @param {string} urlStr @returns "string" */
function extractUrlFileName(urlStr) {
  if (urlStr.startsWith('http')) {
    const urlPath = new URL(urlStr).pathname;
    return /[^/]+$/.exec(urlPath)?.[0] ?? urlPath;
  }
  const fname = /[^/\\]+$/.exec(urlStr)?.[0];
  if (fname) {
    return fname;
  }
  throw new Error(`Could not extract file name from "${urlStr}"`);
}

/** @param {string} urlStr @returns {"zip" | "tar"} */
function getArchiveType(urlStr) {
  const fname = extractUrlFileName(urlStr);
  if (fname.endsWith(".zip")) return "zip";
  if (/\.tar(\.[^.]+)?$|\.tgz$/.test(fname)) return "tar";
  throw new Error(`Unsupported archive type for ${fname}`);
}

/**
 * Executes a callback when the variable goes out of scope.
 * @param {() => void} callback
 * @returns {Disposable}
 */
export const defer = (callback) => ({
  [Symbol.dispose]: callback
});

/**
 * Tries to download from an array of URLs.
 * @param {string[]} urls
 * @param {string} dest
 */
async function downloadWithRetry(urls, dest) {
  const urlArray = Array.isArray(urls) ? urls : [urls];
  let lastErr;

  for (const url of urlArray) {
    try {
      console.log(`Downloading: ${url}`);
      if (/^https?:/.test(url)) {
        return await download(url, dest);
      } else if (existsSync(url)) {
        return await copyFile(url, dest);
      }
      throw new Error(`Path not found: ${url}`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : err?.toString();
      console.warn(`Failed to download from ${url}: ${msg}`);
      lastErr = err;
    }
  }
  throw lastErr;
}

/**
 * @param {string | URL} url
 * @param {import("node:fs").PathLike} dest
 */
async function download(url, dest) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  if (!response.body) {
      throw new Error("Invalid response body");
  }

  const fileStream = createWriteStream(dest);
  const reader = response.body.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    fileStream.write(value);
  }
  fileStream.end();
  return finished(fileStream);
}

/**
 * Atomic extraction into the versioned folder.
 * @param {string} archivePath
 * @param {string} binPath - Path to the binary within the archive
 * @returns {Promise<{dir: string, bin: string}>} - Path to the extracted release directory and binary
 */
async function extractRelease(archivePath, binPath) {
  const archiveType = getArchiveType(archivePath);
  console.log(`Extracting ${archiveType}...`);

  const stagingDir = join(BASE_BIN_DIR, `.staging-${randomBytes(4).toString("hex")}`);
  await mkdir(stagingDir, { recursive: true });

  if (archiveType === "tar") {
    try {
      execSync(`tar -xf "${archivePath}" -C "${stagingDir}"`);
    }
    catch (err) {
      if (process.platform === "win32") {
        throw new Error(`Unsupported archive type for platform ${process.platform}`);
      }
      throw err;
    }
  } else {
    if (process.platform === "win32") {
      execSync(`powershell -command "Expand-Archive -Path '${archivePath}' -DestinationPath '${stagingDir}'"`);
    } else {
      execSync(`unzip "${archivePath}" -d "${stagingDir}"`);
    }
  }

  // Add Windows .exe suffix if not accounted for in manifest
  let sourcePath = join(stagingDir, binPath);
  if (process.platform === "win32" && !sourcePath.endsWith(".exe")) {
    if (!existsSync(sourcePath) && existsSync(sourcePath + ".exe")) {
      sourcePath += ".exe";
    }
  }

  // Atomically move staging to versioned dir
  if (existsSync(VERSIONED_DIR)) {
    await rm(VERSIONED_DIR, { recursive: true });
  }
  await rename(stagingDir, VERSIONED_DIR);

  let bin = join(VERSIONED_DIR, binPath);
  if (process.platform === "win32" && !sourcePath.endsWith(".exe")) {
    if (!existsSync(bin) && existsSync(bin + ".exe")) {
      bin += ".exe";
    }
  }

  return {
    dir: VERSIONED_DIR,
    bin,
  }
}

/**
 * Creates a symlink or copies the file, dependent on platform.
 * @param {string} target
 * @param {string} linkPath
 */
async function linkBinary(target, linkPath) {
  try {
    // Don't check if it exists first because we need to also remove broken symlinks
    await unlink(linkPath);
  } catch (err) {
    if (existsSync(linkPath)) {
      console.error(`Failed to remove existing binary: ${err}`);
      throw err;
    }
  }

  const rel = relative(dirname(linkPath), target);
  if (process.platform === "win32") {
    const runner = `@ECHO OFF\nSETLOCAL\n"%~dp0${rel}" %*`;
    await writeFile(linkPath, runner, "utf8");
  } else {
    // *nix: Always create relative symlink
    await symlink(rel, linkPath);
    await chmod(target, 0o755);
  }
}

async function removeOldVersions() {
  const items = await readdir(BASE_BIN_DIR);
  const currentName = basename(VERSIONED_DIR);
  for (const item of items) {
    if (item.startsWith(`v`) && item !== currentName) {
      await rm(join(BASE_BIN_DIR, item), { recursive: true, force: true }).catch(() => {});
    }
  }
}

/**
* @overload
* @param {string | URL} pathOrUrl
* @param {"text"} result
* @returns {Promise<string>}
*/
/**
* @overload
* @param {string | URL} pathOrUrl
* @param {"json"} result
* @returns {Promise<any>}
*/
/**
* @param {string | URL} pathOrUrl
* @param {"text" | "json"} result
* @returns {Promise<string | any>}
*/
async function resolve(pathOrUrl, result) {
  if (/^https?:/.test(pathOrUrl.toString())) {
    const response = await fetch(pathOrUrl);
    if (!response.ok) {
      throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
    }
    return result === "text" ? await response.text() : await response.json();
  } else if (existsSync(pathOrUrl)) {
    const text = await readFile(pathOrUrl, { encoding: "utf8" });
    return result === "text" ? text : JSON.parse(text);
  } else {
    throw new Error(`Unable to resolve path/url ${pathOrUrl}`);
  }
}

async function main() {
  let downgradeError = false;
  try {
    await mkdir(BASE_BIN_DIR, { recursive: true });

    console.log("Fetching manifest...");

    /** @type {Manifest} */
    const manifest = await (async () => {
      for (const url of MANIFEST_URLS) {
        try {
          const manifest = await resolve(url, "json");
          return manifest;
        } catch {
          continue;
        }
      }
      throw new Error("Unable to load application manifest");
    })();
    const tuple = getPlatformTuple();
    const entry = manifest.precompiled[tuple];

    if (!entry) {
      downgradeError = true;
      throw new Error(`Precompiled binaries for ${tuple} not found`);
    }

    // Normalize manifest entry:
    // We allow tuples to point to either a "url like" (url or array of urls)
    // or an object containing a bin_path override + a "url like".
    const urls = (typeof entry === "string" ? [entry] : Array.isArray(entry) ? entry : (Array.isArray(entry.url) ? entry.url : [entry.url]))
      .filter(url => !!url);
    const binPathInside = (typeof entry === "object" && !Array.isArray(entry) && entry.bin_path) || manifest.bin_path;

    if (!urls[0]) {
        throw new Error(`Missing a url for target ${tuple}`);
    }
    const archivePath = join(tmpdir(), extractUrlFileName(urls[0]));
    using _ = defer(async () => {
      if (existsSync(archivePath)) {
        await rm(archivePath);
      }
    });
    await downloadWithRetry(urls, archivePath);

    const { bin} = await extractRelease(archivePath, binPathInside);

    await linkBinary(bin, ENTRY_POINT);
    await removeOldVersions();

    console.log(`Success: Installed precompiled native ${tuple} ${BIN_NAME}`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : err?.toString();
    if (downgradeError) {
      console.info(msg);
    } else {
      console.warn(`Binary installation failed: ${msg}.`);
    }

    console.info(`Falling back to wasm ${BIN_NAME}...`);

    if (existsSync(ENTRY_POINT)) {
      await unlink(ENTRY_POINT);
    }
    if (process.platform !== "win32") {
      await linkBinary(FALLBACK_JS, ENTRY_POINT);
    } else {
      const rel = relative(dirname(ENTRY_POINT), FALLBACK_JS);
      console.debug({
        rel,
          ENTRY_POINT,
          FALLBACK_JS,
      });
      const runner = `@ECHO OFF\nSETLOCAL\nnode --experimental-wasi-unstable-preview1 "%~dp0${rel}" %*`;
      await writeFile(ENTRY_POINT, runner, "utf8");
    }
  }
}

main();
