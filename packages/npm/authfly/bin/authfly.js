#!/usr/bin/env node
// npx authfly: run the Go binary from the platform package (@authfly/cli-<os>-<arch>, an optionalDependency) after
// verifying its sha256 against checksums.json shipped in this package. No postinstall script, no download at run time.
"use strict";
const { createHash } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { join, dirname } = require("node:path");
const { spawnSync } = require("node:child_process");

const plat = `${process.platform}-${process.arch}`;
const pkg = `@authfly/cli-${plat}`;
const exe = process.platform === "win32" ? "authfly.exe" : "authfly";
let bin = process.env.AUTHFLY_BINARY; // for development: a locally built binary (still checksum-verified unless AUTHFLY_SKIP_VERIFY=1)
if (!bin) {
  try {
    bin = join(dirname(require.resolve(`${pkg}/package.json`)), "bin", exe);
  } catch {
    console.error(`authfly: no binary for ${plat}. Supported: linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64.\n` +
      `If you installed with --no-optional / --omit=optional, reinstall without it.`);
    process.exit(1);
  }
}
const sums = JSON.parse(readFileSync(join(__dirname, "..", "checksums.json"), "utf8"));
const got = createHash("sha256").update(readFileSync(bin)).digest("hex");
if (got !== sums[plat] && process.env.AUTHFLY_SKIP_VERIFY !== "1") {
  console.error(`authfly: checksum mismatch for ${bin}\n  expected ${sums[plat]}\n  got      ${got}\nRefusing to run it.`);
  process.exit(1);
}
const r = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (r.error) { console.error(`authfly: ${r.error.message}`); process.exit(1); }
process.exit(r.status ?? 1);
