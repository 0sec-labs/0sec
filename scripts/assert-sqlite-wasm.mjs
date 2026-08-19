#!/usr/bin/env node
//
// assert-sqlite-wasm.mjs — fail-fast assertion that the sqlite WASM engine the
// node runtime depends on actually instantiates (#610).
//
// Background: a 2-byte-truncated `node-sqlite3-wasm.wasm` shipped from a
// poisoned npm cache on a CI runner. Its first use threw a
// `WebAssembly.Module()` CompileError ("section ... extends past end of
// module"), but the CLI surfaced it only as a vague "DB layer broken", so the
// real cause took hours to find. This probes the lowest level directly and
// lets the REAL error propagate (no try/catch swallowing): resolve the
// installed `node-sqlite3-wasm`, open an in-memory DB, run a trivial query.
//
// Usage: node assert-sqlite-wasm.mjs <install-root-dir>
//   where <install-root-dir> contains node_modules/node-sqlite3-wasm
//   (e.g. the throwaway dir the smoke installs the packed tarball into).
import { createRequire } from "node:module";
import { join } from "node:path";

const installRoot = process.argv[2];
if (!installRoot) {
  console.error("usage: assert-sqlite-wasm.mjs <install-root-dir>");
  process.exit(2);
}

// Resolve node-sqlite3-wasm from the install root (it's an externalized runtime
// dep of 0sec-cli, so it lives under <installRoot>/node_modules).
const require = createRequire(join(installRoot, "package.json"));
const { Database } = require("node-sqlite3-wasm");

// Instantiating the WASM module happens here; a corrupt .wasm throws now, raw.
const db = new Database(":memory:");
const rows = db.all("select 42 as answer");
db.close();

if (!rows || rows.length !== 1 || rows[0].answer !== 42) {
  console.error(
    "sqlite wasm instantiated but returned an unexpected result:",
    JSON.stringify(rows),
  );
  process.exit(1);
}
console.log("sqlite wasm OK — instantiated and 'select 42' returned", rows[0].answer);
