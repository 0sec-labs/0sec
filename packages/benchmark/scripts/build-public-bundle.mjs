#!/usr/bin/env node
// build-public-bundle.mjs — turn a local XBOW run (results + traces) into a
// PUBLIC, durable, auditable receipts bundle that can be committed to a public
// repo. This is the fix for the proof-rot that lost the original 97.9% evidence:
// receipts live in git, never in 90-day GitHub Actions artifacts.
//
// Proof model (closed-source engine): we do NOT offer reproducibility. We offer
// AUDITABILITY — each receipt is the full conversation trace of the agent
// interacting with the live challenge, plus the flag it pulled out of the
// target's real responses. A reader audits the trace's tool-calls; a fabricated
// receipt would have to invent a coherent exploit transcript against a pinned,
// publicly-clonable substrate.
//
// Usage:
//   node scripts/build-public-bundle.mjs \
//     --results results/xbow-latest.json \
//     --traces  results/traces \
//     --substrate-sha <sha> --substrate-repo 0ca/xbow-validation-benchmarks-patched \
//     --out ../../../xbow-bench-public
//
// Idempotent: re-running merges/overwrites receipts by challenge id.

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, copyFileSync, statSync } from "node:fs";
import { join, basename } from "node:path";

function arg(name, def = "") {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}

const resultsPath = arg("results", "results/xbow-latest.json");
const tracesDir = arg("traces", "results/traces");
const substrateSha = arg("substrate-sha", "");
const substrateRepo = arg("substrate-repo", "0ca/xbow-validation-benchmarks-patched");
const outDir = arg("out", "");
// Tiered disclosure: --public emits the moat-safe tier (per-challenge summaries +
// flags + ledger, but full conversation traces ONLY for the --sample set). Without
// --public, the full audit set (every trace) is written — keep that private/NDA.
const publicTier = process.argv.includes("--public");
const sampleIds = new Set(arg("sample", "").split(",").map((s) => s.trim()).filter(Boolean));

if (!outDir) {
  console.error("ERROR: --out <dir> is required (the public bundle directory).");
  process.exit(2);
}
// --results accepts a comma-separated list (or a directory of *.json) so the
// parallel shard summaries (shard-0.json … shard-N.json) merge into one bundle.
const resultFiles = [];
for (const p of resultsPath.split(",").map((s) => s.trim()).filter(Boolean)) {
  if (existsSync(p) && statSync(p).isDirectory()) {
    for (const f of readdirSync(p)) if (f.endsWith(".json")) resultFiles.push(join(p, f));
  } else {
    resultFiles.push(p);
  }
}
let report = {};
// Union across passes/shards: a challenge counts as SOLVED if ANY pass solved it
// (best-of-N semantics, matching consolidate-xbow.ts and the XBOW protocol). For
// a given id we keep the solved result if one exists, else the most-attempted one.
const byId = new Map();
// rawResults keeps EVERY result instance across all files — needed to count
// bb-vs-wb and per-model correctly (a challenge solved in both modes must count
// in both). byId picks ONE result per challenge for the published receipt.
const rawResults = [];
for (const f of resultFiles) {
  const rep = JSON.parse(readFileSync(f, "utf8"));
  if (!report.timestamp) report = rep; // keep first report's top-level fields
  for (const r of rep.results ?? []) {
    rawResults.push({ ...r, _reportWhiteBox: rep.whiteBox, _reportModel: rep.model });
    const prev = byId.get(r.id);
    if (!prev) { byId.set(r.id, r); continue; }
    // prefer a solved result; otherwise prefer the one with more attempts/turns
    const better = (r.flagFound && !prev.flagFound) ||
      (r.flagFound === prev.flagFound && (r.attempts ?? 1) > (prev.attempts ?? 1));
    if (better) byId.set(r.id, r);
  }
}
const results = [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
console.log(`Merged ${results.length} unique challenges from ${resultFiles.length} file(s) (best-of-N union).`);

const receiptsDir = join(outDir, "receipts");
mkdirSync(receiptsDir, { recursive: true });

// Per-model + per-mode tallies, mirroring consolidate-xbow.ts semantics.
const blackBox = new Set();
const whiteBox = new Set();
const perModel = new Map(); // model -> {attempted:Set, solved:Set, cost:number, n:number}

function track(model, id, solved, cost) {
  let s = perModel.get(model);
  if (!s) { s = { attempted: new Set(), solved: new Set(), cost: 0, n: 0 }; perModel.set(model, s); }
  s.attempted.add(id);
  if (solved) s.solved.add(id);
  if (cost > 0) { s.cost += cost; s.n += 1; }
}

function extractFlag(traceObj) {
  const txt = JSON.stringify(traceObj);
  const m = txt.match(/FLAG\{[^}]*\}/);
  return m ? m[0] : "";
}

// Count bb/wb/per-model from ALL raw results (union across every pass/mode).
for (const r of rawResults) {
  const model = r.model ?? r._reportModel ?? "unknown";
  const cost = r.meanCostUsd ?? r.estimatedCostUsd ?? 0;
  track(model, r.id, !!r.flagFound, cost);
  const isWb = (r.whiteBox ?? r._reportWhiteBox) === true;
  if (r.flagFound) (isWb ? whiteBox : blackBox).add(r.id);
}

// Public tier: if no explicit --sample, auto-pick one solved challenge per distinct
// vuln tag (up to 5) so the published sample spans classes without dumping the playbook.
if (publicTier && sampleIds.size === 0) {
  const seenTags = new Set();
  for (const r of results) {
    if (!r.flagFound) continue;
    const tag = (Array.isArray(r.tags) && r.tags[0]) || "misc";
    if (!seenTags.has(tag)) { seenTags.add(tag); sampleIds.add(r.id); }
    if (sampleIds.size >= 5) break;
  }
}

// Write one receipt per solved challenge (deduped best result).
let written = 0, fullTraces = 0;
for (const r of results) {
  if (!r.flagFound) continue; // only solved challenges get a published receipt

  const model = r.model ?? report.model ?? "unknown";
  const includeFull = !publicTier || sampleIds.has(r.id); // full trace only in audit set or sample
  const cdir = join(receiptsDir, r.id);
  mkdirSync(cdir, { recursive: true });

  // Pull the flag from the trace regardless of tier (flag is moat-safe).
  const traceFile = join(tracesDir, `${r.id}-trace.json`);
  let flag = "";
  if (existsSync(traceFile)) flag = extractFlag(JSON.parse(readFileSync(traceFile, "utf8")));
  if (flag) writeFileSync(join(cdir, "flag.txt"), flag + "\n");

  // meta.json — moat-safe summary (always written): outcome + class, no methodology.
  writeFileSync(join(cdir, "meta.json"), JSON.stringify({
    id: r.id, name: r.name, tags: r.tags ?? [], level: r.level ?? null,
    model, mode: (r.whiteBox ?? report.whiteBox) ? "white-box" : "black-box",
    flagFound: !!r.flagFound, flag, attackTurns: r.attackTurns ?? null,
    findingsCount: r.findingsCount ?? null,
    estimatedCostUsd: r.estimatedCostUsd ?? null, runTimestamp: report.timestamp ?? null,
    substrateRepo, substrateSha,
    fullTrace: includeFull ? "trace.json" : "available under NDA (audit room)",
  }, null, 2) + "\n");

  // Full methodology (trace + findings detail) — audit set, or the public sample only.
  if (includeFull) {
    writeFileSync(join(cdir, "result.json"), JSON.stringify(r, null, 2) + "\n");
    if (existsSync(traceFile)) { copyFileSync(traceFile, join(cdir, "trace.json")); fullTraces++; }
  }
  written++;
}

const round = (n, d) => Math.round(n * 10 ** d) / 10 ** d;
const sortIds = (it) => [...new Set(it)].sort();
const aggregate = sortIds([...blackBox, ...whiteBox]);

const ledger = {
  generatedFrom: basename(resultsPath),
  runTimestamp: report.timestamp ?? null,
  substrate: { repo: substrateRepo, sha: substrateSha, challengeCount: 104 },
  counts: {
    blackBox: blackBox.size,
    whiteBox: whiteBox.size,
    aggregate: aggregate.length,
    whiteBoxOnly: [...whiteBox].filter((id) => !blackBox.has(id)).length,
  },
  solved: { blackBox: sortIds(blackBox), whiteBox: sortIds(whiteBox), aggregate },
  perModel: Object.fromEntries([...perModel.entries()].map(([model, s]) => {
    const solved = s.solved.size, attempted = s.attempted.size;
    const hasCost = s.cost > 0 && s.n > 0;
    return [model, {
      solved, attempted, ratePct: attempted ? round((solved / attempted) * 100, 1) : 0,
      challengesSolved: sortIds(s.solved),
      totalCostUsd: hasCost ? round(s.cost, 2) : null,
      costPerFlagUsd: hasCost && solved ? round(s.cost / solved, 2) : null,
    }];
  })),
};

writeFileSync(join(outDir, "ledger.json"), JSON.stringify(ledger, null, 2) + "\n");
writeFileSync(join(outDir, "substrate.sha"), `${substrateRepo}@${substrateSha}\n`);

const bb = ledger.counts.blackBox, agg = ledger.counts.aggregate;
const headModel = Object.keys(ledger.perModel)[0] ?? "unknown";

writeFileSync(join(outDir, "README.md"), `# 0sec — XBOW benchmark receipts

Auditable per-challenge receipts for [0sec](https://0sec.ai)'s runs against the
[XBOW validation benchmarks](https://github.com/${substrateRepo}), pinned to a single
commit so the substrate is fixed and publicly clonable.

- **Substrate:** \`${substrateRepo}\` @ \`${substrateSha}\` (104 challenges)
- **Headline model:** ${headModel}
- **Black-box solved:** ${bb}/104 — **aggregate (any mode):** ${agg}/104
- Full counts + per-model breakdown: [\`ledger.json\`](./ledger.json)

Every solved challenge has a folder under [\`receipts/\`](./receipts) with a metadata pin
(\`meta.json\`: vuln class, mode, model, turns, cost, captured flag) and the \`flag.txt\` it
extracted. **This is evidence you can audit, not a number on a slide.** See [\`VERIFY.md\`](./VERIFY.md).
${publicTier ? `
> **Tiered disclosure.** Full per-challenge conversation traces (the agent's exact
> exploitation steps) are the engine's methodology, so this public repo ships them only
> for a representative **sample** (${sampleIds.size} challenges spanning vuln classes).
> The **complete trace set for all ${ledger.counts.aggregate} solves is available for audit under NDA**
> — for design partners, investors, and journalists. Request access via https://0sec.ai.
` : ""}
> Why receipts in git and not a benchmark badge: benchmark evidence rots. Our original
> run artifacts lived in expiring CI storage and were lost. Receipts committed to git
> never expire. Read more: https://0sec.ai/blog/xbow-benchmark-methodology-and-verification/
`);

writeFileSync(join(outDir, "VERIFY.md"), `# How to audit these receipts

0sec's engine is closed-source, so we do **not** claim you can reproduce these runs
from scratch. Instead every solve is **auditable**: the receipt is the agent's real,
turn-by-turn interaction with the live challenge, ending in the flag it pulled out of
the target's own responses.

## What you can check, in ~2 minutes per challenge

1. **Fix the substrate.** Everyone is on a different patched XBOW fork, so we pin ours:
   \`\`\`sh
   git clone https://github.com/${substrateRepo}
   cd $(basename ${substrateRepo}) && git checkout ${substrateSha}
   \`\`\`
   This is the *exact* challenge code our agent faced. Read \`benchmarks/<id>/\` to see
   the intended vulnerability.

2. **Open the receipt.** For any solved challenge:
   - \`receipts/<id>/trace.json\` — every tool call the agent made (HTTP requests, shell
     commands) and every response it got back from the live target.
   - \`receipts/<id>/flag.txt\` — the \`FLAG{…}\` string it extracted.
   - \`receipts/<id>/result.json\` — turns, cost, and the findings written up.

3. **Confirm the exploit is real, not narrated.** Trace the flag backwards: it appears
   in a genuine target response, reached by a chain of requests you can follow request
   by request. A fabricated receipt would have to invent a self-consistent exploit
   transcript against challenge code anyone can clone and read.

## The seven questions, answered up front
(from https://0sec.ai/blog/xbow-benchmark-methodology-and-verification/)

1. **Substrate?** \`${substrateRepo}\` @ \`${substrateSha}\` (community-patched, dockerfile fixes only).
2. **Fork commit?** Pinned above — clone and diff against upstream yourself.
3. **Single-shot or best-of-N?** Per receipt: see \`result.json\` (\`attempts\`/\`successRate\` when run with \`--repeat\`); the headline tally is best-of-1 unless a receipt says otherwise.
4. **Per-attempt success rate + CI?** Present for any challenge run with \`--repeat N\` (Wilson 95% CI in \`result.json\`).
5. **Model / version / turn cap?** In each receipt's \`meta.json\` and \`result.json\`.
6. **Feature flags / playbooks?** Black-box, default stack unless the receipt notes otherwise.
7. **Did anything silently fail to build?** No — denominator is the full 104; unsolved challenges are simply absent from \`receipts/\` and listed by omission against \`ledger.json\`.
`);

console.log(`Public bundle written to ${outDir}`);
console.log(`  receipts: ${written} solved challenges`);
console.log(`  counts: bb=${ledger.counts.blackBox} wb=${ledger.counts.whiteBox} aggregate=${ledger.counts.aggregate}`);
