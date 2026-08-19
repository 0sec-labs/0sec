#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
RESULT_JSON="${TMP_DIR}/kernel-validator-result.json"
RAW_OUTPUT="${TMP_DIR}/kernel-validator-raw.txt"

REPORT_URL="${PWNKIT_KERNEL_E2E_REPORT_URL:-https://syzkaller.appspot.com/text?tag=CrashReport&x=144881ca580000}"
REPRO_URL="${PWNKIT_KERNEL_E2E_REPRO_URL:-https://syzkaller.appspot.com/text?tag=ReproC&x=1253b3d6580000}"
INPUT_DIR="${TMP_DIR}/input"
ARTIFACT_DIR="${PWNKIT_KERNEL_QEMU_ARTIFACT_DIR:-${TMP_DIR}/vm-artifacts}"

mkdir -p "${INPUT_DIR}" "${ARTIFACT_DIR}"

curl -fL --retry 3 --retry-delay 2 -s "${REPORT_URL}" > "${INPUT_DIR}/sample.log"
curl -fL --retry 3 --retry-delay 2 -s "${REPRO_URL}" > "${INPUT_DIR}/sample.c"

export PWNKIT_KERNEL_QEMU=1
export PWNKIT_KERNEL_QEMU_ARTIFACT_DIR="${ARTIFACT_DIR}"

node "${ROOT_DIR}/packages/cli/dist/index.js" ingest "${INPUT_DIR}" --verify -o json > "${RAW_OUTPUT}"

node - "${RAW_OUTPUT}" "${RESULT_JSON}" <<'EOF'
const fs = require("node:fs");
const [rawPath, jsonPath] = process.argv.slice(2);
const raw = fs.readFileSync(rawPath, "utf8");
const jsonStart = raw.indexOf("[");
if (jsonStart === -1) {
  throw new Error("kernel validator E2E output did not contain a JSON array");
}
const payload = raw.slice(jsonStart);
JSON.parse(payload);
fs.writeFileSync(jsonPath, payload);
EOF

node - "${RESULT_JSON}" <<'EOF'
const fs = require("node:fs");
const path = process.argv[2];
const parsed = JSON.parse(fs.readFileSync(path, "utf8"));

if (!Array.isArray(parsed) || parsed.length === 0) {
  throw new Error("kernel validator E2E produced no findings");
}

const entry = parsed[0];
if (!entry.verification) {
  throw new Error("kernel validator E2E produced no verification payload");
}

if (entry.verification.reproduced !== true) {
  const reason = entry.verification.reason || "unknown";
  const evidence = entry.verification.evidence || "no evidence";
  throw new Error(`kernel validator E2E did not reproduce the crash: ${reason}\n${evidence}`);
}

const summary = {
  templateId: entry.finding?.templateId ?? null,
  verified: entry.verification.verified ?? null,
  reproduced: entry.verification.reproduced ?? null,
  crashMatch: entry.verification.crashMatch ?? null,
  reason: entry.verification.reason ?? null,
  confidence: entry.verification.confidence ?? null,
};

console.log(JSON.stringify(summary, null, 2));
EOF

echo "Kernel validator E2E artifacts saved to: ${ARTIFACT_DIR}"

if [[ -n "${PWNKIT_KERNEL_SOURCE_TREE:-}" ]]; then
  DIRECT_RAW_OUTPUT="${TMP_DIR}/direct-reproducer-raw.txt"
  DIRECT_RESULT_JSON="${TMP_DIR}/direct-reproducer-result.json"

  node "${ROOT_DIR}/packages/cli/dist/index.js" ingest \
    --reproducer "${INPUT_DIR}/sample.c" \
    --kernel-tree "${PWNKIT_KERNEL_SOURCE_TREE}" \
    --config kasan \
    --output json > "${DIRECT_RAW_OUTPUT}"

  node - "${DIRECT_RAW_OUTPUT}" "${DIRECT_RESULT_JSON}" <<'EOF'
const fs = require("node:fs");
const [rawPath, jsonPath] = process.argv.slice(2);
const raw = fs.readFileSync(rawPath, "utf8");
const objectStart = raw.indexOf("{");
if (objectStart === -1) {
  throw new Error("standalone reproducer output did not contain a JSON object");
}
const parsed = JSON.parse(raw.slice(objectStart));
if (parsed.reproducerLanguage !== "c") {
  throw new Error("standalone reproducer did not preserve language=c");
}
if (!parsed.verification || parsed.verification.reproduced !== true) {
  throw new Error(`standalone reproducer did not execute through the oracle: ${parsed.verification?.reason || "unknown"}`);
}
if (!parsed.kernelBuild || !["env", "hit", "miss"].includes(parsed.kernelBuild.cacheStatus)) {
  throw new Error("standalone reproducer did not report kernel build/cache metadata");
}
fs.writeFileSync(jsonPath, JSON.stringify({
  reproducerLanguage: parsed.reproducerLanguage,
  cacheStatus: parsed.kernelBuild.cacheStatus,
  verified: parsed.verification.verified,
  reproduced: parsed.verification.reproduced,
  reproducedCrashType: parsed.verification.reproducedCrashType ?? null,
}, null, 2));
console.log(fs.readFileSync(jsonPath, "utf8"));
EOF

  REVIEW_INPUT_DIR="${TMP_DIR}/review-input"
  REVIEW_FIXTURE="${TMP_DIR}/review-fixture.json"
  REVIEW_RAW_OUTPUT="${TMP_DIR}/review-raw.txt"
  REVIEW_RESULT_JSON="${TMP_DIR}/review-result.json"
  mkdir -p "${REVIEW_INPUT_DIR}"

  cat > "${REVIEW_INPUT_DIR}/nfsd.log" <<'EOF'
==================================================================
BUG: KASAN: slab-out-of-bounds in nfsd_dispatch+0x1a2/0x340 [nfsd]
Read of size 4 at addr ffff88800abcde10 by task nfsd/1234

CPU: 2 PID: 1234 Comm: nfsd Not tainted 6.8.12 #42
Call Trace:
 [<ffffffff81234567>] dump_stack_lvl+0x34/0x44
 [<ffffffff81345678>] print_report+0x171/0x4b6
 [<ffffffff81456789>] kasan_report+0xad/0x130
 [<ffffffff81567890>] nfsd_dispatch+0x1a2/0x340
 [<ffffffff81678901>] svc_process+0x15c/0x2c0
 [<ffffffff81789012>] nfsd+0x1e7/0x310
==================================================================
EOF

  cat > "${REVIEW_FIXTURE}" <<'EOF'
{
  "findings": [
    {
      "id": "kernel-review-fixture-1",
      "templateId": "cli-review-fixture",
      "title": "nfsd sibling fixture",
      "description": "Deterministic CI fixture for crash-directed subsystem review plumbing.",
      "severity": "high",
      "category": "use-after-free",
      "status": "discovered",
      "evidence": {
        "request": "fs/nfsd/vfs.c:1",
        "response": "static-only",
        "analysis": "Fixture finding"
      },
      "confidence": 0.4,
      "timestamp": 0
    }
  ]
}
EOF

  node "${ROOT_DIR}/packages/cli/dist/index.js" ingest "${REVIEW_INPUT_DIR}" \
    --review-subsystem \
    --tree "${PWNKIT_KERNEL_SOURCE_TREE}" \
    --review-subsystem-fixture "${REVIEW_FIXTURE}" \
    --output json > "${REVIEW_RAW_OUTPUT}"

  node - "${REVIEW_RAW_OUTPUT}" "${REVIEW_RESULT_JSON}" <<'EOF'
const fs = require("node:fs");
const [rawPath, jsonPath] = process.argv.slice(2);
const raw = fs.readFileSync(rawPath, "utf8");
const objectStart = raw.indexOf("{");
if (objectStart === -1) {
  throw new Error("review-subsystem output did not contain a JSON object");
}
const payload = raw.slice(objectStart);
const parsed = JSON.parse(payload);
if (!Array.isArray(parsed.crashFindings) || parsed.crashFindings.length !== 1) {
  throw new Error("review-subsystem did not preserve the original crash finding");
}
if (!Array.isArray(parsed.reviewFindings) || parsed.reviewFindings.length !== 1) {
  throw new Error("review-subsystem did not append the fixture review finding");
}
if (parsed.reviewFindings[0].relatedFindingId !== parsed.crashFindings[0].id) {
  throw new Error("review-subsystem finding did not link back with relatedFindingId");
}
fs.writeFileSync(jsonPath, JSON.stringify({
  crashFindingId: parsed.crashFindings[0].id,
  relatedFindingId: parsed.reviewFindings[0].relatedFindingId,
  totalFindings: parsed.findings.length,
}, null, 2));
console.log(fs.readFileSync(jsonPath, "utf8"));
EOF
fi
