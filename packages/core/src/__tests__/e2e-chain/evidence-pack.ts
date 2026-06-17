// Evidence-pack renderer for the CodeWall-chain e2e self-test.
//
// Takes the findings each stage of the chain produced and renders a single
// redacted markdown artifact — the kind of end-to-end output the managed
// service would hand an operator. Secrets are already redacted upstream
// (js-artifacts `redactSecret`); this renderer never reconstructs a raw value.
//
// Pure string assembly — no I/O, no network — so the test owns where (if
// anywhere) it gets written to disk.

import type { SecretHit } from "../../recon/js-artifacts.js";
import type { ReconAsset } from "../../recon/recon.js";
import type { EndpointVerdict } from "../../agent/auth-boundary-prober.js";
import type { ProbeResult } from "../../agent/structural-sqli.js";
import type { BucketProbeResult, TakeoverVerdict } from "../../agent/cloud-surface.js";

export interface EvidencePackInput {
  target: string;
  generatedAt: string;
  /** Stage 2 — js_recon endpoint discovery. */
  discoveredEndpoints: ReconAsset[];
  /** Stage 2 — js_recon secret discovery (already redacted). */
  secrets: SecretHit[];
  /** Stage 3 — auth-boundary verdicts. */
  authBoundary: EndpointVerdict[];
  /** Stage 4 — structural SQLi probe result. */
  sqli: ProbeResult;
  /** Stage 5 — cloud probe (bucket access + takeover classification). */
  cloud: { probe: BucketProbeResult; takeover: TakeoverVerdict };
}

/** Mask a secret excerpt to a kind + length only (defense-in-depth redaction). */
function maskSecret(hit: SecretHit): string {
  return `${hit.kind} [REDACTED, ${hit.confidence} confidence]`;
}

export function renderEvidencePack(input: EvidencePackInput): string {
  const lines: string[] = [];
  const L = (s = "") => lines.push(s);

  L(`# CodeWall chain — evidence pack`);
  L();
  L(`> Self-test against a LOCAL vulnerable fixture (127.0.0.1 only). All`);
  L(`> findings below were planted; this demonstrates the chained tools firing`);
  L(`> end-to-end. No external target was contacted.`);
  L();
  L(`- **Target:** \`${input.target}\``);
  L(`- **Generated:** ${input.generatedAt}`);
  L();

  // ── Stage 2: JS recon ──
  L(`## Stage 2 — JS recon (\`js_recon\`)`);
  L();
  L(`Discovered ${input.discoveredEndpoints.length} endpoint(s) from the public JS bundle:`);
  L();
  for (const ep of input.discoveredEndpoints) {
    L(`- \`${ep.value}\` (source: ${ep.source})`);
  }
  L();
  L(`Leaked secrets (redacted):`);
  L();
  if (input.secrets.length === 0) {
    L(`- _none_`);
  } else {
    for (const s of input.secrets) {
      L(`- ${maskSecret(s)} — found in \`${s.chunk}\``);
    }
  }
  L();

  // ── Stage 3: auth boundary ──
  L(`## Stage 3 — Auth-boundary probe (\`auth_boundary_probe\`)`);
  L();
  const reachable = input.authBoundary.filter((r) => r.unauthReachable);
  L(`${reachable.length} of ${input.authBoundary.length} probed endpoint(s) reachable WITHOUT credentials.`);
  L();
  for (const r of input.authBoundary) {
    const tag = r.unauthReachable ? `LEAK [${r.severity}]` : `holds`;
    L(`- ${tag} — \`${r.method} ${r.url}\` → ${r.verdict} (${r.note})`);
  }
  L();

  // ── Stage 4: structural SQLi ──
  L(`## Stage 4 — Structural SQLi probe (\`structural_sqli_probe\`)`);
  L();
  L(`- **Injected key:** \`${input.sqli.baseKey}\``);
  L(`- **Verdict:** \`${input.sqli.verdict}\``);
  L(`- **Dialect:** \`${input.sqli.dialect ?? "unknown"}\``);
  L();
  L(`Iteration trail:`);
  L();
  for (const step of input.sqli.trail) {
    L(`  ${step.iteration}. payload=\`${step.payload.key}\` balanced=${step.payload.balanced} → ${step.verdict} (${step.note})`);
  }
  L();

  // ── Stage 5: cloud ──
  L(`## Stage 5 — Cloud surface probe (\`cloud_probe_s3\`)`);
  L();
  L(`- **Bucket:** \`${input.cloud.probe.bucket}\``);
  L(`- **Endpoint:** \`${input.cloud.probe.endpoint}\``);
  L(`- **Access verdict:** \`${input.cloud.probe.verdict}\` [${input.cloud.probe.severity}] — ${input.cloud.probe.note}`);
  L(`- **Takeover:** \`${input.cloud.takeover.takeoverable ? "TAKEOVERABLE" : "no"}\` [${input.cloud.takeover.severity}] — ${input.cloud.takeover.note}`);
  L();

  // ── Chain summary ──
  L(`## Chain summary`);
  L();
  L(`recon → js_recon → auth_boundary_probe → structural_sqli → cloud_probe`);
  L();
  L(`The endpoints js_recon pulled out of the public JS fed directly into the`);
  L(`auth-boundary probe and the SQLi probe; the bucket name js_recon found fed`);
  L(`the cloud probe. Each stage consumed the previous stage's output.`);

  return lines.join("\n");
}
