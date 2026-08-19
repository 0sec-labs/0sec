import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "@0sec/shared";
import { runResearch } from "../research-runner.js";
import { LinuxBootMatrixImportAdapter, type ExternalKernelBootMatrixManifest, type LinuxBootMatrixTarget } from "./linux-boot-matrix-adapter.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function setup(controlSignature = false): { target: LinuxBootMatrixTarget; root: string } {
  const root = mkdtempSync(join(tmpdir(), "0sec-matrix-")); roots.push(root); mkdirSync(join(root, "logs"));
  const boots = (side: "v" | "c", count: number) => Array.from({ length: count }, (_, i) => ({ id: `${side}${i + 1}`, logPath: `logs/${side}${i + 1}.log`, bootMarker: `BOOT-${side}${i + 1}` }));
  const manifest: ExternalKernelBootMatrixManifest = { schemaVersion: 1, executedBy: "authorized-colossus-harness", expectedSignature: "TARGET UAF", completionMarker: "RUN-DONE", minVulnerableHits: 2, minCleanControls: 3, vulnerable: { buildId: "vuln", boots: boots("v", 3) }, patched: { buildId: "fixed", boots: boots("c", 3) } };
  for (const [i, boot] of manifest.vulnerable.boots.entries()) writeFileSync(join(root, boot.logPath), `${boot.bootMarker}\n${i > 0 ? "TARGET UAF\n" : ""}RUN-DONE\n`);
  for (const boot of manifest.patched.boots) writeFileSync(join(root, boot.logPath), `${boot.bootMarker}\n${controlSignature ? "TARGET UAF\n" : ""}RUN-DONE\n`);
  const manifestPath = join(root, "matrix.json"); writeFileSync(manifestPath, JSON.stringify(manifest));
  const finding = { id: "alsa", templateId: "kernel", title: "ALSA UAF", description: "control", severity: "high", category: "memory-corruption", status: "verified", evidence: { request: "", response: "" }, timestamp: 1 } as Finding;
  return { root, target: { kind: "linux.kernel-boot-matrix-import", id: "matrix", location: manifestPath, config: { finding } } };
}

describe("LinuxBootMatrixImportAdapter", () => {
  it("promotes a fully attributed differential and hashes manifest, logs, and verdict", async () => {
    const { target, root } = setup();
    const result = await runResearch(new LinuxBootMatrixImportAdapter(), target, { artifactRoot: join(root, "artifacts"), runId: "matrix-run" });
    expect(result.envelopes[0]).toMatchObject({ grade: "reproduced" });
    expect(result.findings[0]?.evidence[0]?.data).toMatchObject({ executionOrigin: "external" });
    expect(result.envelopes[0]?.executionContext).toEqual({ privilege: "unknown", basis: "declared" });
    expect(result.envelopes[0]?.artifacts).toHaveLength(8);
    expect(result.envelopes[0]?.artifacts.every((artifact) => /^[0-9a-f]{64}$/.test(artifact.sha256))).toBe(true);
  });

  it("fails closed on incomplete or misattributed boots", async () => {
    const { target, root } = setup();
    writeFileSync(join(root, "logs/v1.log"), "RUN-DONE\n");
    const result = await runResearch(new LinuxBootMatrixImportAdapter(), target, { artifactRoot: join(root, "artifacts"), runId: "bad-id" });
    expect(result.findings).toHaveLength(0);
  });

  it("marks a patched signature as contradictory", async () => {
    const { target, root } = setup(true);
    const result = await runResearch(new LinuxBootMatrixImportAdapter(), target, { artifactRoot: join(root, "artifacts"), runId: "bad-control" });
    expect(result.findings).toHaveLength(0);
    expect(result.evidence.some((item) => item.stage === "verify" && item.status === "failed")).toBe(true);
  });

  it("rejects duplicate boot identities at discovery", async () => {
    const { target, root } = setup();
    const manifest = JSON.parse(readFileSync(target.location, "utf8")) as ExternalKernelBootMatrixManifest;
    manifest.patched.boots[0]!.id = manifest.vulnerable.boots[0]!.id;
    writeFileSync(target.location, JSON.stringify(manifest));
    const result = await runResearch(new LinuxBootMatrixImportAdapter(), target, { artifactRoot: join(root, "artifacts"), runId: "dup-id" });
    expect(result.candidates).toHaveLength(0);
    expect(result.evidence.some((item) => item.stage === "discover" && item.status === "failed")).toBe(true);
  });

  it("rejects missing logs and unattainable thresholds", async () => {
    const { target, root } = setup();
    const manifest = JSON.parse(readFileSync(target.location, "utf8")) as ExternalKernelBootMatrixManifest;
    manifest.minVulnerableHits = 4;
    manifest.patched.boots[0]!.logPath = "logs/missing.log";
    writeFileSync(target.location, JSON.stringify(manifest));
    const result = await runResearch(new LinuxBootMatrixImportAdapter(), target, { artifactRoot: join(root, "artifacts"), runId: "bad-manifest" });
    expect(result.candidates).toHaveLength(0);
  });
});
