import type { Finding, RuntimeMode, ScanDepth } from "@0sec/shared";
import type { NativeRuntime } from "../runtime/types.js";

export type SecurePhase = "prepare" | "investigate" | "reproduce" | "repair" | "test" | "verify" | "deliver" | "complete";

export interface SecureEvent {
  type: "secure:phase" | "secure:finding" | "secure:repair" | "secure:complete";
  phase: SecurePhase;
  message: string;
  findingId?: string;
  data?: unknown;
}

export interface BehavioralProbeResult {
  status: "vulnerable" | "safe" | "inconclusive";
  controlsPassed: boolean;
  detail: string;
}

export interface BehavioralRepairResult {
  findingId: string;
  status: "verified" | "not_reproduced" | "not_fixed" | "blocked" | "error";
  attempts: number;
  reason?: string;
  patchPath?: string;
  patchSha256?: string;
  baseline?: BehavioralProbeResult;
  verification?: BehavioralProbeResult;
  changedFiles?: string[];
  artifactDir: string;
}

export interface BehavioralRepairOptions {
  repoRoot: string;
  finding: Finding;
  artifactDir: string;
  runtime: NativeRuntime;
  setupCommand?: string;
  testCommand: string;
  maxAttempts: number;
  maxTurns: number;
  timeoutMs: number;
  signal?: AbortSignal;
  onEvent?: (event: SecureEvent) => void;
}

export interface SecureProjectOptions {
  repoRoot: string;
  stateDir: string;
  testCommand: string;
  setupCommand?: string;
  model?: string;
  apiKey?: string;
  runtime?: RuntimeMode;
  depth?: ScanDepth;
  maxFindings?: number;
  maxAttempts?: number;
  maxTurns?: number;
  timeoutMs?: number;
  costCeilingUsd?: number;
  resume?: boolean;
  publish?: boolean;
  signal?: AbortSignal;
  onEvent?: (event: SecureEvent) => void;
}

export interface SecureProjectResult {
  version: 1;
  runId: string;
  status: "completed" | "blocked" | "failed" | "cancelled";
  phase: SecurePhase;
  repoRoot: string;
  revision: string;
  startedAt: string;
  completedAt?: string;
  findings: Finding[];
  repairs: BehavioralRepairResult[];
  errors: string[];
  pullRequests: string[];
}