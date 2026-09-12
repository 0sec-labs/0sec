import { afterEach, expect, it, vi } from "vitest";
import { Command } from "commander";
import { CloudClient } from "@0sec/core";
import { registerHostedCommand } from "../hosted.js";

const output = vi.hoisted(() => ({ stdout: vi.fn(), stderr: vi.fn() }));
vi.mock("../../presentation/process-output.js", () => ({ consolePresentationOutput: output }));
const originalExitCode = process.exitCode;

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  output.stdout.mockClear();
  output.stderr.mockClear();
  process.exitCode = originalExitCode;
});

it("does not round available credits to exhausted or partially used credits to full", async () => {
  vi.stubEnv("0SEC_CLOUD_TOKEN", "synthetic-balance-token");
  vi.stubEnv("0SEC_CLOUD_HOST", "https://fixture.invalid");
  const account = vi.spyOn(CloudClient.prototype, "getInferenceAccount");
  for (const [percent, label] of [[0.001, "<0.1%"], [0, "0%"], [99.999, ">99.9%"], [100, "100%"]] as const) {
    const response = {
      remainingUsd: 12345,
      currency: "USD",
      credits: { featureId: "inference_credits", granted: 100, remaining: percent, remainingPercent: percent, nextResetAt: null },
    };
    account.mockResolvedValueOnce(response);
    const command = new Command("0sec");
    registerHostedCommand(command);
    await command.parseAsync(["node", "0sec", "balance"]);
    const line = String(output.stdout.mock.lastCall?.[0]).replace(/\u001b\[[0-9;]*m/g, "");
    expect(line.match(/[<>]?\d+(?:\.\d+)?%/)?.[0]).toBe(label);
    expect(process.exitCode).toBe(0);
  }
  expect(output.stderr).not.toHaveBeenCalled();
});
