import { afterEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";

const getRuntimeAvailabilityMock = vi.hoisted(() => vi.fn());

vi.mock("../../utils.js", () => ({
  getRuntimeAvailability: getRuntimeAvailabilityMock,
}));

vi.mock("../../tui/runtime.js", () => ({
  canUseOpenTui: () => false,
  isBunRuntime: () => false,
}));

import { registerDoctorCommand } from "../doctor.js";

async function runDoctor(): Promise<string> {
  const lines: string[] = [];
  const log = vi.spyOn(console, "log").mockImplementation((line = "") => {
    lines.push(String(line));
  });
  try {
    const program = new Command();
    registerDoctorCommand(program);
    await program.parseAsync(["node", "0sec", "doctor"]);
    return lines.join("\n");
  } finally {
    log.mockRestore();
  }
}

afterEach(() => {
  vi.clearAllMocks();
});

describe("doctor credential readiness", () => {
  it("reports configured credentials without claiming their first request is ready", async () => {
    getRuntimeAvailabilityMock.mockResolvedValue({
      hasApiKey: true,
      availableRuntimes: ["codex"],
      apiRuntime: {
        configured: true,
        valid: true,
        providerLabel: "ChatGPT (Codex backend)",
      },
    });

    const output = await runDoctor();

    expect(output).toContain("configured");
    expect(output).toContain("The first request verifies credentials.");
    expect(output).not.toContain("Ready to scan.");
  });
});
