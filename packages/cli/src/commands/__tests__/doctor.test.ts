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

describe("doctor Node prerequisites", () => {
  it.each([
    { version: "23.0.0", status: "bad" },
    { version: "24.0.0", status: "ok" },
  ])("reports Node $version as $status", async ({ version, status }) => {
    const nodeDescriptor = Object.getOwnPropertyDescriptor(process.versions, "node")!;
    const versionDescriptor = Object.getOwnPropertyDescriptor(process, "version")!;
    getRuntimeAvailabilityMock.mockResolvedValue({
      hasApiKey: false,
      availableRuntimes: [],
      apiRuntime: { configured: false, valid: false, providerLabel: "fixture" },
    });
    try {
      Object.defineProperty(process.versions, "node", { ...nodeDescriptor, value: version });
      Object.defineProperty(process, "version", { ...versionDescriptor, value: `v${version}` });
      const output = await runDoctor();
      const nodeStatus = output.split("\n").find((line) => line.includes("Node.js"));
      expect(nodeStatus).toMatch(new RegExp(`Node\\.js\\s+${status}\\s+v${version.replaceAll(".", "\\.")}`));
    } finally {
      Object.defineProperty(process.versions, "node", nodeDescriptor);
      Object.defineProperty(process, "version", versionDescriptor);
    }
  });
});
