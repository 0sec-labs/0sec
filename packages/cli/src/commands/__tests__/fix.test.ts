import { describe, expect, it } from "vitest";
import { Command } from "commander";
import { registerFixCommand } from "../fix.js";

describe("fix command", () => {
  it("requires an explicit regression command and exposes the reproduced-result bridge", () => {
    const program = new Command();
    registerFixCommand(program);

    const fixCommand = program.commands.find((command) => command.name() === "fix");
    expect(fixCommand).toBeDefined();
    const help = fixCommand!.helpInformation();
    expect(help).toContain("--finding <path>");
    expect(help).toContain("--verification-result <path>");
    expect(help).toContain("--test-command <command>");
    expect(help).toContain("--apply");
  });
});
