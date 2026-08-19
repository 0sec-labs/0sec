import { describe, expect, it, vi, beforeEach } from "vitest";

vi.mock("node:child_process", () => ({
  execFileSync: vi.fn(),
}));

import { execFileSync } from "node:child_process";
import { parseRepoRef, cloneGitRepo } from "./repo-clone.js";

const execMock = vi.mocked(execFileSync);

describe("parseRepoRef", () => {
  it("splits a url.git@ref version suffix", () => {
    expect(parseRepoRef("https://github.com/torvalds/linux.git@v5.10")).toEqual({
      url: "https://github.com/torvalds/linux.git",
      ref: "v5.10",
    });
  });

  it("does not misfire on SSH-style git@host (the @ precedes .git)", () => {
    expect(parseRepoRef("git@github.com:owner/repo.git")).toEqual({
      url: "git@github.com:owner/repo.git",
    });
  });

  it("leaves a plain https URL untouched", () => {
    expect(parseRepoRef("https://github.com/owner/repo.git")).toEqual({
      url: "https://github.com/owner/repo.git",
    });
  });

  it("leaves a URL without a .git suffix untouched", () => {
    expect(parseRepoRef("https://github.com/owner/repo")).toEqual({
      url: "https://github.com/owner/repo",
    });
  });
});

describe("cloneGitRepo", () => {
  beforeEach(() => execMock.mockClear());

  it("clones with --branch <ref> when a version suffix is present", () => {
    cloneGitRepo("https://github.com/torvalds/linux.git@v5.10", "/tmp/repo");
    expect(execMock).toHaveBeenCalledWith(
      "git",
      ["clone", "--depth", "1", "--branch", "v5.10", "https://github.com/torvalds/linux.git", "/tmp/repo"],
      expect.objectContaining({ stdio: "pipe" }),
    );
  });

  it("clones the default branch (no --branch) when no suffix", () => {
    cloneGitRepo("https://github.com/owner/repo.git", "/tmp/repo");
    expect(execMock).toHaveBeenCalledWith(
      "git",
      ["clone", "--depth", "1", "https://github.com/owner/repo.git", "/tmp/repo"],
      expect.objectContaining({ stdio: "pipe" }),
    );
  });
});
