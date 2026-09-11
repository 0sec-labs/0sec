import { describe, expect, it, vi } from "vitest";
import { ScopePolicy } from "../scope/scope.js";
import { isPublicRepositoryAddress, parseRepositoryAcquisition, repositoryAcquisitionAllowed, runRepositoryAcquisition } from "./repository-acquisition.js";

const dns = vi.hoisted(() => ({ lookup: vi.fn() }));
vi.mock("node:dns/promises", () => dns);

const command = "git -C /nonexistent-source-acquisition-test clone https://code.example/repo.git";
const plan = parseRepositoryAcquisition(command)!;

describe("public repository acquisition boundaries", () => {
  it("rejects private, mapped, and transition addresses while accepting public IPv4 and IPv6", () => {
    expect(isPublicRepositoryAddress("140.82.114.3")).toBe(true);
    expect(isPublicRepositoryAddress("2606:50c0:8000::153")).toBe(true);
    expect(isPublicRepositoryAddress("169.254.169.254")).toBe(false);
    expect(isPublicRepositoryAddress("100.64.0.1")).toBe(false);
    expect(isPublicRepositoryAddress("::ffff:127.0.0.1")).toBe(false);
    expect(isPublicRepositoryAddress("2002:7f00:1::1")).toBe(false);
    expect(isPublicRepositoryAddress("fd00::1")).toBe(false);
  });

  it("refuses mixed public/private DNS answers before starting a checkout", async () => {
    dns.lookup.mockResolvedValue([{ address: "140.82.114.3", family: 4 }, { address: "127.0.0.1", family: 4 }]);
    await expect(runRepositoryAcquisition(plan, command, 500, 500)).rejects.toThrow();
  });

  it("honors excluded address ranges after resolving a public source hostname", async () => {
    dns.lookup.mockResolvedValue([{ address: "140.82.114.3", family: 4 }]);
    const scope = ScopePolicy.fromJson({ in_scope: ["target.example"], out_of_scope: ["140.82.0.0/16"] });
    await expect(runRepositoryAcquisition(plan, command, 500, 500, scope)).rejects.toThrow();
    expect(scope.match("https://code.example/repo.git").allowed).toBe(false);
  });

  it("cannot evade an explicit host exclusion with a trailing DNS dot", () => {
    const dotted = parseRepositoryAcquisition("git clone https://github.com./golang/go.git")!;
    expect(repositoryAcquisitionAllowed(dotted, ScopePolicy.fromJson({ out_of_scope: ["github.com"] }))).toBe(false);
  });

  it("does not classify credentials, shell substitution, or insecure transports as public acquisition", () => {
    expect(parseRepositoryAcquisition("git clone https://user:secret@github.com/golang/go.git")).toBeNull();
    expect(parseRepositoryAcquisition("git clone https://github.com/$(whoami)/go.git")).toBeNull();
    expect(parseRepositoryAcquisition("git clone http://github.com/golang/go.git")).toBeNull();
    expect(parseRepositoryAcquisition("git clone git@github.com:golang/go.git")).toBeNull();
    expect(parseRepositoryAcquisition('git clone "https://github.com/golang/go.git')).toBeNull();
    expect(parseRepositoryAcquisition("git clone https://github.com/golang/go.git # comment")).toBeNull();
  });
});
