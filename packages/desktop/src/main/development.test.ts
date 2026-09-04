import { describe, expect, it } from "vitest";
import { parseDevelopmentDebugPort } from "./development.js";

describe("parseDevelopmentDebugPort", () => {
  it("leaves debugging disabled without an explicit port", () => {
    expect(parseDevelopmentDebugPort(undefined)).toBeUndefined();
    expect(parseDevelopmentDebugPort("   ")).toBeUndefined();
  });

  it("accepts a valid non-privileged loopback debug port", () => {
    expect(parseDevelopmentDebugPort("9222")).toBe(9222);
  });

  it.each(["0", "443", "65536", "abc", "9222.5"])("rejects unsafe port %s", (value) => {
    expect(() => parseDevelopmentDebugPort(value)).toThrow(/between 1024 and 65535/i);
  });
});
