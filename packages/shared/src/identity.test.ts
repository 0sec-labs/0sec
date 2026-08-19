import { describe, it, expect } from "vitest";
import {
  resolveIdentities,
  hasMultipleIdentities,
  compareRoles,
  defaultRoleFor,
} from "./identity.js";
import type { AuthConfig } from "./types.js";

const bearer: AuthConfig = { type: "bearer", token: "tok-a" };
const cookie: AuthConfig = { type: "cookie", value: "sid=b" };

describe("resolveIdentities (back-compat shim, 0sec#564)", () => {
  it("wraps a legacy singular `auth` into a one-entry identity list", () => {
    const out = resolveIdentities({ auth: bearer });
    expect(out).toHaveLength(1);
    expect(out[0].label).toBe("primary");
    expect(out[0].auth).toEqual(bearer);
    expect(out[0].role).toBe("user"); // authenticated → user
  });

  it("returns an empty list when neither auth nor identities are set", () => {
    expect(resolveIdentities({})).toEqual([]);
  });

  it("uses `identities` verbatim and ignores singular `auth` when both set", () => {
    const out = resolveIdentities({
      auth: bearer,
      identities: [
        { label: "admin", role: "admin", auth: bearer },
        { label: "alice", auth: cookie },
      ],
    });
    expect(out).toHaveLength(2);
    expect(out.map((i) => i.label)).toEqual(["admin", "alice"]);
    // singular auth (bearer) is NOT appended
    expect(out.some((i) => i.label === "primary")).toBe(false);
  });

  it("defaults role from auth presence: authed → user, unauthed → anonymous", () => {
    const out = resolveIdentities({
      identities: [{ label: "alice", auth: cookie }, { label: "guest" }],
    });
    expect(out[0].role).toBe("user");
    expect(out[1].role).toBe("anonymous");
    expect(out[1].auth).toBeUndefined();
  });

  it("preserves an explicit role over the default", () => {
    const out = resolveIdentities({ identities: [{ label: "x", role: "admin" }] });
    expect(out[0].role).toBe("admin");
  });

  it("de-duplicates colliding labels with a numeric suffix", () => {
    const out = resolveIdentities({
      identities: [
        { label: "user", auth: bearer },
        { label: "user", auth: cookie },
        { label: "user" },
      ],
    });
    expect(out.map((i) => i.label)).toEqual(["user", "user-2", "user-3"]);
  });

  it("falls back to a positional label when label is blank", () => {
    const out = resolveIdentities({ identities: [{ label: "  ", auth: bearer }] });
    expect(out[0].label).toBe("identity-1");
  });
});

describe("hasMultipleIdentities", () => {
  it("is true only for ≥2 identities", () => {
    expect(hasMultipleIdentities([])).toBe(false);
    expect(hasMultipleIdentities([{ label: "a" }])).toBe(false);
    expect(hasMultipleIdentities([{ label: "a" }, { label: "b" }])).toBe(true);
  });
});

describe("compareRoles", () => {
  it("ranks anonymous < user < admin", () => {
    expect(compareRoles("anonymous", "user")).toBeLessThan(0);
    expect(compareRoles("user", "admin")).toBeLessThan(0);
    expect(compareRoles("admin", "anonymous")).toBeGreaterThan(0);
    expect(compareRoles("user", "user")).toBe(0);
  });

  it("treats unknown/bespoke roles as `user` (never spuriously admin)", () => {
    expect(compareRoles("editor", "admin")).toBeLessThan(0);
    expect(compareRoles(undefined, "admin")).toBeLessThan(0);
    expect(compareRoles("editor", "anonymous")).toBeGreaterThan(0);
  });
});

describe("defaultRoleFor", () => {
  it("maps auth presence to a tier", () => {
    expect(defaultRoleFor(bearer)).toBe("user");
    expect(defaultRoleFor(undefined)).toBe("anonymous");
  });
});
