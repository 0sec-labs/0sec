import { describe, expect, it, vi } from "vitest";
import {
  enumerateSubdomains,
  normalizeCertName,
  parseCrtShRows,
  type ResolvedHost,
} from "./subdomains.js";

describe("normalizeCertName", () => {
  it("strips a leading wildcard and lowercases", () => {
    expect(normalizeCertName("*.Dev.Example.com", "example.com")).toBe("dev.example.com");
  });

  it("strips a trailing FQDN dot", () => {
    expect(normalizeCertName("app.example.com.", "example.com")).toBe("app.example.com");
  });

  it("accepts the apex itself", () => {
    expect(normalizeCertName("example.com", "example.com")).toBe("example.com");
  });

  it("rejects hosts outside the apex", () => {
    expect(normalizeCertName("evil.com", "example.com")).toBeUndefined();
    expect(normalizeCertName("notexample.com", "example.com")).toBeUndefined();
  });

  it("rejects embedded-wildcard / empty noise", () => {
    expect(normalizeCertName("a.*.example.com", "example.com")).toBeUndefined();
    expect(normalizeCertName("   ", "example.com")).toBeUndefined();
  });
});

describe("parseCrtShRows", () => {
  it("harvests common_name + multi-line name_value, dedups, strips wildcards, drops apex", () => {
    const rows = [
      { common_name: "dev.example.com", name_value: "dev.example.com\n*.example.com" },
      { common_name: "app.example.com", name_value: "app.example.com\nexample.com" },
      { name_value: "evil.com" },
    ];
    expect(parseCrtShRows(rows, "example.com")).toEqual(["app.example.com", "dev.example.com"]);
  });

  it("returns [] on non-array input", () => {
    expect(parseCrtShRows(null, "example.com")).toEqual([]);
    expect(parseCrtShRows({ not: "an array" }, "example.com")).toEqual([]);
  });
});

describe("enumerateSubdomains", () => {
  const crtRows = [
    { common_name: "dev.example.com", name_value: "dev.example.com" },
    { common_name: "app.example.com", name_value: "app.example.com" },
    { common_name: "*.example.com", name_value: "example.com" },
    { common_name: "dead.example.com", name_value: "dead.example.com" },
  ];

  it("returns only hosts that resolve, tagged source crt.sh, sorted by host", async () => {
    const resolved: Record<string, ResolvedHost> = {
      "dev.example.com": { addresses: ["10.0.0.1"], cname: "lb.internal.example.com" },
      "app.example.com": { addresses: ["10.0.0.2"] },
    };
    const fetchJson = vi.fn(async () => crtRows);
    const resolve = vi.fn(async (host: string) => {
      const entry = resolved[host];
      if (!entry) throw new Error(`no A/AAAA records for ${host}`);
      return entry;
    });

    const hosts = await enumerateSubdomains({ domain: "example.com", fetchJson, resolve });

    expect(hosts).toEqual([
      { host: "app.example.com", source: "crt.sh", addresses: ["10.0.0.2"] },
      {
        host: "dev.example.com",
        source: "crt.sh",
        addresses: ["10.0.0.1"],
        cname: "lb.internal.example.com",
      },
    ]);
    // `dead.example.com` was queried but dropped (no records); apex skipped.
    expect(resolve).toHaveBeenCalledWith("dead.example.com");
    expect(resolve).not.toHaveBeenCalledWith("example.com");
  });

  it("hits crt.sh with the %25-wildcard JSON query for the apex", async () => {
    const fetchJson = vi.fn(async () => []);
    await enumerateSubdomains({ domain: "example.com", fetchJson, resolve: async () => ({ addresses: [] }) });
    const url = fetchJson.mock.calls[0][0] as string;
    expect(url).toBe("https://crt.sh/?q=%25.example.com&output=json");
  });

  it("normalizes a trailing-dot / mixed-case apex", async () => {
    const fetchJson = vi.fn(async () => []);
    await enumerateSubdomains({ domain: "Example.com.", fetchJson, resolve: async () => ({ addresses: ["1.1.1.1"] }) });
    expect(fetchJson.mock.calls[0][0]).toBe("https://crt.sh/?q=%25.example.com&output=json");
  });

  it("degrades to [] when crt.sh fetch throws", async () => {
    const fetchJson = vi.fn(async () => {
      throw new Error("timeout");
    });
    const resolve = vi.fn();
    const hosts = await enumerateSubdomains({ domain: "example.com", fetchJson, resolve });
    expect(hosts).toEqual([]);
    expect(resolve).not.toHaveBeenCalled();
  });

  it("throws on an empty domain", async () => {
    await expect(enumerateSubdomains({ domain: "   " })).rejects.toThrow(/empty domain/);
  });
});
