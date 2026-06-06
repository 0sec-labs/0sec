import { describe, expect, it } from "vitest";
import {
  detectFrameworkFromHeaders,
  detectFrameworkFromHtml,
  detectFrameworkFromBundle,
  parseGeneratorContent,
  parseLibraryBanners,
  enumerateJsChunkUrls,
  fingerprintWebStack,
  summarizeWebStackFingerprint,
  type FetchTextResult,
} from "./stack-fingerprint.js";

// ── Pure parser tests ──

describe("detectFrameworkFromHeaders", () => {
  it("identifies Next.js from x-powered-by (case-insensitive header key)", () => {
    const fw = detectFrameworkFromHeaders({ "X-Powered-By": "Next.js" });
    expect(fw).toMatchObject({ name: "Next.js", source: "header" });
  });

  it("extracts a version embedded in the header value", () => {
    const fw = detectFrameworkFromHeaders({ "x-powered-by": "Express/4.18.2" });
    expect(fw).toMatchObject({ name: "Express", version: "4.18.2" });
  });

  it("returns undefined when no framework header is present", () => {
    expect(detectFrameworkFromHeaders({ server: "nginx" })).toBeUndefined();
  });
});

describe("detectFrameworkFromHtml", () => {
  it("detects Next.js from /_next/ assets", () => {
    const html = `<html><body><script src="/_next/static/chunks/main.js"></script></body></html>`;
    expect(detectFrameworkFromHtml(html)).toMatchObject({ name: "Next.js", source: "html" });
  });

  it("detects Nuxt from the hydration global", () => {
    expect(detectFrameworkFromHtml("<script>window.__NUXT__={}</script>")).toMatchObject({
      name: "Nuxt",
    });
  });

  it("parses a meta generator with a version", () => {
    const html = `<meta name="generator" content="Next.js 15.0.7" />`;
    expect(detectFrameworkFromHtml(html)).toMatchObject({
      name: "Next.js",
      version: "15.0.7",
      source: "meta_generator",
    });
  });
});

describe("parseGeneratorContent", () => {
  it("extracts framework + version from a generator string", () => {
    expect(parseGeneratorContent("Gatsby 5.12.4")).toMatchObject({
      name: "Gatsby",
      version: "5.12.4",
    });
  });
});

describe("detectFrameworkFromBundle", () => {
  it("extracts Next.js version from the window.next global (live-pilot shape)", () => {
    const body = `(self.__next_f=[]),window.next={version:"15.0.7",appDir:!0};`;
    expect(detectFrameworkFromBundle(body)).toEqual({
      name: "Next.js",
      version: "15.0.7",
      source: "window_global",
    });
  });

  it("extracts a React rc version from a framework chunk (live-pilot shape)", () => {
    const body = `var React={__SECRET_INTERNALS:1};exports.version="19.0.0-rc-66855b96-20241106";`;
    expect(detectFrameworkFromBundle(body)).toMatchObject({
      name: "React",
      version: "19.0.0-rc-66855b96-20241106",
    });
  });
});

describe("parseLibraryBanners", () => {
  it("extracts a library banner with version (live-pilot shape)", () => {
    const libs = parseLibraryBanners("/*! lucide-react v0.417.0 - ISC */");
    expect(libs).toContainEqual({ name: "lucide-react", version: "0.417.0", source: "js_bundle" });
  });

  it("extracts scoped package banners and name@version forms", () => {
    const libs = parseLibraryBanners("* @radix-ui/react-dialog v1.0.5\nresolved axios@1.7.2 too");
    const names = libs.map((l) => `${l.name}@${l.version}`);
    expect(names).toContain("@radix-ui/react-dialog@1.0.5");
    expect(names).toContain("axios@1.7.2");
  });

  it("ignores denylisted / numeric noise tokens", () => {
    const libs = parseLibraryBanners("version v1.2.3\n42@1.0.0");
    expect(libs).toHaveLength(0);
  });
});

describe("enumerateJsChunkUrls", () => {
  it("collects and absolutizes script + modulepreload JS URLs, dedupes", () => {
    const html = `
      <script src="/_next/static/chunks/main-abc.js?v=1"></script>
      <link rel="modulepreload" href="/_next/static/chunks/framework.js"/>
      <script src="https://cdn.example/lib.mjs"></script>
      <link rel="stylesheet" href="/styles.css"/>
      <script src="/_next/static/chunks/main-abc.js?v=1"></script>
    `;
    const urls = enumerateJsChunkUrls(html, "https://t.example");
    expect(urls).toContain("https://t.example/_next/static/chunks/main-abc.js?v=1");
    expect(urls).toContain("https://t.example/_next/static/chunks/framework.js");
    expect(urls).toContain("https://cdn.example/lib.mjs");
    expect(urls.some((u) => u.endsWith(".css"))).toBe(false);
    // deduped
    expect(urls.filter((u) => u.includes("main-abc"))).toHaveLength(1);
  });
});

// ── End-to-end fingerprint with a mocked fetch (reproduces the live pilot) ──

function mockFetch(routes: Record<string, Partial<FetchTextResult>>) {
  return async (url: string): Promise<FetchTextResult> => {
    const r = routes[url] ?? { status: 404, body: "" };
    return { status: r.status ?? 200, headers: r.headers ?? {}, body: r.body ?? "" };
  };
}

describe("fingerprintWebStack (end-to-end)", () => {
  it("reproduces the live-pilot Next.js + React + lucide-react fingerprint", async () => {
    const base = "https://app.example";
    const html = `
      <!doctype html><html><head>
        <meta name="generator" content="Next.js"/>
        <script src="/_next/static/chunks/framework-react.js"></script>
        <script src="/_next/static/chunks/main-app.js"></script>
      </head><body><div id="__next"></div></body></html>
    `;
    const fetchText = mockFetch({
      [base]: { status: 200, headers: { "x-powered-by": "Next.js" }, body: html },
      [`${base}/_next/static/chunks/framework-react.js`]: {
        status: 200,
        body: `var React={__SECRET_INTERNALS_DO_NOT_USE:1};React.version="19.0.0-rc-66855b96-20241106";/*! lucide-react v0.417.0 */`,
      },
      [`${base}/_next/static/chunks/main-app.js`]: {
        status: 200,
        body: `window.next={version:"15.0.7",appDir:!0};`,
      },
    });

    const result = await fingerprintWebStack({ baseUrl: base, fetchText });

    // window.next global is the strongest signal -> Next.js 15.0.7.
    expect(result.framework).toMatchObject({ name: "Next.js", version: "15.0.7" });

    const libNames = result.libraries.map((l) => l.name);
    expect(libNames).toContain("lucide-react");
    expect(result.libraries.find((l) => l.name === "lucide-react")?.version).toBe("0.417.0");

    expect(result.rawSignals.some((s) => /x-powered-by|header: Next\.js/i.test(s) || /Next\.js/.test(s))).toBe(true);
  });

  it("caps the number of JS chunks fetched", async () => {
    const base = "https://big.example";
    const scripts = Array.from({ length: 30 }, (_, i) => `<script src="/c/${i}.js"></script>`).join("");
    const routes: Record<string, Partial<FetchTextResult>> = {
      [base]: { status: 200, headers: {}, body: `<html><head>${scripts}</head></html>` },
    };
    let fetched = 0;
    const fetchText = async (url: string): Promise<FetchTextResult> => {
      if (url !== base) fetched++;
      return { status: 200, headers: {}, body: routes[url]?.body ?? "" };
    };
    await fingerprintWebStack({ baseUrl: base, fetchText, maxChunks: 5 });
    expect(fetched).toBe(5);
  });

  it("tolerates a throwing fetch and returns an empty-ish fingerprint", async () => {
    const result = await fingerprintWebStack({
      baseUrl: "https://down.example",
      fetchText: async () => {
        throw new Error("network down");
      },
    });
    expect(result.framework).toBeUndefined();
    expect(result.libraries).toEqual([]);
  });
});

describe("summarizeWebStackFingerprint", () => {
  it("renders framework + libraries", () => {
    const text = summarizeWebStackFingerprint({
      framework: { name: "Next.js", version: "15.0.7", source: "window_global" },
      libraries: [{ name: "lucide-react", version: "0.417.0", source: "js_bundle" }],
      rawSignals: [],
    });
    expect(text).toContain("Framework: Next.js v15.0.7");
    expect(text).toContain("lucide-react@0.417.0");
  });
});
