import { describe, expect, it, vi } from "vitest";

import {
  OSC52_MAX_BYTES,
  buildOsc52,
  buildOsc52Result,
  copyToClipboard,
  detectClipboardTool,
  type ClipboardSpawn,
  type ClipboardWhich,
} from "./clipboard.js";

const ESC = "\x1b";
const BEL = "\x07";

/** which probe that reports a fixed set of tools as available. */
function whichWith(available: string[]): ClipboardWhich {
  const set = new Set(available);
  return (cmd) => set.has(cmd);
}

describe("buildOsc52", () => {
  it("encodes known text to the exact expected base64 + wrapper", () => {
    // base64("hello") === "aGVsbG8="
    expect(buildOsc52("hello")).toBe(`${ESC}]52;c;aGVsbG8=${BEL}`);
  });

  it("base64-encodes UTF-8 (multi-byte) correctly", () => {
    // "café" -> UTF-8 bytes 63 61 66 C3 A9 -> base64 "Y2Fmw6k="
    expect(buildOsc52("café")).toBe(`${ESC}]52;c;Y2Fmw6k=${BEL}`);
  });

  it("emits an empty-clipboard sequence for empty input", () => {
    expect(buildOsc52("")).toBe(`${ESC}]52;c;${BEL}`);
  });

  it("wraps in tmux passthrough when requested (ESC doubled, DCS framed)", () => {
    const raw = buildOsc52("hi");
    const wrapped = buildOsc52("hi", { passthrough: true });
    expect(wrapped).toBe(`${ESC}Ptmux;${raw.replace(/\x1b/g, ESC + ESC)}${ESC}\\`);
    // Sanity: the inner ESC that starts the OSC is doubled.
    expect(wrapped).toContain(`${ESC}Ptmux;${ESC}${ESC}]52;c;`);
  });
});

describe("buildOsc52Result size cap", () => {
  it("refuses payloads beyond the cap by default (no sequence, capped flag)", () => {
    const big = "a".repeat(OSC52_MAX_BYTES + 1);
    const res = buildOsc52Result(big);
    expect(res.ok).toBe(false);
    expect(res.sequence).toBe("");
    expect(res.capped).toBe(true);
    expect(res.truncated).toBe(false);
    expect(res.bytes).toBe(OSC52_MAX_BYTES + 1);
    // The convenience wrapper yields "" for a refused payload.
    expect(buildOsc52(big)).toBe("");
  });

  it("allows a payload exactly at the cap", () => {
    const exact = "a".repeat(OSC52_MAX_BYTES);
    const res = buildOsc52Result(exact);
    expect(res.ok).toBe(true);
    expect(res.capped).toBe(false);
    expect(res.bytes).toBe(OSC52_MAX_BYTES);
  });

  it("truncates over-cap payloads in truncate mode and flags it", () => {
    const big = "a".repeat(OSC52_MAX_BYTES + 500);
    const res = buildOsc52Result(big, { onOversize: "truncate" });
    expect(res.ok).toBe(true);
    expect(res.truncated).toBe(true);
    expect(res.capped).toBe(false);
    expect(res.bytes).toBe(OSC52_MAX_BYTES);
    expect(res.sequence.startsWith(`${ESC}]52;c;`)).toBe(true);
  });

  it("does not split a multi-byte codepoint when truncating", () => {
    // Fill to one byte under the cap with ASCII, then a 2-byte char that
    // would straddle the boundary — it must be dropped whole, not halved.
    const head = "a".repeat(OSC52_MAX_BYTES - 1);
    const res = buildOsc52Result(head + "é" + "é", { onOversize: "truncate" });
    expect(res.ok).toBe(true);
    // The straddling "é" (2 bytes) cannot fit in the remaining 1 byte, so
    // the encoded payload is just the ASCII head.
    expect(res.bytes).toBe(OSC52_MAX_BYTES - 1);
    const b64 = res.sequence.slice(`${ESC}]52;c;`.length, -1);
    expect(Buffer.from(b64, "base64").toString("utf8")).toBe(head);
  });

  it("honours a custom maxBytes", () => {
    expect(buildOsc52Result("abcd", { maxBytes: 3 }).ok).toBe(false);
    expect(buildOsc52Result("abc", { maxBytes: 3 }).ok).toBe(true);
  });
});

describe("detectClipboardTool", () => {
  it("picks pbcopy on darwin", () => {
    const t = detectClipboardTool("darwin", whichWith(["pbcopy"]));
    expect(t?.method).toBe("pbcopy");
    expect(t?.cmd).toBe("pbcopy");
  });

  it("prefers wl-copy over xclip/xsel on linux (Wayland first)", () => {
    const t = detectClipboardTool("linux", whichWith(["wl-copy", "xclip", "xsel"]));
    expect(t?.method).toBe("wl-copy");
  });

  it("falls to xclip then xsel on linux X11", () => {
    expect(detectClipboardTool("linux", whichWith(["xclip", "xsel"]))?.method).toBe("xclip");
    expect(detectClipboardTool("linux", whichWith(["xsel"]))?.method).toBe("xsel");
    expect(detectClipboardTool("linux", whichWith(["xclip", "xsel"]))?.args).toEqual([
      "-selection",
      "clipboard",
    ]);
    expect(detectClipboardTool("linux", whichWith(["xsel"]))?.args).toEqual([
      "--clipboard",
      "--input",
    ]);
  });

  it("reaches clip.exe as a WSL last resort under linux", () => {
    expect(detectClipboardTool("linux", whichWith(["clip.exe"]))?.method).toBe("clip.exe");
  });

  it("picks clip.exe on win32", () => {
    expect(detectClipboardTool("win32", whichWith(["clip.exe"]))?.method).toBe("clip.exe");
  });

  it("returns null when nothing is available or platform is unknown", () => {
    expect(detectClipboardTool("linux", whichWith([]))).toBeNull();
    expect(detectClipboardTool("sunos", whichWith(["pbcopy", "xclip"]))).toBeNull();
  });
});

describe("copyToClipboard", () => {
  it("prefers OSC 52 via emit when a writer is provided", async () => {
    const emit = vi.fn();
    const spawn = vi.fn();
    const res = await copyToClipboard("hello", { emit, spawn });
    expect(res).toEqual({ ok: true, method: "osc52", bytes: 5 });
    expect(emit).toHaveBeenCalledTimes(1);
    expect(emit).toHaveBeenCalledWith(`${ESC}]52;c;aGVsbG8=${BEL}`);
    // Subprocess path must not be touched when OSC 52 succeeds.
    expect(spawn).not.toHaveBeenCalled();
  });

  it("reports UTF-8 byte length, not string length, in bytes", async () => {
    const res = await copyToClipboard("café", { emit: vi.fn() });
    expect(res.method).toBe("osc52");
    expect(res.bytes).toBe(5); // 4 chars, 5 UTF-8 bytes
  });

  it("falls back to the platform subprocess when no emit is given", async () => {
    const spawn: ClipboardSpawn = vi.fn(async () => ({ ok: true }));
    const res = await copyToClipboard("hi", {
      spawn,
      which: whichWith(["xclip"]),
      platform: "linux",
    });
    expect(res).toEqual({ ok: true, method: "xclip", bytes: 2 });
    expect(spawn).toHaveBeenCalledWith("xclip", ["-selection", "clipboard"], "hi");
  });

  it("picks pbcopy on darwin via the subprocess path", async () => {
    const spawn: ClipboardSpawn = vi.fn(async () => ({ ok: true }));
    const res = await copyToClipboard("mac", {
      spawn,
      which: whichWith(["pbcopy"]),
      platform: "darwin",
    });
    expect(res.method).toBe("pbcopy");
    expect(spawn).toHaveBeenCalledWith("pbcopy", [], "mac");
  });

  it("uses wl-copy on a Wayland linux session", async () => {
    const spawn: ClipboardSpawn = vi.fn(async () => ({ ok: true }));
    const res = await copyToClipboard("way", {
      spawn,
      which: whichWith(["wl-copy", "xclip"]),
      platform: "linux",
    });
    expect(res.method).toBe("wl-copy");
    expect(spawn).toHaveBeenCalledWith("wl-copy", [], "way");
  });

  it("uses clip.exe on win32", async () => {
    const spawn: ClipboardSpawn = vi.fn(async () => ({ ok: true }));
    const res = await copyToClipboard("win", {
      spawn,
      which: whichWith(["clip.exe"]),
      platform: "win32",
    });
    expect(res.method).toBe("clip.exe");
    expect(spawn).toHaveBeenCalledWith("clip.exe", [], "win");
  });

  it("falls through from OSC 52 to subprocess when the payload is over the cap", async () => {
    const emit = vi.fn();
    const spawn: ClipboardSpawn = vi.fn(async () => ({ ok: true }));
    const big = "a".repeat(OSC52_MAX_BYTES + 1);
    const res = await copyToClipboard(big, {
      emit,
      spawn,
      which: whichWith(["xclip"]),
      platform: "linux",
    });
    // Oversize for OSC 52 (refuse mode) -> subprocess handles it.
    expect(emit).not.toHaveBeenCalled();
    expect(res.method).toBe("xclip");
    expect(res.ok).toBe(true);
  });

  it("falls through to subprocess when emit throws", async () => {
    const emit = vi.fn(() => {
      throw new Error("write failed");
    });
    const spawn: ClipboardSpawn = vi.fn(async () => ({ ok: true }));
    const res = await copyToClipboard("x", {
      emit,
      spawn,
      which: whichWith(["xclip"]),
      platform: "linux",
    });
    expect(res.method).toBe("xclip");
    expect(res.ok).toBe(true);
  });

  it("returns method:none ok:false when nothing is available (no throw)", async () => {
    const res = await copyToClipboard("nope", {
      spawn: vi.fn(async () => ({ ok: false })),
      which: whichWith([]),
      platform: "linux",
    });
    expect(res).toEqual({ ok: false, method: "none", bytes: 4 });
  });

  it("returns method:none when a spawn is provided but no emit and no tool", async () => {
    const res = await copyToClipboard("x", { platform: "linux", which: whichWith([]) });
    expect(res).toEqual({ ok: false, method: "none", bytes: 1 });
  });

  it("does not throw when the spawn runner rejects", async () => {
    const spawn: ClipboardSpawn = vi.fn(async () => {
      throw new Error("spawn blew up");
    });
    const res = await copyToClipboard("boom", {
      spawn,
      which: whichWith(["xclip"]),
      platform: "linux",
    });
    expect(res).toEqual({ ok: false, method: "none", bytes: 4 });
  });

  it("reports ok:false when the subprocess exits non-zero", async () => {
    const spawn: ClipboardSpawn = vi.fn(async () => ({ ok: false, code: 1 }));
    const res = await copyToClipboard("hi", {
      spawn,
      which: whichWith(["xclip"]),
      platform: "linux",
    });
    expect(res.ok).toBe(false);
    expect(res.method).toBe("none");
  });
});
