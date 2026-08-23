import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  DEFAULT_PRUNE_KEEP,
  deleteSession,
  isValidSessionId,
  listSessions,
  loadSession,
  pruneSessions,
  relativeAge,
  saveSession,
  sessionsDir,
  type StoredSession,
} from "./session-store.js";

/** Temp homes created by a test, torn down after it regardless of outcome. */
const tempHomes: string[] = [];

function makeHome(): string {
  const dir = mkdtempSync(join(tmpdir(), "0sec-session-store-"));
  tempHomes.push(dir);
  return dir;
}

/** Permission bits only — the file-type bits in `mode` are not ours to assert. */
function permissionsOf(path: string): number {
  return statSync(path).mode & 0o777;
}

/**
 * A complete session. Time is a parameter here for the same reason it is a
 * parameter in the module: every ordering assertion below is exact, not
 * "roughly now".
 */
function makeSession(overrides: Partial<StoredSession> = {}): StoredSession {
  return {
    id: "console-1111",
    savedAt: 1_000,
    target: "https://target.example",
    model: "claude-opus-4",
    mode: "guided",
    cwd: "/work/project-a",
    messageCount: 2,
    preview: "scan the login flow",
    messages: [
      { role: "user", content: [{ type: "text", text: "scan the login flow" }] },
      { role: "assistant", content: [{ type: "text", text: "starting recon" }] },
    ],
    ...overrides,
  };
}

afterEach(() => {
  while (tempHomes.length > 0) {
    const dir = tempHomes.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

describe("sessionsDir", () => {
  it("places transcripts inside the shared 0sec state directory", () => {
    expect(sessionsDir("/home/someone")).toBe("/home/someone/.0sec/console-sessions");
  });

  it("defaults the home directory when none is given", () => {
    expect(sessionsDir().endsWith(join(".0sec", "console-sessions"))).toBe(true);
  });
});

describe("save/load round-trip", () => {
  it("returns the stored session verbatim", () => {
    const home = makeHome();
    const session = makeSession();

    expect(saveSession(session, home)).toBe(true);
    expect(loadSession(session.id, home)).toEqual(session);
  });

  it("writes one file per session so a bad one cannot take out the rest", () => {
    const home = makeHome();
    saveSession(makeSession({ id: "console-a" }), home);
    saveSession(makeSession({ id: "console-b" }), home);

    expect(loadSession("console-a", home)?.id).toBe("console-a");
    expect(loadSession("console-b", home)?.id).toBe("console-b");
  });

  it("recomputes messageCount from the transcript rather than trusting the caller", () => {
    const home = makeHome();
    // A listing that overstates the transcript would send an operator to resume
    // a session that has less context than the row promised.
    saveSession(makeSession({ messageCount: 999 }), home);

    expect(loadSession("console-1111", home)?.messageCount).toBe(2);
  });

  it("keeps the caller's savedAt exactly — the clock is never read here", () => {
    const home = makeHome();
    saveSession(makeSession({ savedAt: 42 }), home);

    expect(loadSession("console-1111", home)?.savedAt).toBe(42);
    // Determinism: an identical input produces an identical file, forever.
    const first = readFileSync(join(sessionsDir(home), "console-1111.json"), "utf8");
    saveSession(makeSession({ savedAt: 42 }), home);
    expect(readFileSync(join(sessionsDir(home), "console-1111.json"), "utf8")).toBe(first);
  });
});

describe("permissions", () => {
  it("creates the directory 0700 and the file 0600", () => {
    const home = makeHome();
    saveSession(makeSession(), home);

    expect(permissionsOf(sessionsDir(home))).toBe(0o700);
    expect(permissionsOf(join(sessionsDir(home), "console-1111.json"))).toBe(0o600);
  });

  it("tightens an already-loose directory and file instead of trusting them", () => {
    const home = makeHome();
    const dir = sessionsDir(home);
    mkdirSync(dir, { recursive: true, mode: 0o755 });
    writeFileSync(join(dir, "console-1111.json"), "{}", { mode: 0o644 });

    expect(saveSession(makeSession(), home)).toBe(true);
    expect(permissionsOf(dir)).toBe(0o700);
    expect(permissionsOf(join(dir, "console-1111.json"))).toBe(0o600);
  });
});

describe("listSessions", () => {
  it("returns nothing when the store has never been written", () => {
    expect(listSessions(makeHome())).toEqual([]);
  });

  it("sorts newest-first and omits the transcript bodies", () => {
    const home = makeHome();
    saveSession(makeSession({ id: "console-old", savedAt: 100 }), home);
    saveSession(makeSession({ id: "console-new", savedAt: 300 }), home);
    saveSession(makeSession({ id: "console-mid", savedAt: 200 }), home);

    const listed = listSessions(home);
    expect(listed.map((meta) => meta.id)).toEqual(["console-new", "console-mid", "console-old"]);
    expect(listed[0]).not.toHaveProperty("messages");
    expect(listed[0]?.messageCount).toBe(2);
  });

  it("filters by cwd so project B's engagements stay out of project A", () => {
    const home = makeHome();
    saveSession(makeSession({ id: "console-a", cwd: "/work/project-a" }), home);
    saveSession(makeSession({ id: "console-b", cwd: "/work/project-b" }), home);

    expect(listSessions(home, { cwd: "/work/project-a" }).map((m) => m.id)).toEqual(["console-a"]);
    expect(listSessions(home, { cwd: "/work/nowhere" })).toEqual([]);
    expect(listSessions(home)).toHaveLength(2);
  });

  it("applies the limit after sorting, so it keeps the newest", () => {
    const home = makeHome();
    saveSession(makeSession({ id: "console-old", savedAt: 100 }), home);
    saveSession(makeSession({ id: "console-new", savedAt: 300 }), home);

    expect(listSessions(home, { limit: 1 }).map((m) => m.id)).toEqual(["console-new"]);
    expect(listSessions(home, { limit: 0 })).toEqual([]);
  });

  it("skips corrupt, foreign and unparseable files while still listing the good ones", () => {
    const home = makeHome();
    saveSession(makeSession({ id: "console-good", savedAt: 500 }), home);
    const dir = sessionsDir(home);
    writeFileSync(join(dir, "console-truncated.json"), '{"messages":[{"role":"user"');
    writeFileSync(join(dir, "console-notobject.json"), '"just a string"');
    writeFileSync(join(dir, "console-nomessages.json"), '{"savedAt":900,"cwd":"/work"}');
    writeFileSync(join(dir, "notes.txt"), "not ours");
    writeFileSync(join(dir, ".hidden.json"), '{"messages":[]}');

    expect(listSessions(home).map((m) => m.id)).toEqual(["console-good"]);
  });

  it("orders sessions saved in the same millisecond deterministically", () => {
    const home = makeHome();
    saveSession(makeSession({ id: "console-b", savedAt: 7 }), home);
    saveSession(makeSession({ id: "console-a", savedAt: 7 }), home);

    expect(listSessions(home).map((m) => m.id)).toEqual(["console-a", "console-b"]);
  });

  it("strips control characters from a preview before it reaches the terminal", () => {
    const home = makeHome();
    const dir = sessionsDir(home);
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "console-evil.json"),
      JSON.stringify({ savedAt: 1, cwd: "/w", preview: "safe\u001B[2Jwiped\nline", messages: [] }),
    );

    expect(listSessions(home)[0]?.preview).toBe("safe [2Jwiped line");
  });
});

describe("loadSession validation", () => {
  it("returns null for an id that was never saved", () => {
    expect(loadSession("console-missing", makeHome())).toBeNull();
  });

  it.each([
    ["a string", '{"messages":"one two three","cwd":"/w"}'],
    ["an object", '{"messages":{"0":{"role":"user"}},"cwd":"/w"}'],
    ["null", '{"messages":null,"cwd":"/w"}'],
    ["absent", '{"cwd":"/w","savedAt":1}'],
    ["not JSON at all", "{{{"],
  ])("returns null rather than a half-session when messages is %s", (_label, contents) => {
    const home = makeHome();
    mkdirSync(sessionsDir(home), { recursive: true });
    writeFileSync(join(sessionsDir(home), "console-bad.json"), contents);

    expect(loadSession("console-bad", home)).toBeNull();
  });

  it("repairs the metadata around a valid transcript instead of rejecting it", () => {
    const home = makeHome();
    mkdirSync(sessionsDir(home), { recursive: true });
    writeFileSync(
      join(sessionsDir(home), "console-odd.json"),
      JSON.stringify({ savedAt: "yesterday", cwd: 7, target: 12, messages: [{ role: "user" }] }),
    );

    expect(loadSession("console-odd", home)).toEqual({
      id: "console-odd",
      savedAt: 0,
      cwd: "",
      messageCount: 1,
      preview: "",
      messages: [{ role: "user" }],
    });
  });

  it("takes the id from the filename, not from a body that drifted", () => {
    const home = makeHome();
    saveSession(makeSession({ id: "console-real" }), home);
    // A row a listing shows must be a row `loadSession` can open.
    expect(loadSession("console-real", home)?.id).toBe("console-real");
    expect(listSessions(home)[0]?.id).toBe("console-real");
  });
});

describe("session id validation", () => {
  const hostile = [
    "../../../etc/passwd",
    "..",
    ".",
    "../escape",
    "sub/dir",
    "back\\slash",
    ".hidden",
    "",
    "with space",
    "a".repeat(200),
  ];

  it.each(hostile)("rejects %j", (id) => {
    expect(isValidSessionId(id)).toBe(false);
  });

  it.each(["console-1", "abc.def_ghi-123", "0"])("accepts %j", (id) => {
    expect(isValidSessionId(id)).toBe(true);
  });

  it("refuses to write outside the store for a traversal id", () => {
    const home = makeHome();
    const outside = join(home, "escaped.json");

    expect(saveSession(makeSession({ id: "../escaped" }), home)).toBe(false);
    expect(() => statSync(outside)).toThrow();
    // The whole store stays untouched, not merely the target path.
    expect(() => statSync(sessionsDir(home))).toThrow();
  });

  it("returns null/false for traversal ids on every read path", () => {
    const home = makeHome();
    saveSession(makeSession(), home);

    expect(loadSession("../../etc/passwd", home)).toBeNull();
    expect(deleteSession("../console-1111", home)).toBe(false);
    // The real session is still there: nothing was resolved outside the store.
    expect(loadSession("console-1111", home)).not.toBeNull();
  });
});

describe("deleteSession", () => {
  it("removes the transcript and reports that it did", () => {
    const home = makeHome();
    saveSession(makeSession(), home);

    expect(deleteSession("console-1111", home)).toBe(true);
    expect(loadSession("console-1111", home)).toBeNull();
    expect(listSessions(home)).toEqual([]);
  });

  it("reports false for a session that was never there", () => {
    expect(deleteSession("console-missing", makeHome())).toBe(false);
  });

  it("deletes a corrupt transcript, which loadSession would refuse to open", () => {
    const home = makeHome();
    mkdirSync(sessionsDir(home), { recursive: true });
    writeFileSync(join(sessionsDir(home), "console-bad.json"), "{{{");

    expect(loadSession("console-bad", home)).toBeNull();
    expect(deleteSession("console-bad", home)).toBe(true);
    expect(() => statSync(join(sessionsDir(home), "console-bad.json"))).toThrow();
  });
});

describe("pruneSessions", () => {
  function seed(home: string, count: number): void {
    for (let i = 0; i < count; i += 1) {
      saveSession(makeSession({ id: `console-${String(i).padStart(3, "0")}`, savedAt: i }), home);
    }
  }

  it("keeps the newest N and returns how many it removed", () => {
    const home = makeHome();
    seed(home, 5);

    expect(pruneSessions(home, { keep: 2 })).toBe(3);
    expect(listSessions(home).map((m) => m.id)).toEqual(["console-004", "console-003"]);
  });

  it("removes nothing when the store is already within the limit", () => {
    const home = makeHome();
    seed(home, 2);

    expect(pruneSessions(home, { keep: 5 })).toBe(0);
    expect(listSessions(home)).toHaveLength(2);
  });

  it("keeps DEFAULT_PRUNE_KEEP when the caller names no limit", () => {
    const home = makeHome();
    seed(home, DEFAULT_PRUNE_KEEP + 3);

    expect(pruneSessions(home)).toBe(3);
    expect(listSessions(home)).toHaveLength(DEFAULT_PRUNE_KEEP);
  });

  it("clears the store when asked to keep none", () => {
    const home = makeHome();
    seed(home, 3);

    expect(pruneSessions(home, { keep: 0 })).toBe(3);
    expect(listSessions(home)).toEqual([]);
  });

  it("treats a nonsense keep as the default rather than deleting everything", () => {
    const home = makeHome();
    seed(home, 3);

    expect(pruneSessions(home, { keep: Number.NaN })).toBe(0);
    expect(pruneSessions(home, { keep: -1 })).toBe(3);
  });

  it("prunes across working directories, since the footprint is global", () => {
    const home = makeHome();
    saveSession(makeSession({ id: "console-a", cwd: "/work/a", savedAt: 1 }), home);
    saveSession(makeSession({ id: "console-b", cwd: "/work/b", savedAt: 2 }), home);

    expect(pruneSessions(home, { keep: 1 })).toBe(1);
    expect(listSessions(home).map((m) => m.id)).toEqual(["console-b"]);
  });

  it("returns 0 on an empty store instead of throwing", () => {
    expect(pruneSessions(makeHome(), { keep: 1 })).toBe(0);
  });
});

describe("relativeAge", () => {
  const NOW = 10_000_000_000; // a fixed, arbitrary "now" so every case is exact.
  const S = 1_000;
  const M = 60 * S;
  const H = 60 * M;
  const D = 24 * H;
  const W = 7 * D;

  it.each([
    ["seconds just after saving", NOW - 0, "0s"],
    ["seconds", NOW - 5 * S, "5s"],
    ["the last second before a minute", NOW - 59 * S, "59s"],
    ["the minute boundary", NOW - 60 * S, "1m"],
    ["minutes", NOW - 45 * M, "45m"],
    ["the last minute before an hour", NOW - 59 * M, "59m"],
    ["the hour boundary", NOW - 60 * M, "1h"],
    ["hours", NOW - 5 * H, "5h"],
    ["the last hour before a day", NOW - 23 * H, "23h"],
    ["the day boundary", NOW - 24 * H, "1d"],
    ["days", NOW - 3 * D, "3d"],
    ["the last day before a week", NOW - 6 * D, "6d"],
    ["the week boundary", NOW - 7 * D, "1w"],
    ["weeks", NOW - 5 * W, "5w"],
  ])("formats %s as %s", (_label, savedAt, expected) => {
    expect(relativeAge(savedAt, NOW)).toBe(expected);
  });

  it("clamps a future savedAt (clock skew) to 0s rather than going negative", () => {
    expect(relativeAge(NOW + 10 * S, NOW)).toBe("0s");
  });

  it("returns '' for the unorderable sentinel and non-finite input", () => {
    // savedAt 0 is `toMeta`'s fallback for a file with no usable timestamp; the
    // picker omits the separator rather than printing a fabricated age.
    expect(relativeAge(0, NOW)).toBe("");
    expect(relativeAge(-1, NOW)).toBe("");
    expect(relativeAge(Number.NaN, NOW)).toBe("");
    expect(relativeAge(Number.POSITIVE_INFINITY, NOW)).toBe("");
  });

  it("is pure: the same inputs always yield the same string", () => {
    expect(relativeAge(NOW - 3 * H, NOW)).toBe(relativeAge(NOW - 3 * H, NOW));
  });
});

describe("I/O failure is a return value, never an exception", () => {
  it("returns false when the store path cannot be a directory", () => {
    const home = makeHome();
    // A regular file where the store directory belongs: mkdir fails with
    // ENOTDIR, which must surface as "could not save", not as a crashed TUI.
    mkdirSync(join(home, ".0sec"), { recursive: true });
    writeFileSync(sessionsDir(home), "in the way");

    expect(saveSession(makeSession(), home)).toBe(false);
    expect(listSessions(home)).toEqual([]);
    expect(loadSession("console-1111", home)).toBeNull();
    expect(deleteSession("console-1111", home)).toBe(false);
    expect(pruneSessions(home)).toBe(0);
  });

  it("returns false for a session whose messages field is not an array", () => {
    const home = makeHome();
    const broken = { ...makeSession(), messages: "not an array" } as unknown as StoredSession;

    expect(saveSession(broken, home)).toBe(false);
    expect(listSessions(home)).toEqual([]);
  });

  it("survives a null-ish session object", () => {
    const home = makeHome();
    expect(saveSession(undefined as unknown as StoredSession, home)).toBe(false);
    expect(saveSession(null as unknown as StoredSession, home)).toBe(false);
  });
});
