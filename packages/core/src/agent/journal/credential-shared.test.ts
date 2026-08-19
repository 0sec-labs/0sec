import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  JOURNAL_SCHEMA_VERSION,
  appendCredentialShared,
  buildCredentialSharedEntry,
  createJournalWriter,
  loadJournal,
  streamJournal,
  type JournalEntry,
} from "./index.js";

let tmpRoot: string;
let id = 0;

function nextId(): string {
  id += 1;
  return `entry-${id}`;
}

function fixedNow(): Date {
  return new Date("2026-06-02T12:00:00.000Z");
}

async function collectStream(path: string): Promise<JournalEntry[]> {
  const entries: JournalEntry[] = [];
  for await (const entry of streamJournal(path)) {
    entries.push(entry);
  }
  return entries;
}

const RECORD = {
  sourceTarget: "web-01.internal",
  destTarget: "db-01.internal",
  credentialKind: "password",
  originatingFindingId: "F-12",
  rationale: "DB password leaked by F-12 also authenticated to db-01",
  turn: 7,
} as const;

describe("credential_shared journal kind", () => {
  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), "pwnkit-cred-shared-"));
    id = 0;
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("builds an input carrying the four chain-attribution fields", () => {
    expect(buildCredentialSharedEntry(RECORD)).toEqual({
      kind: "credential_shared",
      sourceTarget: "web-01.internal",
      destTarget: "db-01.internal",
      credentialKind: "password",
      originatingFindingId: "F-12",
      rationale: "DB password leaked by F-12 also authenticated to db-01",
      turn: 7,
    });
  });

  it("omits optional fields when absent and trims whitespace", () => {
    expect(
      buildCredentialSharedEntry({
        sourceTarget: "  a  ",
        destTarget: "b ",
        credentialKind: " ssh_key",
        originatingFindingId: "F-1 ",
      }),
    ).toEqual({
      kind: "credential_shared",
      sourceTarget: "a",
      destTarget: "b",
      credentialKind: "ssh_key",
      originatingFindingId: "F-1",
    });
  });

  it.each([
    ["sourceTarget", { ...RECORD, sourceTarget: "  " }],
    ["destTarget", { ...RECORD, destTarget: "" }],
    ["credentialKind", { ...RECORD, credentialKind: "" }],
    ["originatingFindingId", { ...RECORD, originatingFindingId: "  " }],
  ])("rejects a missing %s", (field, record) => {
    expect(() => buildCredentialSharedEntry(record)).toThrow(field);
  });

  it("serializes to journal.jsonl and rehydrates byte-for-byte", async () => {
    const writer = createJournalWriter({
      runId: "run-cred",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });

    appendCredentialShared(writer, RECORD);

    const expected = {
      schemaVersion: JOURNAL_SCHEMA_VERSION,
      id: "entry-1",
      runId: "run-cred",
      seq: 0,
      timestamp: "2026-06-02T12:00:00.000Z",
      kind: "credential_shared",
      sourceTarget: "web-01.internal",
      destTarget: "db-01.internal",
      credentialKind: "password",
      originatingFindingId: "F-12",
      rationale: "DB password leaked by F-12 also authenticated to db-01",
      turn: 7,
    };

    const lines = readFileSync(writer.paths.journalPath, "utf8").trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]!)).toEqual(expected);

    // Sync load and async stream rehydration both round-trip the new kind.
    expect(writer.load()).toEqual([expected]);
    expect(await collectStream(writer.paths.journalPath)).toEqual([expected]);
  });
});
