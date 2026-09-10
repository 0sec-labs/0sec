import { randomUUID } from "node:crypto";
import { closeSync, constants, fchmodSync, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, parse, resolve, sep } from "node:path";
import { canonicalEvolutionJson } from "./config.js";

const MAX_ARTIFACT_BYTES = 128 * 1024 * 1024;

function hasCode(error: unknown, code: string): boolean {
  return error instanceof Error && "code" in error && error.code === code;
}

function inspectDirectories(path: string, create: boolean): string {
  if (!isAbsolute(path)) throw new Error("evolution storage paths must be absolute");
  const absolute = resolve(path);
  const root = parse(absolute).root;
  let cursor = root;
  for (const component of absolute.slice(root.length).split(sep).filter(Boolean)) {
    cursor = join(cursor, component);
    if (create) {
      try { mkdirSync(cursor, { mode: 0o700 }); }
      catch (error) { if (!hasCode(error, "EEXIST")) throw error; }
    }
    const stat = lstatSync(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`unsafe evolution directory: ${cursor}`);
  }
  const leaf = lstatSync(absolute);
  if ((typeof process.getuid === "function" && leaf.uid !== process.getuid()) || (leaf.mode & 0o077) !== 0) {
    throw new Error(`evolution storage directory must be owner-only: ${absolute}`);
  }
  return absolute;
}

/** Create private storage directories without following symbolic links. */
export function ensureEvolutionDirectory(path: string): string {
  return inspectDirectories(path, true);
}

/** Read a bounded, owner-owned JSON record without following a symbolic link. */
export function readEvolutionArtifact(path: string): unknown {
  inspectDirectories(dirname(path), false);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > MAX_ARTIFACT_BYTES || (stat.mode & 0o077) !== 0
      || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
      throw new Error(`unsafe evolution artifact: ${path}`);
    }
    const value: unknown = JSON.parse(readFileSync(fd, "utf8"));
    canonicalEvolutionJson(value);
    return value;
  } finally { closeSync(fd); }
}

/** Atomically publish once. Replaying identical content is safe; replacement is forbidden. */
export function publishEvolutionArtifact(path: string, value: unknown): void {
  const content = canonicalEvolutionJson(value);
  if (Buffer.byteLength(content) > MAX_ARTIFACT_BYTES) throw new Error("evolution artifact exceeds retention limit");
  const directory = ensureEvolutionDirectory(dirname(path));
  const temporary = join(directory, `.artifact-${randomUUID()}.tmp`);
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    try {
      writeFileSync(fd, content, "utf8");
      fchmodSync(fd, 0o400);
      fsyncSync(fd);
    } finally { closeSync(fd); }
    try { linkSync(temporary, path); }
    catch (error) {
      if (!hasCode(error, "EEXIST")) throw error;
      if (canonicalEvolutionJson(readEvolutionArtifact(path)) !== content) {
        throw new Error(`immutable evolution artifact collision: ${path}`);
      }
    }
    const directoryFd = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  } finally { unlinkSync(temporary); }
}
