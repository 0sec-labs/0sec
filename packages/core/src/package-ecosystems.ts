import { execFileSync, execSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import type { NpmAuditFinding, Severity } from "@pwnkit/shared";
import type { ScanListener } from "./scanner.js";
import { restoreHistoricalPackageFixture, shouldUseHistoricalPackageFallback } from "./historical-package-fallback.js";
import { bufferToString } from "./shared-analysis.js";
import type { RegistryProbeResult, TransitivePackage } from "./malicious-detector.js";

/**
 * Heuristic to spot npm's ERESOLVE peer-dependency conflict from a captured
 * stderr blob. npm tags every line of the failure with `npm error code
 * ERESOLVE` (or `npm ERR! code ERESOLVE` on older versions), and the human-
 * readable summary line starts with `npm error ERESOLVE`. Match either case-
 * insensitively so older + newer npms both trigger the fallback. Kept loose
 * on purpose — a substring match is enough; we don't want to over-fit to a
 * specific npm version's exact wording.
 */
function stderrLooksLikeEresolve(stderr: string): boolean {
  return /ERESOLVE/i.test(stderr);
}

/** Extract the stderr text from a SpawnSyncReturns-shaped error. */
function extractStderr(err: unknown): string {
  if (!err || typeof err !== "object") return "";
  const raw = (err as { stderr?: Buffer | string | null }).stderr;
  if (!raw) return "";
  if (typeof raw === "string") return raw;
  try {
    return raw.toString("utf-8");
  } catch {
    return String(raw);
  }
}

export type PackageEcosystem = "npm" | "pypi" | "cargo" | "oci";

export interface InstalledPackage {
  ecosystem: PackageEcosystem;
  name: string;
  version: string;
  path: string;
  tempDir: string;
}

export function normalizeSeverity(value: string | undefined): Severity {
  switch ((value ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

export function formatFixAvailable(
  fixAvailable: boolean | { name?: string; version?: string } | string | undefined,
): boolean | string {
  if (typeof fixAvailable === "string" || typeof fixAvailable === "boolean") {
    return fixAvailable;
  }
  if (fixAvailable && typeof fixAvailable === "object") {
    const next = [fixAvailable.name, fixAvailable.version].filter(Boolean).join("@");
    return next || true;
  }
  return false;
}

export function parseNpmAuditOutput(rawOutput: string): NpmAuditFinding[] {
  if (!rawOutput.trim()) return [];

  try {
    const raw = JSON.parse(rawOutput) as {
      vulnerabilities?: Record<
        string,
        {
          name?: string;
          severity?: string;
          via?: Array<string | Record<string, unknown>>;
          range?: string;
          fixAvailable?: boolean | { name?: string; version?: string } | string;
        }
      >;
    };

    return Object.entries(raw.vulnerabilities ?? {}).map(([pkgName, vuln]) => {
      const via = (vuln.via ?? []).map((entry) => {
        if (typeof entry === "string") return entry;
        const source = typeof entry.source === "number" ? `GHSA:${entry.source}` : null;
        const title = typeof entry.title === "string" ? entry.title : null;
        const name = typeof entry.name === "string" ? entry.name : null;
        return [name, title, source].filter(Boolean).join(" - ") || "unknown advisory";
      });

      const firstObjectVia = (vuln.via ?? []).find(
        (entry): entry is Record<string, unknown> => typeof entry === "object" && entry !== null,
      );

      return {
        name: vuln.name ?? pkgName,
        severity: normalizeSeverity(vuln.severity),
        title:
          (typeof firstObjectVia?.title === "string" && firstObjectVia.title) ||
          via[0] ||
          "npm audit advisory",
        range: vuln.range,
        source:
          typeof firstObjectVia?.source === "number" || typeof firstObjectVia?.source === "string"
            ? (firstObjectVia.source as number | string)
            : undefined,
        url: typeof firstObjectVia?.url === "string" ? firstObjectVia.url : undefined,
        via,
        fixAvailable: formatFixAvailable(vuln.fixAvailable),
      };
    });
  } catch {
    return [];
  }
}

interface OsvVulnerability {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ score?: string }>;
  database_specific?: { severity?: string };
  references?: Array<{ url?: string }>;
  affected?: Array<{
    ranges?: Array<{
      type?: string;
      events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
  }>;
}

function osvEcosystemName(ecosystem: PackageEcosystem): string | null {
  if (ecosystem === "npm") return "npm";
  if (ecosystem === "pypi") return "PyPI";
  if (ecosystem === "cargo") return "crates.io";
  return null;
}

function parseCvssVectorSeverity(score: string | undefined): Severity | undefined {
  if (!score) return undefined;
  const match = score.match(/CVSS:\d\.\d\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/([^/]+)/i);
  const label = match?.[1]?.toUpperCase();
  if (label === "CRITICAL") return "critical";
  if (label === "HIGH") return "high";
  if (label === "MEDIUM") return "medium";
  if (label === "LOW") return "low";
  return undefined;
}

function extractOsvSeverity(vuln: OsvVulnerability): Severity {
  const databaseSeverity = vuln.database_specific?.severity;
  if (typeof databaseSeverity === "string" && databaseSeverity.length > 0) {
    return normalizeSeverity(databaseSeverity);
  }
  for (const severity of vuln.severity ?? []) {
    const parsed = parseCvssVectorSeverity(severity.score);
    if (parsed) return parsed;
  }
  return "medium";
}

function extractOsvRange(vuln: OsvVulnerability): string | undefined {
  const segments: string[] = [];
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      if (range.type && range.type !== "SEMVER") continue;
      const events = (range.events ?? []).flatMap((event) => {
        const parts: string[] = [];
        if (event.introduced) parts.push(`introduced:${event.introduced}`);
        if (event.fixed) parts.push(`fixed:${event.fixed}`);
        if (event.last_affected) parts.push(`last_affected:${event.last_affected}`);
        return parts;
      });
      if (events.length > 0) segments.push(events.join(","));
    }
  }
  return segments.length > 0 ? segments.join(" | ") : undefined;
}

function extractOsvFix(vuln: OsvVulnerability): boolean | string {
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return false;
}

function parseOsvOutput(packageName: string, rawOutput: string): NpmAuditFinding[] {
  if (!rawOutput.trim()) return [];
  try {
    const parsed = JSON.parse(rawOutput) as { vulns?: OsvVulnerability[] };
    return (parsed.vulns ?? []).map((vuln) => {
      const aliases = [...new Set([vuln.id, ...(vuln.aliases ?? [])].filter(Boolean) as string[])];
      const source = aliases[0];
      return {
        name: packageName,
        severity: extractOsvSeverity(vuln),
        title:
          (typeof vuln.summary === "string" && vuln.summary.trim()) ||
          (typeof vuln.details === "string" && vuln.details.trim().slice(0, 120)) ||
          source ||
          "OSV advisory",
        range: extractOsvRange(vuln),
        source,
        url: vuln.references?.find((ref) => typeof ref.url === "string")?.url,
        via: aliases.length > 0 ? aliases : ["OSV"],
        fixAvailable: extractOsvFix(vuln),
      };
    });
  } catch {
    return [];
  }
}

function queryOsvAdvisoriesSync(
  ecosystem: PackageEcosystem,
  packageName: string,
  version: string,
): NpmAuditFinding[] {
  const osvEcosystem = osvEcosystemName(ecosystem);
  if (!osvEcosystem || !packageName || !version || version === "unknown") return [];

  const body = JSON.stringify({
    package: {
      ecosystem: osvEcosystem,
      name: packageName,
    },
    version,
  });
  try {
    const rawOutput = execFileSync(
      "curl",
      [
        "-fsSL",
        "--retry",
        "3",
        "--retry-all-errors",
        "--retry-delay",
        "1",
        "--connect-timeout",
        "20",
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
        "--data-binary",
        "@-",
        "https://api.osv.dev/v1/query",
      ],
      {
        input: body,
        encoding: "utf8",
        timeout: 60_000,
        stdio: ["pipe", "pipe", "ignore"],
      },
    );
    return parseOsvOutput(packageName, rawOutput);
  } catch {
    return [];
  }
}

function splitPackageSpec(rawPackageName: string, requestedVersion: string | undefined): {
  packageName: string;
  version: string | undefined;
} {
  let packageName = rawPackageName;
  let version = requestedVersion;
  const atIdx = rawPackageName.startsWith("@")
    ? rawPackageName.indexOf("@", 1)
    : rawPackageName.indexOf("@");
  if (atIdx > 0) {
    packageName = rawPackageName.slice(0, atIdx);
    version = version ?? rawPackageName.slice(atIdx + 1);
  }
  return { packageName, version };
}

function writeMinimalPackageJson(tempDir: string): void {
  execFileSync("npm", ["init", "-y", "--silent"], {
    cwd: tempDir,
    timeout: 15_000,
    stdio: "pipe",
  });
}

function restoreNpmFixtureOrThrow(
  packageName: string,
  tempDir: string,
  msg: string,
  emit: ScanListener,
): InstalledPackage | never {
  if (shouldUseHistoricalPackageFallback(msg)) {
    const restored = restoreHistoricalPackageFixture(packageName, tempDir, emit);
    if (restored) {
      return {
        ecosystem: "npm",
        ...restored,
        tempDir,
      };
    }
  }
  rmSync(tempDir, { recursive: true, force: true });
  throw new Error(msg);
}

function installNpmPackage(
  packageName: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): InstalledPackage {
  const tempDir = join(tmpdir(), `pwnkit-audit-${randomUUID().slice(0, 8)}`);
  mkdirSync(tempDir, { recursive: true });

  const spec = requestedVersion ? `${packageName}@${requestedVersion}` : `${packageName}@latest`;
  emit({ type: "stage:start", stage: "discovery", message: `Installing ${spec}...` });

  try {
    writeMinimalPackageJson(tempDir);
    try {
      execFileSync("npm", ["install", spec, "--ignore-scripts", "--no-audit", "--no-fund"], {
        cwd: tempDir,
        timeout: 120_000,
        stdio: "pipe",
      });
    } catch (firstErr) {
      // Modern AI/JS packages (e.g. @langchain/community) routinely ship
      // mutually-incompatible peer-dependency ranges with their optional
      // peers (@getzep/zep-cloud pins @langchain/core<0.4.0 while
      // @langchain/community itself requires @langchain/core>=1.1.38).
      // npm >=7 refuses these by default with ERESOLVE. We don't want
      // --legacy-peer-deps on the happy path (it masks real bugs), but
      // on a genuine peer-cycle the install is unrecoverable without it
      // and the audit pipeline currently aborts with status 2 and zero
      // findings. Retry once, narrowly, when stderr looks like ERESOLVE.
      const firstStderr = extractStderr(firstErr);
      if (!stderrLooksLikeEresolve(firstStderr)) {
        throw firstErr;
      }

      emit({
        type: "stage:start",
        stage: "discovery",
        message: `npm install ${spec} hit ERESOLVE peer conflict — retrying with --legacy-peer-deps`,
      });

      // --legacy-peer-deps must precede the install spec so npm parses it
      // as a global flag, mirroring the recommended invocation in npm's
      // own ERESOLVE error output.
      execFileSync(
        "npm",
        ["install", "--legacy-peer-deps", spec, "--ignore-scripts", "--no-audit", "--no-fund"],
        {
          cwd: tempDir,
          timeout: 120_000,
          stdio: "pipe",
        },
      );

      // Surface the fallback so the operator sees it in the findings UI.
      // Mirrors the `warnings.push({ stage: "prepare", message: ... })`
      // shape in unified-pipeline; emitting on the legacy event channel
      // is the only mechanism available to this leaf helper, and the
      // cloud relay forwards `stage:end` messages into the scan report.
      emit({
        type: "stage:end",
        stage: "prepare",
        message: `Installed ${spec} with --legacy-peer-deps fallback (peer-dep conflict in upstream package; advisories were still collected, but transitive peer ranges may be inconsistent).`,
      });
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return restoreNpmFixtureOrThrow(packageName, tempDir, `Failed to install ${spec}: ${msg}`, emit);
  }

  const pkgJsonPath = join(tempDir, "node_modules", packageName, "package.json");
  if (!existsSync(pkgJsonPath)) {
    rmSync(tempDir, { recursive: true, force: true });
    throw new Error(`Package ${packageName} not found after install. Check the package name.`);
  }

  const pkgJson = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
  const installedVersion = pkgJson.version as string;
  const packagePath = join(tempDir, "node_modules", packageName);

  emit({ type: "stage:end", stage: "discovery", message: `Installed ${packageName}@${installedVersion}` });
  return {
    ecosystem: "npm",
    name: packageName,
    version: installedVersion,
    path: packagePath,
    tempDir,
  };
}

function extractSingleArchive(archivePath: string, outputDir: string): void {
  execFileSync(
    "python3",
    ["-c", `
import pathlib, tarfile, zipfile, sys
archive = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
name = archive.name
if name.endswith((".whl", ".zip")):
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(out)
else:
    with tarfile.open(archive) as tf:
        tf.extractall(out)
`, archivePath, outputDir],
    { stdio: "pipe", timeout: 60_000 },
  );
}

function pickPythonScopePath(extractRoot: string): string {
  const entries = readdirSync(extractRoot)
    .map((name) => join(extractRoot, name))
    .filter((abs) => existsSync(abs) && statSync(abs).isDirectory());
  return entries.length === 1 ? entries[0]! : extractRoot;
}

function readPythonVersionFromMetadata(scopePath: string): string | undefined {
  const candidates: string[] = [];
  const stack = [scopePath];

  while (stack.length > 0) {
    const current = stack.pop()!;
    let entries: string[] = [];
    try {
      entries = readdirSync(current);
    } catch {
      continue;
    }
    for (const entry of entries) {
      const abs = join(current, entry);
      let st;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (entry.endsWith(".dist-info")) {
          candidates.push(join(abs, "METADATA"));
        } else {
          stack.push(abs);
        }
      } else if (entry === "PKG-INFO") {
        candidates.push(abs);
      }
    }
  }

  for (const metadataPath of candidates) {
    if (!existsSync(metadataPath)) continue;
    const content = readFileSync(metadataPath, "utf8");
    const match = content.match(/^Version:\s*(.+)$/m);
    if (match?.[1]) return match[1].trim();
  }

  return undefined;
}

function readPythonVersionFromArchiveName(packageName: string, archivePath: string): string | undefined {
  const filename = archivePath.split("/").pop() ?? "";
  const stem = filename.replace(/\.(?:tar\.gz|zip|whl)$/i, "");
  const normalized = packageName.replace(/-/g, "_");
  for (const prefix of [`${packageName}-`, `${normalized}-`]) {
    if (!stem.startsWith(prefix)) continue;
    const rest = stem.slice(prefix.length);
    const version = rest.split("-")[0];
    if (version) return version;
  }
  return undefined;
}

function downloadPypiArchive(
  packageName: string,
  requestedVersion: string | undefined,
  downloadDir: string,
): { archivePath: string; resolvedVersion: string } {
  const script = String.raw`
import json, pathlib, sys, urllib.parse, urllib.request

package_name = sys.argv[1]
requested_version = sys.argv[2] or None
download_dir = pathlib.Path(sys.argv[3])
download_dir.mkdir(parents=True, exist_ok=True)
encoded_name = urllib.parse.quote(package_name, safe="")
if requested_version:
    encoded_version = urllib.parse.quote(requested_version, safe="")
    metadata_url = f"https://pypi.org/pypi/{encoded_name}/{encoded_version}/json"
else:
    metadata_url = f"https://pypi.org/pypi/{encoded_name}/json"

with urllib.request.urlopen(metadata_url, timeout=60) as response:
    metadata = json.load(response)

urls = metadata.get("urls") or []
sdists = [item for item in urls if item.get("packagetype") == "sdist"]
wheels = [item for item in urls if item.get("packagetype") == "bdist_wheel"]
choices = sdists + wheels
if not choices:
    raise SystemExit(f"no downloadable sdist or wheel for {package_name}")

choice = choices[0]
filename = choice.get("filename") or pathlib.PurePosixPath(urllib.parse.urlparse(choice["url"]).path).name
archive_path = download_dir / filename
request = urllib.request.Request(choice["url"], headers={"User-Agent": "pwnkit-ci/0.1 (+https://github.com/0sec-labs/pwnkit)"})
with urllib.request.urlopen(request, timeout=120) as response, archive_path.open("wb") as handle:
    handle.write(response.read())

print(json.dumps({"archivePath": str(archive_path), "resolvedVersion": metadata.get("info", {}).get("version") or requested_version or "unknown"}))
`;
  const rawOutput = execFileSync(
    "python3",
    ["-c", script, packageName, requestedVersion ?? "", downloadDir],
    {
      encoding: "utf8",
      timeout: 180_000,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  return JSON.parse(rawOutput) as { archivePath: string; resolvedVersion: string };
}

function installPypiPackage(
  packageName: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): InstalledPackage {
  const tempDir = join(tmpdir(), `pwnkit-audit-${randomUUID().slice(0, 8)}`);
  const downloadDir = join(tempDir, "downloads");
  const extractDir = join(tempDir, "src");
  mkdirSync(downloadDir, { recursive: true });
  mkdirSync(extractDir, { recursive: true });

  const spec = requestedVersion ? `${packageName}==${requestedVersion}` : packageName;
  emit({ type: "stage:start", stage: "discovery", message: `Downloading PyPI package ${spec}...` });

  let archivePath: string;
  let installedVersion: string | undefined = requestedVersion;
  try {
    const downloaded = downloadPypiArchive(packageName, requestedVersion, downloadDir);
    archivePath = downloaded.archivePath;
    installedVersion = downloaded.resolvedVersion;
  } catch (err) {
    rmSync(tempDir, { recursive: true, force: true });
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to download ${spec} from PyPI: ${msg}`);
  }

  extractSingleArchive(archivePath, extractDir);
  const scopePath = pickPythonScopePath(extractDir);

  const pyprojectPath = join(scopePath, "pyproject.toml");
  const setupPyPath = join(scopePath, "setup.py");
  if (!installedVersion && existsSync(pyprojectPath)) {
    const content = readFileSync(pyprojectPath, "utf8");
    const match = content.match(/^\s*version\s*=\s*["']([^"']+)["']/m);
    installedVersion = match?.[1];
  }
  if (!installedVersion && existsSync(setupPyPath)) {
    const content = readFileSync(setupPyPath, "utf8");
    const match = content.match(/version\s*=\s*["']([^"']+)["']/m);
    installedVersion = match?.[1];
  }
  if (!installedVersion) {
    installedVersion = readPythonVersionFromMetadata(scopePath);
  }
  if (!installedVersion) {
    installedVersion = readPythonVersionFromArchiveName(packageName, archivePath);
  }
  installedVersion = installedVersion ?? "unknown";

  writeFileSync(join(tempDir, "requirements.txt"), `${packageName}==${installedVersion}\n`, "utf8");
  emit({ type: "stage:end", stage: "discovery", message: `Prepared ${packageName}==${installedVersion} from PyPI` });

  return {
    ecosystem: "pypi",
    name: packageName,
    version: installedVersion,
    path: scopePath,
    tempDir,
  };
}

function resolveCargoVersion(packageName: string, requestedVersion: string | undefined): string {
  if (requestedVersion) return requestedVersion;

  const raw = execFileSync("curl", buildCratesIoCurlArgs(`https://crates.io/api/v1/crates/${packageName}`), {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 60_000,
  });
  const parsed = JSON.parse(raw) as {
    crate?: { max_stable_version?: string; max_version?: string; newest_version?: string };
  };
  return (
    parsed.crate?.max_stable_version ??
    parsed.crate?.max_version ??
    parsed.crate?.newest_version ??
    "latest"
  );
}

function installCargoPackage(
  packageName: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): InstalledPackage {
  const tempDir = join(tmpdir(), `pwnkit-audit-${randomUUID().slice(0, 8)}`);
  const downloadDir = join(tempDir, "downloads");
  const extractDir = join(tempDir, "src");
  mkdirSync(downloadDir, { recursive: true });
  mkdirSync(extractDir, { recursive: true });

  const version = resolveCargoVersion(packageName, requestedVersion);
  emit({ type: "stage:start", stage: "discovery", message: `Downloading crates.io crate ${packageName}@${version}...` });

  try {
    execFileSync(
      "curl",
      [
        ...buildCratesIoCurlArgs(`https://crates.io/api/v1/crates/${packageName}/${version}/download`),
        "-o",
        join(downloadDir, `${packageName}-${version}.crate`),
      ],
      {
        cwd: tempDir,
        timeout: 120_000,
        stdio: "pipe",
      },
    );
  } catch (err) {
    rmSync(tempDir, { recursive: true, force: true });
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to download ${packageName}@${version} from crates.io: ${msg}`);
  }

  const archivePath = join(downloadDir, `${packageName}-${version}.crate`);
  extractSingleArchive(archivePath, extractDir);
  const scopePath = pickPythonScopePath(extractDir);

  const cargoTomlPath = join(scopePath, "Cargo.toml");
  let resolvedVersion = version;
  if (existsSync(cargoTomlPath)) {
    const content = readFileSync(cargoTomlPath, "utf8");
    const match = content.match(/^\s*version\s*=\s*["']([^"']+)["']/m);
    resolvedVersion = match?.[1] ?? version;
  }

  writeFileSync(
    join(tempDir, "Cargo.toml"),
    `[package]\nname = "pwnkit-cargo-audit"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n${packageName} = "${resolvedVersion}"\n`,
    "utf8",
  );
  mkdirSync(join(tempDir, "src"), { recursive: true });
  writeFileSync(join(tempDir, "src", "main.rs"), "fn main() {}\n", "utf8");
  try {
    execFileSync("cargo", ["generate-lockfile"], {
      cwd: tempDir,
      timeout: 180_000,
      stdio: "pipe",
    });
  } catch {
    // Best-effort: advisory lookup can still degrade to OSV only.
  }

  emit({ type: "stage:end", stage: "discovery", message: `Prepared ${packageName}@${resolvedVersion} from crates.io` });
  return {
    ecosystem: "cargo",
    name: packageName,
    version: resolvedVersion,
    path: scopePath,
    tempDir,
  };
}

function buildCratesIoCurlArgs(url: string): string[] {
  return [
    "-fsSL",
    "--retry",
    "3",
    "--retry-all-errors",
    "--retry-delay",
    "1",
    "--connect-timeout",
    "20",
    "-H",
    "User-Agent: pwnkit-ci/0.1 (+https://github.com/0sec-labs/pwnkit)",
    url,
  ];
}

function hasExplicitOciTag(imageRef: string): boolean {
  if (imageRef.includes("@")) return false;
  const lastSlash = imageRef.lastIndexOf("/");
  const lastColon = imageRef.lastIndexOf(":");
  return lastColon > lastSlash;
}

function resolveOciImageRef(rawImageRef: string, requestedVersion: string | undefined): {
  imageRef: string;
  name: string;
  version: string;
} {
  if (rawImageRef.includes("@")) {
    const [name, digest] = rawImageRef.split("@", 2);
    return { imageRef: rawImageRef, name, version: digest ?? "unknown" };
  }

  if (hasExplicitOciTag(rawImageRef)) {
    const lastColon = rawImageRef.lastIndexOf(":");
    return {
      imageRef: rawImageRef,
      name: rawImageRef.slice(0, lastColon),
      version: rawImageRef.slice(lastColon + 1),
    };
  }

  if (requestedVersion) {
    return {
      imageRef: `${rawImageRef}:${requestedVersion}`,
      name: rawImageRef,
      version: requestedVersion,
    };
  }

  return {
    imageRef: rawImageRef,
    name: rawImageRef,
    version: "latest",
  };
}

function hasExecutable(command: string, args: string[] = ["--version"]): boolean {
  try {
    execFileSync(command, args, {
      timeout: 10_000,
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

function extractDockerArchiveLayers(archivePath: string, rootfsDir: string): void {
  const script = String.raw`
import json, pathlib, tarfile, sys

archive = pathlib.Path(sys.argv[1])
rootfs = pathlib.Path(sys.argv[2])
work = archive.parent / "docker-archive"
work.mkdir(parents=True, exist_ok=True)
rootfs.mkdir(parents=True, exist_ok=True)

with tarfile.open(archive) as image_tar:
    image_tar.extractall(work)

manifest_path = work / "manifest.json"
with manifest_path.open("r", encoding="utf-8") as handle:
    manifest = json.load(handle)
layers = manifest[0].get("Layers", []) if manifest else []

for layer in layers:
    layer_path = work / layer
    if not layer_path.is_file():
        continue
    with tarfile.open(layer_path) as layer_tar:
        for member in layer_tar.getmembers():
            name = pathlib.PurePosixPath(member.name)
            if any(part.startswith(".wh.") for part in name.parts):
                continue
            target = (rootfs / name).resolve()
            if not str(target).startswith(str(rootfs.resolve())):
                continue
            layer_tar.extract(member, rootfs)
`;
  execFileSync("python3", ["-c", script, archivePath, rootfsDir], {
    timeout: 300_000,
    stdio: "pipe",
  });
}

function installOciImage(
  rawImageRef: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): InstalledPackage {
  const tempDir = join(tmpdir(), `pwnkit-audit-${randomUUID().slice(0, 8)}`);
  const rootfsDir = join(tempDir, "rootfs");
  const exportTar = join(tempDir, "image.tar");
  mkdirSync(rootfsDir, { recursive: true });

  const { imageRef, name, version } = resolveOciImageRef(rawImageRef, requestedVersion);
  emit({ type: "stage:start", stage: "discovery", message: `Pulling OCI image ${imageRef}...` });

  let containerId = "";
  try {
    if (hasExecutable("skopeo")) {
      execFileSync(
        "skopeo",
        [
          "copy",
          "--insecure-policy",
          `docker://${imageRef}`,
          `docker-archive:${exportTar}:${imageRef}`,
        ],
        {
          timeout: 300_000,
          stdio: "pipe",
        },
      );
      extractDockerArchiveLayers(exportTar, rootfsDir);
    } else {
      execFileSync("docker", ["pull", imageRef], {
        timeout: 300_000,
        stdio: "pipe",
      });
      containerId = execFileSync("docker", ["create", imageRef], {
        encoding: "utf8",
        timeout: 60_000,
        stdio: ["pipe", "pipe", "pipe"],
      }).trim();
      execFileSync("docker", ["export", containerId, "-o", exportTar], {
        timeout: 300_000,
        stdio: "pipe",
      });
      execFileSync("tar", ["-xf", exportTar, "-C", rootfsDir], {
        timeout: 300_000,
        stdio: "pipe",
      });
    }
  } catch (err) {
    rmSync(tempDir, { recursive: true, force: true });
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to prepare OCI image ${imageRef}: ${msg}`);
  } finally {
    if (containerId) {
      try {
        execFileSync("docker", ["rm", "-f", containerId], {
          timeout: 30_000,
          stdio: "pipe",
        });
      } catch {
        // best-effort cleanup
      }
    }
  }

  emit({ type: "stage:end", stage: "discovery", message: `Prepared OCI image ${name}:${version}` });
  return {
    ecosystem: "oci",
    name,
    version,
    path: rootfsDir,
    tempDir,
  };
}

export function installPackageForEcosystem(
  ecosystem: PackageEcosystem,
  rawPackageName: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): InstalledPackage {
  if (ecosystem === "oci") return installOciImage(rawPackageName, requestedVersion, emit);
  const { packageName, version } = splitPackageSpec(rawPackageName, requestedVersion);
  if (ecosystem === "pypi") return installPypiPackage(packageName, version, emit);
  if (ecosystem === "cargo") return installCargoPackage(packageName, version, emit);
  return installNpmPackage(packageName, version, emit);
}

export function runDependencyAuditForEcosystem(
  ecosystem: PackageEcosystem,
  projectDir: string,
  emit: ScanListener,
  rootPackage?: { name: string; version: string },
): NpmAuditFinding[] {
  if (ecosystem === "oci") {
    emit({ type: "stage:start", stage: "discovery", message: "OCI image advisory lookup unavailable" });
    emit({ type: "stage:end", stage: "discovery", message: "OCI image advisory lookup unavailable" });
    return [];
  }

  if (ecosystem === "cargo") {
    emit({ type: "stage:start", stage: "discovery", message: "Running OSV advisory lookup for crates.io..." });
    const findings = rootPackage
      ? queryOsvAdvisoriesSync(ecosystem, rootPackage.name, rootPackage.version)
      : [];
    emit({ type: "stage:end", stage: "discovery", message: `OSV crates.io lookup: ${findings.length} advisories` });
    return findings;
  }

  if (ecosystem === "pypi") {
    emit({ type: "stage:start", stage: "discovery", message: "Running OSV advisory lookup for PyPI..." });
    const findings = rootPackage
      ? queryOsvAdvisoriesSync(ecosystem, rootPackage.name, rootPackage.version)
      : [];
    emit({ type: "stage:end", stage: "discovery", message: `OSV PyPI lookup: ${findings.length} advisories` });
    return findings;
  }

  emit({ type: "stage:start", stage: "discovery", message: "Running npm audit..." });
  let rawOutput = "";
  try {
    rawOutput = execSync("npm audit --json", {
      cwd: projectDir,
      timeout: 120_000,
      stdio: "pipe",
    }).toString("utf-8");
  } catch (err) {
    const stdout =
      err && typeof err === "object" && "stdout" in err
        ? (err.stdout as Buffer | string | undefined)
        : undefined;
    const stderr =
      err && typeof err === "object" && "stderr" in err
        ? (err.stderr as Buffer | string | undefined)
        : undefined;
    rawOutput = bufferToString(stdout) || bufferToString(stderr) || "";
  }
  const findings = parseNpmAuditOutput(rawOutput);
  emit({ type: "stage:end", stage: "discovery", message: `npm audit: ${findings.length} advisories` });
  return findings;
}

// ────────────────────────────────────────────────────────────────────
// Transitive dependency tree walk (issue #565)
// ────────────────────────────────────────────────────────────────────

/**
 * Walk the resolved `node_modules` tree of an installed npm project and return
 * every installed package found on disk (excluding the audited root). This is
 * the input to the transitive malicious-package source-audit: each entry has
 * the on-disk `path` the install-script reader needs.
 *
 * npm hoists most deps to the top-level `node_modules`, so an exact tree depth
 * isn't recoverable from disk alone; we record a best-effort depth (1 for
 * top-level entries, +1 per nested `node_modules`) and a best-effort
 * `dependencyPath` from the nesting structure. That's enough for attribution —
 * the finding points at the right package even if the precise import chain for
 * a hoisted dep is approximate.
 *
 * Scoped packages (`@scope/name`) and nested `node_modules` are handled. The
 * walk is bounded by `maxPackages` so a pathological tree can't run unbounded.
 */
export function walkInstalledNpmTree(
  projectDir: string,
  rootName: string,
  maxPackages = 5_000,
): TransitivePackage[] {
  const out: TransitivePackage[] = [];
  const rootLower = rootName.toLowerCase();

  function readPackage(pkgDir: string): { name: string; version: string } | null {
    const pkgJsonPath = join(pkgDir, "package.json");
    if (!existsSync(pkgJsonPath)) return null;
    try {
      const pkg = JSON.parse(readFileSync(pkgJsonPath, "utf8")) as { name?: string; version?: string };
      if (!pkg.name) return null;
      return { name: pkg.name, version: typeof pkg.version === "string" ? pkg.version : "unknown" };
    } catch {
      return null;
    }
  }

  function listPackageDirs(nodeModulesDir: string): string[] {
    let entries: string[] = [];
    try {
      entries = readdirSync(nodeModulesDir);
    } catch {
      return [];
    }
    const dirs: string[] = [];
    for (const entry of entries) {
      if (entry === ".bin" || entry === ".cache" || entry === ".package-lock.json") continue;
      const abs = join(nodeModulesDir, entry);
      try {
        if (!statSync(abs).isDirectory()) continue;
      } catch {
        continue;
      }
      if (entry.startsWith("@")) {
        // Scope directory: its children are the actual packages.
        let scoped: string[] = [];
        try {
          scoped = readdirSync(abs);
        } catch {
          continue;
        }
        for (const inner of scoped) {
          const innerAbs = join(abs, inner);
          try {
            if (statSync(innerAbs).isDirectory()) dirs.push(innerAbs);
          } catch {
            // ignore unreadable entry
          }
        }
      } else {
        dirs.push(abs);
      }
    }
    return dirs;
  }

  function walk(nodeModulesDir: string, depth: number, pathPrefix: string[]): void {
    if (out.length >= maxPackages) return;
    for (const pkgDir of listPackageDirs(nodeModulesDir)) {
      if (out.length >= maxPackages) return;
      const meta = readPackage(pkgDir);
      if (!meta) continue;
      const dependencyPath = [...pathPrefix, meta.name];
      // Skip the audited root itself (top-level node_modules/<root>).
      if (!(depth === 1 && meta.name.toLowerCase() === rootLower)) {
        out.push({ name: meta.name, version: meta.version, path: pkgDir, depth, dependencyPath });
      }
      // Recurse into a nested node_modules if present (non-hoisted deps).
      const nested = join(pkgDir, "node_modules");
      if (existsSync(nested)) walk(nested, depth + 1, dependencyPath);
    }
  }

  walk(join(projectDir, "node_modules"), 1, [rootName]);
  return out;
}

// ────────────────────────────────────────────────────────────────────
// Public-registry probe for dependency-confusion (issue #565)
// ────────────────────────────────────────────────────────────────────

interface NpmRegistryMetadata {
  "dist-tags"?: { latest?: string };
  maintainers?: Array<{ name?: string } | string>;
}

/**
 * Probe the PUBLIC npm registry for a package name. Used by the
 * dependency-confusion check to learn whether an internal/private package name
 * is shadowable by a public package. Fail-soft: any error (offline, network,
 * unparseable body) resolves to `{ exists: false }` so a probe failure can
 * never invent a finding.
 *
 * `fetchImpl` is injectable so tests stay offline (mirrors
 * `triage/publishability-sources.ts:resolveRepository`).
 */
export async function probePublicNpmRegistry(
  packageName: string,
  opts: { fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): Promise<RegistryProbeResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  // Scoped names (@scope/pkg) must keep the slash encoded for the registry path.
  const url = `https://registry.npmjs.org/${packageName.replace("/", "%2f")}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15_000);
  try {
    const res = await fetchImpl(url, {
      headers: { Accept: "application/json", "User-Agent": "pwnkit-supply-chain/0.1" },
      signal: controller.signal,
    });
    if (res.status === 404) return { exists: false };
    if (!res.ok) return { exists: false };
    const meta = (await res.json()) as NpmRegistryMetadata;
    const maintainers = (meta.maintainers ?? [])
      .map((m) => (typeof m === "string" ? m : m?.name))
      .filter((m): m is string => typeof m === "string" && m.length > 0);
    return {
      exists: true,
      latestVersion: meta["dist-tags"]?.latest,
      maintainers: maintainers.length > 0 ? maintainers : undefined,
    };
  } catch {
    return { exists: false };
  } finally {
    clearTimeout(timer);
  }
}
