import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { isIP } from "node:net";
import { basename, extname, join } from "node:path";
import { ScopePolicy } from "../scope/scope.js";

export type MobilePlatform = "android" | "ios" | "unknown";

export interface MobileEndpointIndicator {
  value: string;
  kind: "url" | "host";
  sources: string[];
  priority: "high" | "medium" | "low";
  tags: string[];
  scope?: {
    allowed: boolean;
    reason: string;
  };
}

export interface MobileRiskIndicator {
  id: string;
  severity: "high" | "medium" | "low" | "info";
  title: string;
  evidence: string[];
}

export interface AndroidMetadata {
  packageName?: string;
  versionName?: string;
  minSdkVersion?: string;
  targetSdkVersion?: string;
  permissions: string[];
  exportedComponents: string[];
  deepLinks: string[];
}

export interface IosMetadata {
  bundleId?: string;
  version?: string;
  build?: string;
  urlSchemes: string[];
  associatedDomains: string[];
}

export interface MobileStaticIntakeReport {
  target: string;
  platform: MobilePlatform;
  summary: {
    endpointCount: number;
    backendCandidateCount: number;
    highPriorityEndpoints: number;
    mediumPriorityEndpoints: number;
    lowPriorityEndpoints: number;
    riskCount: number;
  };
  android?: AndroidMetadata;
  ios?: IosMetadata;
  endpoints: MobileEndpointIndicator[];
  backendCandidates: MobileEndpointIndicator[];
  risks: MobileRiskIndicator[];
  warnings: string[];
}

export interface MobileStaticIntakeOptions {
  scope?: ScopePolicy;
  maxFileBytes?: number;
}

interface SourceFile {
  path: string;
  content: string;
}

const DEFAULT_MAX_FILE_BYTES = 1024 * 1024;
const TEXT_EXTENSIONS = new Set([
  ".json",
  ".xml",
  ".plist",
  ".txt",
  ".properties",
  ".conf",
  ".config",
  ".yaml",
  ".yml",
  ".js",
  ".ts",
  ".kt",
  ".java",
  ".swift",
  ".m",
  ".h",
]);
const COMMON_PUBLIC_TLDS = new Set([
  "app",
  "biz",
  "ch",
  "cloud",
  "com",
  "dev",
  "edu",
  "gov",
  "io",
  "me",
  "net",
  "org",
  "rocks",
  "travel",
]);
const FILE_LIKE_TLDS = new Set([
  "apk",
  "class",
  "css",
  "dex",
  "gif",
  "html",
  "jar",
  "java",
  "jpg",
  "js",
  "json",
  "kt",
  "png",
  "so",
  "svg",
  "xml",
]);

export function runMobileStaticIntake(
  targetPath: string,
  opts: MobileStaticIntakeOptions = {},
): MobileStaticIntakeReport {
  const warnings: string[] = [];
  const files = collectReadableTextFiles(targetPath, opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES, warnings);
  const platform = detectPlatform(targetPath, files);
  const android = platform === "android" ? extractAndroidMetadata(files) : undefined;
  const ios = platform === "ios" ? extractIosMetadata(files) : undefined;
  const endpoints = sortEndpointIndicators(extractEndpointIndicators(files, opts.scope));
  const backendCandidates = selectBackendCandidates(endpoints);
  const risks = extractRiskIndicators({ android, ios, endpoints });

  return {
    target: targetPath,
    platform,
    summary: {
      endpointCount: endpoints.length,
      backendCandidateCount: backendCandidates.length,
      highPriorityEndpoints: endpoints.filter((endpoint) => endpoint.priority === "high").length,
      mediumPriorityEndpoints: endpoints.filter((endpoint) => endpoint.priority === "medium").length,
      lowPriorityEndpoints: endpoints.filter((endpoint) => endpoint.priority === "low").length,
      riskCount: risks.length,
    },
    android,
    ios,
    endpoints,
    backendCandidates,
    risks,
    warnings,
  };
}

function collectReadableTextFiles(
  targetPath: string,
  maxFileBytes: number,
  warnings: string[],
): SourceFile[] {
  const files: SourceFile[] = [];
  const root = lstatSync(targetPath);
  if (root.isFile()) {
    readCandidateFile(targetPath, maxFileBytes, warnings, files);
    return files;
  }
  if (!root.isDirectory()) {
    warnings.push(`Skipping unsupported target type: ${targetPath}`);
    return files;
  }

  const stack = [targetPath];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(path);
      } else if (entry.isFile()) {
        readCandidateFile(path, maxFileBytes, warnings, files);
      }
    }
  }
  return files;
}

function readCandidateFile(
  path: string,
  maxFileBytes: number,
  warnings: string[],
  out: SourceFile[],
): void {
  const ext = extname(path).toLowerCase();
  const name = basename(path);
  if (!TEXT_EXTENSIONS.has(ext) && name !== "AndroidManifest.xml" && name !== "Info.plist") {
    return;
  }
  const stat = lstatSync(path);
  if (stat.size > maxFileBytes) {
    warnings.push(`Skipping ${path}: exceeds ${maxFileBytes} bytes`);
    return;
  }
  try {
    out.push({ path, content: readFileSync(path, "utf8") });
  } catch (err) {
    warnings.push(`Skipping ${path}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function detectPlatform(targetPath: string, files: SourceFile[]): MobilePlatform {
  const ext = extname(targetPath).toLowerCase();
  if (ext === ".apk" || ext === ".aab") return "android";
  if (ext === ".ipa") return "ios";
  if (files.some((file) => basename(file.path) === "AndroidManifest.xml")) return "android";
  if (files.some((file) => basename(file.path) === "Info.plist")) return "ios";
  return "unknown";
}

function extractAndroidMetadata(files: SourceFile[]): AndroidMetadata {
  const manifest = files.find((file) => basename(file.path) === "AndroidManifest.xml")?.content ?? "";
  return {
    packageName: readXmlAttr(manifest, "package"),
    versionName: readXmlAttr(manifest, "android:versionName"),
    minSdkVersion: readXmlAttr(manifest, "android:minSdkVersion"),
    targetSdkVersion: readXmlAttr(manifest, "android:targetSdkVersion"),
    permissions: unique(readXmlTags(manifest, "uses-permission")
      .map((tag) => readXmlAttr(tag, "android:name"))
      .filter(isString)),
    exportedComponents: extractExportedAndroidComponents(manifest),
    deepLinks: unique(readXmlTags(manifest, "data")
      .flatMap((tag) => {
        const scheme = readXmlAttr(tag, "android:scheme");
        const host = readXmlAttr(tag, "android:host");
        const pathPrefix = readXmlAttr(tag, "android:pathPrefix") ?? readXmlAttr(tag, "android:path") ?? "";
        if (!scheme || !host) return [];
        return [`${scheme}://${host}${pathPrefix}`];
      })),
  };
}

function extractIosMetadata(files: SourceFile[]): IosMetadata {
  const plist = files.find((file) => basename(file.path) === "Info.plist")?.content ?? "";
  return {
    bundleId: readPlistString(plist, "CFBundleIdentifier"),
    version: readPlistString(plist, "CFBundleShortVersionString"),
    build: readPlistString(plist, "CFBundleVersion"),
    urlSchemes: unique(readPlistArray(plist, "CFBundleURLSchemes")),
    associatedDomains: unique(readPlistArray(plist, "com.apple.developer.associated-domains")),
  };
}

function extractEndpointIndicators(files: SourceFile[], scope?: ScopePolicy): MobileEndpointIndicator[] {
  const byValue = new Map<string, MobileEndpointIndicator>();
  for (const file of files) {
    for (const url of extractUrls(file.content)) {
      upsertIndicator(byValue, url, "url", file.path, scope);
      try {
        upsertIndicator(byValue, new URL(url).hostname.toLowerCase(), "host", file.path, scope);
      } catch {
        // extractUrls already validates the URL shape well enough for candidates.
      }
    }
    for (const host of extractHosts(file.content)) {
      upsertIndicator(byValue, host, "host", file.path, scope);
    }
  }
  return Array.from(byValue.values());
}

function upsertIndicator(
  byValue: Map<string, MobileEndpointIndicator>,
  value: string,
  kind: "url" | "host",
  source: string,
  scope?: ScopePolicy,
): void {
  const key = `${kind}:${value}`;
  const existing = byValue.get(key);
  if (existing) {
    if (!existing.sources.includes(source)) existing.sources.push(source);
    return;
  }
  const scopeTarget = kind === "url" ? value : `https://${value}/`;
  const scopeVerdict = scope?.match(scopeTarget);
  byValue.set(key, {
    value,
    kind,
    sources: [source],
    priority: priorityForEndpoint(value, kind, scopeVerdict?.allowed),
    tags: tagsForEndpoint(value, kind),
    scope: scopeVerdict,
  });
}

function priorityForEndpoint(value: string, kind: "url" | "host", inScope?: boolean): "high" | "medium" | "low" {
  if (inScope) return "high";
  if (kind === "url" && value.startsWith("http://")) return "medium";
  if (isLikelyThirdPartyHost(kind === "url" ? safeHost(value) : value)) return "low";
  return "medium";
}

function tagsForEndpoint(value: string, kind: "url" | "host"): string[] {
  const tags: string[] = [];
  const host = kind === "url" ? safeHost(value) : value;
  if (kind === "url" && value.startsWith("http://")) tags.push("cleartext");
  if (host && isLikelyThirdPartyHost(host)) tags.push("third-party");
  return tags;
}

function safeHost(value: string): string | undefined {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function isLikelyThirdPartyHost(host: string | undefined): boolean {
  if (!host) return false;
  return (
    host.includes("doubleclick.")
    || host.includes("google-analytics.")
    || host.includes("googleadservices.")
    || host.includes("googlesyndication.")
    || host.endsWith(".gstatic.com")
    || host === "google.com"
    || host.endsWith(".google.com")
  );
}

function extractRiskIndicators(input: {
  android?: AndroidMetadata;
  ios?: IosMetadata;
  endpoints: MobileEndpointIndicator[];
}): MobileRiskIndicator[] {
  const risks: MobileRiskIndicator[] = [];
  const cleartext = input.endpoints.filter((endpoint) =>
    endpoint.kind === "url" && endpoint.value.startsWith("http://"),
  );
  if (cleartext.length > 0) {
    risks.push({
      id: "mobile-cleartext-url",
      severity: "medium",
      title: "Cleartext HTTP endpoint indicators found",
      evidence: cleartext.slice(0, 10).map((endpoint) => endpoint.value),
    });
  }
  if (input.android && input.android.exportedComponents.length > 0) {
    risks.push({
      id: "android-exported-components",
      severity: "info",
      title: "Exported Android components require manual review",
      evidence: input.android.exportedComponents,
    });
  }
  if (input.android && input.android.deepLinks.length > 0) {
    risks.push({
      id: "android-deep-links",
      severity: "info",
      title: "Android deep links discovered",
      evidence: input.android.deepLinks,
    });
  }
  if (input.ios && input.ios.urlSchemes.length > 0) {
    risks.push({
      id: "ios-url-schemes",
      severity: "info",
      title: "iOS URL schemes discovered",
      evidence: input.ios.urlSchemes,
    });
  }
  return risks;
}

function sortEndpointIndicators(endpoints: MobileEndpointIndicator[]): MobileEndpointIndicator[] {
  return [...endpoints].sort((a, b) =>
    priorityWeight(a.priority) - priorityWeight(b.priority)
    || a.value.localeCompare(b.value),
  );
}

function selectBackendCandidates(endpoints: MobileEndpointIndicator[]): MobileEndpointIndicator[] {
  return sortEndpointIndicators(endpoints.filter((endpoint) => {
    if (endpoint.tags.includes("third-party")) return false;
    if (endpoint.kind === "host" && endpoints.some((other) =>
      other.kind === "url" && safeHost(other.value) === endpoint.value,
    )) {
      return false;
    }
    return endpoint.priority === "high" || endpoint.priority === "medium";
  }));
}

function priorityWeight(priority: "high" | "medium" | "low"): number {
  return priority === "high" ? 0 : priority === "medium" ? 1 : 2;
}

function extractUrls(text: string): string[] {
  const out = new Set<string>();
  const re = /https?:\/\/[^\s'"`<>|\\]+/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    let url = match[0];
    while (/[.,;:)\]}]$/.test(url)) url = url.slice(0, -1);
    if (isLowSignalUrl(url)) continue;
    out.add(url);
  }
  return Array.from(out);
}

function extractHosts(text: string): string[] {
  const out = new Set<string>();
  const re = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    const host = match[0].toLowerCase();
    if (!hasPlausiblePublicTld(host)) continue;
    if (isLikelyMobileIdentifier(host)) continue;
    if (isLikelyJavaPackage(host)) continue;
    if (host.includes("example.")) continue;
    out.add(host);
  }
  return Array.from(out);
}

function hasPlausiblePublicTld(host: string): boolean {
  const parts = host.split(".");
  const tld = parts.at(-1);
  if (!tld) return false;
  if (FILE_LIKE_TLDS.has(tld)) return false;
  return COMMON_PUBLIC_TLDS.has(tld);
}

function isLikelyMobileIdentifier(value: string): boolean {
  return (
    value.startsWith("android.")
    || value.includes(".permission.")
    || value.includes(".android")
    || value.startsWith("com.apple.")
    || value.startsWith("androidx.")
  );
}

function isLikelyJavaPackage(value: string): boolean {
  return (
    value.startsWith("com.google.")
    || value.startsWith("com.android.")
    || value.startsWith("org.apache.")
    || value.startsWith("org.json.")
    || value.startsWith("java.")
    || value.startsWith("javax.")
    || value.startsWith("kotlin.")
  );
}

function isAndroidNamespaceUrl(value: string): boolean {
  return value.startsWith("http://schemas.android.com/");
}

function isLowSignalUrl(value: string): boolean {
  if (isAndroidNamespaceUrl(value)) return true;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return true;
  }
  const host = parsed.hostname.toLowerCase();
  if (host === "schema.org" || host === "schemas.android.com") return true;
  if (!host.includes(".") && host !== "localhost" && isIP(host) === 0) return true;
  if (isLikelyJavaPackage(host)) return true;
  return false;
}

function extractExportedAndroidComponents(manifest: string): string[] {
  const components: string[] = [];
  for (const tagName of ["activity", "activity-alias", "service", "receiver", "provider"]) {
    for (const tag of readXmlTags(manifest, tagName)) {
      if (readXmlAttr(tag, "android:exported") !== "true") continue;
      const name = readXmlAttr(tag, "android:name");
      if (name) components.push(`${tagName}:${name}`);
    }
  }
  return unique(components);
}

function readXmlTags(xml: string, tagName: string): string[] {
  const escaped = tagName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`<${escaped}\\b[^>]*(?:/>|>[\\s\\S]*?</${escaped}>)`, "gi");
  return Array.from(xml.matchAll(re), (match) => match[0]);
}

function readXmlAttr(xml: string, attr: string): string | undefined {
  const escaped = attr.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`\\b${escaped}\\s*=\\s*["']([^"']+)["']`, "i");
  return xml.match(re)?.[1];
}

function readPlistString(plist: string, key: string): string | undefined {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`<key>\\s*${escaped}\\s*</key>\\s*<string>([^<]+)</string>`, "i");
  return plist.match(re)?.[1]?.trim();
}

function readPlistArray(plist: string, key: string): string[] {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`<key>\\s*${escaped}\\s*</key>\\s*<array>([\\s\\S]*?)</array>`, "i");
  const body = plist.match(re)?.[1];
  if (!body) return [];
  return Array.from(body.matchAll(/<string>([^<]+)<\/string>/gi), (match) => match[1].trim());
}

function unique<T>(values: T[]): T[] {
  return Array.from(new Set(values));
}

function isString(value: string | undefined): value is string {
  return typeof value === "string" && value.length > 0;
}
