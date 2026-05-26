import { describe, expect, it } from "vitest";
import {
  compareVersions,
  findWpVulnerabilities,
  isAffectedVersion,
  WP_VULNERABILITY_DB,
} from "./wp-vuln-db.js";

describe("WordPress vulnerability catalog", () => {
  it("matches affected plugin versions and excludes fixed releases", () => {
    const vulnerable = findWpVulnerabilities("backup-backup", "1.3.5");
    expect(vulnerable.some((match) => match.cveId === "CVE-2023-6553")).toBe(true);

    const fixed = findWpVulnerabilities("backup-backup", "1.3.8");
    expect(fixed.some((match) => match.cveId === "CVE-2023-6553")).toBe(false);
  });

  it("handles multi-part semantic-ish WordPress plugin versions", () => {
    expect(compareVersions("1.9.6", "1.9.6.1")).toBeLessThan(0);
    expect(compareVersions("5.7.12", "5.7.11")).toBeGreaterThan(0);
    expect(compareVersions("3.0.4", "3.0.4")).toBe(0);
  });

  it("uses strict less-than ranges when the catalog marks lt", () => {
    const contactForm7 = WP_VULNERABILITY_DB.find((entry) => entry.pluginSlug === "contact-form-7")!;
    expect(isAffectedVersion("5.3.1", contactForm7)).toBe(true);
    expect(isAffectedVersion("5.3.2", contactForm7)).toBe(false);
  });

  it("honors lower bounds when a vulnerable range starts at a specific version", () => {
    const essentialAddons = WP_VULNERABILITY_DB.find((entry) => entry.pluginSlug === "essential-addons-for-elementor-lite")!;
    expect(isAffectedVersion("5.3.9", essentialAddons)).toBe(false);
    expect(isAffectedVersion("5.4.0", essentialAddons)).toBe(true);
    expect(isAffectedVersion("5.7.2", essentialAddons)).toBe(false);
  });
});
