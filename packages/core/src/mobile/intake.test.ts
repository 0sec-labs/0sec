import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { ScopePolicy } from "../scope/scope.js";
import { runMobileStaticIntake } from "./intake.js";

describe("runMobileStaticIntake — Android", () => {
  it("extracts Android metadata and classifies endpoints with scope", () => {
    const root = mkdtempSync(join(tmpdir(), "pwnkit-mobile-android-"));
    writeFileSync(
      join(root, "AndroidManifest.xml"),
      `
      <manifest package="ch.sbb.mobile.android.b2c" android:versionName="1.2.3">
        <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35" />
        <uses-permission android:name="android.permission.INTERNET" />
        <application>
          <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
              <data android:scheme="https" android:host="app.sbbmobile.ch" android:pathPrefix="/trip" />
            </intent-filter>
          </activity>
          <service android:name=".SyncService" android:exported="false" />
        </application>
      </manifest>
      `,
    );
    mkdirSync(join(root, "res", "values"), { recursive: true });
    writeFileSync(
      join(root, "res", "values", "strings.xml"),
      `
      <resources>
        <string name="api_url">https://api.sbbmobile.ch/v1/trips</string>
        <string name="analytics">https://www.google-analytics.com/collect</string>
      </resources>
      `,
    );

    const report = runMobileStaticIntake(root, {
      scope: ScopePolicy.fromJson({ in_scope: ["*.sbbmobile.ch"] }),
    });

    expect(report.platform).toBe("android");
    expect(report.summary).toEqual({
      endpointCount: 5,
      backendCandidateCount: 2,
      highPriorityEndpoints: 3,
      mediumPriorityEndpoints: 0,
      lowPriorityEndpoints: 2,
      riskCount: 2,
    });
    expect(report.android?.packageName).toBe("ch.sbb.mobile.android.b2c");
    expect(report.android?.targetSdkVersion).toBe("35");
    expect(report.android?.permissions).toEqual(["android.permission.INTERNET"]);
    expect(report.android?.exportedComponents).toEqual(["activity:.MainActivity"]);
    expect(report.android?.deepLinks).toEqual(["https://app.sbbmobile.ch/trip"]);
    expect(report.endpoints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          value: "api.sbbmobile.ch",
          kind: "host",
          priority: "high",
          scope: expect.objectContaining({ allowed: true }),
        }),
        expect.objectContaining({
          value: "www.google-analytics.com",
          kind: "host",
          priority: "low",
          tags: ["third-party"],
          scope: expect.objectContaining({ allowed: false }),
        }),
      ]),
    );
    expect(report.risks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "android-exported-components",
          evidence: ["activity:.MainActivity"],
        }),
      ]),
    );
    expect(report.endpoints.map((endpoint) => endpoint.value)).not.toContain("ch.sbb.mobile.android");
    expect(report.endpoints.map((endpoint) => endpoint.value)).not.toContain("android.permission.internet");
    expect(report.endpoints.map((endpoint) => endpoint.value)).not.toContain("a.compareto");
    expect(report.endpoints.map((endpoint) => endpoint.value)).not.toContain("1510314123771.html");
    expect(report.endpoints.map((endpoint) => endpoint.value)).not.toContain("org.apache.commons.codec.net");
    expect(report.endpoints.map((endpoint) => endpoint.value)).not.toContain("http://schemas.android.com/apk/res/android");
    expect(report.endpoints.map((endpoint) => endpoint.value)).not.toContain("http://schema.org/ActivateAction");
    expect(report.endpoints.map((endpoint) => endpoint.value)).not.toContain("http://hostname/?");
  });
});

describe("runMobileStaticIntake — iOS", () => {
  it("extracts Info.plist metadata, URL schemes, associated domains, and hosts", () => {
    const root = mkdtempSync(join(tmpdir(), "pwnkit-mobile-ios-"));
    writeFileSync(
      join(root, "Info.plist"),
      `
      <plist version="1.0">
        <dict>
          <key>CFBundleIdentifier</key><string>ch.sbb.mobile.preview</string>
          <key>CFBundleShortVersionString</key><string>4.5.6</string>
          <key>CFBundleVersion</key><string>789</string>
          <key>CFBundleURLSchemes</key>
          <array><string>sbbmobile</string><string>sbbpreview</string></array>
          <key>com.apple.developer.associated-domains</key>
          <array><string>applinks:app.sbbmobile.ch</string></array>
        </dict>
      </plist>
      `,
    );
    writeFileSync(
      join(root, "Config.plist"),
      `<string>https://app.sbbmobile.ch/timetable</string>`,
    );

    const report = runMobileStaticIntake(root, {
      scope: ScopePolicy.fromJson({ in_scope: ["*.sbbmobile.ch"] }),
    });

    expect(report.platform).toBe("ios");
    expect(report.ios).toEqual({
      bundleId: "ch.sbb.mobile.preview",
      version: "4.5.6",
      build: "789",
      urlSchemes: ["sbbmobile", "sbbpreview"],
      associatedDomains: ["applinks:app.sbbmobile.ch"],
    });
    expect(report.endpoints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          value: "https://app.sbbmobile.ch/timetable",
          kind: "url",
          scope: expect.objectContaining({ allowed: true }),
        }),
      ]),
    );
    expect(report.risks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "ios-url-schemes",
          evidence: ["sbbmobile", "sbbpreview"],
        }),
      ]),
    );
  });
});
