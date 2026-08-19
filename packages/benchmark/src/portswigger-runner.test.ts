import { describe, expect, it } from "vitest";
import {
  buildWidgetRequest,
  extractLaunchHref,
  extractWidgetLabId,
  parseWidgetHtml,
} from "./portswigger-widgets.js";

describe("PortSwigger widget parsing", () => {
  it("extracts the launch lab id from the current widget placeholder", () => {
    const html = `
      <div widget-id="academy-labinfo" widget-lab-id="info-id"></div>
      <div widget-id="academy-launchlab" widget-lab-id="D9A071D8264E85184722707FF5747BBBD77963967D1D01F1B22F5DD8252F9767">
      </div>
    `;

    expect(extractWidgetLabId(html)).toBe("D9A071D8264E85184722707FF5747BBBD77963967D1D01F1B22F5DD8252F9767");
  });

  it("builds the JSON widget request shape used by the browser", () => {
    expect(buildWidgetRequest("academy-launchlab", { "widget-lab-id": "abc123" })).toEqual([
      {
        widgetId: "academy-launchlab",
        additionalData: {
          "widget-lab-id": "abc123",
        },
      },
    ]);
  });

  it("extracts the current academy launch URL from hydrated widget JSON", () => {
    const responseText = JSON.stringify([
      {
        WidgetId: "academy-launchlab",
        Html: `
          <div class="container-buttons-left">
            <a class="button-orange" href="/academy/labs/launch/d9a?referrer=%2fweb-security%2fsql-injection%2flab-retrieve-hidden-data" target="_blank">
              ACCESS THE LAB
            </a>
          </div>
        `,
        ScriptSrc: "",
      },
    ]);

    const html = parseWidgetHtml(responseText, "academy-launchlab");
    expect(html).toContain("/academy/labs/launch/d9a");
    expect(extractLaunchHref(html ?? "")).toBe(
      "/academy/labs/launch/d9a?referrer=%2fweb-security%2fsql-injection%2flab-retrieve-hidden-data"
    );
  });

  it("keeps support for the legacy launch-lab href", () => {
    expect(extractLaunchHref(`<a href="/launch-lab?id=old">Access</a>`)).toBe("/launch-lab?id=old");
  });
});
