interface WidgetRequest {
  widgetId: string;
  additionalData: Record<string, string>;
}

export interface WidgetResponse {
  WidgetId: string;
  Html: string;
  ScriptSrc?: string;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function extractHtmlAttribute(tagHtml: string, attrName: string): string | null {
  const attrRe = new RegExp(`\\b${escapeRegExp(attrName)}=["']([^"']+)["']`, "i");
  return tagHtml.match(attrRe)?.[1] ?? null;
}

export function extractWidgetLabId(pageHtml: string, widgetId = "academy-launchlab"): string | null {
  const widgetRe = new RegExp(`<[^>]+\\bwidget-id=["']${escapeRegExp(widgetId)}["'][^>]*>`, "gi");
  let match: RegExpExecArray | null;
  while ((match = widgetRe.exec(pageHtml)) !== null) {
    const labId = extractHtmlAttribute(match[0], "widget-lab-id");
    if (labId) return labId;
  }
  return null;
}

export function extractLaunchHref(widgetHtml: string): string | null {
  return (
    widgetHtml.match(/href=["']([^"']*\/academy\/labs\/launch\/[^"']*)["']/i)?.[1] ??
    widgetHtml.match(/href=["']([^"']*\/launch-lab[^"']*)["']/i)?.[1] ??
    widgetHtml.match(/<a[^>]*class=["'][^"']*button-orange[^"']*["'][^>]*href=["']([^"']+)["']/i)?.[1] ??
    widgetHtml.match(/href=["']([^"']+)["'][^>]*class=["'][^"']*button-orange/i)?.[1] ??
    null
  );
}

export function buildWidgetRequest(widgetId: string, additionalData: Record<string, string> = {}): WidgetRequest[] {
  return [{ widgetId, additionalData }];
}

export function parseWidgetHtml(responseText: string, widgetId: string): string | null {
  try {
    const parsed = JSON.parse(responseText) as unknown;
    if (!Array.isArray(parsed)) return null;

    const widget = parsed.find((entry): entry is WidgetResponse => {
      if (!entry || typeof entry !== "object") return false;
      const candidate = entry as Partial<WidgetResponse>;
      return candidate.WidgetId === widgetId && typeof candidate.Html === "string";
    });

    return widget?.Html ?? null;
  } catch {
    return null;
  }
}
