import { readFileSync } from "node:fs";

// ── Types ──

export interface ApiSpecEndpoint {
  path: string;
  method: string;
  summary?: string;
  parameters: ApiSpecParameter[];
  requestBody?: ApiSpecRequestBody;
  auth?: string[];
}

export interface ApiSpecParameter {
  name: string;
  in: "query" | "header" | "path" | "cookie";
  required?: boolean;
  type?: string;
}

export interface ApiSpecRequestBody {
  contentType: string;
  fields: Array<{ name: string; type?: string; required?: boolean }>;
}

export interface ApiSpecAuthScheme {
  name: string;
  type: string;
  description?: string;
  /** e.g. "header", "query", "cookie" */
  in?: string;
  /** header/param name for apiKey schemes */
  paramName?: string;
}

export interface ApiSpecSummary {
  title: string;
  version: string;
  baseUrl: string;
  authSchemes: ApiSpecAuthScheme[];
  endpoints: ApiSpecEndpoint[];
  /** Pre-formatted prompt text for injection into agent system prompts */
  promptText: string;
}

// ── Simple YAML-to-JSON converter (regex-based, handles common OpenAPI files) ──

function simpleYamlParse(text: string): unknown {
  // If it looks like JSON, parse directly
  const trimmed = text.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return JSON.parse(text);
  }

  // Strategy: convert YAML to JSON via line-by-line processing.
  // This handles the subset of YAML used by OpenAPI specs (mappings, sequences,
  // scalars, quoted strings). It does NOT handle anchors, multi-line blocks (|, >),
  // or complex keys — which are rare in API specs.

  const lines = text.split("\n");
  const result: string[] = [];
  const indentStack: number[] = []; // track indent levels for closing braces/brackets
  const typeStack: ("object" | "array")[] = [];

  function closeToIndent(indent: number): void {
    while (indentStack.length > 0 && indentStack[indentStack.length - 1] >= indent) {
      indentStack.pop();
      const t = typeStack.pop();
      result.push(t === "array" ? "]" : "}");
    }
  }

  function jsonValue(raw: string): string {
    const v = raw.trim();
    if (v === "" || v === "~" || v === "null") return "null";
    if (v === "true" || v === "false") return v;
    if (/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(v)) return v;
    // Already quoted
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      // Normalize to double quotes
      const inner = v.slice(1, -1);
      return JSON.stringify(inner);
    }
    return JSON.stringify(v);
  }

  let prevIndent = -1;
  let needsComma = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Skip blank lines and comments
    if (/^\s*(#.*)?$/.test(line)) continue;

    const indentMatch = line.match(/^(\s*)/);
    const indent = indentMatch ? indentMatch[1].length : 0;
    const content = line.slice(indent).replace(/#[^"']*$/, "").trimEnd(); // strip inline comments

    if (!content) continue;

    // Close deeper scopes
    if (indent <= prevIndent && indentStack.length > 0) {
      closeToIndent(indent);
    }

    const isListItem = content.startsWith("- ");
    const kvMatch = content.match(/^([^:]+?):\s*(.*)/);

    if (isListItem) {
      // Start array if parent context isn't already an array
      if (typeStack.length === 0 || typeStack[typeStack.length - 1] !== "array" || indent > (indentStack[indentStack.length - 1] ?? -1)) {
        if (needsComma && typeStack.length > 0) result.push(",");
        result.push("[");
        indentStack.push(indent);
        typeStack.push("array");
        needsComma = false;
      } else if (needsComma) {
        result.push(",");
      }

      const itemContent = content.slice(2).trim();
      if (!itemContent) {
        // Multi-line object item — will be opened on next line
        needsComma = false;
      } else {
        const itemKv = itemContent.match(/^([^:]+?):\s*(.*)/);
        if (itemKv) {
          // Inline object in array
          result.push("{");
          result.push(`${JSON.stringify(itemKv[1].trim())}: ${itemKv[2].trim() ? jsonValue(itemKv[2]) : ""}`);
          // Peek ahead for more keys at deeper indent
          // Simple approach: close inline objects later
          indentStack.push(indent + 2);
          typeStack.push("object");
          needsComma = !!itemKv[2].trim();
          if (!itemKv[2].trim()) {
            needsComma = false;
          }
        } else {
          result.push(jsonValue(itemContent));
          needsComma = true;
        }
      }
    } else if (kvMatch) {
      const key = kvMatch[1].trim();
      const val = kvMatch[2].trim();

      // Start object if we haven't yet
      if (typeStack.length === 0) {
        result.push("{");
        indentStack.push(-1);
        typeStack.push("object");
        needsComma = false;
      }

      if (needsComma) result.push(",");

      if (val) {
        result.push(`${JSON.stringify(key)}: ${jsonValue(val)}`);
        needsComma = true;
      } else {
        // Value on next lines (nested object or array)
        result.push(`${JSON.stringify(key)}:`);
        needsComma = false;
        // The next line will open the appropriate container
      }
    }

    prevIndent = indent;
  }

  // Close all remaining scopes
  closeToIndent(-1);

  const jsonStr = result.join(" ");

  try {
    return JSON.parse(jsonStr);
  } catch {
    // If our simple parser fails, throw a helpful error
    throw new Error(
      "Failed to parse YAML API spec. For complex YAML files, convert to JSON first:\n" +
      "  npx js-yaml your-spec.yaml > spec.json\n" +
      "Then use: --api-spec spec.json",
    );
  }
}

// ── OpenAPI 3.x / Swagger 2.0 Parser ──

/**
 * Parse an OpenAPI 3.x or Swagger 2.0 spec file and return a structured summary
 * suitable for injection into agent system prompts.
 */
export async function parseApiSpec(specPath: string): Promise<ApiSpecSummary> {
  const raw = readFileSync(specPath, "utf-8");

  let spec: Record<string, unknown>;
  try {
    spec = simpleYamlParse(raw) as Record<string, unknown>;
  } catch (err) {
    throw new Error(`Failed to parse API spec at ${specPath}: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (!spec || typeof spec !== "object") {
    throw new Error(`Invalid API spec: expected an object, got ${typeof spec}`);
  }

  // Detect format
  const isOpenApi3 = typeof spec.openapi === "string" && (spec.openapi as string).startsWith("3.");
  const isSwagger2 = spec.swagger === "2.0";

  if (!isOpenApi3 && !isSwagger2) {
    throw new Error(
      "Unsupported API spec format. Expected OpenAPI 3.x (openapi: '3.x.x') or Swagger 2.0 (swagger: '2.0').",
    );
  }

  const info = (spec.info as Record<string, unknown>) ?? {};
  const title = String(info.title ?? "Untitled API");
  const version = String(info.version ?? "unknown");

  // Base URL
  let baseUrl = "";
  if (isOpenApi3) {
    const servers = spec.servers as Array<Record<string, unknown>> | undefined;
    if (servers?.[0]?.url) baseUrl = String(servers[0].url);
  } else {
    // Swagger 2.0
    const host = spec.host ? String(spec.host) : "";
    const basePath = spec.basePath ? String(spec.basePath) : "";
    const schemes = spec.schemes as string[] | undefined;
    const scheme = schemes?.[0] ?? "https";
    if (host) baseUrl = `${scheme}://${host}${basePath}`;
  }

  // Auth schemes
  const authSchemes: ApiSpecAuthScheme[] = [];
  if (isOpenApi3) {
    const components = (spec.components as Record<string, unknown>) ?? {};
    const securitySchemes = (components.securitySchemes as Record<string, Record<string, unknown>>) ?? {};
    for (const [name, scheme] of Object.entries(securitySchemes)) {
      authSchemes.push({
        name,
        type: String(scheme.type ?? "unknown"),
        description: scheme.description ? String(scheme.description) : undefined,
        in: scheme.in ? String(scheme.in) : undefined,
        paramName: scheme.name ? String(scheme.name) : undefined,
      });
    }
  } else {
    // Swagger 2.0
    const secDefs = (spec.securityDefinitions as Record<string, Record<string, unknown>>) ?? {};
    for (const [name, scheme] of Object.entries(secDefs)) {
      authSchemes.push({
        name,
        type: String(scheme.type ?? "unknown"),
        description: scheme.description ? String(scheme.description) : undefined,
        in: scheme.in ? String(scheme.in) : undefined,
        paramName: scheme.name ? String(scheme.name) : undefined,
      });
    }
  }

  // Endpoints
  const endpoints: ApiSpecEndpoint[] = [];
  const paths = (spec.paths as Record<string, Record<string, unknown>>) ?? {};
  const httpMethods = new Set(["get", "post", "put", "patch", "delete", "head", "options"]);

  for (const [path, pathItem] of Object.entries(paths)) {
    if (!pathItem || typeof pathItem !== "object") continue;

    // Path-level parameters
    const pathParams = extractParameters(pathItem.parameters as unknown[]);

    for (const [method, operation] of Object.entries(pathItem)) {
      if (!httpMethods.has(method) || !operation || typeof operation !== "object") continue;

      const op = operation as Record<string, unknown>;
      const params = [
        ...pathParams,
        ...extractParameters(op.parameters as unknown[]),
      ];

      let requestBody: ApiSpecRequestBody | undefined;
      if (isOpenApi3 && op.requestBody) {
        requestBody = extractRequestBody(op.requestBody as Record<string, unknown>);
      } else if (isSwagger2) {
        // Swagger 2.0 uses "in: body" parameters
        const bodyParam = (op.parameters as unknown[] | undefined)
          ?.find((p: unknown) => (p as Record<string, unknown>)?.in === "body") as Record<string, unknown> | undefined;
        if (bodyParam?.schema) {
          requestBody = extractSchemaFields(bodyParam.schema as Record<string, unknown>);
        }
      }

      // Operation-level security
      const opSecurity = op.security as Array<Record<string, unknown>> | undefined;
      const authNames = opSecurity
        ? opSecurity.flatMap((s) => Object.keys(s))
        : undefined;

      endpoints.push({
        path,
        method: method.toUpperCase(),
        summary: op.summary ? String(op.summary) : op.description ? String(op.description).slice(0, 100) : undefined,
        parameters: params,
        requestBody,
        auth: authNames,
      });
    }
  }

  // Build prompt text
  const promptText = buildPromptText({ title, version, baseUrl, authSchemes, endpoints });

  return { title, version, baseUrl, authSchemes, endpoints, promptText };
}

// ── Helpers ──

function extractParameters(params: unknown[] | undefined): ApiSpecParameter[] {
  if (!Array.isArray(params)) return [];
  return params
    .filter((p): p is Record<string, unknown> => p !== null && typeof p === "object")
    .filter((p) => p.in !== "body") // body params handled separately
    .map((p) => ({
      name: String(p.name ?? ""),
      in: String(p.in ?? "query") as ApiSpecParameter["in"],
      required: p.required === true,
      type: p.type ? String(p.type) : p.schema ? schemaType(p.schema as Record<string, unknown>) : undefined,
    }));
}

function schemaType(schema: Record<string, unknown>): string {
  if (schema.type) return String(schema.type);
  if (schema.enum) return `enum(${(schema.enum as unknown[]).slice(0, 5).join(",")})`;
  if (schema.oneOf || schema.anyOf) return "mixed";
  return "object";
}

function extractRequestBody(body: Record<string, unknown>): ApiSpecRequestBody | undefined {
  const content = body.content as Record<string, Record<string, unknown>> | undefined;
  if (!content) return undefined;

  // Prefer JSON, fall back to form data, then first available
  const preferred = content["application/json"]
    ?? content["application/x-www-form-urlencoded"]
    ?? content["multipart/form-data"]
    ?? Object.values(content)[0];

  if (!preferred?.schema) return undefined;

  const contentType = content["application/json"]
    ? "application/json"
    : content["application/x-www-form-urlencoded"]
      ? "application/x-www-form-urlencoded"
      : content["multipart/form-data"]
        ? "multipart/form-data"
        : Object.keys(content)[0] ?? "application/json";

  return {
    contentType,
    ...extractFieldsFromSchema(preferred.schema as Record<string, unknown>),
  };
}

function extractSchemaFields(schema: Record<string, unknown>): ApiSpecRequestBody {
  return {
    contentType: "application/json",
    ...extractFieldsFromSchema(schema),
  };
}

function extractFieldsFromSchema(schema: Record<string, unknown>): { fields: ApiSpecRequestBody["fields"] } {
  const fields: ApiSpecRequestBody["fields"] = [];
  const required = new Set<string>((schema.required as string[]) ?? []);

  const properties = (schema.properties as Record<string, Record<string, unknown>>) ?? {};
  for (const [name, prop] of Object.entries(properties)) {
    fields.push({
      name,
      type: prop.type ? String(prop.type) : undefined,
      required: required.has(name),
    });
  }

  // If schema has items (array), note it
  if (schema.type === "array" && schema.items) {
    fields.push({ name: "(array items)", type: schemaType(schema.items as Record<string, unknown>) });
  }

  return { fields };
}

// ── Prompt text builder ──

function buildPromptText(summary: Omit<ApiSpecSummary, "promptText">): string {
  const lines: string[] = [];

  lines.push(`## API Specification: ${summary.title} (v${summary.version})`);
  if (summary.baseUrl) lines.push(`Base URL: ${summary.baseUrl}`);
  lines.push("");

  // Auth
  if (summary.authSchemes.length > 0) {
    lines.push("### Authentication");
    for (const scheme of summary.authSchemes) {
      const details = [scheme.type];
      if (scheme.in) details.push(`in: ${scheme.in}`);
      if (scheme.paramName) details.push(`param: ${scheme.paramName}`);
      lines.push(`- **${scheme.name}**: ${details.join(", ")}${scheme.description ? ` — ${scheme.description}` : ""}`);
    }
    lines.push("");
  }

  // Endpoints — group by path for compactness
  lines.push("### Endpoints");
  lines.push("");

  // Truncate if there are too many endpoints to fit in ~2000 tokens
  const maxEndpoints = 60;
  const eps = summary.endpoints.slice(0, maxEndpoints);
  const truncated = summary.endpoints.length > maxEndpoints;

  for (const ep of eps) {
    const params = ep.parameters
      .map((p) => {
        const req = p.required ? "*" : "";
        return `${p.name}${req}(${p.in}${p.type ? ":" + p.type : ""})`;
      })
      .join(", ");

    const bodyInfo = ep.requestBody
      ? ` [body:${ep.requestBody.contentType} {${ep.requestBody.fields.map((f) => `${f.name}${f.required ? "*" : ""}${f.type ? ":" + f.type : ""}`).join(", ")}}]`
      : "";

    const authInfo = ep.auth?.length ? ` [auth:${ep.auth.join(",")}]` : "";
    const summaryInfo = ep.summary ? ` — ${ep.summary}` : "";

    lines.push(`- **${ep.method}** \`${ep.path}\`${summaryInfo}`);
    if (params) lines.push(`  Params: ${params}`);
    if (bodyInfo) lines.push(`  Body: ${bodyInfo.trim()}`);
    if (authInfo) lines.push(`  Auth: ${authInfo.trim()}`);
  }

  if (truncated) {
    lines.push(`\n... and ${summary.endpoints.length - maxEndpoints} more endpoints (${summary.endpoints.length} total)`);
  }

  lines.push("");
  lines.push("### Scanning Strategy");
  lines.push("You have the complete API specification above. Use it to:");
  lines.push("1. Test EVERY endpoint systematically — do not rely only on discovery/crawling");
  lines.push("2. Use the exact parameter names and types from the spec for injection payloads");
  lines.push("3. Test authentication/authorization: try accessing protected endpoints without auth, with wrong auth, and with other users' tokens");
  lines.push("4. Focus on endpoints that accept user input (body, query params) for injection attacks");
  lines.push("5. Check for IDOR by manipulating ID parameters across endpoints");

  return lines.join("\n");
}
