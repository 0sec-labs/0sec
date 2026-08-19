/**
 * First curated PyPI package-hunt seed list.
 *
 * Goal: give the post-`--ecosystem pypi` audit lane a concrete, security-
 * relevant package set for repeatable hunt runs. These are intentionally
 * versionless package names so the workflow can target "current ecosystem
 * surface" instead of freezing one historical snapshot too early.
 *
 * Selection criteria:
 * - widely used or ecosystem-central
 * - handles attacker-controlled input or output
 * - maps to categories where package-level bugs actually happen:
 *   parsers, template engines, archive/file formats, auth/session tokens,
 *   HTTP clients/servers, serializers/deserializers
 */

export interface PypiHuntSeedCategory {
  id: string;
  label: string;
  rationale: string;
  packages: string[];
}

export const PYPI_HUNT_SEED_CATEGORIES: PypiHuntSeedCategory[] = [
  {
    id: "http-frameworks",
    label: "HTTP / App Frameworks",
    rationale:
      "Server/client HTTP stacks are common SSRF, request-smuggling, session, " +
      "and parser bug surfaces.",
    packages: [
      "requests",
      "urllib3",
      "httpx",
      "aiohttp",
      "flask",
      "django",
      "fastapi",
      "starlette",
      "uvicorn",
      "websockets",
    ],
  },
  {
    id: "templating-markup",
    label: "Templating / Markup",
    rationale:
      "Template engines and markup transformers are common SSTI, XSS, and " +
      "unsafe rendering targets.",
    packages: [
      "jinja2",
      "mako",
      "markdown",
      "bleach",
      "beautifulsoup4",
      "lxml",
    ],
  },
  {
    id: "config-parsing",
    label: "Config / Structured Parsing",
    rationale:
      "Config and structured-data parsers are high-yield for unsafe " +
      "deserialization, object mutation, and validation mistakes.",
    packages: [
      "pyyaml",
      "ruamel.yaml",
      "tomli",
      "configobj",
      "marshmallow",
      "pydantic",
      "cerberus",
    ],
  },
  {
    id: "archives-fileformats",
    label: "Archives / File Formats",
    rationale:
      "Archive and document libraries are common path-traversal, zip-slip, " +
      "and parser memory-safety surfaces.",
    packages: [
      "pillow",
      "openpyxl",
      "python-multipart",
      "defusedxml",
    ],
  },
  {
    id: "serialization",
    label: "Serialization / Object Graphs",
    rationale:
      "Serializer and pickle-adjacent packages are high-value for gadget, " +
      "mutation, and unsafe-deserialization hunts.",
    packages: [
      "jsonpickle",
      "dill",
      "cloudpickle",
      "msgpack",
    ],
  },
  {
    id: "auth-crypto",
    label: "Auth / Crypto / Tokens",
    rationale:
      "Token and signing libraries sit on critical trust boundaries where " +
      "default-misuse and validation bugs matter.",
    packages: [
      "pyjwt",
      "python-jose",
      "itsdangerous",
      "authlib",
      "cryptography",
    ],
  },
];

export const PYPI_HUNT_SEEDS = Array.from(
  new Set(PYPI_HUNT_SEED_CATEGORIES.flatMap((category) => category.packages)),
);

export function pypiHuntSeedsCsv(): string {
  return PYPI_HUNT_SEEDS.join(",");
}
