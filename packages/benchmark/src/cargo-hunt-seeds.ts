/**
 * First curated crates.io package-hunt seed list.
 *
 * Same intent as the PyPI seed artifact: give the newly-shipped
 * `--ecosystem cargo` audit lane a concrete set of security-relevant
 * packages for repeatable hunts and future workflow consumers.
 */

export interface CargoHuntSeedCategory {
  id: string;
  label: string;
  rationale: string;
  crates: string[];
}

export const CARGO_HUNT_SEED_CATEGORIES: CargoHuntSeedCategory[] = [
  {
    id: "http-frameworks",
    label: "HTTP / App Frameworks",
    rationale:
      "Request parsing, routing, header handling, SSRF boundaries, and " +
      "session/auth integration all make this category high-signal.",
    crates: [
      "reqwest",
      "hyper",
      "axum",
      "actix-web",
      "warp",
      "rocket",
      "tokio-tungstenite",
      "tungstenite",
    ],
  },
  {
    id: "serialization-parsing",
    label: "Serialization / Parsing",
    rationale:
      "Deserializer and parser crates are common sites for unsafe shape " +
      "assumptions, resource exhaustion, and boundary mistakes.",
    crates: [
      "serde_json",
      "serde_yaml",
      "toml",
      "quick-xml",
      "bincode",
      "rmp-serde",
      "prost",
    ],
  },
  {
    id: "archives-fileformats",
    label: "Archives / File Formats",
    rationale:
      "Archive extraction and binary/file parsers are common path-traversal, " +
      "zip-slip, and parser robustness targets.",
    crates: [
      "zip",
      "tar",
      "flate2",
      "image",
      "infer",
    ],
  },
  {
    id: "templating-markup",
    label: "Templating / Markup",
    rationale:
      "Template engines and HTML/Markdown handling can hide SSTI, XSS, " +
      "and unsafe rendering assumptions.",
    crates: [
      "tera",
      "handlebars",
      "askama",
      "pulldown-cmark",
      "ammonia",
    ],
  },
  {
    id: "auth-crypto",
    label: "Auth / Crypto / Tokens",
    rationale:
      "These crates sit on trust boundaries where validation and default " +
      "behavior mistakes matter disproportionately.",
    crates: [
      "jsonwebtoken",
      "ring",
      "rustls",
      "cookie",
      "oauth2",
      "openidconnect",
    ],
  },
  {
    id: "storage-queries",
    label: "Storage / Query Builders",
    rationale:
      "ORM and query crates are high-value for injection and object-shape " +
      "boundary issues.",
    crates: [
      "sqlx",
      "diesel",
      "rusqlite",
      "sled",
    ],
  },
];

export const CARGO_HUNT_SEEDS = Array.from(
  new Set(CARGO_HUNT_SEED_CATEGORIES.flatMap((category) => category.crates)),
);

export function cargoHuntSeedsCsv(): string {
  return CARGO_HUNT_SEEDS.join(",");
}
