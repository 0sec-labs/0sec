// MITRE ATT&CK (Enterprise) mapping. See ./mitre.ts for the accuracy rules
// every entry in the catalog is held to.
export { techniquesForCategory, techniquesForEvent } from "./mitre.js";
export type { AttackTechnique } from "./mitre.js";

// MITRE ATLAS mapping — the AI/agentic matrix, with its own `AML.T####` id
// namespace. Complementary to ATT&CK, never merged with it: a finding may
// carry an ATT&CK tag, an ATLAS tag, both, or neither. See ./atlas.ts.
export { atlasTechniquesForCategory, atlasTechniquesForEvent } from "./atlas.js";
export type { AtlasTechnique } from "./atlas.js";
