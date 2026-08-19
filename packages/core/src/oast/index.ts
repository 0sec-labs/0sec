/**
 * OAST (out-of-band application security testing) barrel (pwnkit#659).
 *
 * A hosted interaction collaborator + correlation oracle for confirming
 * blind/out-of-band bugs (blind SSRF/XSS, OOB RCE/SQLi, XXE-OOB, JNDI). See
 * each module for detail; the oracle in `oracle.ts` is the pure, testable core.
 */

export type {
  OastProtocol,
  OastInteraction,
  OastHandle,
  OastProbe,
  OastCollaborator,
} from "./types.js";

export {
  type OastClass,
  type OastVerdict,
  confirmOast,
  matchInteractions,
  categoryToOastClass,
  normalizeLabel,
} from "./oracle.js";

export {
  OastStore,
  InMemoryCollaborator,
  HttpCollaborator,
  createCollaborator,
  deriveProbe,
} from "./collaborator.js";

export {
  type OastRequest,
  type OastServerResponse,
  handleOastRequest,
  createOastServer,
} from "./server.js";
