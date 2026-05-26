// HackerOne hacker-API integration. Read-only.
//
// Surface that other packages (CLI, eventually pwnkit-cloud) consume.
// Tests import implementation files directly.

export {
  loadH1Credentials,
  H1AuthMissingError,
} from "./credentials.js";
export type { H1Credentials, LoadH1CredentialsOptions } from "./credentials.js";

export {
  H1Client,
  H1Error,
  H1AuthError,
  H1ForbiddenError,
  H1RateLimitError,
  H1NetworkError,
  parseRetryAfter,
} from "./client.js";
export type { FetchImpl, H1ClientOptions } from "./client.js";

export {
  listPrograms,
  getProgram,
  getStructuredScopes,
  automationVerdict,
  summariseScopes,
} from "./programs.js";
export type { ListProgramsOptions, AutomationVerdict, H1ProgramPage } from "./programs.js";

export {
  toScopeFile,
  toScopeJson,
} from "./scope-export.js";
export type { ToScopeFileOptions, ScopeExportResult } from "./scope-export.js";

export type {
  H1Resource,
  H1Collection,
  H1Single,
  H1Program,
  H1ProgramAttributes,
  H1Scope,
  H1StructuredScopeAttributes,
  H1BalanceAttributes,
} from "./types.js";
