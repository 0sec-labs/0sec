// pwnkit-cloud client surface.
//
// The CLI half of issue #303. The server-side mint endpoint that issues
// scoped tokens after a better-auth flow lives in pwnkit-cloud and is
// out of scope for this PR.

export {
  loadCloudCredentials,
  CloudAuthMissingError,
  CloudAuthError,
  DEFAULT_CLOUD_HOST,
} from "./credentials.js";
export type { CloudCredentials, LoadCloudCredentialsOptions } from "./credentials.js";

export {
  CloudClient,
  CloudError,
  CloudUnauthorizedError,
  CloudForbiddenError,
  CloudNetworkError,
} from "./client.js";
export type { CloudClientOptions, CloudHealthResponse, FetchImpl } from "./client.js";
