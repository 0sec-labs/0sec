export type EmbeddedDashboardAsset = readonly [relativePath: string, contentBase64: string];

/**
 * Rewritten only while `scripts/bun-compile.sh` builds a standalone binary.
 * Source and Node-distribution dashboards serve `packages/dashboard/dist`
 * directly, so they intentionally keep this checked-in stub empty.
 */
export const DASHBOARD_ASSETS: readonly EmbeddedDashboardAsset[] = [];
