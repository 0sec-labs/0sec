import type { Finding, ResearchNoveltyReceipt } from "@pwnkit/shared";

export interface NoveltySourceResult {
  source: string;
  checked: number;
  duplicates: string[];
  related?: string[];
  error?: string;
}

export interface ResearchNoveltyProvider<T = unknown> {
  readonly id: string;
  check(finding: Finding, target: T): Promise<NoveltySourceResult>;
}

export interface AggregateNoveltyResult {
  receipt: ResearchNoveltyReceipt;
  results: NoveltySourceResult[];
}

/** Aggregate ecosystem-specific novelty providers. No successful checks means unchecked, never novel. */
export async function checkResearchNovelty<T>(
  finding: Finding,
  target: T,
  providers: ResearchNoveltyProvider<T>[],
): Promise<AggregateNoveltyResult> {
  const results = await Promise.all(providers.map(async (provider) => {
    try {
      return await provider.check(finding, target);
    } catch (error) {
      return { source: provider.id, checked: 0, duplicates: [], error: error instanceof Error ? error.message : String(error) };
    }
  }));
  const successful = results.filter((result) => !result.error && result.checked > 0);
  const duplicates = successful.flatMap((result) => result.duplicates);
  const checked = successful.reduce((sum, result) => sum + result.checked, 0);
  const state = duplicates.length > 0
    ? "duplicate" as const
    : checked > 0
      ? "novel" as const
      : results.some((result) => result.error)
        ? "inconclusive" as const
        : "unchecked" as const;
  return {
    receipt: {
      state,
      checkedAt: new Date().toISOString(),
      sources: successful.map((result) => result.source),
      refs: duplicates,
      scanned: checked,
    },
    results,
  };
}
