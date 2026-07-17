import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, LOLFunction, UnifiedLOLEntry } from "../schema/unified-entry.js";

function findEquivalents(
  binary: string,
  sourcePlatform: Platform | undefined,
  targetPlatform: Platform | undefined,
  kb: any,
): any[] {
  const sourceEntries: UnifiedLOLEntry[] = kb.lookupBinary(binary, sourcePlatform);
  if (sourceEntries.length === 0) return [];

  const sourceFunctions = new Set<LOLFunction>();
  for (const e of sourceEntries) {
    for (const f of e.functions) sourceFunctions.add(f);
  }

  // Find entries on the target platform with overlapping functions
  const targetEntries: UnifiedLOLEntry[] = targetPlatform
    ? kb.searchByPlatform(targetPlatform)
    : kb.allEntries;

  const equivalents: any[] = [];
  for (const entry of targetEntries) {
    // Skip same entries
    if (sourceEntries.some((s) => s.id === entry.id)) continue;

    const sharedFunctions = entry.functions.filter((f: LOLFunction) =>
      sourceFunctions.has(f),
    );
    if (sharedFunctions.length === 0) continue;

    const coverage =
      Math.round((sharedFunctions.length / sourceFunctions.size) * 100) / 100;

    equivalents.push({
      binary: entry.binary,
      platform: entry.platform,
      catalog: entry.catalogSource,
      category: entry.category,
      shared_functions: sharedFunctions,
      function_coverage: coverage,
      stealth_score: entry.stealthScore,
      attck_techniques: entry.attckTechniques,
      total_functions: entry.functions.length,
    });
  }

  // Sort by coverage descending
  equivalents.sort((a: any, b: any) => b.function_coverage - a.function_coverage);

  return equivalents.slice(0, 20);
}

function computeCoverageDiff(
  sourcePlatform: Platform,
  targetPlatform: Platform,
  kb: any,
): any {
  const sourceEntries: UnifiedLOLEntry[] = kb.searchByPlatform(sourcePlatform);
  const targetEntries: UnifiedLOLEntry[] = kb.searchByPlatform(targetPlatform);

  // Function coverage per platform
  const sourceFunctions = new Map<LOLFunction, number>();
  const targetFunctions = new Map<LOLFunction, number>();

  for (const e of sourceEntries) {
    for (const f of e.functions) {
      sourceFunctions.set(f, (sourceFunctions.get(f) || 0) + 1);
    }
  }
  for (const e of targetEntries) {
    for (const f of e.functions) {
      targetFunctions.set(f, (targetFunctions.get(f) || 0) + 1);
    }
  }

  // Find differences
  const allFunctions = new Set<LOLFunction>([
    ...sourceFunctions.keys(),
    ...targetFunctions.keys(),
  ]);

  const coverage: any[] = [];
  for (const fn of allFunctions) {
    const sourceCount = sourceFunctions.get(fn) || 0;
    const targetCount = targetFunctions.get(fn) || 0;
    coverage.push({
      function: fn,
      source_count: sourceCount,
      target_count: targetCount,
      diff: targetCount - sourceCount,
      stronger_on: sourceCount > targetCount ? sourcePlatform : targetCount > sourceCount ? targetPlatform : "equal",
    });
  }

  // Category coverage
  const sourceCategories = new Map<string, number>();
  const targetCategories = new Map<string, number>();
  for (const e of sourceEntries) {
    sourceCategories.set(e.category, (sourceCategories.get(e.category) || 0) + 1);
  }
  for (const e of targetEntries) {
    targetCategories.set(e.category, (targetCategories.get(e.category) || 0) + 1);
  }

  return {
    source_platform: sourcePlatform,
    target_platform: targetPlatform,
    source_total: sourceEntries.length,
    target_total: targetEntries.length,
    function_coverage: coverage.sort((a: any, b: any) => Math.abs(b.diff) - Math.abs(a.diff)),
    source_only_functions: coverage
      .filter((c: any) => c.target_count === 0)
      .map((c: any) => c.function),
    target_only_functions: coverage
      .filter((c: any) => c.source_count === 0)
      .map((c: any) => c.function),
    source_categories: Object.fromEntries(sourceCategories),
    target_categories: Object.fromEntries(targetCategories),
  };
}

function computePortability(
  binary: string,
  fn: LOLFunction | undefined,
  kb: any,
): any {
  const entries: UnifiedLOLEntry[] = fn
    ? kb.searchByFunction(fn)
    : kb.lookupBinary(binary);

  if (entries.length === 0) {
    return {
      binary,
      function: fn,
      portability: "not_found",
      platforms: [],
    };
  }

  // Group by platform
  const byPlatform = new Map<Platform, UnifiedLOLEntry[]>();
  for (const e of entries) {
    const list = byPlatform.get(e.platform) || [];
    list.push(e);
    byPlatform.set(e.platform, list);
  }

  const platforms = [...byPlatform.entries()].map(([platform, platformEntries]) => ({
    platform,
    entries: platformEntries.map((e) => ({
      binary: e.binary,
      catalog: e.catalogSource,
      functions: e.functions,
      stealth: e.stealthScore,
    })),
    entry_count: platformEntries.length,
  }));

  const portabilityScore =
    byPlatform.size >= 3
      ? "high"
      : byPlatform.size === 2
        ? "medium"
        : "low";

  return {
    binary: binary || undefined,
    function: fn || undefined,
    portability: portabilityScore,
    platform_count: byPlatform.size,
    platforms,
    cross_platform_note:
      byPlatform.size > 1
        ? `Available on ${[...byPlatform.keys()].join(", ")} — can be used for consistent attack patterns across platforms`
        : `Only available on ${[...byPlatform.keys()][0]} — platform-specific alternatives needed for cross-platform operations`,
  };
}

function buildUnifiedChain(
  environmentIds: string[],
  sessions: Map<string, any>,
  kb: any,
): any {
  const environments: any[] = [];

  for (const envId of environmentIds) {
    const model = sessions.get(envId);
    if (!model) continue;

    environments.push({
      id: envId,
      platform: model.state.platform,
      matched_entries: model.matchedEntries.length,
      privilege_level: model.state.privilegeLevel,
      escalation_binaries: model.matchedEntries
        .filter((m: any) =>
          m.entry.functions.includes("privilege_escalation") ||
          m.entry.functions.includes("shell"),
        )
        .map((m: any) => ({
          binary: m.entry.binary,
          platform: m.entry.platform,
          functions: m.entry.functions,
        })),
      lateral_binaries: model.matchedEntries
        .filter((m: any) =>
          m.entry.functions.includes("lateral_movement") ||
          m.entry.functions.includes("c2") ||
          m.entry.functions.includes("reverse_shell"),
        )
        .map((m: any) => ({
          binary: m.entry.binary,
          platform: m.entry.platform,
          functions: m.entry.functions,
        })),
    });
  }

  // Find binaries available across multiple environments
  const binaryPlatformMap = new Map<string, Set<string>>();
  for (const env of environments) {
    for (const entry of [...env.escalation_binaries, ...env.lateral_binaries]) {
      const key = entry.binary.toLowerCase();
      if (!binaryPlatformMap.has(key)) {
        binaryPlatformMap.set(key, new Set());
      }
      binaryPlatformMap.get(key)!.add(env.platform);
    }
  }

  const crossPlatformBinaries = [...binaryPlatformMap.entries()]
    .filter(([_, platforms]) => platforms.size > 1)
    .map(([binary, platforms]) => ({
      binary,
      platforms: [...platforms],
    }));

  return {
    environments,
    cross_platform_binaries: crossPlatformBinaries,
    unified_chain_suggestion:
      environments.length >= 2
        ? `Chain across ${environments.map((e) => e.platform).join(" → ")} using shared LOL techniques`
        : "Need at least 2 environments for cross-platform chain analysis",
  };
}

export const comparePlatformsComposite: ToolDef = {
  name: "compare_platforms",
  description:
    "Cross-platform LOL binary comparison: find equivalents between platforms, compute coverage differences, assess portability of techniques, and build unified attack chains across environments.",
  schema: {
    mode: z
      .enum(["equivalent", "coverage_diff", "portability", "unified_chain"])
      .describe(
        "Comparison mode: equivalent (find cross-platform alternatives), coverage_diff (compare function coverage between platforms), portability (assess technique portability), unified_chain (build cross-platform attack chains)",
      ),
    binary: z
      .string()
      .optional()
      .describe(
        "Binary name for 'equivalent' and 'portability' modes",
      ),
    function: z
      .string()
      .optional()
      .describe(
        "LOL function to compare across platforms (e.g. shell, file_read, privilege_escalation)",
      ),
    source_platform: z
      .enum(["linux", "windows", "macos"])
      .optional()
      .describe("Source platform for 'equivalent' and 'coverage_diff' modes"),
    target_platform: z
      .enum(["linux", "windows", "macos"])
      .optional()
      .describe("Target platform for 'equivalent' and 'coverage_diff' modes"),
    environment_ids: z
      .array(z.string())
      .optional()
      .describe(
        "List of environment session IDs for 'unified_chain' mode",
      ),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const {
      mode,
      binary,
      function: fn,
      source_platform,
      target_platform,
      environment_ids,
    } = args;

    switch (mode) {
      case "equivalent": {
        if (!binary) {
          return text("'binary' parameter is required for 'equivalent' mode");
        }
        const equivalents = findEquivalents(
          binary,
          source_platform as Platform | undefined,
          target_platform as Platform | undefined,
          ctx.knowledgeBase,
        );
        return json({
          mode: "equivalent",
          binary,
          source_platform: source_platform ?? "all",
          target_platform: target_platform ?? "all",
          total_equivalents: equivalents.length,
          equivalents,
        });
      }

      case "coverage_diff": {
        if (!source_platform || !target_platform) {
          return text(
            "'source_platform' and 'target_platform' are required for 'coverage_diff' mode",
          );
        }
        const diff = computeCoverageDiff(
          source_platform as Platform,
          target_platform as Platform,
          ctx.knowledgeBase,
        );
        return json({
          mode: "coverage_diff",
          ...diff,
        });
      }

      case "portability": {
        if (!binary && !fn) {
          return text(
            "'binary' or 'function' parameter is required for 'portability' mode",
          );
        }
        const portability = computePortability(
          binary ?? "",
          fn as LOLFunction | undefined,
          ctx.knowledgeBase,
        );
        return json({
          mode: "portability",
          ...portability,
        });
      }

      case "unified_chain": {
        if (!environment_ids || environment_ids.length === 0) {
          return text(
            "'environment_ids' parameter is required for 'unified_chain' mode",
          );
        }
        const chain = buildUnifiedChain(
          environment_ids,
          ctx.sessions,
          ctx.knowledgeBase,
        );
        return json({
          mode: "unified_chain",
          ...chain,
        });
      }

      default:
        return text(`Unknown comparison mode: ${mode}`);
    }
  },
};
