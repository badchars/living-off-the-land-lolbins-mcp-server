import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json } from "../types/index.js";
import type { Platform } from "../schema/unified-entry.js";

export const lookupBinaryComposite: ToolDef = {
  name: "lookup_binary",
  description: "Look up a binary/tool across all LOL catalogs (GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM). Returns all known techniques, detection rules, cross-platform equivalents, and chain potential.",
  schema: {
    binary: z.string().describe("Binary name (e.g. python, certutil, osascript, dbutil_2_3.sys, anydesk)"),
    platform: z.enum(["linux", "windows", "macos", "esxi", "all"]).optional().default("all")
      .describe("Filter by platform"),
    include_related: z.boolean().optional().default(true)
      .describe("Include cross-platform equivalents and related entries"),
    include_detection: z.boolean().optional().default(true)
      .describe("Include full detection rules and IOCs"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform === "all" ? undefined : args.platform as Platform;
    const entries = ctx.knowledgeBase.lookupBinary(args.binary, platform);

    if (entries.length === 0) {
      return json({
        binary: args.binary,
        found: false,
        message: `No entries found for "${args.binary}" in any catalog`,
        suggestion: "Try alternative names or check spelling",
      });
    }

    // Collect related entries
    let relatedEntries: any[] = [];
    if (args.include_related) {
      const relatedIds = new Set<string>();
      for (const e of entries) {
        for (const relId of e.relatedEntries) {
          if (!entries.some(x => x.id === relId)) relatedIds.add(relId);
        }
      }
      for (const relId of relatedIds) {
        const rel = ctx.knowledgeBase.getById(relId);
        if (rel) relatedEntries.push({
          id: rel.id,
          binary: rel.binary,
          platform: rel.platform,
          catalog: rel.catalogSource,
          functions: rel.functions,
        });
      }
    }

    // Detection summary
    const detectionSummary = args.include_detection ? {
      totalSigmaRules: entries.reduce((s, e) => s + e.detection.sigmaRules.length, 0),
      totalYaraRules: entries.reduce((s, e) => s + e.detection.yaraRules.length, 0),
      totalBlockRules: entries.reduce((s, e) => s + e.detection.blockRules.length, 0),
      edrCoverage: entries.map(e => e.detection.edrCoverage).sort()[entries.length - 1] || "none",
    } : undefined;

    return json({
      binary: args.binary,
      found: true,
      total_entries: entries.length,
      entries: entries.map(e => ({
        id: e.id,
        binary: e.binary,
        platform: e.platform,
        catalog: e.catalogSource,
        category: e.category,
        description: e.description,
        functions: e.functions,
        stealth_score: e.stealthScore,
        attck_techniques: e.attckTechniques,
        execution_contexts: e.executionContexts,
        detection: args.include_detection ? e.detection : undefined,
        full_paths: e.fullPaths,
        chain_potential: e.chainPotential,
        driver_info: e.driverCategory ? {
          category: e.driverCategory,
          samples_count: e.driverSamples?.length || 0,
          cves: e.cves,
        } : undefined,
      })),
      cross_platform_refs: relatedEntries,
      detection_summary: detectionSummary,
    });
  },
};
