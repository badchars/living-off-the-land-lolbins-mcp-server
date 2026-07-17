import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json } from "../types/index.js";
import { ALL_LOL_FUNCTIONS } from "../schema/unified-entry.js";
import type { LOLFunction, Platform, CatalogSource } from "../schema/unified-entry.js";

export const searchTechniquesComposite: ToolDef = {
  name: "search_techniques",
  description: "Search LOL techniques by function, ATT&CK ID, platform, stealth score, catalog, keyword, detection coverage, or combined filters. Returns matching entries with full details.",
  schema: {
    mode: z.enum(["function", "attck", "platform", "stealth", "catalog", "keyword", "detection_coverage", "combined"])
      .describe("Search mode"),
    function: z.enum(ALL_LOL_FUNCTIONS as [string, ...string[]]).optional()
      .describe("For function mode: shell, reverse_shell, download, upload, edr_disable, c2, etc."),
    attck_id: z.string().optional()
      .describe("For attck mode: T1059.006, T1548.001, etc."),
    platform: z.enum(["linux", "windows", "macos", "esxi", "cicd", "network"]).optional()
      .describe("For platform mode or as additional filter"),
    max_stealth: z.number().optional()
      .describe("For stealth mode: max stealth score (1-5)"),
    catalog: z.string().optional()
      .describe("For catalog mode: gtfobins, lolbas, loobins, loldrivers, lolrmm, etc."),
    keyword: z.string().optional()
      .describe("For keyword mode: free-text search across binary names, descriptions, commands"),
    has_detection: z.boolean().optional()
      .describe("For detection_coverage mode: true=has rules, false=no coverage"),
    filters: z.object({
      platform: z.string().optional(),
      function: z.string().optional(),
      max_stealth: z.number().optional(),
      catalog: z.string().optional(),
      has_detection: z.boolean().optional(),
      category: z.string().optional(),
    }).optional().describe("For combined mode: apply multiple filters simultaneously"),
    limit: z.number().optional().default(20).describe("Max results to return"),
    offset: z.number().optional().default(0).describe("Pagination offset"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const limit = args.limit || 20;
    const offset = args.offset || 0;
    let results: import("../schema/unified-entry.js").UnifiedLOLEntry[] = [];

    switch (args.mode) {
      case "function":
        results = ctx.knowledgeBase.searchByFunction(args.function as LOLFunction, args.platform as Platform);
        break;
      case "attck":
        results = ctx.knowledgeBase.searchByAttck(args.attck_id, args.platform as Platform);
        break;
      case "platform":
        results = ctx.knowledgeBase.searchByPlatform((args.platform || "linux") as Platform);
        break;
      case "stealth":
        results = ctx.knowledgeBase.searchByStealth(args.max_stealth || 3, args.platform as Platform);
        break;
      case "catalog":
        results = ctx.knowledgeBase.searchByCatalog((args.catalog || "gtfobins") as CatalogSource);
        break;
      case "keyword":
        results = ctx.knowledgeBase.searchByKeyword(args.keyword || "", args.platform as Platform);
        break;
      case "detection_coverage":
        results = ctx.knowledgeBase.searchByDetectionCoverage(args.has_detection ?? true);
        break;
      case "combined": {
        const f = args.filters || {};
        results = ctx.knowledgeBase.searchCombined({
          platform: f.platform as Platform,
          function: f.function as LOLFunction,
          maxStealth: f.max_stealth,
          catalog: f.catalog as CatalogSource,
          hasDetection: f.has_detection,
          category: f.category,
        });
        break;
      }
    }

    const total = results.length;
    const slice = results.slice(offset, offset + limit);

    return json({
      mode: args.mode,
      total_matches: total,
      showing: { offset, limit, count: slice.length },
      entries: slice.map(e => ({
        id: e.id,
        binary: e.binary,
        platform: e.platform,
        catalog: e.catalogSource,
        functions: e.functions,
        stealth_score: e.stealthScore,
        attck: e.attckTechniques,
        description: e.description.slice(0, 200),
        contexts_count: e.executionContexts.length,
      })),
    });
  },
};
