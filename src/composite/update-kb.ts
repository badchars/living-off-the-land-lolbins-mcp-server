import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json } from "../types/index.js";
import { updateAll, updateCatalog } from "../knowledge-base/updater.js";
import { loadFromDataDir } from "../knowledge-base/loader.js";

export const updateKbComposite: ToolDef = {
  name: "update_knowledge_base",
  description: "Manage the LOL knowledge base: update all catalogs from upstream, update a specific catalog, show diffs, or display statistics.",
  schema: {
    mode: z.enum(["update_all", "update_catalog", "diff", "stats"])
      .describe("KB management mode"),
    catalog: z.string().optional()
      .describe("For update_catalog: specific catalog name (gtfobins, lolbas, loobins, loldrivers)"),
    since: z.string().optional()
      .describe("For diff: ISO date to compare against"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    switch (args.mode) {
      case "update_all": {
        const results = await updateAll(ctx.config.dataDir);
        const entries = await loadFromDataDir(ctx.config.dataDir);
        ctx.knowledgeBase.load(entries);
        return json({
          mode: "update_all",
          results,
          total_entries_loaded: ctx.knowledgeBase.totalEntries,
          stats: ctx.knowledgeBase.stats(),
        });
      }

      case "update_catalog": {
        if (!args.catalog) {
          return json({ error: "catalog parameter required for update_catalog mode" });
        }
        const result = await updateCatalog(ctx.config.dataDir, args.catalog);
        const entries = await loadFromDataDir(ctx.config.dataDir);
        ctx.knowledgeBase.load(entries);
        return json({
          mode: "update_catalog",
          ...result,
          total_entries_loaded: ctx.knowledgeBase.totalEntries,
        });
      }

      case "diff": {
        return json({
          mode: "diff",
          note: "Diff tracking requires previous snapshot for comparison",
          current_stats: ctx.knowledgeBase.stats(),
          since: args.since || "N/A",
        });
      }

      case "stats": {
        return json({
          mode: "stats",
          ...ctx.knowledgeBase.stats(),
        });
      }

      default:
        return json({ error: `Unknown mode: ${args.mode}` });
    }
  },
};
