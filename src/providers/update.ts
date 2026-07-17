import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import { updateAll, updateCatalog } from "../knowledge-base/updater.js";
import { loadFromDataDir } from "../knowledge-base/loader.js";

const update_all: ToolDef = {
  name: "update_all",
  description: "Update all catalog data from upstream sources",
  schema: {},
  async execute(_args: any, ctx: ToolContext): Promise<ToolResult> {
    const results = await updateAll(ctx.config.dataDir);
    // Reload knowledge base
    const entries = await loadFromDataDir(ctx.config.dataDir);
    ctx.knowledgeBase.load(entries);
    return json({
      results,
      reloaded_entries: ctx.knowledgeBase.totalEntries,
    });
  },
};

const update_catalog_tool: ToolDef = {
  name: "update_catalog",
  description: "Update a specific catalog from its upstream source",
  schema: {
    catalog: z.string().describe("Catalog to update: gtfobins, lolbas, loobins, loldrivers"),
  },
  async execute(args: { catalog: string }, ctx: ToolContext): Promise<ToolResult> {
    const result = await updateCatalog(ctx.config.dataDir, args.catalog);
    // Reload knowledge base
    const entries = await loadFromDataDir(ctx.config.dataDir);
    ctx.knowledgeBase.load(entries);
    return json({
      ...result,
      reloaded_entries: ctx.knowledgeBase.totalEntries,
    });
  },
};

const update_diff: ToolDef = {
  name: "update_diff",
  description: "Show what changed since a given date (requires previous manifest)",
  schema: {
    since: z.string().optional().describe("ISO date to compare against"),
  },
  async execute(args: { since?: string }, ctx: ToolContext): Promise<ToolResult> {
    // For now return current stats as baseline
    const stats = ctx.knowledgeBase.stats();
    return json({
      note: "Diff tracking requires previous manifest comparison — showing current state",
      current: stats,
      since: args.since || "N/A",
    });
  },
};

const kb_stats: ToolDef = {
  name: "kb_stats",
  description: "Show knowledge base statistics",
  schema: {},
  async execute(_args: any, ctx: ToolContext): Promise<ToolResult> {
    return json(ctx.knowledgeBase.stats());
  },
};

export const updateTools: ToolDef[] = [
  update_all,
  update_catalog_tool,
  update_diff,
  kb_stats,
];
