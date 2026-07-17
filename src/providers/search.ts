import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import { ALL_LOL_FUNCTIONS } from "../schema/unified-entry.js";
import type { LOLFunction, Platform, CatalogSource } from "../schema/unified-entry.js";

const search_by_function: ToolDef = {
  name: "search_by_function",
  description: "Search techniques by LOL function type (shell, reverse_shell, download, etc.)",
  schema: {
    function: z.enum(ALL_LOL_FUNCTIONS as [string, ...string[]]).describe("Function type"),
    platform: z.string().optional().describe("Filter by platform"),
    limit: z.number().optional().default(20).describe("Max results"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const results = ctx.knowledgeBase.searchByFunction(args.function as LOLFunction, args.platform as Platform);
    return json({ total: results.length, entries: results.slice(0, args.limit || 20) });
  },
};

const search_by_attck: ToolDef = {
  name: "search_by_attck",
  description: "Search techniques by MITRE ATT&CK technique ID",
  schema: {
    attck_id: z.string().describe("ATT&CK technique ID (e.g. T1059.006)"),
    platform: z.string().optional().describe("Filter by platform"),
    limit: z.number().optional().default(20).describe("Max results"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const results = ctx.knowledgeBase.searchByAttck(args.attck_id, args.platform as Platform);
    return json({ total: results.length, entries: results.slice(0, args.limit || 20) });
  },
};

const search_by_platform: ToolDef = {
  name: "search_by_platform",
  description: "List all techniques available on a given platform",
  schema: {
    platform: z.enum(["linux", "windows", "macos", "esxi", "cicd", "network"]).describe("Target platform"),
    limit: z.number().optional().default(20).describe("Max results"),
    offset: z.number().optional().default(0).describe("Pagination offset"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const results = ctx.knowledgeBase.searchByPlatform(args.platform as Platform);
    const slice = results.slice(args.offset || 0, (args.offset || 0) + (args.limit || 20));
    return json({ total: results.length, offset: args.offset || 0, entries: slice });
  },
};

const search_by_stealth: ToolDef = {
  name: "search_by_stealth",
  description: "Search for techniques with stealth score at or below a threshold",
  schema: {
    max_stealth: z.number().min(1).max(5).describe("Maximum stealth score (1=ghost, 5=loud)"),
    platform: z.string().optional().describe("Filter by platform"),
    limit: z.number().optional().default(20).describe("Max results"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const results = ctx.knowledgeBase.searchByStealth(args.max_stealth, args.platform as Platform);
    return json({ total: results.length, entries: results.slice(0, args.limit || 20) });
  },
};

const search_by_catalog: ToolDef = {
  name: "search_by_catalog",
  description: "List all entries from a specific catalog source",
  schema: {
    catalog: z.string().describe("Catalog name: gtfobins, lolbas, loobins, loldrivers, lolrmm, etc."),
    limit: z.number().optional().default(20).describe("Max results"),
    offset: z.number().optional().default(0).describe("Pagination offset"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const results = ctx.knowledgeBase.searchByCatalog(args.catalog as CatalogSource);
    const slice = results.slice(args.offset || 0, (args.offset || 0) + (args.limit || 20));
    return json({ total: results.length, offset: args.offset || 0, entries: slice });
  },
};

const search_by_keyword: ToolDef = {
  name: "search_by_keyword",
  description: "Free-text search across binary names, descriptions, and commands",
  schema: {
    keyword: z.string().describe("Search keyword"),
    platform: z.string().optional().describe("Filter by platform"),
    limit: z.number().optional().default(20).describe("Max results"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const results = ctx.knowledgeBase.searchByKeyword(args.keyword, args.platform as Platform);
    return json({ total: results.length, entries: results.slice(0, args.limit || 20) });
  },
};

const search_by_detection_coverage: ToolDef = {
  name: "search_by_detection_coverage",
  description: "Find techniques with or without detection rules (Sigma, YARA, etc.)",
  schema: {
    has_detection: z.boolean().describe("true = has detection rules, false = no detection coverage"),
    limit: z.number().optional().default(20).describe("Max results"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const results = ctx.knowledgeBase.searchByDetectionCoverage(args.has_detection);
    return json({ total: results.length, entries: results.slice(0, args.limit || 20) });
  },
};

const search_combined_filter: ToolDef = {
  name: "search_combined_filter",
  description: "Apply multiple filters simultaneously for precise technique search",
  schema: {
    platform: z.string().optional().describe("Platform filter"),
    function: z.string().optional().describe("Function type filter"),
    max_stealth: z.number().optional().describe("Max stealth score"),
    catalog: z.string().optional().describe("Catalog source filter"),
    has_detection: z.boolean().optional().describe("Detection coverage filter"),
    category: z.string().optional().describe("Entry category filter"),
    limit: z.number().optional().default(20).describe("Max results"),
    offset: z.number().optional().default(0).describe("Pagination offset"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const results = ctx.knowledgeBase.searchCombined({
      platform: args.platform as Platform,
      function: args.function as LOLFunction,
      maxStealth: args.max_stealth,
      catalog: args.catalog as CatalogSource,
      hasDetection: args.has_detection,
      category: args.category,
    });
    const slice = results.slice(args.offset || 0, (args.offset || 0) + (args.limit || 20));
    return json({ total: results.length, offset: args.offset || 0, filters_applied: args, entries: slice });
  },
};

export const searchTools: ToolDef[] = [
  search_by_function,
  search_by_attck,
  search_by_platform,
  search_by_stealth,
  search_by_catalog,
  search_by_keyword,
  search_by_detection_coverage,
  search_combined_filter,
];
