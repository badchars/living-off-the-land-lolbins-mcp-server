import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";

const gtfobins_lookup: ToolDef = {
  name: "gtfobins_lookup",
  description: "Look up a binary in GTFOBins (Linux privilege escalation)",
  schema: {
    binary: z.string().describe("Binary name to look up"),
  },
  async execute(args: { binary: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = ctx.knowledgeBase.lookupBinary(args.binary, "linux")
      .filter(e => e.catalogSource === "gtfobins");
    if (entries.length === 0) return text(`No GTFOBins entry found for "${args.binary}"`);
    return json(entries);
  },
};

const lolbas_lookup: ToolDef = {
  name: "lolbas_lookup",
  description: "Look up a binary in LOLBAS (Windows living off the land)",
  schema: {
    binary: z.string().describe("Binary name to look up"),
  },
  async execute(args: { binary: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = ctx.knowledgeBase.lookupBinary(args.binary, "windows")
      .filter(e => e.catalogSource === "lolbas");
    if (entries.length === 0) return text(`No LOLBAS entry found for "${args.binary}"`);
    return json(entries);
  },
};

const loobins_lookup: ToolDef = {
  name: "loobins_lookup",
  description: "Look up a binary in LOOBins (macOS living off the orchard)",
  schema: {
    binary: z.string().describe("Binary name to look up"),
  },
  async execute(args: { binary: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = ctx.knowledgeBase.lookupBinary(args.binary, "macos")
      .filter(e => e.catalogSource === "loobins");
    if (entries.length === 0) return text(`No LOOBins entry found for "${args.binary}"`);
    return json(entries);
  },
};

const loldrivers_lookup: ToolDef = {
  name: "loldrivers_lookup",
  description: "Look up a driver in LOLDrivers (vulnerable/malicious Windows drivers)",
  schema: {
    binary: z.string().describe("Driver name or hash to look up"),
  },
  async execute(args: { binary: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = ctx.knowledgeBase.lookupBinary(args.binary, "windows")
      .filter(e => e.catalogSource === "loldrivers");

    // Also search by hash
    if (entries.length === 0 && args.binary.length >= 32) {
      const hashSearch = ctx.knowledgeBase.allEntries.filter(e =>
        e.driverSamples?.some(s =>
          s.sha256.toLowerCase() === args.binary.toLowerCase() ||
          s.md5.toLowerCase() === args.binary.toLowerCase() ||
          s.sha1.toLowerCase() === args.binary.toLowerCase()
        )
      );
      if (hashSearch.length > 0) return json(hashSearch);
    }

    if (entries.length === 0) return text(`No LOLDrivers entry found for "${args.binary}"`);
    return json(entries);
  },
};

const lolrmm_lookup: ToolDef = {
  name: "lolrmm_lookup",
  description: "Look up an RMM tool in LOLRMM catalog",
  schema: {
    binary: z.string().describe("RMM tool name to look up"),
  },
  async execute(args: { binary: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = ctx.knowledgeBase.lookupBinary(args.binary)
      .filter(e => e.catalogSource === "lolrmm");
    if (entries.length === 0) return text(`No LOLRMM entry found for "${args.binary}"`);
    return json(entries);
  },
};

const cross_platform_lookup: ToolDef = {
  name: "cross_platform_lookup",
  description: "Look up a binary across all catalogs and platforms",
  schema: {
    binary: z.string().describe("Binary name to look up"),
  },
  async execute(args: { binary: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = ctx.knowledgeBase.lookupBinary(args.binary);
    if (entries.length === 0) return text(`No entries found for "${args.binary}" in any catalog`);

    const grouped = {
      total: entries.length,
      byPlatform: {} as Record<string, number>,
      byCatalog: {} as Record<string, number>,
      entries,
    };
    for (const e of entries) {
      grouped.byPlatform[e.platform] = (grouped.byPlatform[e.platform] || 0) + 1;
      grouped.byCatalog[e.catalogSource] = (grouped.byCatalog[e.catalogSource] || 0) + 1;
    }
    return json(grouped);
  },
};

export const lookupTools: ToolDef[] = [
  gtfobins_lookup,
  lolbas_lookup,
  loobins_lookup,
  loldrivers_lookup,
  lolrmm_lookup,
  cross_platform_lookup,
];
