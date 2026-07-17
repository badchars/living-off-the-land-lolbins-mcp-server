import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, buildCompositeResponse } from "./helpers.js";
import { wadcomsTools } from "../providers/wadcoms.js";

const MODE_TOOLS: Record<string, string> = {
  search: "wadcoms_search",
  by_attack_type: "wadcoms_by_attack_type",
  by_service: "wadcoms_by_service",
  by_tool: "wadcoms_by_required_tool",
};

export const queryWadcomsComposite: ToolDef = {
  name: "query_wadcoms",
  description:
    "Query WADComs (Windows/Active Directory Commands) database — search commands, filter by attack type, service, or required tool for AD attacks.",
  schema: {
    mode: z
      .enum(["search", "by_attack_type", "by_service", "by_tool"])
      .optional()
      .default("search")
      .describe("WADComs query mode"),
    query: z.string().optional().describe("Keyword to search in WADComs commands"),
    attack_type: z
      .enum(["Enumeration", "Exploitation", "Lateral Movement", "Persistence", "Credential Access"])
      .optional()
      .describe("Filter by attack type"),
    service: z
      .string()
      .optional()
      .describe("Filter by service: LDAP, Kerberos, SMB, MSSQL"),
    required_tool: z
      .string()
      .optional()
      .describe("Filter by required tool: impacket, rubeus, crackmapexec"),
    os_filter: z
      .enum(["Linux", "Windows"])
      .optional()
      .describe("Filter by OS"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, query, attack_type, service, required_tool, os_filter } = args;

    const baseArgs: Record<string, unknown> = {};
    if (query) baseArgs.query = query;
    if (attack_type) baseArgs.attack_type = attack_type;
    if (service) baseArgs.service = service;
    if (required_tool) baseArgs.required_tool = required_tool;
    if (os_filter) baseArgs.os_filter = os_filter;

    const toolName = MODE_TOOLS[mode];
    if (!toolName) {
      return { content: [{ type: "text", text: `Unknown WADComs mode: ${mode}` }] };
    }

    const result = await callTool(wadcomsTools, toolName, baseArgs, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, {
      composite: "query_wadcoms",
      mode,
      query,
      attack_type,
      service,
      required_tool,
      os_filter,
    });
  },
};
