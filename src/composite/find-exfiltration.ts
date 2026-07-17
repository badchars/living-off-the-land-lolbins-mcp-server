import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { exfiltrationTools } from "../providers/exfiltration.js";

const CHANNEL_TOOLS: Record<string, string> = {
  http: "exfil_http",
  dns: "exfil_dns",
  lots: "exfil_lots",
  tunnel: "exfil_tunnel",
  ads: "exfil_ads_stream",
  icmp: "exfil_icmp",
};

export const findExfiltrationComposite: ToolDef = {
  name: "find_exfiltration_paths",
  description:
    "Find exfiltration techniques using LOL binaries — HTTP, DNS, LOTS (Living off Trusted Sites), tunnels, ADS streams, ICMP.",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by enumerate_host"),
    target_data: z
      .string()
      .optional()
      .describe("Description of data to exfiltrate"),
    data_size: z
      .enum(["small", "medium", "large"])
      .optional()
      .describe("Approximate size of data to exfiltrate"),
    stealth_priority: z
      .boolean()
      .optional()
      .default(false)
      .describe("Prioritize stealthier exfiltration channels"),
    channel_filter: z
      .enum(["all", "http", "dns", "lots", "tunnel", "ads", "icmp"])
      .optional()
      .default("all")
      .describe("Filter by exfiltration channel type"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, target_data, data_size, stealth_priority, channel_filter } =
      args;

    const baseArgs: Record<string, unknown> = { environment_id };
    if (target_data) baseArgs.target_data = target_data;
    if (data_size) baseArgs.data_size = data_size;
    if (stealth_priority) baseArgs.stealth_priority = stealth_priority;

    // Dispatch to specific channel or all
    if (channel_filter && channel_filter !== "all") {
      const toolName = CHANNEL_TOOLS[channel_filter];
      if (!toolName) {
        return { content: [{ type: "text", text: `Unknown channel filter: ${channel_filter}` }] };
      }
      const result = await callTool(exfiltrationTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_exfiltration_paths",
        environment_id,
        channel_filter,
        data_size,
        stealth_priority,
      });
    }

    const calls = Object.values(CHANNEL_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(exfiltrationTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_exfiltration_paths",
      environment_id,
      channel_filter: "all",
      target_data,
      data_size,
      stealth_priority,
      tools_called: Object.values(CHANNEL_TOOLS),
    });
  },
};
