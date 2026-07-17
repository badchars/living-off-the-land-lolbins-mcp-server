import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { wmiAbuseTools } from "../providers/wmi-abuse.js";

const MODE_TOOLS: Record<string, string> = {
  persistence: "wmi_persistence",
  lateral: "wmi_lateral_movement",
  execution: "wmi_execution",
  recon: "wmi_recon",
  subscription: "wmi_event_subscription",
};

export const findWmiAbuseComposite: ToolDef = {
  name: "find_wmi_abuse",
  description:
    "Find WMI abuse techniques — persistence via event subscriptions, lateral movement, process execution, reconnaissance.",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID returned by enumerate_host"),
    mode: z
      .enum(["all", "persistence", "lateral", "execution", "recon", "subscription"])
      .optional()
      .default("all")
      .describe("WMI abuse mode to search for"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, mode } = args;

    const baseArgs: Record<string, unknown> = {};
    if (environment_id) baseArgs.environment_id = environment_id;

    // Dispatch to specific mode or all
    if (mode && mode !== "all") {
      const toolName = MODE_TOOLS[mode];
      if (!toolName) {
        return { content: [{ type: "text", text: `Unknown WMI abuse mode: ${mode}` }] };
      }
      const result = await callTool(wmiAbuseTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_wmi_abuse",
        environment_id,
        mode,
      });
    }

    const calls = Object.values(MODE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(wmiAbuseTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_wmi_abuse",
      environment_id,
      mode: "all",
      tools_called: Object.values(MODE_TOOLS),
    });
  },
};
