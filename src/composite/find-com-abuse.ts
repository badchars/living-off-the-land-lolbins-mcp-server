import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { comAbuseTools } from "../providers/com-abuse.js";

const MODE_TOOLS: Record<string, string> = {
  hijack: "com_hijack_persist",
  dcom: "com_dcom_lateral",
  execution: "com_execution",
  scriptlet: "com_scriptlet",
  inventory: "com_inventory",
};

export const findComAbuseComposite: ToolDef = {
  name: "find_com_abuse",
  description:
    "Find COM object abuse techniques — hijacking, DCOM lateral movement, execution proxying, scriptlet loading.",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID returned by enumerate_host"),
    mode: z
      .enum(["all", "hijack", "dcom", "execution", "scriptlet", "inventory"])
      .optional()
      .default("all")
      .describe("COM abuse mode to search for"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, mode } = args;

    const baseArgs: Record<string, unknown> = {};
    if (environment_id) baseArgs.environment_id = environment_id;

    // Dispatch to specific tool or all
    if (mode && mode !== "all") {
      const toolName = MODE_TOOLS[mode];
      if (!toolName) {
        return { content: [{ type: "text", text: `Unknown COM abuse mode: ${mode}` }] };
      }
      const result = await callTool(comAbuseTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_com_abuse",
        environment_id,
        mode,
      });
    }

    const calls = Object.values(MODE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(comAbuseTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_com_abuse",
      environment_id,
      mode: "all",
      tools_called: Object.values(MODE_TOOLS),
    });
  },
};
