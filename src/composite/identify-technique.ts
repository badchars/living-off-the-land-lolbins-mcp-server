import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, buildCompositeResponse } from "./helpers.js";
import { identifyTechniqueTools } from "../providers/identify-technique.js";

const MODE_TOOLS: Record<string, string> = {
  from_commandline: "id_from_commandline",
  from_sysmon: "id_from_sysmon",
  from_process_tree: "id_from_process_tree",
  from_edr_alert: "id_from_edr_alert",
};

export const identifyTechniqueComposite: ToolDef = {
  name: "identify_technique",
  description:
    "Identify LOL technique from forensic evidence — command line analysis, Sysmon events, process trees, EDR alerts.",
  schema: {
    mode: z
      .enum(["from_commandline", "from_sysmon", "from_process_tree", "from_edr_alert"])
      .describe("Identification source"),
    command: z.string().optional().describe("Command line string to analyze"),
    event_id: z.number().optional().describe("Sysmon event ID"),
    event_data: z.string().optional().describe("Sysmon event XML/JSON data"),
    process_tree: z.string().optional().describe("Process tree text (parent->child)"),
    alert_text: z.string().optional().describe("EDR alert text to analyze"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };

    const result = await callTool(identifyTechniqueTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, { composite: "identify_technique", mode });
  },
};
