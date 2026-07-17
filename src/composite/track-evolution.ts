import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, buildCompositeResponse } from "./helpers.js";
import { techniqueEvolutionTools } from "../providers/technique-evolution.js";

const MODE_TOOLS: Record<string, string> = {
  history: "evolution_history",
  os_changes: "evolution_os_changes",
  deprecation: "evolution_deprecation",
};

export const trackEvolutionComposite: ToolDef = {
  name: "track_technique_evolution",
  description:
    "Track evolution of LOL binary techniques over time — usage history, OS version changes affecting techniques, and deprecated/removed techniques.",
  schema: {
    mode: z
      .enum(["history", "os_changes", "deprecation"])
      .describe("Evolution tracking mode"),
    binary: z.string().optional().describe("Binary name to track evolution of"),
    os_version: z.string().optional().describe("OS version to check (e.g. 'Windows 11', 'Ubuntu 24.04')"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };

    const result = await callTool(techniqueEvolutionTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, { composite: "track_technique_evolution", mode });
  },
};
