import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { visualizeTools } from "../providers/visualize.js";

const MODE_TOOLS: Record<string, string> = {
  mermaid: "viz_mermaid_diagram",
  graphviz: "viz_graphviz_dot",
  ascii_tree: "viz_ascii_tree",
  json_graph: "viz_json_graph",
};

export const visualizeAttackComposite: ToolDef = {
  name: "visualize_attack_path",
  description:
    "Visualize attack paths and chains — Mermaid diagrams, Graphviz DOT, ASCII trees, JSON graph data.",
  schema: {
    mode: z
      .enum(["mermaid", "graphviz", "ascii_tree", "json_graph"])
      .describe("Visualization format"),
    environment_id: z.string().optional().describe("Environment session ID"),
    path_type: z
      .enum(["escalation", "persistence", "lateral", "full"])
      .optional()
      .describe("Attack path type to visualize"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };
    const result = await callTool(visualizeTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);
    return buildCompositeResponse(results, { composite: "visualize_attack_path", mode });
  },
};
