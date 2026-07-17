import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { osVersionsTools } from "../providers/os-versions.js";

const MODE_TOOLS: Record<string, string> = {
  behavior_diff: "osver_binary_behavior_diff",
  validity: "osver_technique_validity",
  deprecation: "osver_deprecation",
  new_capabilities: "osver_new_capabilities",
};

export const compareOsVersionsComposite: ToolDef = {
  name: "compare_os_versions",
  description:
    "Compare LOL technique behavior across OS versions — binary behavior differences, technique validity, deprecation tracking, new capabilities.",
  schema: {
    mode: z
      .enum(["behavior_diff", "validity", "deprecation", "new_capabilities"])
      .describe("OS version comparison mode"),
    binary: z.string().optional().describe("Binary name to compare"),
    os_versions: z
      .array(z.string())
      .optional()
      .describe("OS versions to compare (e.g. ['Windows 10', 'Windows 11'])"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };
    const result = await callTool(osVersionsTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);
    return buildCompositeResponse(results, { composite: "compare_os_versions", mode });
  },
};
