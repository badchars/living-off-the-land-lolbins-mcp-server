import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import {
  callTool,
  callToolsParallel,
  buildCompositeResponse,
} from "./helpers.js";
import { processManipulationTools } from "../providers/process-manipulation.js";

const MODE_TOOLS: Record<string, string> = {
  parent_spoof: "proc_parent_spoof",
  hollowing: "proc_hollowing",
  injection: "proc_injection_lol",
  doppelganging: "proc_doppelganging",
  herpaderping: "proc_herpaderping",
};

export const findProcessManipulationComposite: ToolDef = {
  name: "find_process_manipulation",
  description:
    "Find process manipulation techniques — parent PID spoofing, process hollowing, LOL binary injection, doppelganging, herpaderping",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID returned by enumerate_host"),
    mode: z
      .enum([
        "all",
        "parent_spoof",
        "hollowing",
        "injection",
        "doppelganging",
        "herpaderping",
      ])
      .optional()
      .default("all")
      .describe("Type of process manipulation technique to search for"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, mode } = args;

    const baseArgs: Record<string, unknown> = {};
    if (environment_id) baseArgs.environment_id = environment_id;

    if (mode && mode !== "all") {
      const toolName = MODE_TOOLS[mode];
      if (!toolName) {
        return {
          content: [{ type: "text", text: `Unknown mode: ${mode}` }],
        };
      }
      const result = await callTool(
        processManipulationTools,
        toolName,
        baseArgs,
        ctx,
      );
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_process_manipulation",
        environment_id,
        mode,
      });
    }

    const calls = Object.values(MODE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(
      processManipulationTools,
      calls,
      ctx,
    );

    return buildCompositeResponse(results, {
      composite: "find_process_manipulation",
      environment_id,
      mode: "all",
      tools_called: Object.values(MODE_TOOLS),
    });
  },
};
