import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { namedPipeTools } from "../providers/named-pipe.js";

const MODE_TOOLS: Record<string, string> = {
  impersonation: "pipe_impersonation",
  c2: "pipe_c2_channel",
  relay: "pipe_relay",
  discovery: "pipe_discovery",
};

export const findNamedPipeComposite: ToolDef = {
  name: "find_named_pipe_abuse",
  description:
    "Find named pipe abuse techniques — impersonation, C2 channels, relay, and discovery.",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID returned by enumerate_host"),
    mode: z
      .enum(["all", "impersonation", "c2", "relay", "discovery"])
      .optional()
      .default("all")
      .describe("Named pipe abuse mode to search for"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, mode } = args;

    const baseArgs: Record<string, unknown> = {};
    if (environment_id) baseArgs.environment_id = environment_id;

    // Dispatch to specific mode or all
    if (mode && mode !== "all") {
      const toolName = MODE_TOOLS[mode];
      if (!toolName) {
        return { content: [{ type: "text", text: `Unknown named pipe mode: ${mode}` }] };
      }
      const result = await callTool(namedPipeTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_named_pipe_abuse",
        environment_id,
        mode,
      });
    }

    const calls = Object.values(MODE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(namedPipeTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_named_pipe_abuse",
      environment_id,
      mode: "all",
      tools_called: Object.values(MODE_TOOLS),
    });
  },
};
