import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { executionTools } from "../providers/execution.js";

const TYPE_TOOLS: Record<string, string> = {
  proxy: "exec_proxy",
  compile: "exec_compile",
  script_host: "exec_script_host",
  wmi: "exec_wmi",
  mmc: "exec_mmc",
};

export const findExecutionComposite: ToolDef = {
  name: "find_execution_proxy",
  description:
    "Find execution proxy techniques — signed binary proxy execution, compile-and-execute, script hosts, WMI execution, MMC snap-in abuse.",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID returned by enumerate_host"),
    platform: z
      .enum(["linux", "windows", "macos"])
      .optional()
      .describe("Target platform to filter execution techniques"),
    execution_type: z
      .enum(["all", "proxy", "compile", "script_host", "wmi", "mmc"])
      .optional()
      .default("all")
      .describe("Type of execution proxy technique to search for"),
    target_payload: z
      .string()
      .optional()
      .describe("Target payload or binary to execute via proxy"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, platform, execution_type, target_payload } = args;

    const baseArgs: Record<string, unknown> = {};
    if (environment_id) baseArgs.environment_id = environment_id;
    if (platform) baseArgs.platform = platform;
    if (target_payload) baseArgs.target_payload = target_payload;

    // Dispatch to specific type or all
    if (execution_type && execution_type !== "all") {
      const toolName = TYPE_TOOLS[execution_type];
      if (!toolName) {
        return { content: [{ type: "text", text: `Unknown execution type: ${execution_type}` }] };
      }
      const result = await callTool(executionTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_execution_proxy",
        environment_id,
        platform,
        execution_type,
        target_payload,
      });
    }

    const calls = Object.values(TYPE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(executionTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_execution_proxy",
      environment_id,
      platform,
      execution_type: "all",
      target_payload,
      tools_called: Object.values(TYPE_TOOLS),
    });
  },
};
