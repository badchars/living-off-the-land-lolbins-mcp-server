import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { collectionTools } from "../providers/collection.js";

const TYPE_TOOLS: Record<string, string> = {
  file_read: "collect_file_read",
  screen: "collect_screen_capture",
  clipboard: "collect_clipboard",
  input: "collect_input_capture",
};

export const findCollectionComposite: ToolDef = {
  name: "find_collection",
  description:
    "Find collection techniques using LOL binaries — file reading, screen capture, clipboard access, input capture.",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID returned by enumerate_host"),
    platform: z
      .enum(["linux", "windows", "macos", "all"])
      .optional()
      .default("all")
      .describe("Target platform for collection techniques"),
    collection_type: z
      .enum(["all", "file_read", "screen", "clipboard", "input"])
      .optional()
      .default("all")
      .describe("Type of collection technique to search for"),
    target_data: z
      .string()
      .optional()
      .describe("Specific data type or file to target for collection"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, platform, collection_type, target_data } = args;

    const baseArgs: Record<string, unknown> = {};
    if (environment_id) baseArgs.environment_id = environment_id;
    if (platform && platform !== "all") baseArgs.platform = platform;
    if (target_data) baseArgs.target_data = target_data;

    // Dispatch to specific type or all
    if (collection_type && collection_type !== "all") {
      const toolName = TYPE_TOOLS[collection_type];
      if (!toolName) {
        return { content: [{ type: "text", text: `Unknown collection type: ${collection_type}` }] };
      }
      const result = await callTool(collectionTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_collection",
        environment_id,
        platform,
        collection_type,
        target_data,
      });
    }

    const calls = Object.values(TYPE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(collectionTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_collection",
      environment_id,
      platform,
      collection_type: "all",
      target_data,
      tools_called: Object.values(TYPE_TOOLS),
    });
  },
};
