import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, buildCompositeResponse } from "./helpers.js";
import { cicdTools } from "../providers/cicd.js";

const MODE_TOOLS: Record<string, string> = {
  tool_lookup: "cicd_tool_lookup",
  footgun_search: "cicd_footgun_search",
  pipeline_poison: "cicd_pipeline_poison",
  config_exploit: "cicd_config_exploit",
  supply_chain: "cicd_supply_chain",
};

export const findCicdComposite: ToolDef = {
  name: "find_cicd_abuse",
  description:
    "Find CI/CD pipeline abuse techniques — tool lookup from LOTP catalog, footgun search, pipeline poisoning, config exploitation, supply chain attacks.",
  schema: {
    mode: z
      .enum(["tool_lookup", "footgun_search", "pipeline_poison", "config_exploit", "supply_chain"])
      .optional()
      .default("tool_lookup")
      .describe("CI/CD abuse analysis mode"),
    tool_name: z
      .string()
      .optional()
      .describe("CI/CD tool name (make, gradle, npm, pip, docker, terraform)"),
    tag: z
      .string()
      .optional()
      .describe("Tag to search: eval-sh, config-file, env-var, build-plugin"),
    pipeline_type: z
      .string()
      .optional()
      .describe("Pipeline type: github-actions, gitlab-ci, jenkins"),
    config_file: z
      .string()
      .optional()
      .describe("Config file to analyze: Makefile, package.json"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, tool_name, tag, pipeline_type, config_file } = args;

    const baseArgs: Record<string, unknown> = {};
    if (tool_name) baseArgs.tool_name = tool_name;
    if (tag) baseArgs.tag = tag;
    if (pipeline_type) baseArgs.pipeline_type = pipeline_type;
    if (config_file) baseArgs.config_file = config_file;

    const toolName = MODE_TOOLS[mode];
    if (!toolName) {
      return { content: [{ type: "text", text: `Unknown CI/CD mode: ${mode}` }] };
    }

    const result = await callTool(cicdTools, toolName, baseArgs, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, {
      composite: "find_cicd_abuse",
      mode,
      tool_name,
      pipeline_type,
      config_file,
    });
  },
};
