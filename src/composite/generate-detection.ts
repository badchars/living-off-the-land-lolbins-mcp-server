import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { detectionGenTools } from "../providers/detection-gen.js";

const MODE_TOOLS: Record<string, string> = {
  sigma: "gen_sigma_rule",
  yara: "gen_yara_rule",
  sysmon: "gen_sysmon_config",
  edr_query: "gen_edr_query",
  hunt_query: "gen_hunt_query",
  atomic_test: "gen_atomic_test",
};

export const generateDetectionComposite: ToolDef = {
  name: "generate_detection",
  description:
    "Generate detection rules and tests for LOL techniques — Sigma rules, YARA rules, Sysmon config, EDR queries, hunt queries, Atomic Red Team tests.",
  schema: {
    mode: z
      .enum(["sigma", "yara", "sysmon", "edr_query", "hunt_query", "atomic_test"])
      .describe("Detection rule type to generate"),
    binary: z.string().optional().describe("Binary name to generate detection for"),
    technique_id: z.string().optional().describe("LOL technique ID"),
    attck_id: z.string().optional().describe("ATT&CK technique ID"),
    edr_product: z
      .enum(["elastic", "splunk", "microsoft_defender", "crowdstrike", "sentinel_one"])
      .optional()
      .describe("Target EDR for query generation"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };
    const result = await callTool(detectionGenTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);
    return buildCompositeResponse(results, { composite: "generate_detection", mode });
  },
};
