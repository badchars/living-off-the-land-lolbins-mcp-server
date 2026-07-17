import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import {
  callTool,
  callToolsParallel,
  buildCompositeResponse,
} from "./helpers.js";
import { opsecRiskTools } from "../providers/opsec-risk.js";

const MODE_TOOLS: Record<string, string> = {
  noise: "opsec_noise_level",
  logs: "opsec_log_footprint",
  edr: "opsec_edr_trigger",
  alternatives: "opsec_safe_alternatives",
};

export const analyzeOpsecComposite: ToolDef = {
  name: "analyze_opsec_risk",
  description:
    "Analyze operational security risk — noise level, log footprint, EDR trigger probability, and safer alternatives for a given command",
  schema: {
    command: z
      .string()
      .describe("Command to analyze for operational security risk"),
    platform: z
      .enum(["linux", "windows", "macos"])
      .describe("Target platform for OPSEC analysis"),
    edr_product: z
      .string()
      .optional()
      .describe("Specific EDR product to evaluate trigger probability for"),
    mode: z
      .enum(["all", "noise", "logs", "edr", "alternatives"])
      .optional()
      .default("all")
      .describe("Type of OPSEC analysis to perform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { command, platform, edr_product, mode } = args;

    const baseArgs: Record<string, unknown> = { command, platform };
    if (edr_product) baseArgs.edr_product = edr_product;

    if (mode && mode !== "all") {
      const toolName = MODE_TOOLS[mode];
      if (!toolName) {
        return {
          content: [{ type: "text", text: `Unknown mode: ${mode}` }],
        };
      }
      const result = await callTool(opsecRiskTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "analyze_opsec_risk",
        mode,
        platform,
        command,
      });
    }

    const calls = Object.values(MODE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(opsecRiskTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "analyze_opsec_risk",
      mode: "all",
      platform,
      command,
      tools_called: Object.values(MODE_TOOLS),
    });
  },
};
