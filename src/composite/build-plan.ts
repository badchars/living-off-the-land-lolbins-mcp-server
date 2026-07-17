import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import {
  callTool,
  callToolsParallel,
  buildCompositeResponse,
} from "./helpers.js";
import { planTools } from "../providers/plan.js";

const MODE_TOOLS: Record<string, string> = {
  generate: "plan_generate",
  score: "plan_score",
  optimize: "plan_optimize",
  export: "plan_export",
};

export const buildPlanComposite: ToolDef = {
  name: "build_attack_plan",
  description:
    "Build structured attack plans from environment assessment — plan generation, scoring, optimization, and export",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by enumerate_host"),
    objectives: z
      .array(z.string())
      .describe("List of attack objectives to plan for"),
    stealth_priority: z
      .boolean()
      .optional()
      .default(false)
      .describe("Prioritize stealth over speed in plan generation"),
    max_complexity: z
      .number()
      .optional()
      .default(10)
      .describe("Maximum complexity score for generated plan steps"),
    constraints: z
      .record(z.unknown())
      .optional()
      .describe("Additional constraints for plan generation"),
    mode: z
      .enum(["all", "generate", "score", "optimize", "export"])
      .optional()
      .default("generate")
      .describe("Plan operation mode"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const {
      environment_id,
      objectives,
      stealth_priority,
      max_complexity,
      constraints,
      mode,
    } = args;

    const baseArgs: Record<string, unknown> = { environment_id, objectives };
    if (stealth_priority !== undefined)
      baseArgs.stealth_priority = stealth_priority;
    if (max_complexity !== undefined)
      baseArgs.max_complexity = max_complexity;
    if (constraints) baseArgs.constraints = constraints;

    if (mode && mode !== "all") {
      const toolName = MODE_TOOLS[mode];
      if (!toolName) {
        return {
          content: [{ type: "text", text: `Unknown mode: ${mode}` }],
        };
      }
      const result = await callTool(planTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "build_attack_plan",
        environment_id,
        mode,
        objectives,
      });
    }

    const calls = Object.values(MODE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(planTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "build_attack_plan",
      environment_id,
      mode: "all",
      objectives,
      tools_called: Object.values(MODE_TOOLS),
    });
  },
};
