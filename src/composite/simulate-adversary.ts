import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, buildCompositeResponse } from "./helpers.js";
import { adversarySimTools } from "../providers/adversary-sim.js";

const MODE_TOOLS: Record<string, string> = {
  select_profile: "sim_select_profile",
  generate_playbook: "sim_generate_playbook",
  validate_env: "sim_validate_env",
  execution_plan: "sim_execution_plan",
};

export const simulateAdversaryComposite: ToolDef = {
  name: "simulate_adversary",
  description:
    "Simulate adversary behavior using LOL binaries — select simulation profile, generate playbook, validate environment, create execution plan.",
  schema: {
    mode: z
      .enum(["select_profile", "generate_playbook", "validate_env", "execution_plan"])
      .describe("Adversary simulation mode"),
    actor_profile: z.string().optional().describe("Adversary profile: APT29, FIN7, Lazarus, etc."),
    environment_id: z.string().optional().describe("Environment session ID"),
    objectives: z.array(z.string()).optional().describe("Simulation objectives"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };

    const result = await callTool(adversarySimTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, { composite: "simulate_adversary", mode });
  },
};
