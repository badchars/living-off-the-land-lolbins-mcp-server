import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, buildCompositeResponse } from "./helpers.js";
import { threatActorTools } from "../providers/threat-actor.js";

const MODE_TOOLS: Record<string, string> = {
  actor_to_techniques: "actor_to_techniques",
  technique_to_actors: "technique_to_actors",
  actor_profile: "actor_profile",
  campaign: "campaign_techniques",
  predict_for_env: "predict_actor_for_env",
};

export const mapThreatActorComposite: ToolDef = {
  name: "map_threat_actor",
  description:
    "Map threat actor TTPs to LOL binary techniques — actor-to-technique lookup, technique-to-actor reverse mapping, actor profiles, campaign analysis, and environment-based actor prediction.",
  schema: {
    mode: z
      .enum(["actor_to_techniques", "technique_to_actors", "actor_profile", "campaign", "predict_for_env"])
      .describe("Threat actor mapping mode"),
    actor: z.string().optional().describe("Threat actor name (e.g. APT29, FIN7, Lazarus)"),
    technique_id: z.string().optional().describe("LOL technique or binary name to reverse-map"),
    campaign: z.string().optional().describe("Campaign name to analyze"),
    environment_id: z.string().optional().describe("Environment session ID for prediction"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };

    const result = await callTool(threatActorTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, { composite: "map_threat_actor", mode });
  },
};
