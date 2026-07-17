import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import { buildAttackGraph } from "../graph/builder.js";
import { discoverChains, allPaths } from "../graph/pathfinder.js";
import { rankPaths } from "../graph/scorer.js";
import type { AttackPath } from "../schema/graph.js";

type ChainType = "escalate_persist" | "escalate_lateral" | "escalate_exfil" | "full" | "custom";

function filterByChainType(
  chains: AttackPath[],
  chainType: ChainType,
  startBinary?: string,
  endGoal?: string,
): AttackPath[] {
  switch (chainType) {
    case "escalate_persist":
      return chains.filter(
        (c) =>
          c.chainReasoning.toLowerCase().includes("escalat") &&
          c.chainReasoning.toLowerCase().includes("persist"),
      );
    case "escalate_lateral":
      return chains.filter(
        (c) =>
          c.chainReasoning.toLowerCase().includes("escalat") &&
          c.chainReasoning.toLowerCase().includes("lateral"),
      );
    case "escalate_exfil":
      return chains.filter(
        (c) =>
          c.steps.some(
            (s) =>
              s.action === "CanUpload" ||
              s.action === "CanReadFile" ||
              s.action === "CanDownload",
          ) &&
          c.steps.some(
            (s) =>
              s.action === "CanEscalateVia" || s.action === "CanExecuteAs",
          ),
      );
    case "custom": {
      let filtered = chains;
      if (startBinary) {
        const norm = startBinary.toLowerCase();
        filtered = filtered.filter((c) =>
          c.steps.some((s) => s.binary.toLowerCase().includes(norm)),
        );
      }
      if (endGoal) {
        const normGoal = endGoal.toLowerCase();
        filtered = filtered.filter(
          (c) =>
            c.steps[c.steps.length - 1]?.result
              .toLowerCase()
              .includes(normGoal) ||
            c.chainReasoning.toLowerCase().includes(normGoal),
        );
      }
      return filtered;
    }
    case "full":
    default:
      return chains;
  }
}

export const discoverChainsComposite: ToolDef = {
  name: "discover_chains",
  description:
    "Discover multi-step attack chains in an enumerated environment. Chains combine escalation, persistence, lateral movement, and exfiltration steps into coherent attack narratives with reasoning.",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by enumerate_host"),
    chain_type: z
      .enum([
        "escalate_persist",
        "escalate_lateral",
        "escalate_exfil",
        "full",
        "custom",
      ])
      .describe(
        "Type of chain to discover: escalate+persist, escalate+lateral, escalate+exfiltrate, full (all), or custom with start/end constraints",
      ),
    max_depth: z
      .number()
      .optional()
      .default(4)
      .describe("Maximum depth (steps) for chain discovery"),
    start_binary: z
      .string()
      .optional()
      .describe(
        "For custom chain_type: require chains that start with or include this binary",
      ),
    end_goal: z
      .string()
      .optional()
      .describe(
        "For custom chain_type: require chains that end at this goal (e.g. root, persist, lateral)",
      ),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, chain_type, max_depth, start_binary, end_goal } =
      args;

    // 1. Look up session
    const model = ctx.sessions.get(environment_id);
    if (!model) {
      return text(
        `Environment session "${environment_id}" not found. Run enumerate_host first.`,
      );
    }

    const state = model.state;

    // 2. Build attack graph
    const graph = buildAttackGraph(model);

    // 3. Discover all chains
    const rawChains = discoverChains(model, graph, max_depth);

    // 4. Filter by chain type
    const filtered = filterByChainType(
      rawChains,
      chain_type as ChainType,
      start_binary,
      end_goal,
    );

    // 5. Rank the chains
    const ranked = rankPaths(filtered, undefined, state);

    // 6. Generate chain reasoning enrichment
    const enrichedChains = ranked.map((chain) => {
      const techniques = new Set<string>();
      const catalogs = new Set<string>();
      const binaries: string[] = [];

      for (const step of chain.steps) {
        for (const t of step.attck) techniques.add(t);
        catalogs.add(step.sourceCatalog);
        binaries.push(step.binary);
      }

      return {
        rank: chain.rank,
        name: chain.name,
        chain_type: chain_type,
        steps: chain.steps.map((s) => ({
          action: s.action,
          binary: s.binary,
          catalog: s.sourceCatalog,
          result: s.result,
          attck: s.attck,
          stealth: s.stealthScore,
        })),
        score: chain.score,
        certainty: chain.certainty,
        stealth: chain.totalStealth,
        impact: chain.impact,
        reasoning: chain.chainReasoning,
        attck_techniques: [...techniques],
        catalogs_used: [...catalogs],
        binary_sequence: binaries,
        step_count: chain.steps.length,
      };
    });

    return json({
      environment_id,
      chain_type,
      platform: state.platform,
      total_chains: enrichedChains.length,
      max_depth,
      chains: enrichedChains,
      graph_stats: {
        total_nodes: graph.nodes.size,
        total_edges: graph.edges.length,
        matched_binaries: model.matchedEntries.length,
      },
    });
  },
};
