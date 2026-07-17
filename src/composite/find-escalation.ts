import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import { buildAttackGraph } from "../graph/builder.js";
import { allPaths } from "../graph/pathfinder.js";
import { rankPaths } from "../graph/scorer.js";
import type { AttackPath } from "../schema/graph.js";

export const findEscalationComposite: ToolDef = {
  name: "find_escalation_paths",
  description:
    "Find and rank all privilege escalation paths in an enumerated environment. Supports stealth-priority ranking, multi-step chains, token abuse paths, and container escape detection.",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by enumerate_host"),
    target_privilege: z
      .string()
      .optional()
      .default("root")
      .describe(
        "Target privilege level to escalate to (e.g. root, system, administrator)",
      ),
    max_steps: z
      .number()
      .optional()
      .default(5)
      .describe("Maximum number of steps in an escalation path"),
    stealth_priority: z
      .boolean()
      .optional()
      .default(false)
      .describe("Prioritize stealthier paths over higher-certainty ones"),
    include_chains: z
      .boolean()
      .optional()
      .default(true)
      .describe("Include multi-step chained escalation paths"),
    include_token: z
      .boolean()
      .optional()
      .default(true)
      .describe("Include Windows token privilege abuse paths"),
    include_container_escape: z
      .boolean()
      .optional()
      .default(true)
      .describe("Include container/Docker escape paths if docker socket is accessible"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const {
      environment_id,
      target_privilege,
      max_steps,
      stealth_priority,
      include_chains,
      include_token,
      include_container_escape,
    } = args;

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

    // 3. Determine target node(s)
    const targetNodeId = target_privilege.toLowerCase();
    const targetNodes: string[] = [];

    if (graph.nodes.has(targetNodeId)) {
      targetNodes.push(targetNodeId);
    } else {
      // Try common mappings
      if (targetNodeId === "root" && graph.nodes.has("root")) {
        targetNodes.push("root");
      }
      if (
        (targetNodeId === "system" || targetNodeId === "nt authority\\system") &&
        graph.nodes.has("system")
      ) {
        targetNodes.push("system");
      }
      if (
        targetNodeId === "administrator" &&
        graph.nodes.has("administrator")
      ) {
        targetNodes.push("administrator");
      }
      // Fallback: try all privilege targets
      if (targetNodes.length === 0) {
        for (const [id, node] of graph.nodes) {
          if (node.type === "TargetPrivilege") {
            targetNodes.push(id);
          }
        }
      }
    }

    if (targetNodes.length === 0) {
      return json({
        environment_id,
        target_privilege,
        paths: [],
        message: `No privilege target "${target_privilege}" found in attack graph`,
      });
    }

    // 4. Find all paths to target(s)
    let allFoundPaths: AttackPath[] = [];

    for (const target of targetNodes) {
      const paths = allPaths(graph, "current-user", target, max_steps);
      allFoundPaths.push(...paths);
    }

    // 5. Token-based escalation paths (Windows)
    if (include_token && state.tokenPrivileges.length > 0) {
      const tokenPaths = allFoundPaths.filter((p) =>
        p.steps.some(
          (s) =>
            s.action === "CanExecuteAs" &&
            (s.binary.includes("token") ||
              s.binary.includes("impersonate") ||
              s.binary.includes("potato")),
        ),
      );
      // Tag token paths with reasoning
      for (const tp of tokenPaths) {
        if (!tp.chainReasoning) {
          tp.chainReasoning = `Token privilege abuse via ${state.tokenPrivileges.join(", ")}`;
        }
      }
    }

    // 6. Container escape paths
    if (include_container_escape && state.dockerSocket) {
      const dockerEntries = model.matchedEntries.filter(
        (m) =>
          m.entry.binary.toLowerCase().includes("docker") ||
          m.matchReason.toLowerCase().includes("docker"),
      );
      for (const de of dockerEntries) {
        const binId = `bin-${de.entry.id}`;
        for (const target of targetNodes) {
          const containerPaths = allPaths(graph, binId, target, max_steps);
          for (const cp of containerPaths) {
            cp.chainReasoning = `Container escape via Docker socket → ${target}`;
            cp.isChain = true;
            allFoundPaths.push(cp);
          }
        }
      }
    }

    // 7. Rank paths
    const weights = stealth_priority
      ? { certainty: 0.2, brevity: 0.1, stealth: 0.5, impact: 0.2 }
      : undefined;

    const ranked = rankPaths(allFoundPaths, weights, state);

    // 8. Group by type
    const directPaths = ranked.filter((p) => p.steps.length <= 2);
    const chainedPaths = include_chains
      ? ranked.filter((p) => p.steps.length > 2)
      : [];

    return json({
      environment_id,
      target_privilege,
      platform: state.platform,
      total_paths: ranked.length,
      direct_paths_count: directPaths.length,
      chained_paths_count: chainedPaths.length,
      edr_active: state.edrDetected !== "none" ? state.edrDetected : null,
      paths: ranked.map((p) => ({
        rank: p.rank,
        name: p.name,
        type: p.steps.length <= 2 ? "direct" : "chained",
        steps: p.steps.map((s) => ({
          action: s.action,
          binary: s.binary,
          catalog: s.sourceCatalog,
          result: s.result,
          attck: s.attck,
          stealth: s.stealthScore,
        })),
        score: p.score,
        certainty: p.certainty,
        stealth: p.totalStealth,
        impact: p.impact,
        is_chain: p.isChain,
        reasoning: p.chainReasoning,
      })),
    });
  },
};
