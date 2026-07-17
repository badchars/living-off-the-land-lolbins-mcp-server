import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import { buildAttackGraph } from "../graph/builder.js";
import { allPaths, discoverChains } from "../graph/pathfinder.js";
import { scorePath, rankPaths } from "../graph/scorer.js";
import type { EnvironmentModel } from "../schema/environment.js";
import type { AttackGraph, AttackPath, PathStep } from "../schema/graph.js";

function lookupSession(
  envId: string,
  ctx: ToolContext,
): EnvironmentModel | null {
  return ctx.sessions.get(envId) ?? null;
}

function sessionNotFound(envId: string): ToolResult {
  return text(
    `Session not found for environment_id "${envId}". ` +
      "Run a parse_*_enum tool first to create an environment session.",
  );
}

function getPrivilegeTarget(platform: string): string {
  if (platform === "windows") return "system";
  return "root";
}

function serializePath(p: AttackPath): Record<string, unknown> {
  return {
    rank: p.rank,
    name: p.name,
    steps: p.steps.map((s) => ({
      action: s.action,
      binary: s.binary,
      command: s.result,
      attck: s.attck,
      stealth_score: s.stealthScore,
      catalog: s.sourceCatalog,
    })),
    total_stealth: p.totalStealth,
    certainty: p.certainty,
    impact: p.impact,
    score: p.score,
    reasoning: p.chainReasoning,
    is_chain: p.isChain,
  };
}

/**
 * Find persistence targets in the graph (Configuration nodes).
 */
function findPersistenceTargets(graph: AttackGraph): string[] {
  return [...graph.nodes.entries()]
    .filter(([_, node]) => node.type === "Configuration")
    .map(([id]) => id);
}

/**
 * Find lateral movement targets in the graph (Network nodes).
 */
function findLateralTargets(graph: AttackGraph): string[] {
  return [...graph.nodes.entries()]
    .filter(([_, node]) => node.type === "Network")
    .map(([id]) => id);
}

/**
 * Find exfiltration-capable binary nodes (binaries with upload/download functions).
 */
function findExfilTargets(graph: AttackGraph): string[] {
  return [...graph.nodes.entries()]
    .filter(
      ([_, node]) =>
        node.type === "Binary" &&
        ((node.metadata.functions as string[]) ?? []).some(
          (f: string) =>
            f === "upload" ||
            f === "download" ||
            f === "file_read" ||
            f === "c2",
        ),
    )
    .map(([id]) => id);
}

/**
 * Combine two path sequences into a composite chain.
 */
function combinePaths(
  a: AttackPath,
  b: AttackPath,
  reasoning: string,
): AttackPath {
  const allSteps = [...a.steps, ...b.steps];
  const totalStealth =
    allSteps.length > 0
      ? allSteps.reduce((sum, s) => sum + s.stealthScore, 0) / allSteps.length
      : 0;

  return {
    rank: 0,
    name: `${a.name} -> ${b.name}`,
    steps: allSteps,
    totalStealth: Math.round(totalStealth * 100) / 100,
    certainty: Math.round(a.certainty * b.certainty * 100) / 100,
    impact: 0,
    score: 0,
    chainReasoning: reasoning,
    isChain: true,
  };
}

const chain_escalate_persist: ToolDef = {
  name: "chain_escalate_persist",
  description:
    "Build attack chains that escalate privileges then establish persistence",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by a parse_*_enum tool"),
    target: z
      .string()
      .optional()
      .describe("Target privilege node; auto-detected if omitted"),
    max_depth: z
      .number()
      .optional()
      .default(4)
      .describe("Maximum depth per chain segment"),
    limit: z
      .number()
      .optional()
      .default(10)
      .describe("Maximum number of chains to return"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const model = lookupSession(args.environment_id, ctx);
    if (!model) return sessionNotFound(args.environment_id);

    const graph = buildAttackGraph(model);
    const target =
      args.target || getPrivilegeTarget(model.state.platform);
    const maxDepth = args.max_depth || 4;

    const escalationPaths = allPaths(
      graph,
      "current-user",
      target,
      maxDepth,
    );
    const persistTargets = findPersistenceTargets(graph);

    const chains: AttackPath[] = [];

    for (const esc of escalationPaths) {
      for (const pt of persistTargets) {
        const persistPaths = allPaths(graph, target, pt, maxDepth);
        for (const per of persistPaths) {
          if (esc.steps.length + per.steps.length <= maxDepth * 2) {
            chains.push(
              combinePaths(
                esc,
                per,
                `Escalate to ${target} via ${esc.name}, then persist via ${pt}`,
              ),
            );
          }
        }
      }
    }

    const ranked = rankPaths(chains, undefined, model.state);
    const limited = ranked.slice(0, args.limit || 10);

    return json({
      environment_id: model.id,
      chain_type: "escalate_persist",
      target,
      persistence_targets: persistTargets.length,
      total_chains: chains.length,
      chains: limited.map(serializePath),
    });
  },
};

const chain_escalate_lateral: ToolDef = {
  name: "chain_escalate_lateral",
  description:
    "Build attack chains that escalate privileges then move laterally to other network segments",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by a parse_*_enum tool"),
    target: z
      .string()
      .optional()
      .describe("Target privilege node; auto-detected if omitted"),
    max_depth: z
      .number()
      .optional()
      .default(4)
      .describe("Maximum depth per chain segment"),
    limit: z
      .number()
      .optional()
      .default(10)
      .describe("Maximum number of chains to return"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const model = lookupSession(args.environment_id, ctx);
    if (!model) return sessionNotFound(args.environment_id);

    const graph = buildAttackGraph(model);
    const target =
      args.target || getPrivilegeTarget(model.state.platform);
    const maxDepth = args.max_depth || 4;

    const escalationPaths = allPaths(
      graph,
      "current-user",
      target,
      maxDepth,
    );
    const lateralTargets = findLateralTargets(graph);

    const chains: AttackPath[] = [];

    for (const esc of escalationPaths) {
      for (const lt of lateralTargets) {
        const lateralPaths = allPaths(graph, target, lt, maxDepth);
        for (const lat of lateralPaths) {
          if (esc.steps.length + lat.steps.length <= maxDepth * 2) {
            chains.push(
              combinePaths(
                esc,
                lat,
                `Escalate to ${target} via ${esc.name}, then pivot to ${lt}`,
              ),
            );
          }
        }
      }
    }

    // Also add direct lateral paths (no escalation needed)
    for (const lt of lateralTargets) {
      const directPaths = allPaths(
        graph,
        "current-user",
        lt,
        maxDepth,
      );
      for (const dp of directPaths) {
        dp.chainReasoning = `Direct lateral movement to ${lt}`;
        dp.isChain = dp.steps.length > 1;
        chains.push(dp);
      }
    }

    const ranked = rankPaths(chains, undefined, model.state);
    const limited = ranked.slice(0, args.limit || 10);

    return json({
      environment_id: model.id,
      chain_type: "escalate_lateral",
      target,
      lateral_targets: lateralTargets.length,
      total_chains: chains.length,
      chains: limited.map(serializePath),
    });
  },
};

const chain_escalate_exfil: ToolDef = {
  name: "chain_escalate_exfil",
  description:
    "Build attack chains that escalate privileges then exfiltrate data using LOL binaries",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by a parse_*_enum tool"),
    target: z
      .string()
      .optional()
      .describe("Target privilege node; auto-detected if omitted"),
    max_depth: z
      .number()
      .optional()
      .default(4)
      .describe("Maximum depth per chain segment"),
    limit: z
      .number()
      .optional()
      .default(10)
      .describe("Maximum number of chains to return"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const model = lookupSession(args.environment_id, ctx);
    if (!model) return sessionNotFound(args.environment_id);

    const graph = buildAttackGraph(model);
    const target =
      args.target || getPrivilegeTarget(model.state.platform);
    const maxDepth = args.max_depth || 4;

    const escalationPaths = allPaths(
      graph,
      "current-user",
      target,
      maxDepth,
    );
    const exfilTargets = findExfilTargets(graph);

    const chains: AttackPath[] = [];

    // Escalation → exfil chains
    for (const esc of escalationPaths) {
      for (const et of exfilTargets) {
        const exfilPaths = allPaths(graph, target, et, maxDepth);
        for (const exf of exfilPaths) {
          if (esc.steps.length + exf.steps.length <= maxDepth * 2) {
            chains.push(
              combinePaths(
                esc,
                exf,
                `Escalate to ${target} via ${esc.name}, then exfiltrate via ${et}`,
              ),
            );
          }
        }
      }
    }

    // Direct exfil paths (no escalation needed)
    for (const et of exfilTargets) {
      const directPaths = allPaths(
        graph,
        "current-user",
        et,
        maxDepth,
      );
      for (const dp of directPaths) {
        dp.chainReasoning = `Direct data exfiltration via ${et}`;
        dp.isChain = dp.steps.length > 1;
        chains.push(dp);
      }
    }

    const ranked = rankPaths(chains, undefined, model.state);
    const limited = ranked.slice(0, args.limit || 10);

    return json({
      environment_id: model.id,
      chain_type: "escalate_exfil",
      target,
      exfil_binaries: exfilTargets.length,
      total_chains: chains.length,
      chains: limited.map(serializePath),
    });
  },
};

const chain_full: ToolDef = {
  name: "chain_full",
  description:
    "Build full attack chains: escalate -> persist -> lateral move -> exfiltrate",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by a parse_*_enum tool"),
    target: z
      .string()
      .optional()
      .describe("Target privilege node; auto-detected if omitted"),
    max_depth: z
      .number()
      .optional()
      .default(3)
      .describe(
        "Maximum depth per individual chain segment (total chain may be up to 4x this value)",
      ),
    limit: z
      .number()
      .optional()
      .default(5)
      .describe("Maximum number of full chains to return"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const model = lookupSession(args.environment_id, ctx);
    if (!model) return sessionNotFound(args.environment_id);

    const graph = buildAttackGraph(model);
    const target =
      args.target || getPrivilegeTarget(model.state.platform);
    const maxDepth = args.max_depth || 3;

    // Discover all chain patterns via discoverChains
    const discovered = discoverChains(model, graph, maxDepth);

    // Additionally try to build full 4-phase chains
    const escalationPaths = allPaths(
      graph,
      "current-user",
      target,
      maxDepth,
    );
    const persistTargets = findPersistenceTargets(graph);
    const lateralTargets = findLateralTargets(graph);
    const exfilTargets = findExfilTargets(graph);

    const fullChains: AttackPath[] = [];

    for (const esc of escalationPaths.slice(0, 5)) {
      // Phase 2: Persist
      for (const pt of persistTargets.slice(0, 3)) {
        const persistPaths = allPaths(graph, target, pt, maxDepth);
        for (const per of persistPaths.slice(0, 3)) {
          // Phase 3: Lateral
          for (const lt of lateralTargets.slice(0, 3)) {
            const latPaths = allPaths(graph, target, lt, maxDepth);
            for (const lat of latPaths.slice(0, 2)) {
              // Phase 4: Exfil
              for (const et of exfilTargets.slice(0, 3)) {
                const exfPaths = allPaths(graph, target, et, maxDepth);
                for (const exf of exfPaths.slice(0, 2)) {
                  const totalSteps =
                    esc.steps.length +
                    per.steps.length +
                    lat.steps.length +
                    exf.steps.length;

                  if (totalSteps <= maxDepth * 4) {
                    const allSteps = [
                      ...esc.steps,
                      ...per.steps,
                      ...lat.steps,
                      ...exf.steps,
                    ];

                    const avgStealth =
                      allSteps.length > 0
                        ? allSteps.reduce(
                            (sum, s) => sum + s.stealthScore,
                            0,
                          ) / allSteps.length
                        : 0;

                    fullChains.push({
                      rank: 0,
                      name: `${esc.name} -> persist(${pt}) -> lateral(${lt}) -> exfil(${et})`,
                      steps: allSteps,
                      totalStealth: Math.round(avgStealth * 100) / 100,
                      certainty:
                        Math.round(
                          esc.certainty *
                            per.certainty *
                            lat.certainty *
                            exf.certainty *
                            100,
                        ) / 100,
                      impact: 0,
                      score: 0,
                      chainReasoning:
                        `Full attack chain: Escalate to ${target}, persist via ${pt}, ` +
                        `pivot to ${lt}, exfiltrate via ${et}`,
                      isChain: true,
                    });
                  }
                }
              }
            }
          }

          // Also create 2-phase chains (escalate+persist) without lateral/exfil
          const escPersistChain = combinePaths(
            esc,
            per,
            `Escalate to ${target}, then persist via ${pt}`,
          );
          fullChains.push(escPersistChain);
        }
      }
    }

    // Merge discovered chains with full chains, deduplicate by name
    const allChains = [...discovered, ...fullChains];
    const seen = new Set<string>();
    const unique: AttackPath[] = [];
    for (const chain of allChains) {
      if (!seen.has(chain.name)) {
        seen.add(chain.name);
        unique.push(chain);
      }
    }

    const ranked = rankPaths(unique, undefined, model.state);
    const limited = ranked.slice(0, args.limit || 5);

    return json({
      environment_id: model.id,
      chain_type: "full",
      target,
      phases: ["escalate", "persist", "lateral", "exfil"],
      graph_stats: {
        nodes: graph.nodes.size,
        edges: graph.edges.length,
        persistence_targets: persistTargets.length,
        lateral_targets: lateralTargets.length,
        exfil_binaries: exfilTargets.length,
      },
      total_chains: unique.length,
      chains: limited.map(serializePath),
    });
  },
};

const chain_custom: ToolDef = {
  name: "chain_custom",
  description:
    "Build a custom attack chain between any two nodes in the environment's attack graph",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by a parse_*_enum tool"),
    start_node: z
      .string()
      .optional()
      .describe(
        "Starting node ID in the attack graph (default: 'current-user')",
      ),
    end_node: z
      .string()
      .describe(
        "Target node ID in the attack graph (e.g. 'root', 'system', a binary node ID, a config node ID)",
      ),
    max_depth: z
      .number()
      .optional()
      .default(5)
      .describe("Maximum path depth to search"),
    shortest_only: z
      .boolean()
      .optional()
      .default(false)
      .describe("If true, return only the shortest path instead of all paths"),
    limit: z
      .number()
      .optional()
      .default(10)
      .describe("Maximum number of paths to return"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const model = lookupSession(args.environment_id, ctx);
    if (!model) return sessionNotFound(args.environment_id);

    const graph = buildAttackGraph(model);
    const startNode = args.start_node || "current-user";
    const endNode = args.end_node;
    const maxDepth = args.max_depth || 5;

    if (!graph.nodes.has(startNode)) {
      // List available nodes for guidance
      const available = [...graph.nodes.keys()].slice(0, 30);
      return json({
        error: `Start node "${startNode}" not found in the attack graph.`,
        available_nodes: available,
      });
    }

    if (!graph.nodes.has(endNode)) {
      const available = [...graph.nodes.keys()].slice(0, 30);
      return json({
        error: `End node "${endNode}" not found in the attack graph.`,
        available_nodes: available,
      });
    }

    if (args.shortest_only) {
      const path = allPaths(graph, startNode, endNode, maxDepth);
      // Find the actual shortest by step count
      if (path.length === 0) {
        return json({
          environment_id: model.id,
          start_node: startNode,
          end_node: endNode,
          paths: [],
          message: `No path found from "${startNode}" to "${endNode}" within depth ${maxDepth}.`,
        });
      }

      const sorted = path.sort((a, b) => a.steps.length - b.steps.length);
      const shortest = sorted[0];
      scorePath(shortest, undefined, model.state);
      shortest.rank = 1;
      shortest.chainReasoning = `Shortest path from ${startNode} to ${endNode}`;

      return json({
        environment_id: model.id,
        start_node: startNode,
        end_node: endNode,
        total_found: path.length,
        paths: [serializePath(shortest)],
      });
    }

    const paths = allPaths(graph, startNode, endNode, maxDepth);

    if (paths.length === 0) {
      return json({
        environment_id: model.id,
        start_node: startNode,
        end_node: endNode,
        paths: [],
        message: `No path found from "${startNode}" to "${endNode}" within depth ${maxDepth}.`,
        available_nodes: [...graph.nodes.keys()].slice(0, 30),
      });
    }

    const ranked = rankPaths(paths, undefined, model.state);
    const limited = ranked.slice(0, args.limit || 10);

    return json({
      environment_id: model.id,
      chain_type: "custom",
      start_node: startNode,
      end_node: endNode,
      max_depth: maxDepth,
      total_found: paths.length,
      chains: limited.map(serializePath),
    });
  },
};

export const chainTools: ToolDef[] = [
  chain_escalate_persist,
  chain_escalate_lateral,
  chain_escalate_exfil,
  chain_full,
  chain_custom,
];
