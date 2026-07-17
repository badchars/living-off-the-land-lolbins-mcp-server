import type { AttackGraph, AttackPath, GraphEdge, PathStep } from "../schema/graph.js";
import type { EnvironmentModel } from "../schema/environment.js";
import { emptyDetection } from "../schema/unified-entry.js";

/**
 * Convert a sequence of edges to an AttackPath with PathSteps.
 */
export function edgesToAttackPath(edges: GraphEdge[], graph: AttackGraph): AttackPath {
  const steps: PathStep[] = edges.map((edge) => {
    const targetNode = graph.nodes.get(edge.to);
    const sourceNode = graph.nodes.get(edge.from);

    return {
      action: edge.type,
      binary: sourceNode?.label ?? edge.from,
      sourceCatalog: (sourceNode?.metadata?.catalogSource as string) ?? "gtfobins",
      sourceEntryId: edge.entryId,
      result: targetNode?.label ?? edge.to,
      attck: edge.attckTechniques,
      stealthScore: edge.stealthScore,
      detection: emptyDetection(),
    } as PathStep;
  });

  const totalStealth =
    steps.length > 0
      ? steps.reduce((sum, s) => sum + s.stealthScore, 0) / steps.length
      : 0;

  const certainty =
    steps.length > 0
      ? steps.reduce((prod, _s, i) => prod * edges[i].certainty, 1)
      : 0;

  return {
    rank: 0,
    name: steps.map((s) => s.binary).join(" → "),
    steps,
    totalStealth: Math.round(totalStealth * 100) / 100,
    certainty: Math.round(certainty * 100) / 100,
    impact: 0,
    score: 0,
    chainReasoning: "",
    isChain: steps.length > 2,
  };
}

/**
 * BFS: find the shortest path (by edge count) from `from` to `to`.
 */
export function shortestPath(graph: AttackGraph, from: string, to: string): AttackPath | null {
  if (!graph.nodes.has(from) || !graph.nodes.has(to)) {
    return null;
  }
  if (from === to) {
    return edgesToAttackPath([], graph);
  }

  const visited = new Set<string>();
  // Each queue entry: [currentNodeId, edges taken to get here]
  const queue: Array<[string, GraphEdge[]]> = [[from, []]];
  visited.add(from);

  while (queue.length > 0) {
    const [current, pathEdges] = queue.shift()!;
    const adj = graph.adjacency.get(current) ?? [];

    for (const edge of adj) {
      if (edge.to === to) {
        return edgesToAttackPath([...pathEdges, edge], graph);
      }
      if (!visited.has(edge.to)) {
        visited.add(edge.to);
        queue.push([edge.to, [...pathEdges, edge]]);
      }
    }
  }

  return null;
}

/**
 * DFS: find all paths from `from` to `to` up to `maxDepth` edges.
 */
export function allPaths(
  graph: AttackGraph,
  from: string,
  to: string,
  maxDepth: number,
): AttackPath[] {
  if (!graph.nodes.has(from) || !graph.nodes.has(to)) {
    return [];
  }

  const results: AttackPath[] = [];
  const visitedInPath = new Set<string>();

  function dfs(current: string, pathEdges: GraphEdge[], depth: number): void {
    if (depth > maxDepth) return;

    if (current === to && pathEdges.length > 0) {
      results.push(edgesToAttackPath([...pathEdges], graph));
      return;
    }

    const adj = graph.adjacency.get(current) ?? [];
    for (const edge of adj) {
      if (!visitedInPath.has(edge.to)) {
        visitedInPath.add(edge.to);
        pathEdges.push(edge);
        dfs(edge.to, pathEdges, depth + 1);
        pathEdges.pop();
        visitedInPath.delete(edge.to);
      }
    }
  }

  visitedInPath.add(from);
  dfs(from, [], 0);

  return results;
}

/**
 * Discover multi-step attack chains in the graph.
 * Looks for patterns like: escalate → persist, escalate → lateral,
 * escalate → disable EDR → escalate, download → escalate, etc.
 */
export function discoverChains(
  model: EnvironmentModel,
  graph: AttackGraph,
  maxDepth: number = 3,
): AttackPath[] {
  const chains: AttackPath[] = [];
  const platform = model.state.platform;

  // Determine target privilege nodes
  const targets: string[] = [];
  if (platform === "linux" || platform === "macos") {
    if (graph.nodes.has("root")) targets.push("root");
  }
  if (platform === "windows") {
    if (graph.nodes.has("system")) targets.push("system");
    if (graph.nodes.has("administrator")) targets.push("administrator");
  }

  // 1. Find all escalation paths from current-user to privilege targets
  for (const target of targets) {
    const escalationPaths = allPaths(graph, "current-user", target, maxDepth);
    for (const path of escalationPaths) {
      path.chainReasoning = `Privilege escalation chain to ${target}`;
      path.isChain = path.steps.length > 1;
      chains.push(path);
    }
  }

  // 2. Find escalation → persistence chains
  // Look for paths that go through a privilege target and then to a configuration node
  const configNodes = [...graph.nodes.entries()]
    .filter(([_, node]) => node.type === "Configuration")
    .map(([id]) => id);

  for (const target of targets) {
    for (const configNode of configNodes) {
      const toTarget = allPaths(graph, "current-user", target, maxDepth);
      const toPersist = allPaths(graph, target, configNode, maxDepth);

      // Combine escalation + persistence steps
      for (const escalation of toTarget) {
        for (const persist of toPersist) {
          if (escalation.steps.length + persist.steps.length <= maxDepth) {
            const combined: AttackPath = {
              rank: 0,
              name: `${escalation.name} → ${persist.name}`,
              steps: [...escalation.steps, ...persist.steps],
              totalStealth:
                (escalation.totalStealth * escalation.steps.length +
                  persist.totalStealth * persist.steps.length) /
                (escalation.steps.length + persist.steps.length),
              certainty: escalation.certainty * persist.certainty,
              impact: 0,
              score: 0,
              chainReasoning: `Escalate to ${target}, then establish persistence via ${configNode}`,
              isChain: true,
            };
            chains.push(combined);
          }
        }
      }
    }
  }

  // 3. Find escalation → lateral movement chains
  const networkNodes = [...graph.nodes.entries()]
    .filter(([_, node]) => node.type === "Network")
    .map(([id]) => id);

  for (const target of targets) {
    for (const netNode of networkNodes) {
      const toTarget = allPaths(graph, "current-user", target, maxDepth);
      const toLateral = allPaths(graph, target, netNode, maxDepth);

      for (const escalation of toTarget) {
        for (const lateral of toLateral) {
          if (escalation.steps.length + lateral.steps.length <= maxDepth) {
            const combined: AttackPath = {
              rank: 0,
              name: `${escalation.name} → ${lateral.name}`,
              steps: [...escalation.steps, ...lateral.steps],
              totalStealth:
                (escalation.totalStealth * escalation.steps.length +
                  lateral.totalStealth * lateral.steps.length) /
                (escalation.steps.length + lateral.steps.length),
              certainty: escalation.certainty * lateral.certainty,
              impact: 0,
              score: 0,
              chainReasoning: `Escalate to ${target}, then move laterally to ${netNode}`,
              isChain: true,
            };
            chains.push(combined);
          }
        }
      }
    }
  }

  // 4. Direct lateral paths from current-user (no escalation needed)
  for (const netNode of networkNodes) {
    const lateralPaths = allPaths(graph, "current-user", netNode, maxDepth);
    for (const path of lateralPaths) {
      path.chainReasoning = `Direct lateral movement to ${netNode}`;
      path.isChain = path.steps.length > 1;
      chains.push(path);
    }
  }

  // Deduplicate by name
  const seen = new Set<string>();
  const uniqueChains: AttackPath[] = [];
  for (const chain of chains) {
    if (!seen.has(chain.name)) {
      seen.add(chain.name);
      uniqueChains.push(chain);
    }
  }

  return uniqueChains;
}
