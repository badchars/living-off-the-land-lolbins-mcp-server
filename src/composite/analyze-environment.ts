import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { EnvironmentModel, MatchedEntry } from "../schema/environment.js";
import type { LOLFunction } from "../schema/unified-entry.js";
import { buildAttackGraph } from "../graph/builder.js";
import { allPaths, discoverChains } from "../graph/pathfinder.js";
import { rankPaths, scorePath } from "../graph/scorer.js";

function computeEnvironmentRisk(model: EnvironmentModel): {
  overall: number;
  level: string;
  factors: Record<string, { score: number; weight: number; detail: string }>;
} {
  const state = model.state;
  const factors: Record<string, { score: number; weight: number; detail: string }> = {};

  // Privilege escalation vectors
  const escalationCount = model.matchedEntries.filter((m) =>
    m.entry.functions.includes("privilege_escalation") ||
    m.entry.functions.includes("shell"),
  ).length;
  factors.escalation_vectors = {
    score: Math.min(1.0, escalationCount / 5),
    weight: 0.25,
    detail: `${escalationCount} escalation vectors found`,
  };

  // SUID/sudo/capability exposure (Linux)
  const privExposure =
    state.suidBinaries.length * 0.3 +
    state.sudoEntries.filter((s) => s.nopasswd).length * 0.5 +
    state.capabilities.length * 0.3;
  factors.privilege_exposure = {
    score: Math.min(1.0, privExposure / 5),
    weight: 0.2,
    detail: `${state.suidBinaries.length} SUID, ${state.sudoEntries.length} sudo entries, ${state.capabilities.length} capabilities`,
  };

  // Token privileges (Windows)
  const dangerousTokens = state.tokenPrivileges.filter((t) =>
    ["SeImpersonatePrivilege", "SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeLoadDriverPrivilege"].some(
      (d) => t.toLowerCase().includes(d.toLowerCase().replace("privilege", "")),
    ),
  ).length;
  factors.token_risk = {
    score: Math.min(1.0, dangerousTokens / 3),
    weight: state.platform === "windows" ? 0.2 : 0.05,
    detail: `${dangerousTokens} dangerous token privileges`,
  };

  // Detection coverage gap
  const undetectedEntries = model.matchedEntries.filter(
    (m) =>
      m.entry.detection.sigmaRules.length === 0 &&
      m.entry.detection.yaraRules.length === 0 &&
      m.entry.detection.edrCoverage === "none",
  ).length;
  const detectionGap =
    model.matchedEntries.length > 0
      ? undetectedEntries / model.matchedEntries.length
      : 0;
  factors.detection_gap = {
    score: detectionGap,
    weight: 0.15,
    detail: `${undetectedEntries}/${model.matchedEntries.length} entries lack detection`,
  };

  // Network exposure
  const networkScore =
    (state.networkAccess.outboundHttp ? 0.3 : 0) +
    (state.networkAccess.outboundDns ? 0.2 : 0) +
    Math.min(0.5, state.networkAccess.internalSubnets.length * 0.1);
  factors.network_exposure = {
    score: networkScore,
    weight: 0.1,
    detail: `HTTP: ${state.networkAccess.outboundHttp}, DNS: ${state.networkAccess.outboundDns}, ${state.networkAccess.internalSubnets.length} internal subnets`,
  };

  // EDR presence (inverted: EDR present = lower risk from attacker perspective, but we score attack surface)
  factors.edr_bypass_needed = {
    score: state.edrDetected !== "none" ? 0.3 : 0.8,
    weight: 0.05,
    detail: state.edrDetected !== "none" ? `EDR: ${state.edrDetected}` : "No EDR detected",
  };

  // Compute weighted score
  let overall = 0;
  let totalWeight = 0;
  for (const factor of Object.values(factors)) {
    overall += factor.score * factor.weight;
    totalWeight += factor.weight;
  }
  overall = totalWeight > 0 ? Math.round((overall / totalWeight) * 100) / 100 : 0;

  const level =
    overall >= 0.8
      ? "critical"
      : overall >= 0.6
        ? "high"
        : overall >= 0.4
          ? "medium"
          : "low";

  return { overall, level, factors };
}

function computeAttackSurface(model: EnvironmentModel): any {
  const state = model.state;
  const functionBreakdown: Record<string, { count: number; entries: string[] }> = {};

  for (const m of model.matchedEntries) {
    for (const fn of m.entry.functions) {
      if (!functionBreakdown[fn]) {
        functionBreakdown[fn] = { count: 0, entries: [] };
      }
      functionBreakdown[fn].count++;
      functionBreakdown[fn].entries.push(m.entry.binary);
    }
  }

  const contextBreakdown: Record<string, number> = {};
  for (const m of model.matchedEntries) {
    for (const ctx of m.applicableContexts) {
      contextBreakdown[ctx.context] = (contextBreakdown[ctx.context] || 0) + 1;
    }
  }

  const catalogBreakdown: Record<string, number> = {};
  for (const m of model.matchedEntries) {
    catalogBreakdown[m.entry.catalogSource] =
      (catalogBreakdown[m.entry.catalogSource] || 0) + 1;
  }

  return {
    total_entries: model.matchedEntries.length,
    by_function: functionBreakdown,
    by_context: contextBreakdown,
    by_catalog: catalogBreakdown,
    stealth_distribution: {
      very_stealthy: model.matchedEntries.filter((m) => m.effectiveStealthScore >= 0.8).length,
      stealthy: model.matchedEntries.filter(
        (m) => m.effectiveStealthScore >= 0.5 && m.effectiveStealthScore < 0.8,
      ).length,
      noisy: model.matchedEntries.filter((m) => m.effectiveStealthScore < 0.5).length,
    },
    platform_specifics: {
      suid_matches: state.suidBinaries.length,
      sudo_matches: state.sudoEntries.length,
      capability_matches: state.capabilities.length,
      token_privileges: state.tokenPrivileges.length,
      writable_paths: state.writablePaths.length,
      docker_socket: state.dockerSocket,
      sensitive_files: state.sensitiveFiles.length,
    },
  };
}

function prioritizeObjectives(
  model: EnvironmentModel,
  objectives: string[],
): any[] {
  const graph = buildAttackGraph(model);
  const state = model.state;
  const prioritized: any[] = [];

  for (const objective of objectives) {
    const objectiveLower = objective.toLowerCase();
    let targetNodes: string[] = [];
    let description = "";

    if (objectiveLower.includes("escalat") || objectiveLower.includes("root") || objectiveLower.includes("system")) {
      targetNodes = state.platform === "windows" ? ["system", "administrator"] : ["root"];
      description = "Privilege escalation";
    } else if (objectiveLower.includes("persist")) {
      targetNodes = [...graph.nodes.entries()]
        .filter(([_, n]) => n.type === "Configuration")
        .map(([id]) => id);
      description = "Persistence establishment";
    } else if (objectiveLower.includes("lateral")) {
      targetNodes = [...graph.nodes.entries()]
        .filter(([_, n]) => n.type === "Network")
        .map(([id]) => id);
      description = "Lateral movement";
    } else if (objectiveLower.includes("exfil") || objectiveLower.includes("data")) {
      targetNodes = [...graph.nodes.entries()]
        .filter(([_, n]) => n.type === "File")
        .map(([id]) => id);
      description = "Data exfiltration";
    } else if (objectiveLower.includes("edr") || objectiveLower.includes("defense")) {
      targetNodes = [...graph.nodes.entries()]
        .filter(([_, n]) => n.type === "Service" && n.metadata?.isEdr)
        .map(([id]) => id);
      description = "Defense evasion / EDR disable";
    }

    let paths: any[] = [];
    for (const target of targetNodes) {
      const found = allPaths(graph, "current-user", target, 5);
      paths.push(...found);
    }
    const ranked = rankPaths(paths, undefined, state);

    prioritized.push({
      objective,
      description,
      feasible: ranked.length > 0,
      path_count: ranked.length,
      best_path: ranked.length > 0
        ? {
            name: ranked[0].name,
            score: ranked[0].score,
            certainty: ranked[0].certainty,
            stealth: ranked[0].totalStealth,
            steps: ranked[0].steps.map((s) => ({
              action: s.action,
              binary: s.binary,
              result: s.result,
            })),
          }
        : null,
      difficulty: ranked.length === 0
        ? "infeasible"
        : ranked[0].score >= 0.7
          ? "easy"
          : ranked[0].score >= 0.4
            ? "moderate"
            : "hard",
    });
  }

  // Sort by feasibility and best score
  prioritized.sort((a, b) => {
    if (a.feasible !== b.feasible) return a.feasible ? -1 : 1;
    return (b.best_path?.score ?? 0) - (a.best_path?.score ?? 0);
  });

  return prioritized;
}

function compareEnvironments(
  modelA: EnvironmentModel,
  modelB: EnvironmentModel,
): any {
  const stateA = modelA.state;
  const stateB = modelB.state;

  const entriesA = new Set(modelA.matchedEntries.map((m) => m.entry.id));
  const entriesB = new Set(modelB.matchedEntries.map((m) => m.entry.id));

  const common = [...entriesA].filter((id) => entriesB.has(id));
  const onlyA = [...entriesA].filter((id) => !entriesB.has(id));
  const onlyB = [...entriesB].filter((id) => !entriesA.has(id));

  const riskA = computeEnvironmentRisk(modelA);
  const riskB = computeEnvironmentRisk(modelB);

  return {
    environment_a: {
      id: modelA.id,
      platform: stateA.platform,
      matched_entries: modelA.matchedEntries.length,
      risk: riskA,
    },
    environment_b: {
      id: modelB.id,
      platform: stateB.platform,
      matched_entries: modelB.matchedEntries.length,
      risk: riskB,
    },
    comparison: {
      common_entries: common.length,
      unique_to_a: onlyA.length,
      unique_to_b: onlyB.length,
      riskier_environment: riskA.overall > riskB.overall ? "a" : riskB.overall > riskA.overall ? "b" : "equal",
      risk_difference: Math.round(Math.abs(riskA.overall - riskB.overall) * 100) / 100,
    },
    unique_to_a_entries: onlyA.map((id) => {
      const m = modelA.matchedEntries.find((x) => x.entry.id === id);
      return m
        ? { binary: m.entry.binary, functions: m.entry.functions, reason: m.matchReason }
        : { id };
    }),
    unique_to_b_entries: onlyB.map((id) => {
      const m = modelB.matchedEntries.find((x) => x.entry.id === id);
      return m
        ? { binary: m.entry.binary, functions: m.entry.functions, reason: m.matchReason }
        : { id };
    }),
  };
}

function buildTimeline(model: EnvironmentModel, steps: number): any[] {
  const graph = buildAttackGraph(model);
  const state = model.state;
  const chains = discoverChains(model, graph, Math.min(steps, 6));
  const ranked = rankPaths(chains, undefined, state);

  // Build a timeline from the best chain
  if (ranked.length === 0) {
    return [
      {
        phase: 1,
        action: "Reconnaissance",
        description: "No viable attack chains found. Additional enumeration needed.",
        binaries: [],
      },
    ];
  }

  const bestChain = ranked[0];
  const timeline: any[] = [];

  // Phase 0: Recon
  timeline.push({
    phase: 0,
    action: "Reconnaissance",
    description: `Identify ${model.matchedEntries.length} LOL binaries on ${state.platform}`,
    binaries: model.matchedEntries.slice(0, 5).map((m) => m.entry.binary),
    attck: ["T1083", "T1057"],
  });

  // Map each step to a timeline phase
  for (let i = 0; i < Math.min(bestChain.steps.length, steps - 1); i++) {
    const step = bestChain.steps[i];
    timeline.push({
      phase: i + 1,
      action: step.action,
      description: `Use ${step.binary} (${step.sourceCatalog}) → ${step.result}`,
      binary: step.binary,
      command_hint: step.result,
      stealth: step.stealthScore,
      attck: step.attck,
      detection_risk: step.detection.edrCoverage,
    });
  }

  // Final phase: objective achieved
  timeline.push({
    phase: timeline.length,
    action: "Objective",
    description: bestChain.chainReasoning || "Attack chain completed",
    score: bestChain.score,
    certainty: bestChain.certainty,
  });

  return timeline.slice(0, steps);
}

export const analyzeEnvironmentComposite: ToolDef = {
  name: "analyze_environment",
  description:
    "Multi-mode environment analysis: compute risk scores, map attack surface, prioritize objectives, compare environments, or generate attack timelines.",
  schema: {
    mode: z
      .enum(["risk_score", "attack_surface", "prioritize", "compare", "timeline"])
      .describe(
        "Analysis mode: risk_score (overall risk), attack_surface (detailed breakdown), prioritize (rank attack objectives), compare (diff two environments), timeline (attack phase planning)",
      ),
    environment_id: z
      .string()
      .describe("Primary environment session ID"),
    compare_environment_id: z
      .string()
      .optional()
      .describe(
        "Second environment ID for 'compare' mode",
      ),
    attack_objectives: z
      .array(z.string())
      .optional()
      .describe(
        "List of attack objectives for 'prioritize' mode (e.g. ['escalate to root', 'establish persistence', 'lateral movement'])",
      ),
    timeline_steps: z
      .number()
      .optional()
      .default(10)
      .describe("Maximum number of timeline phases for 'timeline' mode"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, environment_id, compare_environment_id, attack_objectives, timeline_steps } = args;

    // 1. Look up primary session
    const model = ctx.sessions.get(environment_id);
    if (!model) {
      return text(
        `Environment session "${environment_id}" not found. Run enumerate_host first.`,
      );
    }

    switch (mode) {
      case "risk_score": {
        const risk = computeEnvironmentRisk(model);
        return json({
          environment_id,
          platform: model.state.platform,
          current_user: model.state.currentUser,
          privilege_level: model.state.privilegeLevel,
          risk_score: risk.overall,
          risk_level: risk.level,
          factors: risk.factors,
          matched_entries: model.matchedEntries.length,
          edr_detected: model.state.edrDetected,
        });
      }

      case "attack_surface": {
        const surface = computeAttackSurface(model);
        return json({
          environment_id,
          platform: model.state.platform,
          attack_surface: surface,
        });
      }

      case "prioritize": {
        const objectives = attack_objectives ?? [
          "privilege escalation",
          "persistence",
          "lateral movement",
          "data exfiltration",
          "defense evasion",
        ];
        const prioritized = prioritizeObjectives(model, objectives);
        return json({
          environment_id,
          platform: model.state.platform,
          objectives: prioritized,
        });
      }

      case "compare": {
        if (!compare_environment_id) {
          return text(
            "compare_environment_id is required for 'compare' mode",
          );
        }
        const modelB = ctx.sessions.get(compare_environment_id);
        if (!modelB) {
          return text(
            `Environment session "${compare_environment_id}" not found.`,
          );
        }
        const comparison = compareEnvironments(model, modelB);
        return json(comparison);
      }

      case "timeline": {
        const timeline = buildTimeline(model, timeline_steps);
        return json({
          environment_id,
          platform: model.state.platform,
          total_phases: timeline.length,
          timeline,
        });
      }

      default:
        return text(`Unknown analysis mode: ${mode}`);
    }
  },
};
