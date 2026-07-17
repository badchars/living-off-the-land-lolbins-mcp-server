import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, UnifiedLOLEntry, LOLFunction } from "../schema/unified-entry.js";
import { buildAttackGraph } from "../graph/builder.js";
import { discoverChains } from "../graph/pathfinder.js";
import { rankPaths } from "../graph/scorer.js";

function computeRiskScore(entry: UnifiedLOLEntry): {
  score: number;
  breakdown: Record<string, number>;
  level: string;
} {
  const breakdown: Record<string, number> = {};

  // Function diversity (more functions = more dangerous)
  breakdown.function_diversity = Math.min(1.0, entry.functions.length / 10);

  // Escalation potential
  const escalationFns: LOLFunction[] = [
    "privilege_escalation",
    "shell",
    "command",
    "command_execution",
  ];
  breakdown.escalation_potential = escalationFns.some((f) =>
    entry.functions.includes(f),
  )
    ? 0.9
    : 0.2;

  // Stealth (inverted: lower stealthScore = stealthier = riskier)
  breakdown.stealth_risk = 1.0 - entry.stealthScore;

  // Detection coverage (less detection = riskier)
  const detectionScore =
    (entry.detection.sigmaRules.length > 0 ? 0.25 : 0) +
    (entry.detection.yaraRules.length > 0 ? 0.25 : 0) +
    (entry.detection.elasticRules.length > 0 ? 0.25 : 0) +
    (entry.detection.edrCoverage !== "none" ? 0.25 : 0);
  breakdown.detection_gap = 1.0 - detectionScore;

  // Context flexibility
  breakdown.context_flexibility = Math.min(
    1.0,
    entry.executionContexts.length / 5,
  );

  // Chain potential
  breakdown.chain_potential = Math.min(
    1.0,
    entry.chainPotential.length / 5,
  );

  // ATT&CK coverage
  breakdown.attck_coverage = Math.min(
    1.0,
    entry.attckTechniques.length / 5,
  );

  // Weighted average
  const weights: Record<string, number> = {
    function_diversity: 0.15,
    escalation_potential: 0.25,
    stealth_risk: 0.15,
    detection_gap: 0.15,
    context_flexibility: 0.1,
    chain_potential: 0.1,
    attck_coverage: 0.1,
  };

  let score = 0;
  for (const [key, weight] of Object.entries(weights)) {
    score += (breakdown[key] || 0) * weight;
  }
  score = Math.round(score * 100) / 100;

  const level =
    score >= 0.8
      ? "critical"
      : score >= 0.6
        ? "high"
        : score >= 0.4
          ? "medium"
          : "low";

  return { score, breakdown, level };
}

function findAlternatives(
  entry: UnifiedLOLEntry,
  kb: any,
  platform?: Platform,
): any[] {
  const alternatives: any[] = [];
  const targetFunctions = entry.functions;

  for (const fn of targetFunctions) {
    const entries = kb.searchByFunction(fn, platform);
    for (const alt of entries) {
      if (alt.id === entry.id) continue;
      if (alternatives.some((a: any) => a.id === alt.id)) continue;

      const sharedFunctions = alt.functions.filter((f: LOLFunction) =>
        targetFunctions.includes(f),
      );

      alternatives.push({
        id: alt.id,
        binary: alt.binary,
        platform: alt.platform,
        catalog: alt.catalogSource,
        shared_functions: sharedFunctions,
        stealth_score: alt.stealthScore,
        function_coverage:
          Math.round(
            (sharedFunctions.length / targetFunctions.length) * 100,
          ) / 100,
      });
    }
  }

  // Sort by coverage descending
  alternatives.sort(
    (a: any, b: any) => b.function_coverage - a.function_coverage,
  );
  return alternatives.slice(0, 10);
}

export const analyzeBinaryComposite: ToolDef = {
  name: "analyze_binary",
  description:
    "Deep analysis of a specific binary across all LOL catalogs. Returns full technique details, chain potential, detection surface analysis, functional alternatives, and computed risk score.",
  schema: {
    binary: z
      .string()
      .describe(
        "Binary name to analyze (e.g. python, certutil, osascript)",
      ),
    platform: z
      .enum(["linux", "windows", "macos", "all"])
      .optional()
      .default("all")
      .describe("Filter analysis by platform"),
    analysis_type: z
      .enum(["full", "chains", "detection", "alternatives", "history", "risk"])
      .optional()
      .default("full")
      .describe(
        "Type of analysis: full (everything), chains (chain potential), detection (detection surface), alternatives (functional equivalents), history (ATT&CK mapping), risk (risk scoring)",
      ),
    environment_id: z
      .string()
      .optional()
      .describe(
        "Optional environment session ID for context-aware analysis",
      ),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { binary, platform, analysis_type, environment_id } = args;

    const lookupPlatform =
      platform === "all" ? undefined : (platform as Platform);
    const entries = ctx.knowledgeBase.lookupBinary(binary, lookupPlatform);

    if (entries.length === 0) {
      return json({
        binary,
        found: false,
        message: `No entries found for "${binary}" in any catalog`,
        suggestion:
          "Try alternative names, check spelling, or search by function with search_techniques",
      });
    }

    const result: any = {
      binary,
      found: true,
      total_entries: entries.length,
      platforms: [...new Set(entries.map((e) => e.platform))],
      catalogs: [...new Set(entries.map((e) => e.catalogSource))],
    };

    // Core entry details (always included)
    result.entries = entries.map((e) => ({
      id: e.id,
      binary: e.binary,
      aliases: e.aliases,
      platform: e.platform,
      catalog: e.catalogSource,
      category: e.category,
      description: e.description,
      functions: e.functions,
      full_paths: e.fullPaths,
      stealth_score: e.stealthScore,
      stealth_notes: e.stealthNotes,
      attck_techniques: e.attckTechniques,
      execution_contexts: e.executionContexts.map((c) => ({
        context: c.context,
        prerequisite: c.prerequisite,
        command: c.command,
        result: c.result,
        one_liner: c.oneLiner,
      })),
    }));

    // Chain analysis
    if (analysis_type === "full" || analysis_type === "chains") {
      result.chain_analysis = {
        chain_potential: [
          ...new Set(entries.flatMap((e) => e.chainPotential)),
        ],
        related_entries: [
          ...new Set(entries.flatMap((e) => e.relatedEntries)),
        ],
        can_chain_functions: entries
          .flatMap((e) => e.functions)
          .filter(
            (f) =>
              f === "file_write" ||
              f === "download" ||
              f === "command_execution" ||
              f === "shell" ||
              f === "library_load",
          ),
      };

      // If environment is available, compute actual chains
      if (environment_id) {
        const model = ctx.sessions.get(environment_id);
        if (model) {
          const graph = buildAttackGraph(model);
          const chains = discoverChains(model, graph, 4);
          const binaryChains = chains.filter((c) =>
            c.steps.some(
              (s) => s.binary.toLowerCase() === binary.toLowerCase(),
            ),
          );
          const ranked = rankPaths(binaryChains, undefined, model.state);
          result.chain_analysis.environment_chains = ranked
            .slice(0, 5)
            .map((c) => ({
              name: c.name,
              steps: c.steps.map((s) => ({
                action: s.action,
                binary: s.binary,
                result: s.result,
              })),
              score: c.score,
              reasoning: c.chainReasoning,
            }));
        }
      }
    }

    // Detection surface analysis
    if (analysis_type === "full" || analysis_type === "detection") {
      const allDetections = entries.map((e) => e.detection);
      result.detection_surface = {
        sigma_rules: [
          ...new Set(allDetections.flatMap((d) => d.sigmaRules)),
        ],
        yara_rules: [...new Set(allDetections.flatMap((d) => d.yaraRules))],
        elastic_rules: [
          ...new Set(allDetections.flatMap((d) => d.elasticRules)),
        ],
        splunk_rules: [
          ...new Set(allDetections.flatMap((d) => d.splunkRules)),
        ],
        sysmon_events: [
          ...new Set(allDetections.flatMap((d) => d.sysmonEvents)),
        ],
        block_rules: [
          ...new Set(allDetections.flatMap((d) => d.blockRules)),
        ],
        log_sources: [
          ...new Set(allDetections.flatMap((d) => d.logSources)),
        ],
        iocs: [...new Set(allDetections.flatMap((d) => d.iocs))],
        atomic_tests: [
          ...new Set(allDetections.flatMap((d) => d.atomicTests)),
        ],
        edr_coverage: allDetections.map((d) => d.edrCoverage).sort()[
          allDetections.length - 1
        ],
        coverage_summary: {
          has_sigma: allDetections.some((d) => d.sigmaRules.length > 0),
          has_yara: allDetections.some((d) => d.yaraRules.length > 0),
          has_edr:
            allDetections.some((d) => d.edrCoverage !== "none"),
          has_sysmon: allDetections.some(
            (d) => d.sysmonEvents.length > 0,
          ),
          total_rules:
            allDetections.reduce((s, d) => s + d.sigmaRules.length, 0) +
            allDetections.reduce((s, d) => s + d.yaraRules.length, 0) +
            allDetections.reduce(
              (s, d) => s + d.elasticRules.length,
              0,
            ),
        },
      };
    }

    // Alternatives analysis
    if (analysis_type === "full" || analysis_type === "alternatives") {
      result.alternatives = findAlternatives(
        entries[0],
        ctx.knowledgeBase,
        lookupPlatform,
      );
    }

    // ATT&CK technique history/mapping
    if (analysis_type === "full" || analysis_type === "history") {
      const allTechniques = [
        ...new Set(entries.flatMap((e) => e.attckTechniques)),
      ];
      result.attck_mapping = {
        techniques: allTechniques,
        technique_count: allTechniques.length,
        tactics_covered: allTechniques.map((t) => {
          if (t.startsWith("T1548")) return "Privilege Escalation";
          if (t.startsWith("T1055")) return "Defense Evasion";
          if (t.startsWith("T1003")) return "Credential Access";
          if (t.startsWith("T1134")) return "Privilege Escalation";
          if (t.startsWith("T1059")) return "Execution";
          if (t.startsWith("T1105")) return "Command and Control";
          if (t.startsWith("T1574")) return "Persistence";
          if (t.startsWith("T1543")) return "Persistence";
          if (t.startsWith("T1218")) return "Defense Evasion";
          return "Other";
        }),
        resources: [...new Set(entries.flatMap((e) => e.resources))],
      };
    }

    // Risk scoring
    if (analysis_type === "full" || analysis_type === "risk") {
      result.risk_assessment = entries.map((e) => ({
        id: e.id,
        platform: e.platform,
        catalog: e.catalogSource,
        ...computeRiskScore(e),
      }));

      // Overall risk (highest among entries)
      const riskScores = result.risk_assessment.map(
        (r: any) => r.score,
      );
      result.overall_risk = {
        score: Math.max(...riskScores),
        level: result.risk_assessment.find(
          (r: any) => r.score === Math.max(...riskScores),
        )?.level,
      };
    }

    return json(result);
  },
};
