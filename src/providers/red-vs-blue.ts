import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Helpers ━━━

function deduplicateByBinary(entries: UnifiedLOLEntry[]): UnifiedLOLEntry[] {
  const seen = new Set<string>();
  return entries.filter(e => {
    const key = `${e.binary}-${e.platform}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ━━━ Tools ━━━

const score_coverage: ToolDef = {
  name: "score_coverage",
  description: "Score detection coverage percentage across all LOL techniques in an environment. Higher score = better blue team visibility.",
  schema: {
    environment_id: z.string().optional().describe("Environment session ID"),
    platform: z.string().optional().describe("Platform filter"),
  },
  async execute(args: { environment_id?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    let entries: UnifiedLOLEntry[];

    if (args.environment_id) {
      const session = ctx.sessions.get(args.environment_id);
      if (!session) return text(`Session not found: ${args.environment_id}`);
      entries = session.matchedEntries.map(m => m.entry);
    } else {
      entries = args.platform
        ? ctx.knowledgeBase.allEntries.filter(e => e.platform === args.platform)
        : ctx.knowledgeBase.allEntries;
    }

    const unique = deduplicateByBinary(entries);
    const withDetection = unique.filter(e =>
      e.detection.sigmaRules.length > 0 ||
      e.detection.edrCoverage !== "none" ||
      e.detection.yaraRules.length > 0
    );

    const coverageScore = unique.length > 0
      ? Math.round((withDetection.length / unique.length) * 100)
      : 0;

    const byFunction = new Map<string, { total: number; covered: number }>();
    for (const e of unique) {
      for (const f of e.functions) {
        if (!byFunction.has(f)) byFunction.set(f, { total: 0, covered: 0 });
        const stat = byFunction.get(f)!;
        stat.total++;
        if (withDetection.includes(e)) stat.covered++;
      }
    }

    return json({
      overallCoverageScore: coverageScore,
      totalTechniques: unique.length,
      coveredTechniques: withDetection.length,
      uncoveredTechniques: unique.length - withDetection.length,
      coverageByFunction: Array.from(byFunction.entries())
        .map(([func, stat]) => ({
          function: func,
          total: stat.total,
          covered: stat.covered,
          coveragePercent: Math.round((stat.covered / stat.total) * 100),
        }))
        .sort((a, b) => a.coveragePercent - b.coveragePercent),
    });
  },
};

const score_blind_spots: ToolDef = {
  name: "score_blind_spots",
  description: "Score blind spot severity — how many high-risk techniques have zero detection coverage. Lower score = more dangerous blind spots.",
  schema: {
    environment_id: z.string().optional().describe("Environment session ID"),
    platform: z.string().optional().describe("Platform filter"),
  },
  async execute(args: { environment_id?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    let entries: UnifiedLOLEntry[];

    if (args.environment_id) {
      const session = ctx.sessions.get(args.environment_id);
      if (!session) return text(`Session not found: ${args.environment_id}`);
      entries = session.matchedEntries.map(m => m.entry);
    } else {
      entries = args.platform
        ? ctx.knowledgeBase.allEntries.filter(e => e.platform === args.platform)
        : ctx.knowledgeBase.allEntries;
    }

    const unique = deduplicateByBinary(entries);
    const blindSpots = unique.filter(e =>
      e.detection.edrCoverage === "none" &&
      e.detection.sigmaRules.length === 0 &&
      e.detection.yaraRules.length === 0
    );

    const criticalBlindSpots = blindSpots.filter(e => e.stealthScore >= 4);
    const highBlindSpots = blindSpots.filter(e => e.stealthScore === 3);
    const mediumBlindSpots = blindSpots.filter(e => e.stealthScore <= 2);

    const severityScore = unique.length > 0
      ? Math.round(100 - ((criticalBlindSpots.length * 3 + highBlindSpots.length * 2 + mediumBlindSpots.length) / (unique.length * 3)) * 100)
      : 100;

    return json({
      blindSpotSeverityScore: Math.max(0, severityScore),
      totalBlindSpots: blindSpots.length,
      critical: criticalBlindSpots.length,
      high: highBlindSpots.length,
      medium: mediumBlindSpots.length,
      topCriticalBlindSpots: criticalBlindSpots.slice(0, 10).map(e => ({
        binary: e.binary,
        platform: e.platform,
        functions: e.functions,
        attck: e.attckTechniques,
      })),
    });
  },
};

const score_overall_posture: ToolDef = {
  name: "score_overall_posture",
  description: "Calculate overall security posture score combining red team attack surface and blue team detection capability. Returns 0-100 score with breakdown.",
  schema: {
    environment_id: z.string().optional().describe("Environment session ID"),
    platform: z.string().optional().describe("Platform filter"),
  },
  async execute(args: { environment_id?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    let entries: UnifiedLOLEntry[];

    if (args.environment_id) {
      const session = ctx.sessions.get(args.environment_id);
      if (!session) return text(`Session not found: ${args.environment_id}`);
      entries = session.matchedEntries.map(m => m.entry);
    } else {
      entries = args.platform
        ? ctx.knowledgeBase.allEntries.filter(e => e.platform === args.platform)
        : ctx.knowledgeBase.allEntries;
    }

    const unique = deduplicateByBinary(entries);
    const withDetection = unique.filter(e =>
      e.detection.sigmaRules.length > 0 ||
      e.detection.edrCoverage !== "none" ||
      e.detection.yaraRules.length > 0
    );

    const coverageScore = unique.length > 0 ? (withDetection.length / unique.length) * 100 : 0;
    const avgStealth = unique.length > 0
      ? unique.reduce((s, e) => s + e.stealthScore, 0) / unique.length
      : 0;
    const redTeamScore = Math.round(avgStealth * 20); // 1-5 → 20-100
    const blueTeamScore = Math.round(coverageScore);
    const overallPosture = Math.round((blueTeamScore * 0.6 + (100 - redTeamScore) * 0.4));

    return json({
      overallPostureScore: overallPosture,
      redTeamCapability: redTeamScore,
      blueTeamCapability: blueTeamScore,
      breakdown: {
        detectionCoverage: Math.round(coverageScore),
        averageStealthExposure: Math.round(avgStealth * 10) / 10,
        totalAvailableTechniques: unique.length,
        detectedTechniques: withDetection.length,
      },
      rating: overallPosture >= 80 ? "strong" :
        overallPosture >= 60 ? "moderate" :
          overallPosture >= 40 ? "weak" : "critical",
      summary: overallPosture >= 60
        ? "Blue team has reasonable coverage but gaps remain in high-stealth techniques"
        : "Significant detection gaps allow red team to operate with low detection risk",
    });
  },
};

const score_improvement_plan: ToolDef = {
  name: "score_improvement_plan",
  description: "Generate prioritized improvement plan to increase blue team detection posture. Lists specific actions ranked by impact on overall score.",
  schema: {
    environment_id: z.string().optional().describe("Environment session ID"),
    platform: z.string().optional().describe("Platform filter"),
    max_recommendations: z.number().optional().describe("Max recommendations (default 10)"),
  },
  async execute(args: { environment_id?: string; platform?: string; max_recommendations?: number }, ctx: ToolContext): Promise<ToolResult> {
    const maxRec = args.max_recommendations || 10;
    let entries: UnifiedLOLEntry[];

    if (args.environment_id) {
      const session = ctx.sessions.get(args.environment_id);
      if (!session) return text(`Session not found: ${args.environment_id}`);
      entries = session.matchedEntries.map(m => m.entry);
    } else {
      entries = args.platform
        ? ctx.knowledgeBase.allEntries.filter(e => e.platform === args.platform)
        : ctx.knowledgeBase.allEntries;
    }

    const unique = deduplicateByBinary(entries);
    const uncovered = unique
      .filter(e => e.detection.edrCoverage === "none" && e.detection.sigmaRules.length === 0)
      .sort((a, b) => b.stealthScore - a.stealthScore);

    const highRiskFunctions = ["privilege_escalation", "credential_access", "edr_disable", "lateral_movement"];

    const recommendations = uncovered.slice(0, maxRec).map((e, i) => {
      const isHighRisk = e.functions.some(f => highRiskFunctions.includes(f));
      const impactScore = e.stealthScore * 20 + (isHighRisk ? 30 : 0) + e.functions.length * 5;

      return {
        priority: i + 1,
        action: `Deploy detection for ${e.binary} (${e.functions.join(", ")})`,
        binary: e.binary,
        platform: e.platform,
        impactScore,
        steps: [
          `Create Sigma rule for ${e.binary} process creation with suspicious args`,
          `Add Sysmon config to log ${e.binary} activity (Event IDs: 1, 3, 11)`,
          `Configure EDR alert for ${e.binary} anomalous behavior`,
          ...(isHighRisk ? [`Flag as high-priority: involves ${e.functions.filter(f => highRiskFunctions.includes(f)).join(", ")}`] : []),
        ],
        estimatedScoreIncrease: Math.round(impactScore / unique.length),
        attck: e.attckTechniques,
      };
    });

    return json({
      improvementPlan: recommendations,
      estimatedTotalScoreIncrease: recommendations.reduce((s, r) => s + r.estimatedScoreIncrease, 0),
      currentUncoveredCount: uncovered.length,
      planCoversPercent: Math.round((Math.min(maxRec, uncovered.length) / (uncovered.length || 1)) * 100),
    });
  },
};

export const redVsBlueTools: ToolDef[] = [
  score_coverage,
  score_blind_spots,
  score_overall_posture,
  score_improvement_plan,
];
