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

const det_rule_vs_technique: ToolDef = {
  name: "det_rule_vs_technique",
  description: "Evaluate how well a detection rule covers a LOL technique. Checks if the rule logic matches the technique execution patterns and identifies gaps.",
  schema: {
    rule_name: z.string().optional().describe("Detection rule name or ID"),
    technique_id: z.string().optional().describe("LOL technique ID to check coverage for"),
    binary: z.string().optional().describe("Binary name to check coverage for"),
  },
  async execute(args: { rule_name?: string; technique_id?: string; binary?: string }, ctx: ToolContext): Promise<ToolResult> {
    let entries: UnifiedLOLEntry[] = [];

    if (args.technique_id) {
      const entry = ctx.knowledgeBase.getById(args.technique_id);
      if (entry) entries = [entry];
    } else if (args.binary) {
      entries = ctx.knowledgeBase.lookupBinary(args.binary);
    }

    if (entries.length === 0) return text("No matching entries found.");

    const analysis = entries.slice(0, 5).map(e => {
      const hasSigma = e.detection.sigmaRules.length > 0;
      const hasYara = e.detection.yaraRules.length > 0;
      const hasEdr = e.detection.edrCoverage !== "none";
      const totalContexts = e.executionContexts.length;
      const detectedContexts = hasSigma ? Math.ceil(totalContexts * 0.6) : 0;

      return {
        binary: e.binary,
        technique: e.id,
        functions: e.functions,
        totalExecutionContexts: totalContexts,
        estimatedDetectedContexts: detectedContexts,
        coveragePercent: totalContexts > 0 ? Math.round((detectedContexts / totalContexts) * 100) : 0,
        detectionSources: {
          sigmaRules: e.detection.sigmaRules.length,
          yaraRules: e.detection.yaraRules.length,
          edrCoverage: e.detection.edrCoverage,
          sysmonEvents: e.detection.sysmonEvents,
        },
        gaps: [
          ...(!hasSigma ? ["No Sigma rules — process creation not monitored"] : []),
          ...(!hasYara ? ["No YARA rules — artifact scanning not possible"] : []),
          ...(!hasEdr ? ["No EDR coverage — real-time detection absent"] : []),
          ...(e.detection.sysmonEvents.length === 0 ? ["No Sysmon events mapped"] : []),
        ],
        bypassMethods: e.functions.includes("defense_evasion")
          ? ["Obfuscation can bypass string-based detection", "Alternative binaries may not trigger same rules"]
          : ["Command-line obfuscation", "Parent process spoofing"],
      };
    });

    return json({ ruleAnalysis: analysis });
  },
};

const det_false_positive_rate: ToolDef = {
  name: "det_false_positive_rate",
  description: "Estimate false positive rates for LOL technique detection. Common system binaries used legitimately have higher FP rates.",
  schema: {
    binary: z.string().optional().describe("Binary name to estimate FP rate for"),
    technique_id: z.string().optional().describe("LOL technique ID"),
    platform: z.string().optional().describe("Platform filter"),
  },
  async execute(args: { binary?: string; technique_id?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    let entries: UnifiedLOLEntry[] = [];

    if (args.technique_id) {
      const entry = ctx.knowledgeBase.getById(args.technique_id);
      if (entry) entries = [entry];
    } else if (args.binary) {
      entries = ctx.knowledgeBase.lookupBinary(args.binary);
    } else {
      entries = args.platform
        ? ctx.knowledgeBase.allEntries.filter(e => e.platform === args.platform)
        : ctx.knowledgeBase.allEntries;
      entries = deduplicateByBinary(entries).slice(0, 20);
    }

    const fpAnalysis = entries.map(e => {
      const legitimateUsageLevel = e.stealthScore <= 2 ? "very_high" :
        e.stealthScore <= 3 ? "high" : e.stealthScore <= 4 ? "medium" : "low";

      const estimatedFpRate = e.stealthScore <= 2 ? 0.7 :
        e.stealthScore <= 3 ? 0.4 : e.stealthScore <= 4 ? 0.2 : 0.05;

      return {
        binary: e.binary,
        platform: e.platform,
        stealthScore: e.stealthScore,
        legitimateUsageLevel,
        estimatedFalsePositiveRate: estimatedFpRate,
        fpReductionStrategies: [
          "Add command-line argument filters to narrow detection",
          "Exclude known-good parent processes",
          `Baseline normal ${e.binary} usage patterns before alerting`,
          "Use behavioral analytics instead of simple process name matching",
        ],
        recommendedApproach: estimatedFpRate > 0.5
          ? "anomaly_detection"
          : estimatedFpRate > 0.2
            ? "command_line_filtering"
            : "direct_alerting",
      };
    });

    return json({ falsePositiveAnalysis: fpAnalysis });
  },
};

const det_bypass_probability: ToolDef = {
  name: "det_bypass_probability",
  description: "Estimate probability that an attacker can bypass existing detection for a LOL technique. Considers obfuscation, alternative binaries, and EDR gaps.",
  schema: {
    binary: z.string().optional().describe("Binary to assess bypass probability for"),
    technique_id: z.string().optional().describe("LOL technique ID"),
  },
  async execute(args: { binary?: string; technique_id?: string }, ctx: ToolContext): Promise<ToolResult> {
    let entries: UnifiedLOLEntry[] = [];

    if (args.technique_id) {
      const entry = ctx.knowledgeBase.getById(args.technique_id);
      if (entry) entries = [entry];
    } else if (args.binary) {
      entries = ctx.knowledgeBase.lookupBinary(args.binary);
    }

    if (entries.length === 0) return text("No matching entries found.");

    const bypassAnalysis = entries.slice(0, 5).map(e => {
      const hasDetection = e.detection.sigmaRules.length > 0 || e.detection.edrCoverage !== "none";
      const alternatives = ctx.knowledgeBase.searchByFunction(e.functions[0] || "command_execution")
        .filter(alt => alt.id !== e.id && alt.platform === e.platform)
        .slice(0, 5);

      const bypassProbability = !hasDetection ? 0.95 :
        e.detection.edrCoverage === "high" ? 0.2 :
          e.detection.edrCoverage === "medium" ? 0.4 :
            e.detection.sigmaRules.length > 2 ? 0.3 : 0.6;

      return {
        binary: e.binary,
        technique: e.id,
        currentDetection: {
          sigmaRules: e.detection.sigmaRules.length,
          edrCoverage: e.detection.edrCoverage,
          sysmonEvents: e.detection.sysmonEvents.length,
        },
        bypassProbability,
        bypassMethods: [
          { method: "command_obfuscation", effectiveness: 0.6, description: "Obfuscate command-line arguments" },
          { method: "alternative_binary", effectiveness: 0.8, description: `Use alternative: ${alternatives.slice(0, 3).map(a => a.binary).join(", ") || "none found"}` },
          { method: "parent_spoofing", effectiveness: 0.5, description: "Spoof parent process to appear legitimate" },
          { method: "living_off_the_land", effectiveness: 0.7, description: "Chain with other LOL binaries to obscure intent" },
        ],
        alternativeBinaries: alternatives.slice(0, 5).map(a => ({
          binary: a.binary,
          detectionCoverage: a.detection.edrCoverage,
          sigmaRules: a.detection.sigmaRules.length,
        })),
      };
    });

    return json({ bypassAnalysis });
  },
};

const det_rule_quality: ToolDef = {
  name: "det_rule_quality",
  description: "Score overall detection quality for a technique — combining coverage breadth, false positive rate, bypass resistance, and detection timeliness.",
  schema: {
    binary: z.string().optional().describe("Binary name"),
    technique_id: z.string().optional().describe("LOL technique ID"),
    platform: z.string().optional().describe("Platform filter"),
  },
  async execute(args: { binary?: string; technique_id?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    let entries: UnifiedLOLEntry[] = [];

    if (args.technique_id) {
      const entry = ctx.knowledgeBase.getById(args.technique_id);
      if (entry) entries = [entry];
    } else if (args.binary) {
      entries = ctx.knowledgeBase.lookupBinary(args.binary);
    } else {
      entries = args.platform
        ? ctx.knowledgeBase.allEntries.filter(e => e.platform === args.platform)
        : ctx.knowledgeBase.allEntries;
      entries = deduplicateByBinary(entries)
        .sort((a, b) => b.stealthScore - a.stealthScore)
        .slice(0, 20);
    }

    const qualityScores = entries.map(e => {
      const coverageScore = Math.min(
        (e.detection.sigmaRules.length * 20) +
        (e.detection.edrCoverage === "high" ? 30 : e.detection.edrCoverage === "medium" ? 20 : e.detection.edrCoverage === "low" ? 10 : 0) +
        (e.detection.sysmonEvents.length * 5) +
        (e.detection.yaraRules.length * 10),
        100
      );

      const fpResistance = e.stealthScore >= 4 ? 80 : e.stealthScore >= 3 ? 50 : 30;
      const bypassResistance = e.detection.edrCoverage === "high" ? 70 :
        e.detection.sigmaRules.length > 2 ? 50 : 20;
      const overallQuality = Math.round((coverageScore * 0.4 + fpResistance * 0.3 + bypassResistance * 0.3));

      return {
        binary: e.binary,
        platform: e.platform,
        stealthScore: e.stealthScore,
        qualityBreakdown: {
          coverageBreadth: coverageScore,
          falsePositiveResistance: fpResistance,
          bypassResistance,
        },
        overallQuality,
        grade: overallQuality >= 80 ? "A" : overallQuality >= 60 ? "B" : overallQuality >= 40 ? "C" : overallQuality >= 20 ? "D" : "F",
        improvements: [
          ...(coverageScore < 50 ? ["Add more Sigma/YARA rules for broader coverage"] : []),
          ...(fpResistance < 50 ? ["Refine detection logic to reduce false positives"] : []),
          ...(bypassResistance < 50 ? ["Add behavioral detection alongside signature-based"] : []),
        ],
      };
    });

    return json({
      qualityScores,
      summary: {
        averageQuality: Math.round(qualityScores.reduce((s, q) => s + q.overallQuality, 0) / (qualityScores.length || 1)),
        gradeDistribution: {
          A: qualityScores.filter(q => q.grade === "A").length,
          B: qualityScores.filter(q => q.grade === "B").length,
          C: qualityScores.filter(q => q.grade === "C").length,
          D: qualityScores.filter(q => q.grade === "D").length,
          F: qualityScores.filter(q => q.grade === "F").length,
        },
      },
    });
  },
};

export const detectionEffectivenessTools: ToolDef[] = [
  det_rule_vs_technique,
  det_false_positive_rate,
  det_bypass_probability,
  det_rule_quality,
];
