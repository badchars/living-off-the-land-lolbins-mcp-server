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

function hasZeroCoverage(e: UnifiedLOLEntry): boolean {
  return e.detection.edrCoverage === "none" &&
    e.detection.sigmaRules.length === 0 &&
    e.detection.yaraRules.length === 0 &&
    e.detection.elasticRules.length === 0 &&
    e.detection.splunkRules.length === 0;
}

function hasPartialCoverage(e: UnifiedLOLEntry): boolean {
  if (hasZeroCoverage(e)) return false;
  const sources = [
    e.detection.sigmaRules.length > 0,
    e.detection.yaraRules.length > 0,
    e.detection.edrCoverage !== "none",
    e.detection.elasticRules.length > 0,
    e.detection.splunkRules.length > 0,
  ];
  const coveredCount = sources.filter(Boolean).length;
  return coveredCount < 3;
}

// ━━━ Tools ━━━

const blind_zero_coverage: ToolDef = {
  name: "blind_zero_coverage",
  description: "Find LOL techniques with absolutely zero detection coverage — no Sigma, no YARA, no EDR, no vendor rules. These are critical blind spots.",
  schema: {
    platform: z.string().optional().describe("Filter by platform (windows, linux, macos)"),
    environment_id: z.string().optional().describe("Environment session ID to check against"),
    top_n: z.number().optional().describe("Number of results (default 25)"),
  },
  async execute(args: { platform?: string; environment_id?: string; top_n?: number }, ctx: ToolContext): Promise<ToolResult> {
    const topN = args.top_n || 25;
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

    const zeroCoverage = deduplicateByBinary(entries.filter(hasZeroCoverage))
      .sort((a, b) => b.stealthScore - a.stealthScore)
      .slice(0, topN);

    return json({
      totalAnalyzed: entries.length,
      zeroCoverageCount: zeroCoverage.length,
      zeroCoveragePercent: entries.length > 0 ? Math.round((zeroCoverage.length / entries.length) * 100) : 0,
      blindSpots: zeroCoverage.map(e => ({
        binary: e.binary,
        platform: e.platform,
        catalog: e.catalogSource,
        stealthScore: e.stealthScore,
        functions: e.functions,
        attck: e.attckTechniques,
        risk: e.stealthScore >= 4 ? "critical" : e.stealthScore >= 3 ? "high" : "medium",
        recommendation: `Create Sigma rule for ${e.binary} covering ${e.functions.join(", ")}`,
      })),
    });
  },
};

const blind_partial_coverage: ToolDef = {
  name: "blind_partial_coverage",
  description: "Find techniques with only partial detection coverage — some rules exist but gaps remain. Identifies which detection sources are missing.",
  schema: {
    platform: z.string().optional().describe("Filter by platform"),
    environment_id: z.string().optional().describe("Environment session ID"),
    top_n: z.number().optional().describe("Number of results (default 20)"),
  },
  async execute(args: { platform?: string; environment_id?: string; top_n?: number }, ctx: ToolContext): Promise<ToolResult> {
    const topN = args.top_n || 20;
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

    const partial = deduplicateByBinary(entries.filter(hasPartialCoverage))
      .sort((a, b) => b.stealthScore - a.stealthScore)
      .slice(0, topN);

    return json({
      totalAnalyzed: entries.length,
      partialCoverageCount: partial.length,
      partialCoverage: partial.map(e => ({
        binary: e.binary,
        platform: e.platform,
        stealthScore: e.stealthScore,
        existingCoverage: {
          sigma: e.detection.sigmaRules.length > 0,
          yara: e.detection.yaraRules.length > 0,
          edr: e.detection.edrCoverage,
          elastic: e.detection.elasticRules.length > 0,
          splunk: e.detection.splunkRules.length > 0,
          sysmon: e.detection.sysmonEvents.length > 0,
        },
        missingCoverage: [
          ...(e.detection.sigmaRules.length === 0 ? ["sigma"] : []),
          ...(e.detection.yaraRules.length === 0 ? ["yara"] : []),
          ...(e.detection.edrCoverage === "none" ? ["edr"] : []),
          ...(e.detection.sysmonEvents.length === 0 ? ["sysmon"] : []),
        ],
        recommendation: `Add ${e.detection.sigmaRules.length === 0 ? "Sigma" : "YARA"} rules for ${e.binary}`,
      })),
    });
  },
};

const blind_evasion_possible: ToolDef = {
  name: "blind_evasion_possible",
  description: "Find techniques where detection exists but evasion is likely possible. Identifies cases where obfuscation or alternative methods can bypass existing rules.",
  schema: {
    platform: z.string().optional().describe("Filter by platform"),
    environment_id: z.string().optional().describe("Environment session ID"),
  },
  async execute(args: { platform?: string; environment_id?: string }, ctx: ToolContext): Promise<ToolResult> {
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

    const evasionProne = deduplicateByBinary(entries)
      .filter(e => {
        const hasDetection = e.detection.sigmaRules.length > 0 || e.detection.edrCoverage !== "none";
        const isEvasionCapable = e.functions.includes("defense_evasion") ||
          e.functions.includes("awl_bypass") ||
          e.stealthScore <= 2;
        return hasDetection && isEvasionCapable;
      })
      .sort((a, b) => a.stealthScore - b.stealthScore)
      .slice(0, 20);

    return json({
      evasionProneTechniques: evasionProne.map(e => ({
        binary: e.binary,
        platform: e.platform,
        stealthScore: e.stealthScore,
        functions: e.functions,
        currentDetection: {
          edrCoverage: e.detection.edrCoverage,
          sigmaRules: e.detection.sigmaRules.length,
        },
        evasionVectors: [
          ...(e.stealthScore <= 2 ? ["Blends with normal system activity — high false positive baseline"] : []),
          ...(e.functions.includes("defense_evasion") ? ["Binary has built-in evasion capabilities"] : []),
          "Command-line obfuscation bypasses string-matching rules",
          "Alternative execution context may not trigger same detection",
        ],
        mitigations: [
          "Implement behavioral detection alongside signature-based",
          "Monitor for unusual parent-child process relationships",
          "Correlate with other indicators (network, file access)",
        ],
      })),
    });
  },
};

const blind_priority_ranking: ToolDef = {
  name: "blind_priority_ranking",
  description: "Rank blind spots by priority — combining stealth score, function severity, and environment relevance to determine which gaps to fix first.",
  schema: {
    environment_id: z.string().optional().describe("Environment session ID for contextual ranking"),
    platform: z.string().optional().describe("Platform filter"),
    top_n: z.number().optional().describe("Number of top priorities (default 15)"),
  },
  async execute(args: { environment_id?: string; platform?: string; top_n?: number }, ctx: ToolContext): Promise<ToolResult> {
    const topN = args.top_n || 15;
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

    const highRiskFunctions = ["privilege_escalation", "credential_access", "defense_evasion", "lateral_movement", "edr_disable"];

    const ranked = deduplicateByBinary(entries.filter(e => hasZeroCoverage(e) || hasPartialCoverage(e)))
      .map(e => {
        const functionSeverity = e.functions.filter(f => highRiskFunctions.includes(f)).length;
        const priorityScore = (e.stealthScore * 25) + (functionSeverity * 20) +
          (e.attckTechniques.length * 5) + (hasZeroCoverage(e) ? 30 : 10);
        return { entry: e, priorityScore };
      })
      .sort((a, b) => b.priorityScore - a.priorityScore)
      .slice(0, topN);

    return json({
      prioritizedBlindSpots: ranked.map((r, i) => ({
        rank: i + 1,
        binary: r.entry.binary,
        platform: r.entry.platform,
        priorityScore: r.priorityScore,
        stealthScore: r.entry.stealthScore,
        functions: r.entry.functions,
        attck: r.entry.attckTechniques,
        coverageStatus: hasZeroCoverage(r.entry) ? "zero" : "partial",
        actionPlan: [
          `1. Create Sigma rule for ${r.entry.binary} ${r.entry.functions[0]} activity`,
          `2. Add Sysmon monitoring (events: ${r.entry.detection.sysmonEvents.length > 0 ? r.entry.detection.sysmonEvents.join(", ") : "1, 3, 11"})`,
          `3. Configure EDR custom rule for ${r.entry.binary}`,
        ],
      })),
    });
  },
};

export const detectionBlindSpotsTools: ToolDef[] = [
  blind_zero_coverage,
  blind_partial_coverage,
  blind_evasion_possible,
  blind_priority_ranking,
];
