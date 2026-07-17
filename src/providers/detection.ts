import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

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

function summarizeKbEntry(e: UnifiedLOLEntry): Record<string, unknown> {
  return {
    binary: e.binary,
    platform: e.platform,
    catalog: e.catalogSource,
    functions: e.functions,
    stealthScore: e.stealthScore,
    attck: e.attckTechniques,
    detection: {
      edrCoverage: e.detection.edrCoverage,
      sigmaRules: e.detection.sigmaRules.length,
      sysmonEvents: e.detection.sysmonEvents,
      logSources: e.detection.logSources,
    },
  };
}

// ━━━ Sysmon Event Map ━━━

const SYSMON_EVENTS: Record<number, { name: string; relevance: string }> = {
  1: { name: "Process Create", relevance: "Detect LOL binary execution with suspicious arguments" },
  3: { name: "Network Connection", relevance: "Detect LOL binaries making outbound connections" },
  7: { name: "Image Loaded", relevance: "Detect DLL sideloading and proxy execution" },
  8: { name: "CreateRemoteThread", relevance: "Detect process injection via LOL binaries" },
  10: { name: "ProcessAccess", relevance: "Detect credential dumping and process manipulation" },
  11: { name: "FileCreate", relevance: "Detect file drops from LOL binaries" },
  12: { name: "RegistryObject Add/Delete", relevance: "Detect persistence via registry manipulation" },
  13: { name: "RegistryValue Set", relevance: "Detect Run key and service persistence" },
  15: { name: "FileCreateStreamHash", relevance: "Detect ADS (Alternate Data Streams) abuse" },
  17: { name: "PipeEvent Created", relevance: "Detect named pipe creation for C2" },
  22: { name: "DNSEvent", relevance: "Detect DNS-based exfil and C2 lookups" },
  23: { name: "FileDelete", relevance: "Detect anti-forensics file deletion" },
  25: { name: "ProcessTampering", relevance: "Detect process hollowing and tampering" },
};

// ━━━ Tools ━━━

const detection_sigma_coverage: ToolDef = {
  name: "detection_sigma_coverage",
  description: "Analyze which LOL techniques have Sigma rule coverage. Query KB entries with sigma detection rules and report coverage statistics.",
  schema: {
    platform: z.string().optional().describe("Filter by platform (windows, linux, macos)"),
    min_stealth: z.number().optional().describe("Minimum stealth score to filter (1-5)"),
  },
  async execute(args: { platform?: string; min_stealth?: number }, ctx: ToolContext): Promise<ToolResult> {
    const all = ctx.knowledgeBase.allEntries;
    let entries = args.platform
      ? all.filter(e => e.platform === args.platform)
      : all;
    if (args.min_stealth) {
      entries = entries.filter(e => e.stealthScore >= args.min_stealth!);
    }

    const withSigma = entries.filter(e => e.detection.sigmaRules.length > 0);
    const withoutSigma = entries.filter(e => e.detection.sigmaRules.length === 0);
    const coveragePercent = entries.length > 0 ? Math.round((withSigma.length / entries.length) * 100) : 0;

    const topCovered = deduplicateByBinary(withSigma)
      .sort((a, b) => b.detection.sigmaRules.length - a.detection.sigmaRules.length)
      .slice(0, 10)
      .map(e => ({
        binary: e.binary,
        platform: e.platform,
        sigmaRuleCount: e.detection.sigmaRules.length,
        rules: e.detection.sigmaRules.slice(0, 5),
        stealthScore: e.stealthScore,
      }));

    const uncoveredHighStealth = deduplicateByBinary(withoutSigma)
      .sort((a, b) => b.stealthScore - a.stealthScore)
      .slice(0, 10)
      .map(e => ({
        binary: e.binary,
        platform: e.platform,
        stealthScore: e.stealthScore,
        functions: e.functions,
        attck: e.attckTechniques,
      }));

    return json({
      totalEntries: entries.length,
      withSigmaCoverage: withSigma.length,
      withoutSigmaCoverage: withoutSigma.length,
      coveragePercent,
      topCoveredBinaries: topCovered,
      uncoveredHighStealthBinaries: uncoveredHighStealth,
    });
  },
};

const detection_edr_coverage: ToolDef = {
  name: "detection_edr_coverage",
  description: "Assess EDR detection coverage level for LOL techniques in an environment. Shows distribution of none/low/medium/high EDR coverage.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID to assess coverage for"),
    platform: z.string().optional().describe("Filter by platform (windows, linux, macos)"),
  },
  async execute(args: { session_id?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    let entries: UnifiedLOLEntry[];

    if (args.session_id) {
      const session = ctx.sessions.get(args.session_id);
      if (!session) return text(`Session not found: ${args.session_id}`);
      entries = session.matchedEntries.map(m => m.entry);
    } else {
      entries = args.platform
        ? ctx.knowledgeBase.allEntries.filter(e => e.platform === args.platform)
        : ctx.knowledgeBase.allEntries;
    }

    const coverage = { none: 0, low: 0, medium: 0, high: 0 };
    for (const e of entries) {
      coverage[e.detection.edrCoverage]++;
    }

    const total = entries.length;
    const coverageScore = total > 0
      ? Math.round(((coverage.high * 3 + coverage.medium * 2 + coverage.low * 1) / (total * 3)) * 100)
      : 0;

    const noCoverageEntries = deduplicateByBinary(entries.filter(e => e.detection.edrCoverage === "none"))
      .sort((a, b) => b.stealthScore - a.stealthScore)
      .slice(0, 10)
      .map(summarizeKbEntry);

    return json({
      totalTechniques: total,
      coverageDistribution: coverage,
      coverageScore,
      noCoverageHighRisk: noCoverageEntries,
    });
  },
};

const detection_sysmon_events: ToolDef = {
  name: "detection_sysmon_events",
  description: "List required Sysmon event IDs for detecting LOL techniques. Maps binaries to the Sysmon events needed for detection.",
  schema: {
    binary: z.string().optional().describe("Specific binary to get Sysmon events for"),
    platform: z.string().optional().describe("Filter by platform"),
  },
  async execute(args: { binary?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    let entries: UnifiedLOLEntry[];

    if (args.binary) {
      entries = ctx.knowledgeBase.lookupBinary(args.binary, args.platform as Platform);
    } else {
      entries = args.platform
        ? ctx.knowledgeBase.allEntries.filter(e => e.platform === args.platform)
        : ctx.knowledgeBase.allEntries;
    }

    const eventUsage = new Map<number, { binaries: Set<string>; techniques: Set<string> }>();

    for (const e of entries) {
      for (const eventId of e.detection.sysmonEvents) {
        if (!eventUsage.has(eventId)) {
          eventUsage.set(eventId, { binaries: new Set(), techniques: new Set() });
        }
        const usage = eventUsage.get(eventId)!;
        usage.binaries.add(e.binary);
        for (const t of e.attckTechniques) usage.techniques.add(t);
      }
    }

    const sysmonRequirements = Array.from(eventUsage.entries())
      .sort((a, b) => b[1].binaries.size - a[1].binaries.size)
      .map(([eventId, usage]) => ({
        eventId,
        eventName: SYSMON_EVENTS[eventId]?.name || "Unknown",
        relevance: SYSMON_EVENTS[eventId]?.relevance || "Monitors LOL technique activity",
        binaryCount: usage.binaries.size,
        binaries: Array.from(usage.binaries).slice(0, 10),
        techniqueCount: usage.techniques.size,
      }));

    return json({
      totalEntriesAnalyzed: entries.length,
      uniqueSysmonEvents: sysmonRequirements.length,
      sysmonRequirements,
      recommendedMinimalConfig: sysmonRequirements
        .filter(s => s.binaryCount >= 3)
        .map(s => s.eventId),
    });
  },
};

const detection_priority_gaps: ToolDef = {
  name: "detection_priority_gaps",
  description: "Find highest-priority detection gaps: techniques with high stealth score and no detection coverage. These are the most dangerous blind spots.",
  schema: {
    platform: z.string().optional().describe("Filter by platform (windows, linux, macos)"),
    top_n: z.number().optional().describe("Number of top gaps to return (default 20)"),
  },
  async execute(args: { platform?: string; top_n?: number }, ctx: ToolContext): Promise<ToolResult> {
    const topN = args.top_n || 20;
    const noCoverage = ctx.knowledgeBase.searchByDetectionCoverage(false);
    let filtered = args.platform
      ? noCoverage.filter(e => e.platform === args.platform)
      : noCoverage;

    const prioritized = deduplicateByBinary(filtered)
      .map(e => {
        const riskScore = e.stealthScore * 20 + e.functions.length * 5 + e.attckTechniques.length * 3;
        return { entry: e, riskScore };
      })
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, topN);

    return json({
      totalGaps: filtered.length,
      topPriorityGaps: prioritized.map(p => ({
        binary: p.entry.binary,
        platform: p.entry.platform,
        stealthScore: p.entry.stealthScore,
        riskScore: p.riskScore,
        functions: p.entry.functions,
        attck: p.entry.attckTechniques,
        catalog: p.entry.catalogSource,
        recommendation: `Deploy Sigma/YARA rules for ${p.entry.binary} covering ${p.entry.functions.join(", ")}`,
      })),
    });
  },
};

const detection_recommend_rules: ToolDef = {
  name: "detection_recommend_rules",
  description: "Recommend specific Sigma/YARA rules to deploy based on environment binaries and current detection gaps.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID for targeted recommendations"),
    platform: z.string().optional().describe("Filter by platform"),
    max_recommendations: z.number().optional().describe("Maximum recommendations to return (default 15)"),
  },
  async execute(args: { session_id?: string; platform?: string; max_recommendations?: number }, ctx: ToolContext): Promise<ToolResult> {
    const maxRec = args.max_recommendations || 15;
    let entries: UnifiedLOLEntry[];

    if (args.session_id) {
      const session = ctx.sessions.get(args.session_id);
      if (!session) return text(`Session not found: ${args.session_id}`);
      entries = session.matchedEntries.map(m => m.entry);
    } else {
      entries = args.platform
        ? ctx.knowledgeBase.allEntries.filter(e => e.platform === args.platform)
        : ctx.knowledgeBase.allEntries;
    }

    // Find entries with existing rules to recommend
    const withRules = deduplicateByBinary(entries)
      .filter(e => e.detection.sigmaRules.length > 0 || e.detection.yaraRules.length > 0)
      .sort((a, b) => b.stealthScore - a.stealthScore)
      .slice(0, maxRec);

    // Find entries without rules that need them
    const needRules = deduplicateByBinary(entries)
      .filter(e => e.detection.sigmaRules.length === 0 && e.detection.yaraRules.length === 0)
      .sort((a, b) => b.stealthScore - a.stealthScore)
      .slice(0, maxRec);

    const recommendations = withRules.map(e => ({
      binary: e.binary,
      platform: e.platform,
      priority: e.stealthScore >= 4 ? "critical" : e.stealthScore >= 3 ? "high" : "medium",
      existingSigmaRules: e.detection.sigmaRules,
      existingYaraRules: e.detection.yaraRules,
      sysmonEvents: e.detection.sysmonEvents,
      logSources: e.detection.logSources,
      action: "deploy_existing",
    }));

    const newRuleNeeded = needRules.map(e => ({
      binary: e.binary,
      platform: e.platform,
      priority: e.stealthScore >= 4 ? "critical" : e.stealthScore >= 3 ? "high" : "medium",
      functions: e.functions,
      attck: e.attckTechniques,
      suggestedSysmonEvents: e.detection.sysmonEvents.length > 0
        ? e.detection.sysmonEvents
        : [1, 3, 11],
      action: "create_new_rule",
    }));

    return json({
      deployExistingRules: recommendations,
      createNewRules: newRuleNeeded,
      summary: {
        totalRecommendations: recommendations.length + newRuleNeeded.length,
        deployExisting: recommendations.length,
        createNew: newRuleNeeded.length,
      },
    });
  },
};

const detection_blind_spots: ToolDef = {
  name: "detection_blind_spots",
  description: "Find techniques with zero detection coverage that are available in the environment. Critical blind spots an attacker could exploit undetected.",
  schema: {
    session_id: z.string().describe("Environment session ID to find blind spots for"),
  },
  async execute(args: { session_id: string }, ctx: ToolContext): Promise<ToolResult> {
    const session = ctx.sessions.get(args.session_id);
    if (!session) return text(`Session not found: ${args.session_id}`);

    const blindSpots = session.matchedEntries
      .filter(m => {
        const det = m.entry.detection;
        return det.edrCoverage === "none" &&
          det.sigmaRules.length === 0 &&
          det.yaraRules.length === 0 &&
          det.elasticRules.length === 0 &&
          det.splunkRules.length === 0;
      })
      .sort((a, b) => b.effectiveStealthScore - a.effectiveStealthScore);

    return json({
      sessionId: args.session_id,
      totalMatchedTechniques: session.matchedEntries.length,
      totalBlindSpots: blindSpots.length,
      blindSpotPercent: session.matchedEntries.length > 0
        ? Math.round((blindSpots.length / session.matchedEntries.length) * 100)
        : 0,
      blindSpots: blindSpots.slice(0, 25).map(m => ({
        binary: m.entry.binary,
        platform: m.entry.platform,
        stealthScore: m.effectiveStealthScore,
        functions: m.entry.functions,
        attck: m.entry.attckTechniques,
        matchReason: m.matchReason,
        risk: m.effectiveStealthScore >= 4 ? "critical" : m.effectiveStealthScore >= 3 ? "high" : "medium",
      })),
    });
  },
};

export const detectionTools: ToolDef[] = [
  detection_sigma_coverage,
  detection_edr_coverage,
  detection_sysmon_events,
  detection_priority_gaps,
  detection_recommend_rules,
  detection_blind_spots,
];
