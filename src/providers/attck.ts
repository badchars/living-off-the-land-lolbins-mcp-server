import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ ATT&CK Tactic Mapping ━━━

const TACTIC_TECHNIQUES: Record<string, string[]> = {
  "initial-access": ["T1189", "T1190", "T1133", "T1200", "T1566"],
  "execution": ["T1059", "T1203", "T1204", "T1047", "T1053"],
  "persistence": ["T1098", "T1197", "T1136", "T1543", "T1546", "T1547", "T1053"],
  "privilege-escalation": ["T1548", "T1134", "T1068", "T1574", "T1055"],
  "defense-evasion": ["T1140", "T1036", "T1027", "T1218", "T1562", "T1070"],
  "credential-access": ["T1110", "T1003", "T1552", "T1558", "T1539"],
  "discovery": ["T1087", "T1082", "T1083", "T1057", "T1049", "T1016"],
  "lateral-movement": ["T1021", "T1091", "T1080", "T1570"],
  "collection": ["T1005", "T1039", "T1113", "T1115"],
  "exfiltration": ["T1041", "T1048", "T1567", "T1029"],
  "command-and-control": ["T1071", "T1095", "T1102", "T1105", "T1572"],
  "impact": ["T1485", "T1486", "T1489", "T1490"],
};

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

function getTacticForTechnique(techniqueId: string): string {
  const baseId = techniqueId.split(".")[0];
  for (const [tactic, techniques] of Object.entries(TACTIC_TECHNIQUES)) {
    if (techniques.includes(baseId)) return tactic;
  }
  return "unknown";
}

// ━━━ Tools ━━━

const attck_technique_lookup: ToolDef = {
  name: "attck_technique_lookup",
  description: "Look up which LOL binaries implement a specific ATT&CK technique. Returns all binaries across catalogs that map to the given technique ID.",
  schema: {
    technique_id: z.string().describe("ATT&CK technique ID (e.g. T1059, T1059.006, T1548.001)"),
    platform: z.string().optional().describe("Filter by platform"),
  },
  async execute(args: { technique_id: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    let entries = ctx.knowledgeBase.searchByAttck(args.technique_id);
    if (args.platform) {
      entries = entries.filter(e => e.platform === args.platform);
    }

    const unique = deduplicateByBinary(entries);
    const tactic = getTacticForTechnique(args.technique_id);

    return json({
      techniqueId: args.technique_id,
      tactic,
      totalBinaries: unique.length,
      binaries: unique.slice(0, 30).map(e => ({
        binary: e.binary,
        platform: e.platform,
        catalog: e.catalogSource,
        functions: e.functions,
        stealthScore: e.stealthScore,
        detection: {
          edrCoverage: e.detection.edrCoverage,
          sigmaRules: e.detection.sigmaRules.length,
        },
      })),
    });
  },
};

const attck_coverage_map: ToolDef = {
  name: "attck_coverage_map",
  description: "Map LOL technique coverage across the ATT&CK matrix. Shows which tactics and techniques have LOL binary implementations available.",
  schema: {
    environment_id: z.string().optional().describe("Environment session ID for contextual coverage"),
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

    const techniqueMap = new Map<string, { binaries: Set<string>; count: number }>();
    for (const e of entries) {
      for (const t of e.attckTechniques) {
        if (!techniqueMap.has(t)) techniqueMap.set(t, { binaries: new Set(), count: 0 });
        const stat = techniqueMap.get(t)!;
        stat.binaries.add(e.binary);
        stat.count++;
      }
    }

    const tacticCoverage: Record<string, { techniques: number; binaries: number }> = {};
    for (const [technique, stat] of techniqueMap.entries()) {
      const tactic = getTacticForTechnique(technique);
      if (!tacticCoverage[tactic]) tacticCoverage[tactic] = { techniques: 0, binaries: 0 };
      tacticCoverage[tactic].techniques++;
      tacticCoverage[tactic].binaries += stat.binaries.size;
    }

    return json({
      totalTechniques: techniqueMap.size,
      tacticCoverage,
      topTechniques: Array.from(techniqueMap.entries())
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 20)
        .map(([t, stat]) => ({
          technique: t,
          tactic: getTacticForTechnique(t),
          binaryCount: stat.binaries.size,
          binaries: Array.from(stat.binaries).slice(0, 5),
        })),
    });
  },
};

const attck_navigator_export: ToolDef = {
  name: "attck_navigator_export",
  description: "Export ATT&CK Navigator JSON layer showing LOL technique coverage. The layer can be imported directly into ATT&CK Navigator for visualization.",
  schema: {
    environment_id: z.string().optional().describe("Environment session ID"),
    platform: z.string().optional().describe("Platform filter"),
    layer_name: z.string().optional().describe("Navigator layer name"),
  },
  async execute(args: { environment_id?: string; platform?: string; layer_name?: string }, ctx: ToolContext): Promise<ToolResult> {
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

    const techniqueScores = new Map<string, number>();
    for (const e of entries) {
      for (const t of e.attckTechniques) {
        techniqueScores.set(t, (techniqueScores.get(t) || 0) + 1);
      }
    }

    const maxScore = Math.max(...Array.from(techniqueScores.values()), 1);
    const techniques = Array.from(techniqueScores.entries()).map(([id, count]) => ({
      techniqueID: id,
      score: Math.ceil((count / maxScore) * 100),
      color: count > 10 ? "#ff0000" : count > 5 ? "#ff6600" : count > 2 ? "#ffcc00" : "#66cc00",
      comment: `${count} LOL binaries implement this technique`,
      enabled: true,
    }));

    const navigatorLayer = {
      name: args.layer_name || "LOL Technique Coverage",
      versions: { attack: "14", navigator: "4.9.1", layer: "4.5" },
      domain: "enterprise-attack",
      description: `LOL binary technique coverage (${entries.length} entries analyzed)`,
      techniques,
      gradient: {
        colors: ["#66cc00", "#ffcc00", "#ff6600", "#ff0000"],
        minValue: 0,
        maxValue: 100,
      },
    };

    return json({
      navigatorLayer,
      stats: {
        totalTechniques: techniques.length,
        entriesAnalyzed: entries.length,
      },
    });
  },
};

const attck_heatmap: ToolDef = {
  name: "attck_heatmap",
  description: "Generate ATT&CK technique frequency heatmap showing which techniques are most commonly implemented by LOL binaries.",
  schema: {
    platform: z.string().optional().describe("Platform filter"),
    tactic_filter: z.string().optional().describe("Filter by tactic"),
    top_n: z.number().optional().describe("Top N techniques (default 30)"),
  },
  async execute(args: { platform?: string; tactic_filter?: string; top_n?: number }, ctx: ToolContext): Promise<ToolResult> {
    const topN = args.top_n || 30;
    let entries = args.platform
      ? ctx.knowledgeBase.allEntries.filter(e => e.platform === args.platform)
      : ctx.knowledgeBase.allEntries;

    const techniqueFreq = new Map<string, { count: number; binaries: Set<string>; catalogs: Set<string> }>();
    for (const e of entries) {
      for (const t of e.attckTechniques) {
        if (args.tactic_filter) {
          const tactic = getTacticForTechnique(t);
          if (tactic !== args.tactic_filter) continue;
        }
        if (!techniqueFreq.has(t)) techniqueFreq.set(t, { count: 0, binaries: new Set(), catalogs: new Set() });
        const stat = techniqueFreq.get(t)!;
        stat.count++;
        stat.binaries.add(e.binary);
        stat.catalogs.add(e.catalogSource);
      }
    }

    const heatmap = Array.from(techniqueFreq.entries())
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, topN)
      .map(([t, stat]) => ({
        technique: t,
        tactic: getTacticForTechnique(t),
        frequency: stat.count,
        uniqueBinaries: stat.binaries.size,
        catalogs: Array.from(stat.catalogs),
        heat: stat.count > 50 ? "extreme" : stat.count > 20 ? "high" : stat.count > 10 ? "medium" : "low",
      }));

    return json({ heatmap, totalTechniques: techniqueFreq.size });
  },
};

const attck_gap_analysis: ToolDef = {
  name: "attck_gap_analysis",
  description: "Identify gaps in ATT&CK tactic coverage — which tactics have few or no LOL technique implementations. Helps prioritize detection engineering.",
  schema: {
    platform: z.string().optional().describe("Platform filter"),
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

    const tacticStats: Record<string, { techniques: Set<string>; binaries: Set<string>; detected: number }> = {};
    for (const tactic of Object.keys(TACTIC_TECHNIQUES)) {
      tacticStats[tactic] = { techniques: new Set(), binaries: new Set(), detected: 0 };
    }

    for (const e of entries) {
      for (const t of e.attckTechniques) {
        const tactic = getTacticForTechnique(t);
        if (tacticStats[tactic]) {
          tacticStats[tactic].techniques.add(t);
          tacticStats[tactic].binaries.add(e.binary);
          if (e.detection.sigmaRules.length > 0 || e.detection.edrCoverage !== "none") {
            tacticStats[tactic].detected++;
          }
        }
      }
    }

    const gapAnalysis = Object.entries(tacticStats)
      .map(([tactic, stat]) => ({
        tactic,
        uniqueTechniques: stat.techniques.size,
        uniqueBinaries: stat.binaries.size,
        detectedCount: stat.detected,
        detectionGapPercent: stat.binaries.size > 0
          ? Math.round(100 - (stat.detected / stat.binaries.size) * 100)
          : 100,
      }))
      .sort((a, b) => b.detectionGapPercent - a.detectionGapPercent);

    return json({
      gapAnalysis,
      worstGaps: gapAnalysis.filter(g => g.detectionGapPercent > 70).map(g => g.tactic),
      bestCovered: gapAnalysis.filter(g => g.detectionGapPercent < 30).map(g => g.tactic),
    });
  },
};

export const attckTools: ToolDef[] = [
  attck_technique_lookup,
  attck_coverage_map,
  attck_navigator_export,
  attck_heatmap,
  attck_gap_analysis,
];
