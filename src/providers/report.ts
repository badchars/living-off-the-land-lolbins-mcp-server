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

function getEntries(args: { session_id?: string }, ctx: ToolContext): UnifiedLOLEntry[] | null {
  if (args.session_id) {
    const session = ctx.sessions.get(args.session_id);
    if (!session) return null;
    return session.matchedEntries.map(m => m.entry);
  }
  return ctx.knowledgeBase.allEntries;
}

function computeRiskScore(entries: UnifiedLOLEntry[]): number {
  if (entries.length === 0) return 0;
  const avgStealth = entries.reduce((sum, e) => sum + e.stealthScore, 0) / entries.length;
  const noCoverage = entries.filter(e => e.detection.edrCoverage === "none").length;
  const noCoverageRatio = noCoverage / entries.length;
  return Math.min(100, Math.round(avgStealth * 15 + noCoverageRatio * 40));
}

// ━━━ Tools ━━━

const export_json: ToolDef = {
  name: "export_json",
  description: "Export environment findings as structured JSON. Returns all matched LOL techniques with detection info, stealth scores, and ATT&CK mappings in a machine-readable format.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID to export findings for"),
    include_sections: z.array(z.string()).optional().describe("Sections to include: binaries, detection, attck, stats (default: all)"),
  },
  async execute(args: { session_id?: string; include_sections?: string[] }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const sections = args.include_sections || ["binaries", "detection", "attck", "stats"];
    const deduplicated = deduplicateByBinary(entries);
    const result: Record<string, unknown> = { exportedAt: new Date().toISOString() };

    if (sections.includes("stats")) {
      result.stats = {
        totalEntries: entries.length,
        uniqueBinaries: deduplicated.length,
        platforms: Array.from(new Set(entries.map(e => e.platform))),
        avgStealthScore: entries.length > 0
          ? Math.round((entries.reduce((s, e) => s + e.stealthScore, 0) / entries.length) * 10) / 10
          : 0,
        riskScore: computeRiskScore(entries),
      };
    }

    if (sections.includes("binaries")) {
      result.binaries = deduplicated.map(e => ({
        id: e.id,
        binary: e.binary,
        platform: e.platform,
        catalog: e.catalogSource,
        category: e.category,
        functions: e.functions,
        stealthScore: e.stealthScore,
        attck: e.attckTechniques,
      }));
    }

    if (sections.includes("detection")) {
      const covered = entries.filter(e => e.detection.edrCoverage !== "none").length;
      result.detection = {
        totalWithCoverage: covered,
        totalWithoutCoverage: entries.length - covered,
        coveragePercent: entries.length > 0 ? Math.round((covered / entries.length) * 100) : 0,
        sigmaRuleCount: entries.reduce((s, e) => s + e.detection.sigmaRules.length, 0),
        yaraRuleCount: entries.reduce((s, e) => s + e.detection.yaraRules.length, 0),
      };
    }

    if (sections.includes("attck")) {
      const techniques = new Set<string>();
      for (const e of entries) {
        for (const t of e.attckTechniques) techniques.add(t);
      }
      result.attck = {
        uniqueTechniques: techniques.size,
        techniques: Array.from(techniques).sort(),
      };
    }

    return json(result);
  },
};

const export_markdown: ToolDef = {
  name: "export_markdown",
  description: "Export findings as a formatted markdown report. Includes risk summary, technique details, detection coverage, and recommendations.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID to export findings for"),
    classification: z.enum(["public", "internal", "confidential"]).optional().describe("Document classification level (default: internal)"),
  },
  async execute(args: { session_id?: string; classification?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const classification = args.classification || "internal";
    const deduplicated = deduplicateByBinary(entries);
    const riskScore = computeRiskScore(entries);
    const noCoverage = entries.filter(e => e.detection.edrCoverage === "none");

    const techniques = new Set<string>();
    for (const e of entries) {
      for (const t of e.attckTechniques) techniques.add(t);
    }

    const lines: string[] = [];
    lines.push(`# LOL Binary Assessment Report`);
    lines.push(`**Classification:** ${classification.toUpperCase()}`);
    lines.push(`**Generated:** ${new Date().toISOString()}`);
    lines.push(`**Risk Score:** ${riskScore}/100`);
    lines.push(``);
    lines.push(`## Executive Summary`);
    lines.push(`- **Total LOL Techniques Found:** ${entries.length}`);
    lines.push(`- **Unique Binaries:** ${deduplicated.length}`);
    lines.push(`- **ATT&CK Techniques Covered:** ${techniques.size}`);
    lines.push(`- **Detection Blind Spots:** ${noCoverage.length} (${entries.length > 0 ? Math.round((noCoverage.length / entries.length) * 100) : 0}%)`);
    lines.push(``);
    lines.push(`## Risk Assessment`);
    lines.push(`| Metric | Value |`);
    lines.push(`|--------|-------|`);
    lines.push(`| Overall Risk Score | ${riskScore}/100 |`);
    lines.push(`| High Stealth Binaries (4-5) | ${entries.filter(e => e.stealthScore >= 4).length} |`);
    lines.push(`| No EDR Coverage | ${noCoverage.length} |`);
    lines.push(``);
    lines.push(`## Top Risk Binaries`);
    const topRisk = deduplicated
      .sort((a, b) => b.stealthScore - a.stealthScore)
      .slice(0, 10);
    lines.push(`| Binary | Platform | Stealth | Functions | EDR Coverage |`);
    lines.push(`|--------|----------|---------|-----------|--------------|`);
    for (const e of topRisk) {
      lines.push(`| ${e.binary} | ${e.platform} | ${e.stealthScore}/5 | ${e.functions.join(", ")} | ${e.detection.edrCoverage} |`);
    }
    lines.push(``);
    lines.push(`## ATT&CK Techniques`);
    lines.push(Array.from(techniques).sort().map(t => `- ${t}`).join("\n"));
    lines.push(``);
    lines.push(`## Recommendations`);
    if (noCoverage.length > 0) {
      lines.push(`1. Deploy detection rules for ${noCoverage.length} uncovered techniques`);
    }
    if (topRisk.some(e => e.stealthScore >= 4)) {
      lines.push(`2. Prioritize monitoring high-stealth binaries: ${topRisk.filter(e => e.stealthScore >= 4).map(e => e.binary).join(", ")}`);
    }
    lines.push(`3. Review ATT&CK technique coverage against ${techniques.size} identified techniques`);

    return text(lines.join("\n"));
  },
};

const export_navigator_layer: ToolDef = {
  name: "export_navigator_layer",
  description: "Export an ATT&CK Navigator layer JSON that visualizes technique coverage. Can be imported directly into MITRE ATT&CK Navigator.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID to generate layer for"),
    layer_name: z.string().optional().describe("Name for the Navigator layer (default: LOL Assessment)"),
  },
  async execute(args: { session_id?: string; layer_name?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const layerName = args.layer_name || "LOL Assessment";
    const techniqueMap = new Map<string, { count: number; maxStealth: number; binaries: Set<string> }>();

    for (const e of entries) {
      for (const t of e.attckTechniques) {
        if (!techniqueMap.has(t)) {
          techniqueMap.set(t, { count: 0, maxStealth: 0, binaries: new Set() });
        }
        const entry = techniqueMap.get(t)!;
        entry.count++;
        entry.maxStealth = Math.max(entry.maxStealth, e.stealthScore);
        entry.binaries.add(e.binary);
      }
    }

    const techniques = Array.from(techniqueMap.entries()).map(([techId, data]) => {
      const score = Math.min(100, data.count * 10 + data.maxStealth * 10);
      return {
        techniqueID: techId,
        tactic: "",
        color: data.maxStealth >= 4 ? "#ff0000" : data.maxStealth >= 3 ? "#ff6600" : "#ffcc00",
        comment: `${data.count} LOL binaries: ${Array.from(data.binaries).slice(0, 5).join(", ")}`,
        enabled: true,
        metadata: [],
        links: [],
        showSubtechniques: true,
        score,
      };
    });

    const layer = {
      name: layerName,
      versions: { attack: "14", navigator: "4.9", layer: "4.5" },
      domain: "enterprise-attack",
      description: `LOL binary assessment - ${entries.length} entries mapped`,
      filters: { platforms: ["Windows", "Linux", "macOS"] },
      sorting: 3,
      layout: { layout: "side", aggregateFunction: "max", showID: true, showName: true },
      hideDisabled: false,
      techniques,
      gradient: { colors: ["#ffffff", "#ffcc00", "#ff6600", "#ff0000"], minValue: 0, maxValue: 100 },
      legendItems: [
        { label: "Low Risk (1-2)", color: "#ffcc00" },
        { label: "Medium Risk (3)", color: "#ff6600" },
        { label: "High Risk (4-5)", color: "#ff0000" },
      ],
      metadata: [],
      links: [],
      showTacticRowBackground: true,
      tacticRowBackground: "#205b8f",
      selectTechniquesAcrossTactics: true,
      selectSubtechniquesWithParent: false,
      selectVisibleTechniques: false,
    };

    return json(layer);
  },
};

const export_csv: ToolDef = {
  name: "export_csv",
  description: "Export findings as CSV format for spreadsheet analysis. Configurable columns for flexible reporting.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID to export findings for"),
    columns: z.array(z.string()).optional().describe("Columns to include (default: binary, platform, functions, stealthScore, edrCoverage, attck)"),
  },
  async execute(args: { session_id?: string; columns?: string[] }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const columns = args.columns || ["binary", "platform", "functions", "stealthScore", "edrCoverage", "attck"];
    const deduplicated = deduplicateByBinary(entries);

    const columnGetters: Record<string, (e: UnifiedLOLEntry) => string> = {
      binary: e => e.binary,
      platform: e => e.platform,
      catalog: e => e.catalogSource,
      category: e => e.category,
      functions: e => e.functions.join(";"),
      stealthScore: e => String(e.stealthScore),
      edrCoverage: e => e.detection.edrCoverage,
      attck: e => e.attckTechniques.join(";"),
      sigmaRules: e => e.detection.sigmaRules.join(";"),
      sysmonEvents: e => e.detection.sysmonEvents.join(";"),
      logSources: e => e.detection.logSources.join(";"),
      description: e => `"${e.description.replace(/"/g, '""')}"`,
    };

    const header = columns.join(",");
    const rows = deduplicated.map(e =>
      columns.map(col => {
        const getter = columnGetters[col];
        return getter ? getter(e) : "";
      }).join(",")
    );

    const csv = [header, ...rows].join("\n");
    return text(csv);
  },
};

const export_executive_summary: ToolDef = {
  name: "export_executive_summary",
  description: "Generate an executive summary with risk scores, key findings, and prioritized recommendations. Tailored to the target audience level.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID to summarize"),
    audience: z.enum(["technical", "executive", "board"]).optional().describe("Target audience for tone and detail level (default: executive)"),
  },
  async execute(args: { session_id?: string; audience?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const audience = args.audience || "executive";
    const deduplicated = deduplicateByBinary(entries);
    const riskScore = computeRiskScore(entries);
    const noCoverage = entries.filter(e => e.detection.edrCoverage === "none");
    const highStealth = entries.filter(e => e.stealthScore >= 4);

    const techniques = new Set<string>();
    for (const e of entries) {
      for (const t of e.attckTechniques) techniques.add(t);
    }

    const platforms = new Set<string>();
    for (const e of entries) platforms.add(e.platform);

    const functionCounts = new Map<string, number>();
    for (const e of entries) {
      for (const f of e.functions) {
        functionCounts.set(f, (functionCounts.get(f) || 0) + 1);
      }
    }
    const topFunctions = Array.from(functionCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([fn, count]) => ({ function: fn, count }));

    const riskLevel = riskScore >= 70 ? "CRITICAL" : riskScore >= 50 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW";

    const summary: Record<string, unknown> = {
      audience,
      generatedAt: new Date().toISOString(),
      riskAssessment: {
        overallScore: riskScore,
        riskLevel,
        confidence: entries.length >= 50 ? "high" : entries.length >= 20 ? "medium" : "low",
      },
      keyFindings: {
        totalLOLTechniques: entries.length,
        uniqueBinaries: deduplicated.length,
        platforms: Array.from(platforms),
        attckTechniques: techniques.size,
        detectionBlindSpots: noCoverage.length,
        highStealthTechniques: highStealth.length,
        topAttackFunctions: topFunctions,
      },
      prioritizedRecommendations: [] as string[],
    };

    const recommendations: string[] = [];
    if (noCoverage.length > 0) {
      recommendations.push(`Deploy detection coverage for ${noCoverage.length} unmonitored LOL techniques (${Math.round((noCoverage.length / entries.length) * 100)}% blind spot)`);
    }
    if (highStealth.length > 0) {
      recommendations.push(`Prioritize monitoring of ${highStealth.length} high-stealth binaries that can evade current defenses`);
    }
    if (techniques.size > 20) {
      recommendations.push(`Review ATT&CK coverage: ${techniques.size} techniques identified across ${Array.from(platforms).length} platforms`);
    }
    recommendations.push("Implement application whitelisting for non-essential LOL binaries");
    recommendations.push("Conduct purple team exercise to validate detection of top-risk techniques");
    summary.prioritizedRecommendations = recommendations;

    if (audience === "technical") {
      summary.technicalDetails = {
        topRiskBinaries: deduplicated
          .sort((a, b) => b.stealthScore - a.stealthScore)
          .slice(0, 10)
          .map(e => ({
            binary: e.binary,
            platform: e.platform,
            stealthScore: e.stealthScore,
            functions: e.functions,
            attck: e.attckTechniques,
            edrCoverage: e.detection.edrCoverage,
          })),
        missingDetections: noCoverage.length,
        recommendedSysmonEvents: Array.from(
          new Set(entries.flatMap(e => e.detection.sysmonEvents))
        ).sort((a, b) => a - b),
      };
    }

    return json(summary);
  },
};

export const reportTools: ToolDef[] = [
  export_json,
  export_markdown,
  export_navigator_layer,
  export_csv,
  export_executive_summary,
];
