import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform } from "../schema/unified-entry.js";
import type { MatchedEntry, EnvironmentModel } from "../schema/environment.js";

function deduplicateByBinary(entries: any[]): any[] {
  const seen = new Set<string>();
  return entries.filter(e => {
    if (seen.has(e.id)) return false;
    seen.add(e.id);
    return true;
  });
}

function summarizeKbEntry(e: any): Record<string, unknown> {
  return {
    id: e.id, binary: e.binary, platform: e.platform, catalog: e.catalogSource,
    functions: e.functions, stealth_score: e.stealthScore, description: e.description,
    attck_techniques: e.attckTechniques,
  };
}

interface PlanPhase {
  phase: string;
  order: number;
  objective: string;
  entries: Record<string, unknown>[];
  attck_techniques: string[];
  estimated_stealth: number;
}

interface Plan {
  environment_id: string;
  platform: string;
  phases: PlanPhase[];
  total_entries: number;
  overall_stealth: number;
  attck_coverage: string[];
}

const objectiveToFunction: Record<string, string[]> = {
  escalate: ["privilege_escalation", "uac_bypass", "inherit"],
  persist: ["persistence", "lateral_movement"],
  exfil: ["file_read", "upload", "download", "copy"],
  discover: ["reconnaissance", "command_execution"],
  evade: ["defense_evasion", "conceal", "awl_bypass"],
  credential: ["credential_access", "dump"],
  execute: ["shell", "command", "command_execution"],
  lateral: ["lateral_movement", "c2"],
  c2: ["c2", "reverse_shell", "bind_shell"],
};

// ── plan_generate ───────────────────────────────────────────────────────────

const plan_generate: ToolDef = {
  name: "plan_generate",
  description: "Generate an attack plan from objectives using environment session data and matched LOL entries",
  schema: {
    environment_id: z.string().describe("Environment session ID"),
    objectives: z.array(z.string()).describe('Array of objectives, e.g., ["escalate", "persist", "exfil"]'),
    stealth_priority: z.boolean().default(false).describe("Prioritize stealth over speed"),
    max_complexity: z.number().default(10).describe("Maximum plan complexity (1-10)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, objectives, stealth_priority, max_complexity } = args;

    const model = ctx.sessions.get(environment_id);
    if (!model) return json({ error: "Session not found", environment_id });

    const phases: PlanPhase[] = [];
    const allAttck = new Set<string>();

    for (let i = 0; i < objectives.length; i++) {
      const objective = objectives[i];
      const targetFunctions = objectiveToFunction[objective] || [objective];

      let matched = model.matchedEntries.filter((me: MatchedEntry) =>
        me.entry.functions.some(f => targetFunctions.includes(f)),
      );

      if (stealth_priority) {
        matched = matched.sort((a: MatchedEntry, b: MatchedEntry) =>
          a.effectiveStealthScore - b.effectiveStealthScore,
        );
      }

      const limited = matched.slice(0, max_complexity);
      const phaseAttck: string[] = [];
      for (const me of limited) {
        for (const t of me.entry.attckTechniques) { allAttck.add(t); phaseAttck.push(t); }
      }

      phases.push({
        phase: objective,
        order: i + 1,
        objective: `Achieve ${objective} using available LOL binaries`,
        entries: limited.map((me: MatchedEntry) => ({
          binary: me.entry.binary,
          platform: me.entry.platform,
          functions: me.entry.functions,
          stealth_score: me.effectiveStealthScore,
          match_reason: me.matchReason,
          contexts: me.applicableContexts.map(c => ({
            context: c.context,
            command: c.command,
            prerequisite: c.prerequisite,
          })),
        })),
        attck_techniques: Array.from(new Set(phaseAttck)),
        estimated_stealth: limited.length > 0
          ? Math.round(limited.reduce((s: number, m: MatchedEntry) => s + m.effectiveStealthScore, 0) / limited.length)
          : 0,
      });
    }

    const overallStealth = phases.length > 0
      ? Math.round(phases.reduce((s, p) => s + p.estimated_stealth, 0) / phases.length)
      : 0;

    const plan: Plan = {
      environment_id,
      platform: model.state.platform,
      phases,
      total_entries: phases.reduce((s, p) => s + p.entries.length, 0),
      overall_stealth: overallStealth,
      attck_coverage: Array.from(allAttck),
    };

    return json(plan);
  },
};

// ── plan_score ──────────────────────────────────────────────────────────────

const plan_score: ToolDef = {
  name: "plan_score",
  description: "Score an existing plan for stealth and effectiveness — returns breakdown by phase",
  schema: {
    plan: z.object({
      phases: z.array(z.object({
        phase: z.string(),
        entries: z.array(z.any()),
        estimated_stealth: z.number().optional(),
      })),
    }).describe("Plan object with phases array"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { plan } = args;

    const phaseScores = plan.phases.map((phase: any, i: number) => {
      const entryCount = phase.entries?.length || 0;
      const avgStealth = phase.estimated_stealth || 3;

      const complexityPenalty = Math.min(2, Math.floor(entryCount / 3));
      const stealthScore = Math.max(1, Math.min(5, avgStealth - complexityPenalty));
      const effectivenessScore = Math.min(5, Math.ceil(entryCount / 2) + 1);
      const reliabilityScore = Math.max(1, 5 - Math.floor(entryCount / 4));

      return {
        phase: phase.phase,
        order: i + 1,
        entry_count: entryCount,
        stealth_score: stealthScore,
        effectiveness_score: effectivenessScore,
        reliability_score: reliabilityScore,
        overall_phase_score: Math.round((stealthScore + effectivenessScore + reliabilityScore) / 3 * 10) / 10,
      };
    });

    const overallStealth = phaseScores.length > 0
      ? Math.round(phaseScores.reduce((s: number, p: any) => s + p.stealth_score, 0) / phaseScores.length * 10) / 10
      : 0;
    const overallEffectiveness = phaseScores.length > 0
      ? Math.round(phaseScores.reduce((s: number, p: any) => s + p.effectiveness_score, 0) / phaseScores.length * 10) / 10
      : 0;

    return json({
      total_phases: plan.phases.length,
      phase_scores: phaseScores,
      overall_stealth: overallStealth,
      overall_effectiveness: overallEffectiveness,
      overall_score: Math.round((overallStealth + overallEffectiveness) / 2 * 10) / 10,
      recommendations: overallStealth < 3
        ? ["Plan has low stealth — consider reducing entry count per phase", "Use stealth_priority when generating"]
        : ["Stealth profile is acceptable"],
    });
  },
};

// ── plan_optimize ───────────────────────────────────────────────────────────

const plan_optimize: ToolDef = {
  name: "plan_optimize",
  description: "Optimize a plan for stealth, speed, or reliability — reorders and prunes phases",
  schema: {
    plan: z.object({
      phases: z.array(z.object({
        phase: z.string(),
        entries: z.array(z.any()),
        estimated_stealth: z.number().optional(),
        order: z.number().optional(),
        objective: z.string().optional(),
        attck_techniques: z.array(z.string()).optional(),
      })),
    }).describe("Plan object to optimize"),
    optimize_for: z.enum(["stealth", "speed", "reliability"]).describe("Optimization target"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { plan, optimize_for } = args;

    const optimizedPhases = plan.phases.map((phase: any, i: number) => {
      let entries = [...(phase.entries || [])];

      if (optimize_for === "stealth") {
        entries = entries
          .sort((a: any, b: any) => (a.stealth_score || 3) - (b.stealth_score || 3))
          .slice(0, Math.max(1, Math.ceil(entries.length * 0.6)));
      } else if (optimize_for === "speed") {
        entries = entries.slice(0, Math.max(1, Math.min(2, entries.length)));
      } else {
        entries = entries.filter((e: any) => (e.stealth_score || 3) <= 3);
        if (entries.length === 0) entries = [phase.entries[0]].filter(Boolean);
      }

      return {
        ...phase,
        entries,
        order: i + 1,
        optimization_notes: optimize_for === "stealth"
          ? "Pruned high-noise entries and sorted by stealth score"
          : optimize_for === "speed"
            ? "Reduced to minimum entries for fastest execution"
            : "Filtered to most reliable entries with proven LOL techniques",
      };
    });

    return json({
      optimized_for: optimize_for,
      original_entry_count: plan.phases.reduce((s: number, p: any) => s + (p.entries?.length || 0), 0),
      optimized_entry_count: optimizedPhases.reduce((s: number, p: any) => s + (p.entries?.length || 0), 0),
      phases: optimizedPhases,
      notes: `Plan optimized for ${optimize_for}. Review entries before execution.`,
    });
  },
};

// ── plan_export ─────────────────────────────────────────────────────────────

const plan_export: ToolDef = {
  name: "plan_export",
  description: "Export plan to JSON, Markdown, or CSV format for documentation and reporting",
  schema: {
    plan: z.object({
      phases: z.array(z.any()),
      environment_id: z.string().optional(),
      platform: z.string().optional(),
      overall_stealth: z.number().optional(),
    }).describe("Plan object to export"),
    format: z.enum(["json", "markdown", "csv"]).describe("Export format"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { plan, format } = args;

    if (format === "json") {
      return json({ format: "json", exported: plan });
    }

    if (format === "markdown") {
      const lines: string[] = [
        `# Attack Plan — ${plan.environment_id || "Unknown"}`,
        "",
        `**Platform:** ${plan.platform || "N/A"}`,
        `**Stealth Score:** ${plan.overall_stealth || "N/A"}`,
        `**Total Phases:** ${plan.phases?.length || 0}`,
        "",
      ];

      for (const phase of (plan.phases || [])) {
        lines.push(`## Phase ${phase.order || "?"}: ${phase.phase || phase.objective || "Unknown"}`);
        lines.push("");
        if (phase.entries) {
          lines.push("| Binary | Stealth | Functions |");
          lines.push("|--------|---------|-----------|");
          for (const entry of phase.entries) {
            const funcs = Array.isArray(entry.functions) ? entry.functions.join(", ") : "N/A";
            lines.push(`| ${entry.binary || "?"} | ${entry.stealth_score ?? "?"} | ${funcs} |`);
          }
        }
        if (phase.attck_techniques?.length) {
          lines.push("");
          lines.push(`**ATT&CK:** ${phase.attck_techniques.join(", ")}`);
        }
        lines.push("");
      }

      return json({ format: "markdown", content: lines.join("\n") });
    }

    if (format === "csv") {
      const rows: string[] = ["phase,order,binary,stealth_score,functions,attck_techniques"];

      for (const phase of (plan.phases || [])) {
        for (const entry of (phase.entries || [])) {
          const funcs = Array.isArray(entry.functions) ? entry.functions.join(";") : "";
          const attck = Array.isArray(phase.attck_techniques) ? phase.attck_techniques.join(";") : "";
          rows.push(`"${phase.phase || ""}",${phase.order || 0},"${entry.binary || ""}",${entry.stealth_score ?? ""},${funcs},"${attck}"`);
        }
      }

      return json({ format: "csv", content: rows.join("\n") });
    }

    return json({ error: "Unsupported format", format });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const planTools: ToolDef[] = [
  plan_generate,
  plan_score,
  plan_optimize,
  plan_export,
];
