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

// ━━━ Tools ━━━

const purple_red_plan: ToolDef = {
  name: "purple_red_plan",
  description: "Generate a red team execution plan from environment findings. Produces ordered attack steps using LOL binaries with specific commands and expected outcomes.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID for targeted plan generation"),
    objectives: z.array(z.string()).optional().describe("Attack objectives to achieve (e.g., privilege_escalation, lateral_movement, exfiltration)"),
    max_steps: z.number().optional().describe("Maximum number of steps in the plan (default: 10)"),
  },
  async execute(args: { session_id?: string; objectives?: string[]; max_steps?: number }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const maxSteps = args.max_steps || 10;
    const objectives = args.objectives || ["reconnaissance", "privilege_escalation", "persistence", "lateral_movement", "exfiltration"];

    const deduplicated = deduplicateByBinary(entries);
    const steps: Array<Record<string, unknown>> = [];

    for (const objective of objectives) {
      if (steps.length >= maxSteps) break;

      const matching = deduplicated.filter(e =>
        e.functions.some(f => f === objective || f.includes(objective.replace("_", "")))
      );

      const sorted = matching.sort((a, b) => b.stealthScore - a.stealthScore);
      const best = sorted.slice(0, Math.ceil(maxSteps / objectives.length));

      for (const e of best) {
        if (steps.length >= maxSteps) break;

        const relevantCtx = e.executionContexts.find(c =>
          c.result.toLowerCase().includes(objective.replace("_", " ")) ||
          e.functions.includes(objective as any)
        ) || e.executionContexts[0];

        steps.push({
          step: steps.length + 1,
          objective,
          binary: e.binary,
          platform: e.platform,
          stealthScore: e.stealthScore,
          command: relevantCtx?.command || `Use ${e.binary} for ${objective}`,
          context: relevantCtx?.context || "user",
          prerequisite: relevantCtx?.prerequisite || "Access to target system",
          expectedResult: relevantCtx?.result || `Achieve ${objective} via ${e.binary}`,
          attckTechniques: e.attckTechniques,
          detectionRisk: e.detection.edrCoverage,
        });
      }
    }

    return json({
      planName: "Red Team LOL Execution Plan",
      generatedAt: new Date().toISOString(),
      objectives,
      totalSteps: steps.length,
      steps,
      opsecNotes: [
        "Prioritize binaries with stealth score >= 4",
        "Avoid binaries with high EDR coverage unless necessary",
        "Chain multiple low-stealth binaries rather than one high-risk tool",
        "Monitor defender telemetry during execution",
      ],
    });
  },
};

const purple_blue_detection: ToolDef = {
  name: "purple_blue_detection",
  description: "Generate a blue team detection plan for LOL techniques found in the environment. Maps each technique to specific detection rules and monitoring requirements.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID for targeted detection plan"),
    detection_tools: z.enum(["sysmon", "sigma", "edr", "all"]).optional().describe("Detection toolset to generate rules for (default: all)"),
  },
  async execute(args: { session_id?: string; detection_tools?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const toolset = args.detection_tools || "all";
    const deduplicated = deduplicateByBinary(entries)
      .sort((a, b) => b.stealthScore - a.stealthScore);

    const detectionPlan: Array<Record<string, unknown>> = [];

    for (const e of deduplicated.slice(0, 30)) {
      const plan: Record<string, unknown> = {
        binary: e.binary,
        platform: e.platform,
        stealthScore: e.stealthScore,
        functions: e.functions,
        attckTechniques: e.attckTechniques,
        priority: e.stealthScore >= 4 ? "critical" : e.stealthScore >= 3 ? "high" : "medium",
      };

      if (toolset === "all" || toolset === "sysmon") {
        plan.sysmon = {
          requiredEvents: e.detection.sysmonEvents,
          configRecommendation: e.detection.sysmonEvents.length > 0
            ? `Enable Sysmon Event IDs: ${e.detection.sysmonEvents.join(", ")}`
            : "Enable Event IDs 1, 3, 7, 11 for baseline monitoring",
        };
      }

      if (toolset === "all" || toolset === "sigma") {
        plan.sigma = {
          existingRules: e.detection.sigmaRules,
          hasRules: e.detection.sigmaRules.length > 0,
          recommendation: e.detection.sigmaRules.length > 0
            ? `Deploy ${e.detection.sigmaRules.length} existing Sigma rules`
            : `Create custom Sigma rule for ${e.binary} monitoring ${e.functions.join(", ")} activity`,
        };
      }

      if (toolset === "all" || toolset === "edr") {
        plan.edr = {
          currentCoverage: e.detection.edrCoverage,
          logSources: e.detection.logSources,
          recommendation: e.detection.edrCoverage === "none"
            ? `Critical: No EDR coverage for ${e.binary} — create custom detection rule`
            : `Current coverage: ${e.detection.edrCoverage} — consider enhancing with behavioral rules`,
        };
      }

      detectionPlan.push(plan);
    }

    const noCoverage = deduplicated.filter(e => e.detection.edrCoverage === "none");

    return json({
      planName: "Blue Team Detection Plan",
      generatedAt: new Date().toISOString(),
      toolset,
      summary: {
        totalTechniques: deduplicated.length,
        criticalPriority: detectionPlan.filter(p => p.priority === "critical").length,
        highPriority: detectionPlan.filter(p => p.priority === "high").length,
        noExistingCoverage: noCoverage.length,
      },
      detectionPlan,
    });
  },
};

const purple_validation_steps: ToolDef = {
  name: "purple_validation_steps",
  description: "Generate validation test cases to verify that detections are working correctly. Produces atomic-style test procedures for each technique.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID for targeted validation"),
    atomic_format: z.boolean().optional().describe("Output in Atomic Red Team format (default: false)"),
  },
  async execute(args: { session_id?: string; atomic_format?: boolean }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const atomicFormat = args.atomic_format || false;
    const deduplicated = deduplicateByBinary(entries)
      .sort((a, b) => b.stealthScore - a.stealthScore)
      .slice(0, 20);

    const validationTests: Array<Record<string, unknown>> = [];

    for (const e of deduplicated) {
      const relevantCtx = e.executionContexts[0];

      if (atomicFormat) {
        validationTests.push({
          attack_technique: e.attckTechniques[0] || "T0000",
          display_name: `Validate detection of ${e.binary} LOL technique`,
          atomic_tests: [{
            name: `${e.binary} - ${e.functions[0] || "execution"}`,
            description: `Test detection of ${e.binary} used for ${e.functions.join(", ")}`,
            supported_platforms: [e.platform],
            executor: {
              name: e.platform === "windows" ? "command_prompt" : "sh",
              command: relevantCtx?.command || `${e.binary} --help`,
              elevation_required: relevantCtx?.context === "admin" || relevantCtx?.context === "system",
            },
            input_arguments: {},
          }],
        });
      } else {
        validationTests.push({
          testId: `val_${e.binary}_${e.platform}`,
          binary: e.binary,
          platform: e.platform,
          technique: e.attckTechniques[0] || "unknown",
          functions: e.functions,
          procedure: {
            step1_prepare: `Ensure detection rules are active for ${e.binary}`,
            step2_execute: relevantCtx?.command || `Execute ${e.binary} with suspicious arguments`,
            step3_validate: `Check SIEM/EDR for alerts on ${e.binary} execution`,
            step4_verify: `Confirm alert includes: process name, command line, parent process`,
          },
          expectedDetections: {
            sysmonEvents: e.detection.sysmonEvents,
            sigmaRules: e.detection.sigmaRules,
            logSources: e.detection.logSources,
          },
          passFailCriteria: {
            pass: `Alert generated within 60 seconds with correct binary name and technique classification`,
            fail: `No alert generated or alert missing critical context (command line, parent process)`,
          },
        });
      }
    }

    return json({
      planName: "Detection Validation Test Suite",
      generatedAt: new Date().toISOString(),
      format: atomicFormat ? "atomic_red_team" : "standard",
      totalTests: validationTests.length,
      tests: validationTests,
    });
  },
};

const purple_combined_exercise: ToolDef = {
  name: "purple_combined_exercise",
  description: "Combine red team plan, blue team detections, and validation into a complete purple team exercise. Provides end-to-end attack-detect-validate workflow.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID for targeted exercise"),
    exercise_name: z.string().optional().describe("Name for the purple team exercise (default: LOL Purple Team Exercise)"),
  },
  async execute(args: { session_id?: string; exercise_name?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const exerciseName = args.exercise_name || "LOL Purple Team Exercise";
    const deduplicated = deduplicateByBinary(entries)
      .sort((a, b) => b.stealthScore - a.stealthScore)
      .slice(0, 15);

    const phases: Array<Record<string, unknown>> = [];

    for (const e of deduplicated) {
      const relevantCtx = e.executionContexts[0];

      phases.push({
        binary: e.binary,
        platform: e.platform,
        stealthScore: e.stealthScore,
        attckTechniques: e.attckTechniques,
        redTeam: {
          objective: `Execute ${e.functions[0] || "technique"} using ${e.binary}`,
          command: relevantCtx?.command || `${e.binary} [arguments]`,
          context: relevantCtx?.context || "user",
          prerequisite: relevantCtx?.prerequisite || "System access",
          expectedOutcome: relevantCtx?.result || `Successful ${e.functions[0] || "execution"}`,
        },
        blueTeam: {
          expectedAlert: `${e.binary} suspicious execution detected`,
          detectionSources: e.detection.logSources,
          sigmaRules: e.detection.sigmaRules,
          sysmonEvents: e.detection.sysmonEvents,
          edrCoverage: e.detection.edrCoverage,
        },
        validation: {
          alertGenerated: "Check SIEM for alert within 60 seconds",
          contextComplete: "Verify command line and parent process in alert",
          classification: `Verify technique mapped to ${e.attckTechniques.join(", ") || "appropriate ATT&CK technique"}`,
          responseTriggered: "Confirm automated response (if configured)",
        },
      });
    }

    const noCoverage = deduplicated.filter(e => e.detection.edrCoverage === "none");

    return json({
      exerciseName,
      generatedAt: new Date().toISOString(),
      scope: {
        totalTechniques: deduplicated.length,
        platforms: Array.from(new Set(deduplicated.map(e => e.platform))),
        attckTechniques: Array.from(new Set(deduplicated.flatMap(e => e.attckTechniques))),
      },
      preRequisites: [
        "SIEM/EDR systems operational and collecting logs",
        "Sysmon deployed with appropriate configuration",
        "Sigma rules deployed to detection pipeline",
        "Test system isolated from production",
        "Incident response team notified of exercise",
      ],
      phases,
      expectedOutcomes: {
        detectionRate: `Target: >${Math.round(((deduplicated.length - noCoverage.length) / deduplicated.length) * 100)}% technique detection`,
        meanTimeToDetect: "Target: < 60 seconds for high-priority techniques",
        falsePositiveRate: "Target: < 5% false positive rate",
        gapsIdentified: `${noCoverage.length} known blind spots to address post-exercise`,
      },
      postExerciseActions: [
        "Document all detection gaps discovered",
        "Create/update detection rules for missed techniques",
        "Update incident response playbooks",
        "Schedule follow-up exercise in 30 days",
      ],
    });
  },
};

export const purpleTeamTools: ToolDef[] = [
  purple_red_plan,
  purple_blue_detection,
  purple_validation_steps,
  purple_combined_exercise,
];
