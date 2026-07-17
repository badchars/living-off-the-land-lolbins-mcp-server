import { z } from "zod";
import crypto from "node:crypto";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json } from "../types/index.js";
import type { EnvironmentModel } from "../schema/environment.js";
import { parseEnumeration } from "../environment/parser.js";
import { buildAttackGraph } from "../graph/builder.js";
import { allPaths } from "../graph/pathfinder.js";
import { rankPaths } from "../graph/scorer.js";

export const enumerateHostComposite: ToolDef = {
  name: "enumerate_host",
  description:
    "Parse host enumeration data (linpeas, winpeas, manual output), match against LOL knowledge base, and create an environment session for follow-up analysis. Returns matched binaries, attack surface summary, and top quick-win escalation paths.",
  schema: {
    platform: z
      .enum(["linux", "windows", "macos", "esxi", "auto"])
      .describe("Target platform, or 'auto' to detect from enumeration data"),
    enumeration_data: z
      .union([z.string(), z.record(z.unknown())])
      .describe(
        "Raw enumeration output (linpeas, winpeas, manual commands) as text or structured object",
      ),
    session_name: z
      .string()
      .optional()
      .describe(
        "Optional human-readable session name for later reference",
      ),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { platform, enumeration_data, session_name } = args;

    // 1. Parse enumeration data into EnvironmentState
    const envState = parseEnumeration(
      enumeration_data,
      platform === "auto" ? undefined : platform,
    );

    // 2. Match environment state against knowledge base
    const matchedEntries = ctx.knowledgeBase.matchEnvironment(envState);

    // 3. Create EnvironmentModel with unique ID
    const environmentId = crypto.randomUUID();
    const model: EnvironmentModel = {
      id: environmentId,
      state: envState,
      matchedEntries,
      createdAt: Date.now(),
    };

    // 4. Store in sessions
    const sessionKey = session_name ?? environmentId;
    ctx.sessions.set(sessionKey, model);
    // Also store by ID for lookup by environment_id
    if (session_name) {
      ctx.sessions.set(environmentId, model);
    }

    // 5. Build attack graph and find quick wins (top 5 escalation paths)
    const graph = buildAttackGraph(model);
    const targets =
      envState.platform === "windows"
        ? ["system", "administrator"]
        : ["root"];

    let quickWinPaths: any[] = [];
    for (const target of targets) {
      const paths = allPaths(graph, "current-user", target, 3);
      const ranked = rankPaths(paths, undefined, envState);
      quickWinPaths.push(...ranked);
    }
    // Re-rank combined and take top 5
    quickWinPaths = rankPaths(quickWinPaths, undefined, envState).slice(0, 5);

    // 6. Build attack surface summary
    const functionCounts: Record<string, number> = {};
    for (const m of matchedEntries) {
      for (const fn of m.entry.functions) {
        functionCounts[fn] = (functionCounts[fn] || 0) + 1;
      }
    }

    const attackSurface = {
      total_matched_binaries: matchedEntries.length,
      by_function: functionCounts,
      suid_binaries: envState.suidBinaries.length,
      sudo_entries: envState.sudoEntries.length,
      capabilities: envState.capabilities.length,
      cron_jobs: envState.cronJobs.length,
      writable_paths: envState.writablePaths.length,
      token_privileges: envState.tokenPrivileges.length,
      loaded_drivers: envState.loadedDrivers.length,
      docker_socket: envState.dockerSocket,
      edr_detected: envState.edrDetected,
      network_access: envState.networkAccess,
    };

    return json({
      environment_id: environmentId,
      session_name: sessionKey,
      platform: envState.platform,
      current_user: envState.currentUser,
      privilege_level: envState.privilegeLevel,
      matched_entries_count: matchedEntries.length,
      attack_surface_summary: attackSurface,
      quick_wins: quickWinPaths.map((p) => ({
        rank: p.rank,
        name: p.name,
        steps: p.steps.map((s: any) => ({
          action: s.action,
          binary: s.binary,
          command: s.result,
          attck: s.attck,
        })),
        score: p.score,
        certainty: p.certainty,
        stealth: p.totalStealth,
        reasoning: p.chainReasoning,
      })),
      matched_entries_preview: matchedEntries.slice(0, 10).map((m) => ({
        binary: m.entry.binary,
        catalog: m.entry.catalogSource,
        functions: m.entry.functions,
        match_reason: m.matchReason,
        stealth: m.effectiveStealthScore,
      })),
    });
  },
};
