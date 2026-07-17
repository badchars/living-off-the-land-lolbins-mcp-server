import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import { parseEnumeration } from "../environment/parser.js";
import type { EnvironmentModel, MatchedEntry } from "../schema/environment.js";
import type { Platform } from "../schema/unified-entry.js";

function generateId(): string {
  return `env-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function buildResult(
  model: EnvironmentModel,
  matchedEntries: MatchedEntry[],
): Record<string, unknown> {
  // Identify quick wins: entries with high certainty escalation contexts
  const quickWins = matchedEntries
    .filter((m) =>
      m.applicableContexts.some(
        (c) =>
          c.context === "sudo" ||
          c.context === "suid" ||
          c.context === "capabilities",
      ),
    )
    .slice(0, 5)
    .map((m) => ({
      binary: m.entry.binary,
      reason: m.matchReason,
      functions: m.entry.functions,
      stealthScore: m.effectiveStealthScore,
      contexts: m.applicableContexts.map((c) => c.context),
    }));

  return {
    environment_id: model.id,
    platform: model.state.platform,
    current_user: model.state.currentUser,
    privilege_level: model.state.privilegeLevel,
    matched_counts: {
      total: matchedEntries.length,
      escalation: matchedEntries.filter((m) =>
        m.entry.functions.some(
          (f) =>
            f === "shell" ||
            f === "privilege_escalation" ||
            f === "command_execution",
        ),
      ).length,
      file_ops: matchedEntries.filter((m) =>
        m.entry.functions.some((f) => f === "file_read" || f === "file_write"),
      ).length,
      network: matchedEntries.filter((m) =>
        m.entry.functions.some(
          (f) =>
            f === "download" ||
            f === "upload" ||
            f === "reverse_shell" ||
            f === "c2",
        ),
      ).length,
      persistence: matchedEntries.filter((m) =>
        m.entry.functions.includes("persistence"),
      ).length,
    },
    quick_wins: quickWins,
    summary: {
      suid_binaries: model.state.suidBinaries.length,
      sudo_entries: model.state.sudoEntries.length,
      capabilities: model.state.capabilities.length,
      cron_jobs: model.state.cronJobs.length,
      writable_paths: model.state.writablePaths.length,
      token_privileges: model.state.tokenPrivileges.length,
      scheduled_tasks: model.state.scheduledTasks.length,
      loaded_drivers: model.state.loadedDrivers.length,
      docker_socket: model.state.dockerSocket,
      edr_detected: model.state.edrDetected,
    },
  };
}

function createAndStoreModel(
  rawText: string,
  platform: Platform,
  ctx: ToolContext,
): { model: EnvironmentModel; matched: MatchedEntry[] } {
  const state = parseEnumeration(rawText, platform);
  const matched = ctx.knowledgeBase.matchEnvironment(state);

  const model: EnvironmentModel = {
    id: generateId(),
    state,
    matchedEntries: matched,
    createdAt: Date.now(),
  };

  ctx.sessions.set(model.id, model);
  return { model, matched };
}

const parse_linux_enum: ToolDef = {
  name: "parse_linux_enum",
  description:
    "Parse Linux enumeration output (sudo -l, SUID, capabilities, cron) and identify applicable LOL techniques",
  schema: {
    raw_text: z
      .string()
      .describe(
        "Raw enumeration output text (sudo -l, find SUID, getcap, crontab, etc.)",
      ),
  },
  async execute(
    args: { raw_text: string },
    ctx: ToolContext,
  ): Promise<ToolResult> {
    const { model, matched } = createAndStoreModel(
      args.raw_text,
      "linux",
      ctx,
    );
    return json(buildResult(model, matched));
  },
};

const parse_windows_enum: ToolDef = {
  name: "parse_windows_enum",
  description:
    "Parse Windows enumeration output (whoami /priv, driverquery, schtasks) and identify applicable LOL techniques",
  schema: {
    raw_text: z
      .string()
      .describe(
        "Raw enumeration output text (whoami /priv, driverquery, schtasks /query, etc.)",
      ),
  },
  async execute(
    args: { raw_text: string },
    ctx: ToolContext,
  ): Promise<ToolResult> {
    const { model, matched } = createAndStoreModel(
      args.raw_text,
      "windows",
      ctx,
    );
    return json(buildResult(model, matched));
  },
};

const parse_macos_enum: ToolDef = {
  name: "parse_macos_enum",
  description:
    "Parse macOS enumeration output (launchctl, TCC database, SIP status) and identify applicable LOL techniques",
  schema: {
    raw_text: z
      .string()
      .describe(
        "Raw enumeration output text (launchctl list, csrutil status, TCC.db query, etc.)",
      ),
  },
  async execute(
    args: { raw_text: string },
    ctx: ToolContext,
  ): Promise<ToolResult> {
    const { model, matched } = createAndStoreModel(
      args.raw_text,
      "macos",
      ctx,
    );
    return json(buildResult(model, matched));
  },
};

const parse_esxi_enum: ToolDef = {
  name: "parse_esxi_enum",
  description:
    "Parse ESXi enumeration output and identify applicable LOL techniques (placeholder — limited support)",
  schema: {
    raw_text: z
      .string()
      .describe("Raw ESXi enumeration output text (esxcli, vim-cmd, etc.)"),
  },
  async execute(
    args: { raw_text: string },
    ctx: ToolContext,
  ): Promise<ToolResult> {
    // ESXi parsing is placeholder: store as-is with esxi platform
    const state = parseEnumeration(args.raw_text, "esxi");
    const matched = ctx.knowledgeBase.matchEnvironment(state);

    const model: EnvironmentModel = {
      id: generateId(),
      state,
      matchedEntries: matched,
      createdAt: Date.now(),
    };

    ctx.sessions.set(model.id, model);

    return json({
      environment_id: model.id,
      platform: "esxi",
      current_user: model.state.currentUser,
      privilege_level: model.state.privilegeLevel,
      matched_counts: { total: matched.length },
      quick_wins: [],
      note: "ESXi enumeration parsing is in early development. Results may be incomplete.",
    });
  },
};

const parse_generic_enum: ToolDef = {
  name: "parse_generic_enum",
  description:
    "Auto-detect platform from raw enumeration output and parse accordingly",
  schema: {
    raw_text: z
      .string()
      .describe("Raw enumeration output text from any platform"),
    platform_hint: z
      .enum(["linux", "windows", "macos", "esxi", "auto"])
      .optional()
      .describe(
        "Optional platform hint; if omitted or 'auto', platform is auto-detected from content",
      ),
  },
  async execute(
    args: { raw_text: string; platform_hint?: string },
    ctx: ToolContext,
  ): Promise<ToolResult> {
    const platform =
      args.platform_hint && args.platform_hint !== "auto"
        ? (args.platform_hint as Platform)
        : undefined;

    const state = parseEnumeration(args.raw_text, platform ?? "auto");
    const matched = ctx.knowledgeBase.matchEnvironment(state);

    const model: EnvironmentModel = {
      id: generateId(),
      state,
      matchedEntries: matched,
      createdAt: Date.now(),
    };

    ctx.sessions.set(model.id, model);

    return json({
      ...buildResult(model, matched),
      detected_platform: state.platform,
    });
  },
};

export const enumerateTools: ToolDef[] = [
  parse_linux_enum,
  parse_windows_enum,
  parse_macos_enum,
  parse_esxi_enum,
  parse_generic_enum,
];
