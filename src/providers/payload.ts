import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform } from "../schema/unified-entry.js";

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

function contextCommands(entry: any, context?: string): any[] {
  if (!entry.executionContexts || entry.executionContexts.length === 0) return [];
  if (context) {
    return entry.executionContexts.filter((c: any) => c.context === context);
  }
  return entry.executionContexts;
}

// ── payload_command ─────────────────────────────────────────────────────────

const payload_command: ToolDef = {
  name: "payload_command",
  description: "Look up LOL binary command execution payloads from the knowledge base — returns applicable execution contexts and command templates for a given technique",
  schema: {
    technique_id: z.string().describe("Knowledge base technique ID to look up"),
    context: z.enum(["sudo", "suid", "capabilities", "unprivileged", "user", "admin", "system", "kernel"]).optional().describe("Filter by execution context type"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const entry = ctx.knowledgeBase.getById(args.technique_id);

    if (!entry) {
      return json({
        error: "technique_not_found",
        technique_id: args.technique_id,
        message: `No knowledge base entry found for technique ID '${args.technique_id}'. Use the search tools to find valid technique IDs.`,
      });
    }

    const contexts = contextCommands(entry, args.context);
    const commandFunctions = entry.functions.filter(f =>
      f === "command" || f === "command_execution" || f === "shell",
    );

    return json({
      technique_id: entry.id,
      binary: entry.binary,
      platform: entry.platform,
      payload_type: "command_execution",
      commands: contexts.map((c: any) => ({
        context: c.context,
        prerequisite: c.prerequisite,
        command: c.command,
        result: c.result,
        one_liner: c.oneLiner,
      })),
      variants: commandFunctions,
      attck_techniques: entry.attckTechniques,
      detection_surface: {
        sigma_rules: entry.detection.sigmaRules,
        sysmon_events: entry.detection.sysmonEvents,
        edr_coverage: entry.detection.edrCoverage,
        log_sources: entry.detection.logSources,
      },
    });
  },
};

// ── payload_reverse_shell ───────────────────────────────────────────────────

const payload_reverse_shell: ToolDef = {
  name: "payload_reverse_shell",
  description: "Reverse shell payload information for a LOL binary — returns reverse shell command templates for the specified technique with attacker IP and port substituted",
  schema: {
    technique_id: z.string().describe("Knowledge base technique ID to look up"),
    attacker_ip: z.string().describe("Attacker IP address for the reverse shell callback"),
    attacker_port: z.number().describe("Attacker port number for the reverse shell listener"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const entry = ctx.knowledgeBase.getById(args.technique_id);

    if (!entry) {
      return json({
        error: "technique_not_found",
        technique_id: args.technique_id,
        message: `No knowledge base entry found for technique ID '${args.technique_id}'. Use the search tools to find valid technique IDs.`,
      });
    }

    const reverseShellContexts = entry.executionContexts.filter(
      (c: any) => c.command.includes("RHOST") || c.command.includes("LHOST") ||
        c.result?.toLowerCase().includes("reverse") ||
        entry.functions.includes("reverse_shell"),
    );

    const commands = reverseShellContexts.map((c: any) => ({
      context: c.context,
      prerequisite: c.prerequisite,
      command: c.command
        .replace(/RHOST|LHOST|<IP>|<ATTACKER_IP>/gi, args.attacker_ip)
        .replace(/RPORT|LPORT|<PORT>|<ATTACKER_PORT>/gi, String(args.attacker_port)),
      result: c.result,
      one_liner: c.oneLiner,
    }));

    const genericTemplates = [];
    if (entry.functions.includes("reverse_shell") && commands.length === 0) {
      genericTemplates.push({
        context: "generic",
        note: "Binary supports reverse_shell function but no specific template matched. Refer to GTFOBins/LOLBAS documentation for this binary.",
        binary: entry.binary,
        attacker_ip: args.attacker_ip,
        attacker_port: args.attacker_port,
      });
    }

    return json({
      technique_id: entry.id,
      binary: entry.binary,
      platform: entry.platform,
      payload_type: "reverse_shell",
      attacker_ip: args.attacker_ip,
      attacker_port: args.attacker_port,
      commands: commands.length > 0 ? commands : genericTemplates,
      variants: entry.functions.filter((f: string) => f === "reverse_shell" || f === "shell"),
      attck_techniques: entry.attckTechniques,
      detection_surface: {
        sigma_rules: entry.detection.sigmaRules,
        sysmon_events: entry.detection.sysmonEvents,
        edr_coverage: entry.detection.edrCoverage,
        log_sources: entry.detection.logSources,
      },
    });
  },
};

// ── payload_bind_shell ──────────────────────────────────────────────────────

const payload_bind_shell: ToolDef = {
  name: "payload_bind_shell",
  description: "Bind shell payload information for a LOL binary — returns bind shell command templates that open a listening port on the target host",
  schema: {
    technique_id: z.string().describe("Knowledge base technique ID to look up"),
    port: z.number().default(4444).describe("Port to bind the shell listener on (default 4444)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const entry = ctx.knowledgeBase.getById(args.technique_id);

    if (!entry) {
      return json({
        error: "technique_not_found",
        technique_id: args.technique_id,
        message: `No knowledge base entry found for technique ID '${args.technique_id}'. Use the search tools to find valid technique IDs.`,
      });
    }

    const bindShellContexts = entry.executionContexts.filter(
      (c: any) => c.command.includes("LPORT") || c.command.includes("listen") ||
        c.result?.toLowerCase().includes("bind") ||
        entry.functions.includes("bind_shell"),
    );

    const commands = bindShellContexts.map((c: any) => ({
      context: c.context,
      prerequisite: c.prerequisite,
      command: c.command
        .replace(/LPORT|<PORT>|<BIND_PORT>/gi, String(args.port)),
      result: c.result,
      one_liner: c.oneLiner,
    }));

    const genericTemplates = [];
    if (entry.functions.includes("bind_shell") && commands.length === 0) {
      genericTemplates.push({
        context: "generic",
        note: "Binary supports bind_shell function but no specific template matched. Refer to GTFOBins/LOLBAS documentation for this binary.",
        binary: entry.binary,
        port: args.port,
      });
    }

    return json({
      technique_id: entry.id,
      binary: entry.binary,
      platform: entry.platform,
      payload_type: "bind_shell",
      port: args.port,
      commands: commands.length > 0 ? commands : genericTemplates,
      variants: entry.functions.filter((f: string) => f === "bind_shell" || f === "shell"),
      attck_techniques: entry.attckTechniques,
      detection_surface: {
        sigma_rules: entry.detection.sigmaRules,
        sysmon_events: entry.detection.sysmonEvents,
        edr_coverage: entry.detection.edrCoverage,
        log_sources: entry.detection.logSources,
      },
    });
  },
};

// ── payload_file_read ───────────────────────────────────────────────────────

const payload_file_read: ToolDef = {
  name: "payload_file_read",
  description: "File read payload information for a LOL binary — returns commands to read arbitrary files using the specified LOL technique",
  schema: {
    technique_id: z.string().describe("Knowledge base technique ID to look up"),
    target_file: z.string().describe("Target file path to read (e.g., /etc/shadow, C:\\Windows\\SAM)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const entry = ctx.knowledgeBase.getById(args.technique_id);

    if (!entry) {
      return json({
        error: "technique_not_found",
        technique_id: args.technique_id,
        message: `No knowledge base entry found for technique ID '${args.technique_id}'. Use the search tools to find valid technique IDs.`,
      });
    }

    const fileReadContexts = entry.executionContexts.filter(
      (c: any) => c.command.includes("LFILE") || c.command.includes("TF=") ||
        c.result?.toLowerCase().includes("read") ||
        entry.functions.includes("file_read"),
    );

    const commands = fileReadContexts.map((c: any) => ({
      context: c.context,
      prerequisite: c.prerequisite,
      command: c.command
        .replace(/LFILE|<FILE>|<TARGET_FILE>/gi, args.target_file)
        .replace(/\$TF/g, args.target_file),
      result: c.result,
      one_liner: c.oneLiner,
    }));

    const genericTemplates = [];
    if (entry.functions.includes("file_read") && commands.length === 0) {
      genericTemplates.push({
        context: "generic",
        note: "Binary supports file_read function but no specific template matched. Refer to GTFOBins/LOLBAS documentation for this binary.",
        binary: entry.binary,
        target_file: args.target_file,
      });
    }

    return json({
      technique_id: entry.id,
      binary: entry.binary,
      platform: entry.platform,
      payload_type: "file_read",
      target_file: args.target_file,
      commands: commands.length > 0 ? commands : genericTemplates,
      variants: entry.functions.filter((f: string) => f === "file_read" || f === "download"),
      attck_techniques: entry.attckTechniques,
      detection_surface: {
        sigma_rules: entry.detection.sigmaRules,
        sysmon_events: entry.detection.sysmonEvents,
        edr_coverage: entry.detection.edrCoverage,
        log_sources: entry.detection.logSources,
      },
    });
  },
};

// ── payload_file_write ──────────────────────────────────────────────────────

const payload_file_write: ToolDef = {
  name: "payload_file_write",
  description: "File write payload information for a LOL binary — returns commands to write data to arbitrary files using the specified LOL technique",
  schema: {
    technique_id: z.string().describe("Knowledge base technique ID to look up"),
    target_file: z.string().describe("Target file path to write (e.g., /etc/crontab, C:\\Windows\\Tasks\\task.xml)"),
    content: z.string().optional().describe("Content to write to the target file (optional, placeholder used if omitted)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const entry = ctx.knowledgeBase.getById(args.technique_id);

    if (!entry) {
      return json({
        error: "technique_not_found",
        technique_id: args.technique_id,
        message: `No knowledge base entry found for technique ID '${args.technique_id}'. Use the search tools to find valid technique IDs.`,
      });
    }

    const contentPlaceholder = args.content || "<DATA>";

    const fileWriteContexts = entry.executionContexts.filter(
      (c: any) => c.command.includes("LFILE") || c.command.includes("TF=") ||
        c.result?.toLowerCase().includes("write") ||
        entry.functions.includes("file_write"),
    );

    const commands = fileWriteContexts.map((c: any) => ({
      context: c.context,
      prerequisite: c.prerequisite,
      command: c.command
        .replace(/LFILE|<FILE>|<TARGET_FILE>/gi, args.target_file)
        .replace(/\$TF/g, args.target_file)
        .replace(/<DATA>|<CONTENT>/gi, contentPlaceholder),
      result: c.result,
      one_liner: c.oneLiner,
    }));

    const genericTemplates = [];
    if (entry.functions.includes("file_write") && commands.length === 0) {
      genericTemplates.push({
        context: "generic",
        note: "Binary supports file_write function but no specific template matched. Refer to GTFOBins/LOLBAS documentation for this binary.",
        binary: entry.binary,
        target_file: args.target_file,
        content: contentPlaceholder,
      });
    }

    return json({
      technique_id: entry.id,
      binary: entry.binary,
      platform: entry.platform,
      payload_type: "file_write",
      target_file: args.target_file,
      content: contentPlaceholder,
      commands: commands.length > 0 ? commands : genericTemplates,
      variants: entry.functions.filter((f: string) => f === "file_write" || f === "upload"),
      attck_techniques: entry.attckTechniques,
      detection_surface: {
        sigma_rules: entry.detection.sigmaRules,
        sysmon_events: entry.detection.sysmonEvents,
        edr_coverage: entry.detection.edrCoverage,
        log_sources: entry.detection.logSources,
      },
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const payloadTools: ToolDef[] = [
  payload_command,
  payload_reverse_shell,
  payload_bind_shell,
  payload_file_read,
  payload_file_write,
];
