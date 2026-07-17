import type { UnifiedLOLEntry, LOLFunction, EntryCategory } from "../schema/unified-entry.js";
import { emptyDetection } from "../schema/unified-entry.js";

// ━━━ LOTP Tag → LOLFunction ━━━
const TAG_FUNC_MAP: Record<string, LOLFunction> = {
  "execution": "command_execution",
  "command-execution": "command_execution",
  "code-execution": "command_execution",
  "rce": "command_execution",
  "download": "download",
  "fetch": "download",
  "upload": "upload",
  "exfiltration": "upload",
  "persistence": "persistence",
  "credential-access": "credential_access",
  "credentials": "credential_access",
  "secrets": "credential_access",
  "reconnaissance": "reconnaissance",
  "discovery": "reconnaissance",
  "defense-evasion": "defense_evasion",
  "bypass": "defense_evasion",
  "lateral-movement": "lateral_movement",
  "privilege-escalation": "privilege_escalation",
  "file-read": "file_read",
  "file-write": "file_write",
  "shell": "shell",
  "reverse-shell": "reverse_shell",
};

function mapTags(tags: any[]): { functions: LOLFunction[]; attck: string[] } {
  if (!Array.isArray(tags)) return { functions: ["command_execution"], attck: [] };
  const funcs = new Set<LOLFunction>();
  const attck = new Set<string>();

  for (const tag of tags) {
    const tagLower = String(tag).toLowerCase();
    for (const [keyword, func] of Object.entries(TAG_FUNC_MAP)) {
      if (tagLower.includes(keyword)) {
        funcs.add(func);
      }
    }
    // Detect ATT&CK IDs in tags
    if (/^T\d{4}/.test(String(tag))) {
      attck.add(String(tag));
    }
  }
  if (funcs.size === 0) funcs.add("command_execution");
  return { functions: Array.from(funcs), attck: Array.from(attck) };
}

function determineCategory(entry: any): EntryCategory {
  const name = (entry.name || "").toLowerCase();
  if (name.endsWith(".sh") || name.endsWith(".py") || name.endsWith(".rb") || name.endsWith(".ps1")) {
    return "script";
  }
  return "binary";
}

export function parseLOTPEntries(data: any[]): UnifiedLOLEntry[] {
  const entries: UnifiedLOLEntry[] = [];

  for (const lotpEntry of data) {
    if (!lotpEntry) continue;
    const name = lotpEntry.name;
    if (!name) continue;

    const description = lotpEntry.description || "";
    const tags = lotpEntry.tags || [];
    const { functions, attck } = mapTags(tags);

    const commands = lotpEntry.commands || [];
    const configFiles = lotpEntry.config_files || [];
    const references = lotpEntry.references || [];

    const contexts: import("../schema/unified-entry.js").ExecutionContext[] = [];

    if (Array.isArray(commands)) {
      for (const cmd of commands) {
        if (!cmd) continue;
        const command = typeof cmd === "string" ? cmd : (cmd.command || cmd.Command || "");
        const desc = typeof cmd === "string" ? "" : (cmd.description || cmd.Description || "");
        if (!command) continue;
        contexts.push({
          context: "unprivileged",
          prerequisite: "CI/CD pipeline access",
          command,
          result: desc || "Pipeline command execution",
          oneLiner: !command.includes("\n"),
        });
      }
    }

    if (contexts.length === 0) {
      contexts.push({
        context: "unprivileged",
        prerequisite: "CI/CD pipeline access",
        command: name,
        result: description || "Pipeline tool execution",
        oneLiner: true,
      });
    }

    const detection = emptyDetection();
    if (configFiles.length > 0) {
      detection.logSources.push(...configFiles.map((f: any) => typeof f === "string" ? f : String(f)));
    }

    const entry: UnifiedLOLEntry = {
      id: `lotp-${name.toLowerCase().replace(/[^a-z0-9]+/g, "_")}`,
      binary: name,
      aliases: [],
      platform: "cicd",
      catalogSource: "lotp",
      category: determineCategory(lotpEntry),
      description,
      functions,
      executionContexts: contexts,
      attckTechniques: attck,
      detection,
      stealthScore: 2,
      stealthNotes: "CI/CD pipeline tool — rarely monitored for abuse",
      fullPaths: [],
      resources: Array.isArray(references)
        ? references.map((r: any) => typeof r === "string" ? r : (r.url || r.link || String(r))).filter(Boolean)
        : [],
      relatedEntries: [],
      chainPotential: [
        `${name} can be abused in CI/CD pipelines for code execution`,
      ],
    };

    entries.push(entry);
  }

  return entries;
}
