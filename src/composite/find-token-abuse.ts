import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { MatchedEntry } from "../schema/environment.js";
import type { UnifiedLOLEntry, ExecutionContext } from "../schema/unified-entry.js";

/** Well-known Windows token privileges and their abuse techniques. */
const TOKEN_PRIVILEGE_MAP: Record<
  string,
  {
    description: string;
    abuse_technique: string;
    common_tools: string[];
    attck: string[];
  }
> = {
  SeImpersonatePrivilege: {
    description: "Impersonate a client after authentication",
    abuse_technique:
      "Potato attacks (JuicyPotato, PrintSpoofer, RoguePotato, GodPotato) to escalate from service account to SYSTEM",
    common_tools: [
      "JuicyPotato",
      "PrintSpoofer",
      "RoguePotato",
      "GodPotato",
      "SweetPotato",
    ],
    attck: ["T1134.001", "T1134.002"],
  },
  SeDebugPrivilege: {
    description: "Debug programs",
    abuse_technique:
      "Inject into or dump memory of privileged processes (lsass.exe for credentials, winlogon.exe for SYSTEM shell)",
    common_tools: ["procdump", "mimikatz", "Process Hacker"],
    attck: ["T1003.001", "T1055"],
  },
  SeBackupPrivilege: {
    description: "Back up files and directories",
    abuse_technique:
      "Read any file regardless of ACL (SAM/SYSTEM hives, NTDS.dit for credential extraction)",
    common_tools: ["robocopy", "wbadmin", "diskshadow"],
    attck: ["T1003.002", "T1003.003"],
  },
  SeRestorePrivilege: {
    description: "Restore files and directories",
    abuse_technique:
      "Write to any file regardless of ACL (replace service binaries, DLL hijacking)",
    common_tools: ["robocopy", "copy"],
    attck: ["T1574.001", "T1574.002"],
  },
  SeTakeOwnershipPrivilege: {
    description: "Take ownership of files or objects",
    abuse_technique:
      "Take ownership of protected files/registry keys, then modify ACLs for access",
    common_tools: ["takeown", "icacls"],
    attck: ["T1222.001"],
  },
  SeLoadDriverPrivilege: {
    description: "Load and unload device drivers",
    abuse_technique:
      "Load a vulnerable driver (BYOVD) to gain kernel-level code execution or disable EDR",
    common_tools: ["sc.exe", "LOLDrivers"],
    attck: ["T1543.003", "T1068"],
  },
  SeAssignPrimaryTokenPrivilege: {
    description: "Replace a process-level token",
    abuse_technique:
      "Create processes with different tokens, similar to SeImpersonate for potato attacks",
    common_tools: ["JuicyPotato", "CreateProcessAsUser"],
    attck: ["T1134.002"],
  },
  SeTcbPrivilege: {
    description: "Act as part of the operating system",
    abuse_technique:
      "Create tokens with arbitrary privileges, impersonate any user without credentials",
    common_tools: ["NtCreateToken"],
    attck: ["T1134"],
  },
};

function matchTokenPrivilege(priv: string): string | null {
  const normalized = priv.trim();
  // Direct match
  if (TOKEN_PRIVILEGE_MAP[normalized]) return normalized;
  // Case-insensitive match
  for (const key of Object.keys(TOKEN_PRIVILEGE_MAP)) {
    if (key.toLowerCase() === normalized.toLowerCase()) return key;
  }
  return null;
}

export const findTokenAbuseComposite: ToolDef = {
  name: "find_token_abuse",
  description:
    "Analyze Windows token privileges in an enumerated environment and map them to known abuse techniques, potato attacks, and LOL binaries for privilege escalation.",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by enumerate_host"),
    token_type: z
      .enum([
        "all",
        "se_impersonate",
        "se_debug",
        "se_backup",
        "se_restore",
        "duplicate",
        "privilege_map",
      ])
      .optional()
      .describe(
        "Filter by token type: specific privilege, 'duplicate' for token duplication techniques, 'privilege_map' for full mapping, or 'all' for everything",
      ),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, token_type } = args;

    // 1. Look up session
    const model = ctx.sessions.get(environment_id);
    if (!model) {
      return text(
        `Environment session "${environment_id}" not found. Run enumerate_host first.`,
      );
    }

    const state = model.state;

    if (state.platform !== "windows") {
      return json({
        environment_id,
        platform: state.platform,
        message:
          "Token privilege abuse analysis is only applicable to Windows environments",
        techniques: [],
      });
    }

    const tokenPrivileges = state.tokenPrivileges;

    if (tokenPrivileges.length === 0) {
      return json({
        environment_id,
        platform: "windows",
        token_privileges: [],
        message:
          "No token privileges found in environment. Run 'whoami /priv' and re-enumerate.",
        techniques: [],
      });
    }

    // 2. Filter by token_type
    const tokenTypeMap: Record<string, string> = {
      se_impersonate: "SeImpersonatePrivilege",
      se_debug: "SeDebugPrivilege",
      se_backup: "SeBackupPrivilege",
      se_restore: "SeRestorePrivilege",
    };

    let filteredPrivileges = tokenPrivileges;
    if (token_type && token_type !== "all" && token_type !== "privilege_map" && token_type !== "duplicate") {
      const targetPriv = tokenTypeMap[token_type];
      if (targetPriv) {
        filteredPrivileges = tokenPrivileges.filter(
          (p) => matchTokenPrivilege(p) === targetPriv,
        );
      }
    }

    // 3. Map privileges to techniques
    const techniques: any[] = [];

    for (const priv of filteredPrivileges) {
      const matchedKey = matchTokenPrivilege(priv);
      if (!matchedKey) continue;

      const info = TOKEN_PRIVILEGE_MAP[matchedKey];

      // Find matching LOL entries from the knowledge base
      const matchingEntries: any[] = [];
      for (const matched of model.matchedEntries) {
        const entry = matched.entry;
        // Check if entry is relevant to this token privilege
        const isRelevant =
          entry.functions.includes("privilege_escalation") ||
          entry.functions.includes("credential_access") ||
          entry.functions.includes("command_execution");

        if (isRelevant) {
          // Check if any context matches admin/system
          const relevantContexts = entry.executionContexts.filter(
            (c) => c.context === "admin" || c.context === "system",
          );
          if (relevantContexts.length > 0) {
            matchingEntries.push({
              binary: entry.binary,
              catalog: entry.catalogSource,
              functions: entry.functions,
              contexts: relevantContexts.map((c) => ({
                context: c.context,
                command: c.command,
                result: c.result,
              })),
              stealth: matched.effectiveStealthScore,
            });
          }
        }
      }

      techniques.push({
        privilege: matchedKey,
        enabled: true,
        description: info.description,
        abuse_technique: info.abuse_technique,
        common_tools: info.common_tools,
        attck_techniques: info.attck,
        matching_lol_entries: matchingEntries,
      });
    }

    // 4. Handle "duplicate" token_type: token duplication/manipulation techniques
    if (token_type === "duplicate" || token_type === "all") {
      const dupEntries = model.matchedEntries.filter(
        (m) =>
          m.entry.executionContexts.some(
            (c) =>
              c.command.toLowerCase().includes("token") ||
              c.command.toLowerCase().includes("impersonate") ||
              c.command.toLowerCase().includes("duplicate"),
          ),
      );

      if (dupEntries.length > 0) {
        techniques.push({
          privilege: "TokenDuplication",
          enabled: tokenPrivileges.some(
            (p) =>
              matchTokenPrivilege(p) === "SeImpersonatePrivilege" ||
              matchTokenPrivilege(p) === "SeAssignPrimaryTokenPrivilege",
          ),
          description: "Token duplication and manipulation techniques",
          abuse_technique:
            "Duplicate an existing privileged token and use it to spawn a new process",
          common_tools: ["DuplicateTokenEx", "CreateProcessWithTokenW"],
          attck_techniques: ["T1134.001"],
          matching_lol_entries: dupEntries.map((m) => ({
            binary: m.entry.binary,
            catalog: m.entry.catalogSource,
            functions: m.entry.functions,
            stealth: m.effectiveStealthScore,
          })),
        });
      }
    }

    // 5. Handle "privilege_map": full mapping of all privileges
    if (token_type === "privilege_map") {
      const fullMap: any[] = [];
      for (const [priv, info] of Object.entries(TOKEN_PRIVILEGE_MAP)) {
        const present = tokenPrivileges.some(
          (p) => matchTokenPrivilege(p) === priv,
        );
        fullMap.push({
          privilege: priv,
          present,
          description: info.description,
          abuse_technique: info.abuse_technique,
          risk: present ? "high" : "not_applicable",
        });
      }

      return json({
        environment_id,
        platform: "windows",
        current_user: state.currentUser,
        token_privileges: tokenPrivileges,
        privilege_map: fullMap,
        abusable_count: fullMap.filter((p: any) => p.present).length,
        total_known_abusable: Object.keys(TOKEN_PRIVILEGE_MAP).length,
      });
    }

    return json({
      environment_id,
      platform: "windows",
      current_user: state.currentUser,
      privilege_level: state.privilegeLevel,
      token_privileges: tokenPrivileges,
      abusable_privileges: techniques.length,
      techniques,
      recommendations:
        techniques.length > 0
          ? techniques.map((t) => ({
              privilege: t.privilege,
              recommended_action: t.abuse_technique,
              tools: t.common_tools,
            }))
          : [
              {
                message:
                  "No directly abusable token privileges found. Consider other escalation vectors.",
              },
            ],
    });
  },
};
