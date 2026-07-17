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

function platformToCaldera(platform: string): string {
  switch (platform) {
    case "windows": return "windows";
    case "linux": return "linux";
    case "macos": return "darwin";
    default: return "unknown";
  }
}

function functionToTactic(fn: string): string {
  const mapping: Record<string, string> = {
    reconnaissance: "discovery",
    shell: "execution",
    command: "execution",
    command_execution: "execution",
    reverse_shell: "command-and-control",
    bind_shell: "command-and-control",
    c2: "command-and-control",
    file_read: "collection",
    file_write: "exfiltration",
    upload: "exfiltration",
    download: "command-and-control",
    library_load: "defense-evasion",
    privilege_escalation: "privilege-escalation",
    uac_bypass: "privilege-escalation",
    inherit: "privilege-escalation",
    persistence: "persistence",
    lateral_movement: "lateral-movement",
    defense_evasion: "defense-evasion",
    credential_access: "credential-access",
    encode_decode: "defense-evasion",
    compile: "defense-evasion",
    copy: "lateral-movement",
    ads: "defense-evasion",
    awl_bypass: "defense-evasion",
    dump: "credential-access",
    tamper: "defense-evasion",
    conceal: "defense-evasion",
    edr_disable: "defense-evasion",
  };
  return mapping[fn] || "execution";
}

function generateAbilityId(binary: string, fn: string): string {
  const hash = `${binary}-${fn}`.split("").reduce((acc, c) => {
    const h = ((acc << 5) - acc) + c.charCodeAt(0);
    return h & h;
  }, 0);
  return Math.abs(hash).toString(16).padStart(8, "0").slice(0, 8);
}

// ━━━ Tools ━━━

const caldera_adversary_profile: ToolDef = {
  name: "caldera_adversary_profile",
  description: "Generate a MITRE Caldera adversary profile JSON. Defines an adversary with LOL-based abilities that can be imported into Caldera for automated adversary emulation.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID to build adversary profile from"),
    actor_name: z.string().optional().describe("Name for the adversary profile (default: LOL Adversary)"),
    description: z.string().optional().describe("Description of the adversary profile"),
  },
  async execute(args: { session_id?: string; actor_name?: string; description?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const actorName = args.actor_name || "LOL Adversary";
    const description = args.description || "Adversary profile using Living-off-the-Land binaries for stealthy operations";
    const deduplicated = deduplicateByBinary(entries)
      .sort((a, b) => b.stealthScore - a.stealthScore)
      .slice(0, 30);

    const abilityIds: string[] = [];
    for (const e of deduplicated) {
      for (const fn of e.functions.slice(0, 2)) {
        abilityIds.push(generateAbilityId(e.binary, fn));
      }
    }

    const techniques = new Set<string>();
    for (const e of deduplicated) {
      for (const t of e.attckTechniques) techniques.add(t);
    }

    const adversaryProfile = {
      adversary_id: generateAbilityId(actorName, "adversary"),
      name: actorName,
      description,
      atomic_ordering: abilityIds,
      objective: "default",
      tags: ["lol", "living-off-the-land", "stealth"],
      has_repeatable_abilities: false,
      plugin: "",
      techniques: Array.from(techniques),
      metadata: {
        totalAbilities: abilityIds.length,
        platforms: Array.from(new Set(deduplicated.map(e => platformToCaldera(e.platform)))),
        avgStealthScore: deduplicated.length > 0
          ? Math.round((deduplicated.reduce((s, e) => s + e.stealthScore, 0) / deduplicated.length) * 10) / 10
          : 0,
        generatedAt: new Date().toISOString(),
      },
    };

    return json(adversaryProfile);
  },
};

const caldera_ability_set: ToolDef = {
  name: "caldera_ability_set",
  description: "Generate MITRE Caldera ability definitions from LOL techniques. Each ability includes the command, platform, tactic, and technique mapping for Caldera import.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID to generate abilities from"),
    platform: z.string().optional().describe("Filter abilities by platform (windows, linux, macos)"),
    tactic_filter: z.string().optional().describe("Filter by ATT&CK tactic (e.g., execution, persistence, privilege-escalation)"),
  },
  async execute(args: { session_id?: string; platform?: string; tactic_filter?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    let filtered = args.platform
      ? entries.filter(e => e.platform === args.platform)
      : entries;

    const deduplicated = deduplicateByBinary(filtered)
      .sort((a, b) => b.stealthScore - a.stealthScore);

    const abilities: Array<Record<string, unknown>> = [];

    for (const e of deduplicated) {
      for (const fn of e.functions) {
        const tactic = functionToTactic(fn);
        if (args.tactic_filter && tactic !== args.tactic_filter) continue;

        const relevantCtx = e.executionContexts.find(c =>
          c.result.toLowerCase().includes(fn.replace("_", " "))
        ) || e.executionContexts[0];

        const abilityId = generateAbilityId(e.binary, fn);
        const calderaPlatform = platformToCaldera(e.platform);

        abilities.push({
          ability_id: abilityId,
          name: `${e.binary} - ${fn}`,
          description: `Use ${e.binary} for ${fn.replace(/_/g, " ")} (stealth: ${e.stealthScore}/5)`,
          tactic,
          technique: {
            attack_id: e.attckTechniques[0] || "T0000",
            name: fn.replace(/_/g, " "),
          },
          platforms: {
            [calderaPlatform]: {
              psh: e.platform === "windows" ? {
                command: relevantCtx?.command || `${e.binary}`,
                cleanup: "",
                parsers: {},
              } : undefined,
              sh: e.platform !== "windows" ? {
                command: relevantCtx?.command || `./${e.binary}`,
                cleanup: "",
                parsers: {},
              } : undefined,
            },
          },
          privilege: relevantCtx?.context === "admin" || relevantCtx?.context === "system" ? "Elevated" : "",
          singleton: false,
          plugin: "",
          tags: ["lol", e.binary, e.platform],
          metadata: {
            stealthScore: e.stealthScore,
            edrCoverage: e.detection.edrCoverage,
            catalog: e.catalogSource,
          },
        });
      }
    }

    return json({
      totalAbilities: abilities.length,
      platforms: Array.from(new Set(abilities.map(a => {
        const platforms = a.platforms as Record<string, unknown>;
        return Object.keys(platforms)[0];
      }))),
      tactics: Array.from(new Set(abilities.map(a => a.tactic as string))).sort(),
      abilities,
    });
  },
};

const caldera_operation_plan: ToolDef = {
  name: "caldera_operation_plan",
  description: "Generate a MITRE Caldera operation plan JSON with sequentially ordered abilities. Defines the operation execution flow for automated adversary simulation.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID to build operation plan from"),
    operation_name: z.string().optional().describe("Name for the Caldera operation (default: LOL Operation)"),
    autonomous: z.boolean().optional().describe("Run operation autonomously without human approval (default: true)"),
  },
  async execute(args: { session_id?: string; operation_name?: string; autonomous?: boolean }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const operationName = args.operation_name || "LOL Operation";
    const autonomous = args.autonomous !== undefined ? args.autonomous : true;
    const deduplicated = deduplicateByBinary(entries)
      .sort((a, b) => b.stealthScore - a.stealthScore)
      .slice(0, 20);

    // Order by kill chain phase
    const phaseOrder = [
      "discovery",
      "execution",
      "privilege-escalation",
      "defense-evasion",
      "credential-access",
      "lateral-movement",
      "collection",
      "exfiltration",
      "command-and-control",
      "persistence",
    ];

    const orderedAbilities: Array<Record<string, unknown>> = [];

    for (const phase of phaseOrder) {
      for (const e of deduplicated) {
        const matchingFns = e.functions.filter(fn => functionToTactic(fn) === phase);
        if (matchingFns.length === 0) continue;

        const fn = matchingFns[0];
        const abilityId = generateAbilityId(e.binary, fn);

        // Avoid duplicates
        if (orderedAbilities.some(a => a.ability_id === abilityId)) continue;

        const relevantCtx = e.executionContexts[0];

        orderedAbilities.push({
          ability_id: abilityId,
          name: `${e.binary} - ${fn}`,
          tactic: phase,
          technique: e.attckTechniques[0] || "T0000",
          platform: platformToCaldera(e.platform),
          command: relevantCtx?.command || `${e.binary}`,
          stealthScore: e.stealthScore,
        });
      }
    }

    const adversaryId = generateAbilityId(operationName, "adversary");

    const operationPlan = {
      operation: {
        name: operationName,
        adversary: {
          adversary_id: adversaryId,
          name: `${operationName} Adversary`,
          atomic_ordering: orderedAbilities.map(a => a.ability_id),
        },
        planner: {
          id: "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a",
          name: autonomous ? "atomic" : "batch",
          module: autonomous ? "plugins.stockpile.app.atomic" : "plugins.stockpile.app.batch",
        },
        source: {
          id: "ed32b9c3-9593-4c33-b0db-e2007315096b",
          name: "basic",
        },
        state: "paused",
        autonomous: autonomous ? 1 : 0,
        jitter: "2/8",
        visibility: 50,
        auto_close: false,
        obfuscator: "plain-text",
        use_learning_parsers: true,
      },
      phases: orderedAbilities.map((a, idx) => ({
        phase: idx + 1,
        ...a,
      })),
      metadata: {
        totalPhases: orderedAbilities.length,
        platforms: Array.from(new Set(orderedAbilities.map(a => a.platform as string))),
        tactics: Array.from(new Set(orderedAbilities.map(a => a.tactic as string))),
        estimatedDuration: `${orderedAbilities.length * 2}-${orderedAbilities.length * 5} minutes`,
        generatedAt: new Date().toISOString(),
      },
    };

    return json(operationPlan);
  },
};

export const calderaTools: ToolDef[] = [
  caldera_adversary_profile,
  caldera_ability_set,
  caldera_operation_plan,
];
