import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Hardcoded APT/Threat Actor Data ━━━

interface ActorTechnique {
  binary: string;
  attckIds: string[];
  usage: string;
  stealthNotes: string;
}

interface ThreatActorProfile {
  name: string;
  aliases: string[];
  origin: string;
  motivation: string;
  campaigns: string[];
  preferredPlatforms: Platform[];
  techniques: ActorTechnique[];
  stealthPreference: "low" | "medium" | "high";
  description: string;
}

const THREAT_ACTORS: Map<string, ThreatActorProfile> = new Map([
  ["APT29", {
    name: "APT29",
    aliases: ["Cozy Bear", "The Dukes", "Nobelium", "Midnight Blizzard"],
    origin: "Russia",
    motivation: "Espionage",
    campaigns: ["SolarWinds", "WellMess", "EnvyScout"],
    preferredPlatforms: ["windows", "linux"] as Platform[],
    techniques: [
      { binary: "rundll32", attckIds: ["T1218.011"], usage: "Execute DLL payloads for lateral movement and persistence", stealthNotes: "Leverages trusted Windows binary to bypass application whitelisting" },
      { binary: "certutil", attckIds: ["T1140", "T1105"], usage: "Download encoded payloads and decode base64 content", stealthNotes: "Commonly used for certificate operations, download activity may blend in" },
      { binary: "powershell", attckIds: ["T1059.001", "T1027"], usage: "Execute obfuscated scripts for C2 communication and data collection", stealthNotes: "Heavily monitored but offers wide capability; uses encoded commands" },
      { binary: "mshta", attckIds: ["T1218.005"], usage: "Execute HTA payloads for initial access", stealthNotes: "Trusted binary, used to run inline VBScript/JScript" },
      { binary: "regsvr32", attckIds: ["T1218.010"], usage: "Proxy execution of COM scriptlets for persistence", stealthNotes: "Squiblydoo technique bypasses AppLocker" },
    ],
    stealthPreference: "high",
    description: "Russian state-sponsored group known for sophisticated espionage operations targeting government and critical infrastructure. Prefers stealthy LOL techniques with heavy obfuscation.",
  }],
  ["APT28", {
    name: "APT28",
    aliases: ["Fancy Bear", "Sofacy", "Sednit", "Forest Blizzard"],
    origin: "Russia",
    motivation: "Espionage, Information Operations",
    campaigns: ["DNC Hack", "Olympic Destroyer", "Zebrocy"],
    preferredPlatforms: ["windows"] as Platform[],
    techniques: [
      { binary: "certutil", attckIds: ["T1140", "T1105"], usage: "Download and decode payloads from C2 infrastructure", stealthNotes: "Uses certutil -urlcache for downloads" },
      { binary: "mshta", attckIds: ["T1218.005"], usage: "Execute HTA-based droppers and initial payloads", stealthNotes: "Runs inline scripts without touching disk" },
      { binary: "regsvr32", attckIds: ["T1218.010"], usage: "Register COM objects containing malicious code", stealthNotes: "Squiblydoo and Squiblytwo variants for AWL bypass" },
      { binary: "rundll32", attckIds: ["T1218.011"], usage: "Execute DLL exports for defense evasion", stealthNotes: "Common system binary, blends with normal activity" },
      { binary: "cmd", attckIds: ["T1059.003"], usage: "Execute batch scripts and chain commands for reconnaissance", stealthNotes: "Noisy but ubiquitous; hard to distinguish from admin usage" },
    ],
    stealthPreference: "medium",
    description: "Russian military intelligence group targeting government, military, and media organizations. Uses a mix of custom malware and LOL techniques for rapid operations.",
  }],
  ["FIN7", {
    name: "FIN7",
    aliases: ["Carbanak", "Carbon Spider", "Sangria Tempest"],
    origin: "Russia",
    motivation: "Financial",
    campaigns: ["Carbanak", "FIN7 POS Attacks", "Lizar"],
    preferredPlatforms: ["windows"] as Platform[],
    techniques: [
      { binary: "mshta", attckIds: ["T1218.005"], usage: "Execute HTA files delivered via spearphishing for initial access", stealthNotes: "Frequently used in document-based attacks" },
      { binary: "wscript", attckIds: ["T1059.005"], usage: "Execute VBScript/JScript payloads dropped by macros", stealthNotes: "Commonly associated with Office macro chains" },
      { binary: "cscript", attckIds: ["T1059.005"], usage: "Execute command-line scripts for data collection and staging", stealthNotes: "Console-based scripting host, less visible than wscript" },
      { binary: "powershell", attckIds: ["T1059.001"], usage: "Download and execute second-stage payloads", stealthNotes: "Uses encoded and obfuscated commands to evade detection" },
      { binary: "cmd", attckIds: ["T1059.003"], usage: "Batch script execution for environment discovery", stealthNotes: "Chained with other LOL binaries" },
    ],
    stealthPreference: "medium",
    description: "Financially motivated threat group targeting retail, hospitality, and food industries. Known for sophisticated spearphishing and LOL-heavy intrusion chains.",
  }],
  ["Lazarus", {
    name: "Lazarus",
    aliases: ["Hidden Cobra", "ZINC", "Diamond Sleet", "Labyrinth Chollima"],
    origin: "North Korea",
    motivation: "Financial, Espionage",
    campaigns: ["WannaCry", "Operation DreamJob", "AppleJeus"],
    preferredPlatforms: ["windows", "macos", "linux"] as Platform[],
    techniques: [
      { binary: "certutil", attckIds: ["T1140", "T1105"], usage: "Download payloads and decode obfuscated content from C2", stealthNotes: "Uses -urlcache -split -f pattern" },
      { binary: "bitsadmin", attckIds: ["T1197", "T1105"], usage: "Download payloads using BITS jobs for persistence and transfer", stealthNotes: "BITS jobs survive reboots and run in background" },
      { binary: "mshta", attckIds: ["T1218.005"], usage: "Execute HTA-based payloads for initial access", stealthNotes: "Used in spearphishing attack chains" },
      { binary: "rundll32", attckIds: ["T1218.011"], usage: "Load malicious DLLs for execution and defense evasion", stealthNotes: "Trusted binary for DLL proxy execution" },
      { binary: "powershell", attckIds: ["T1059.001"], usage: "Execute encoded PowerShell scripts for C2 and reconnaissance", stealthNotes: "Uses -enc and -nop flags to avoid profiling" },
    ],
    stealthPreference: "medium",
    description: "North Korean state-sponsored group conducting financially motivated attacks and espionage. Targets cryptocurrency exchanges, financial institutions, and defense contractors.",
  }],
  ["Turla", {
    name: "Turla",
    aliases: ["Snake", "Venomous Bear", "Waterbug", "Secret Blizzard"],
    origin: "Russia",
    motivation: "Espionage",
    campaigns: ["Snake Campaign", "Penguin Turla", "ComRAT"],
    preferredPlatforms: ["windows", "linux"] as Platform[],
    techniques: [
      { binary: "powershell", attckIds: ["T1059.001", "T1027"], usage: "Execute obfuscated PowerShell scripts for C2 and data collection", stealthNotes: "Uses PowerShell Empire-style payloads with heavy obfuscation" },
      { binary: "cmd", attckIds: ["T1059.003"], usage: "Execute batch commands for system reconnaissance and staging", stealthNotes: "Chains cmd with native utilities for enumeration" },
      { binary: "certutil", attckIds: ["T1140"], usage: "Decode base64-encoded payloads on disk", stealthNotes: "Uses legitimate certificate utility for decoding" },
      { binary: "rundll32", attckIds: ["T1218.011"], usage: "Side-load DLLs for persistence mechanisms", stealthNotes: "Exploits DLL search order hijacking" },
      { binary: "reg", attckIds: ["T1112"], usage: "Modify registry keys for persistence and configuration storage", stealthNotes: "Registry modifications blend with system activity" },
    ],
    stealthPreference: "high",
    description: "Highly sophisticated Russian espionage group targeting government, military, and diplomatic entities. Known for innovative covert communication channels and long-dwell-time operations.",
  }],
  ["Cobalt Group", {
    name: "Cobalt Group",
    aliases: ["Cobalt Gang", "Cobalt Spider", "Gold Kingswood"],
    origin: "Russia",
    motivation: "Financial",
    campaigns: ["ATM Jackpotting", "SWIFT Attacks", "Cobalt Strike Campaigns"],
    preferredPlatforms: ["windows"] as Platform[],
    techniques: [
      { binary: "regsvr32", attckIds: ["T1218.010"], usage: "Execute COM scriptlets for AWL bypass and initial payload delivery", stealthNotes: "Squiblydoo technique for AppLocker bypass" },
      { binary: "mshta", attckIds: ["T1218.005"], usage: "Execute HTA payloads for initial access via spearphishing", stealthNotes: "Signed Microsoft binary, trusted by default" },
      { binary: "powershell", attckIds: ["T1059.001"], usage: "Execute Cobalt Strike beacon loaders and stagers", stealthNotes: "Uses obfuscated download cradles" },
      { binary: "rundll32", attckIds: ["T1218.011"], usage: "Load Cobalt Strike DLL beacons", stealthNotes: "Common technique for in-memory execution" },
      { binary: "cmstp", attckIds: ["T1218.003"], usage: "Bypass UAC and AWL using CMSTP INF files", stealthNotes: "CMSTP bypass is less monitored than other techniques" },
    ],
    stealthPreference: "medium",
    description: "Financially motivated group targeting financial institutions worldwide. Known for ATM attacks, SWIFT network abuse, and heavy use of Cobalt Strike with LOL binary chains.",
  }],
]);

// ━━━ Campaign Data ━━━

interface CampaignInfo {
  name: string;
  actor: string;
  year: string;
  description: string;
  techniques: Array<{ binary: string; attckId: string; role: string }>;
}

const CAMPAIGNS: CampaignInfo[] = [
  {
    name: "SolarWinds",
    actor: "APT29",
    year: "2020",
    description: "Supply chain attack via trojanized SolarWinds Orion update, followed by LOL-based lateral movement",
    techniques: [
      { binary: "rundll32", attckId: "T1218.011", role: "Execute TEARDROP/RAINDROP DLL payloads" },
      { binary: "certutil", attckId: "T1140", role: "Decode obfuscated payloads on target systems" },
      { binary: "powershell", attckId: "T1059.001", role: "Execute reconnaissance and data collection scripts" },
    ],
  },
  {
    name: "DNC Hack",
    actor: "APT28",
    year: "2016",
    description: "Targeted intrusion into Democratic National Committee infrastructure for intelligence collection",
    techniques: [
      { binary: "certutil", attckId: "T1105", role: "Download second-stage payloads from C2" },
      { binary: "cmd", attckId: "T1059.003", role: "Execute batch reconnaissance scripts" },
      { binary: "regsvr32", attckId: "T1218.010", role: "Register malicious COM objects for persistence" },
    ],
  },
  {
    name: "Carbanak",
    actor: "FIN7",
    year: "2014-2016",
    description: "Sophisticated bank heist campaign targeting financial institutions via spearphishing and LOL techniques",
    techniques: [
      { binary: "mshta", attckId: "T1218.005", role: "Execute HTA droppers from spearphishing emails" },
      { binary: "wscript", attckId: "T1059.005", role: "Run VBScript payloads for C2 communication" },
      { binary: "powershell", attckId: "T1059.001", role: "Download and execute Carbanak backdoor components" },
    ],
  },
  {
    name: "WannaCry",
    actor: "Lazarus",
    year: "2017",
    description: "Global ransomware attack exploiting EternalBlue with LOL binary abuse for propagation",
    techniques: [
      { binary: "cmd", attckId: "T1059.003", role: "Execute worm propagation and encryption routines" },
      { binary: "certutil", attckId: "T1140", role: "Decode embedded payloads" },
      { binary: "bitsadmin", attckId: "T1197", role: "Background transfer of ransomware components" },
    ],
  },
  {
    name: "Snake Campaign",
    actor: "Turla",
    year: "2004-2023",
    description: "Long-running espionage campaign using Snake/Uroburos malware with LOL techniques for covert persistence",
    techniques: [
      { binary: "powershell", attckId: "T1059.001", role: "Execute obfuscated reconnaissance and C2 scripts" },
      { binary: "cmd", attckId: "T1059.003", role: "Batch-based system enumeration" },
      { binary: "reg", attckId: "T1112", role: "Modify registry for persistence and configuration" },
    ],
  },
  {
    name: "ATM Jackpotting",
    actor: "Cobalt Group",
    year: "2016-2018",
    description: "Attacks on ATM infrastructure using Cobalt Strike and LOL binaries for lateral movement to ATM controllers",
    techniques: [
      { binary: "regsvr32", attckId: "T1218.010", role: "AppLocker bypass for initial payload execution" },
      { binary: "powershell", attckId: "T1059.001", role: "Load Cobalt Strike beacons in memory" },
      { binary: "mshta", attckId: "T1218.005", role: "Execute HTA-based droppers from phishing" },
    ],
  },
  {
    name: "Operation DreamJob",
    actor: "Lazarus",
    year: "2020-2023",
    description: "Social engineering campaign targeting defense and aerospace via fake job offers with LOL-based payloads",
    techniques: [
      { binary: "certutil", attckId: "T1105", role: "Download second-stage payload from attacker infrastructure" },
      { binary: "rundll32", attckId: "T1218.011", role: "Execute DLL-based backdoor components" },
      { binary: "mshta", attckId: "T1218.005", role: "Execute HTA files delivered via phishing lures" },
    ],
  },
];

// ━━━ Helper Functions ━━━

function deduplicateByBinary(entries: UnifiedLOLEntry[]): UnifiedLOLEntry[] {
  const seen = new Set<string>();
  return entries.filter(e => {
    const key = `${e.binary}-${e.platform}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function summarizeKbEntry(e: UnifiedLOLEntry): Record<string, unknown> {
  return {
    binary: e.binary,
    platform: e.platform,
    catalog: e.catalogSource,
    functions: e.functions,
    stealthScore: e.stealthScore,
    attck: e.attckTechniques,
    commands: e.executionContexts.slice(0, 2).map(c => ({
      context: c.context,
      command: c.command,
    })),
  };
}

function findActorCaseInsensitive(name: string): ThreatActorProfile | undefined {
  const lower = name.toLowerCase();
  for (const [key, profile] of THREAT_ACTORS) {
    if (key.toLowerCase() === lower) return profile;
    if (profile.aliases.some(a => a.toLowerCase() === lower)) return profile;
  }
  return undefined;
}

// ━━━ Tools ━━━

const actor_to_techniques: ToolDef = {
  name: "actor_to_techniques",
  description: "Given a threat actor name, return their known LOL techniques and matching knowledge base entries",
  schema: {
    actor: z.string().describe("Threat actor name or alias (e.g. APT29, Fancy Bear, FIN7)"),
    platform: z.string().optional().describe("Filter KB results by platform (linux, windows, macos)"),
  },
  async execute(args: { actor: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const profile = findActorCaseInsensitive(args.actor);
    if (!profile) {
      const available = Array.from(THREAT_ACTORS.keys()).join(", ");
      return text(`Unknown actor: "${args.actor}". Available actors: ${available}`);
    }

    const kbMatches: Array<{ technique: ActorTechnique; kbEntries: Record<string, unknown>[] }> = [];

    for (const technique of profile.techniques) {
      const entries = ctx.knowledgeBase.lookupBinary(technique.binary, args.platform as Platform);
      const attckEntries: UnifiedLOLEntry[] = [];
      for (const id of technique.attckIds) {
        const found = ctx.knowledgeBase.searchByAttck(id, args.platform as Platform);
        for (const e of found) attckEntries.push(e);
      }

      const combined = deduplicateByBinary([...entries, ...attckEntries]);
      kbMatches.push({
        technique,
        kbEntries: combined.slice(0, 5).map(summarizeKbEntry),
      });
    }

    return json({
      actor: profile.name,
      aliases: profile.aliases,
      origin: profile.origin,
      motivation: profile.motivation,
      stealthPreference: profile.stealthPreference,
      totalTechniques: profile.techniques.length,
      techniques: kbMatches,
    });
  },
};

const technique_to_actors: ToolDef = {
  name: "technique_to_actors",
  description: "Given a technique or binary name, return which threat actors are known to use it",
  schema: {
    technique: z.string().describe("Binary name (e.g. certutil, mshta) or ATT&CK ID (e.g. T1218.005)"),
  },
  async execute(args: { technique: string }, ctx: ToolContext): Promise<ToolResult> {
    const lower = args.technique.toLowerCase();
    const isAttckId = /^t\d{4}/i.test(args.technique);

    const matchingActors: Array<{
      actor: string;
      aliases: string[];
      origin: string;
      matchingTechniques: ActorTechnique[];
    }> = [];

    for (const [, profile] of THREAT_ACTORS) {
      const matching = profile.techniques.filter(t => {
        if (isAttckId) {
          return t.attckIds.some(id => id.toLowerCase() === lower);
        }
        return t.binary.toLowerCase() === lower;
      });

      if (matching.length > 0) {
        matchingActors.push({
          actor: profile.name,
          aliases: profile.aliases,
          origin: profile.origin,
          matchingTechniques: matching,
        });
      }
    }

    // Also get KB entries for context
    const kbEntries = isAttckId
      ? ctx.knowledgeBase.searchByAttck(args.technique.toUpperCase())
      : ctx.knowledgeBase.lookupBinary(args.technique);

    return json({
      technique: args.technique,
      matchingActors,
      totalActors: matchingActors.length,
      kbEntries: deduplicateByBinary(kbEntries).slice(0, 10).map(summarizeKbEntry),
    });
  },
};

const actor_profile: ToolDef = {
  name: "actor_profile",
  description: "Get full threat actor profile including TTPs, preferred LOL binaries, campaigns, and stealth patterns",
  schema: {
    actor: z.string().describe("Threat actor name or alias"),
  },
  async execute(args: { actor: string }, ctx: ToolContext): Promise<ToolResult> {
    const profile = findActorCaseInsensitive(args.actor);
    if (!profile) {
      const available = Array.from(THREAT_ACTORS.keys()).join(", ");
      return text(`Unknown actor: "${args.actor}". Available actors: ${available}`);
    }

    // Collect all ATT&CK IDs from this actor
    const allAttckIds = new Set<string>();
    for (const t of profile.techniques) {
      for (const id of t.attckIds) allAttckIds.add(id);
    }

    // Collect all unique binaries
    const allBinaries = new Set<string>();
    for (const t of profile.techniques) allBinaries.add(t.binary);

    // Find related campaigns
    const relatedCampaigns = CAMPAIGNS.filter(c => c.actor === profile.name);

    return json({
      profile: {
        name: profile.name,
        aliases: profile.aliases,
        origin: profile.origin,
        motivation: profile.motivation,
        description: profile.description,
        stealthPreference: profile.stealthPreference,
        preferredPlatforms: profile.preferredPlatforms,
      },
      techniques: profile.techniques,
      campaigns: relatedCampaigns.map(c => ({
        name: c.name,
        year: c.year,
        description: c.description,
        techniques: c.techniques,
      })),
      summary: {
        totalTechniques: profile.techniques.length,
        totalCampaigns: relatedCampaigns.length,
        uniqueBinaries: Array.from(allBinaries),
        uniqueAttckIds: Array.from(allAttckIds),
      },
    });
  },
};

const campaign_techniques: ToolDef = {
  name: "campaign_techniques",
  description: "Return LOL techniques used in specific known attack campaigns",
  schema: {
    campaign: z.string().describe("Campaign name (e.g. SolarWinds, DNC Hack, Carbanak, WannaCry)"),
    platform: z.string().optional().describe("Filter KB results by platform"),
  },
  async execute(args: { campaign: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const lower = args.campaign.toLowerCase();
    const campaign = CAMPAIGNS.find(c => c.name.toLowerCase().includes(lower));

    if (!campaign) {
      const available = CAMPAIGNS.map(c => c.name).join(", ");
      return text(`Unknown campaign: "${args.campaign}". Available: ${available}`);
    }

    const techniquesWithKB = campaign.techniques.map(t => {
      const binaryEntries = ctx.knowledgeBase.lookupBinary(t.binary, args.platform as Platform);
      const attckEntries = ctx.knowledgeBase.searchByAttck(t.attckId, args.platform as Platform);
      const combined = deduplicateByBinary([...binaryEntries, ...attckEntries]);

      return {
        ...t,
        kbEntries: combined.slice(0, 5).map(summarizeKbEntry),
      };
    });

    return json({
      campaign: campaign.name,
      actor: campaign.actor,
      year: campaign.year,
      description: campaign.description,
      techniques: techniquesWithKB,
    });
  },
};

const predict_actor_for_env: ToolDef = {
  name: "predict_actor_for_env",
  description: "Given an environment session ID, predict which threat actor TTPs match the environment based on installed binaries and platform",
  schema: {
    environment_id: z.string().describe("Environment session ID from env_set"),
  },
  async execute(args: { environment_id: string }, ctx: ToolContext): Promise<ToolResult> {
    const session = ctx.sessions.get(args.environment_id);
    if (!session) {
      return text(`Environment session "${args.environment_id}" not found. Use env_set first.`);
    }

    const env = session.state;
    const installedLower = new Set(env.installedBinaries.map(b => b.toLowerCase()));

    const actorScores: Array<{
      actor: string;
      aliases: string[];
      score: number;
      matchedTechniques: ActorTechnique[];
      missingBinaries: string[];
      platformMatch: boolean;
    }> = [];

    for (const [, profile] of THREAT_ACTORS) {
      const platformMatch = profile.preferredPlatforms.includes(env.platform);
      const matched: ActorTechnique[] = [];
      const missing: string[] = [];

      for (const tech of profile.techniques) {
        if (installedLower.has(tech.binary.toLowerCase())) {
          matched.push(tech);
        } else {
          missing.push(tech.binary);
        }
      }

      let score = matched.length;
      if (platformMatch) score += 2;
      if (env.edrDetected !== "none" && profile.stealthPreference === "high") score += 1;

      actorScores.push({
        actor: profile.name,
        aliases: profile.aliases,
        score,
        matchedTechniques: matched,
        missingBinaries: missing,
        platformMatch,
      });
    }

    actorScores.sort((a, b) => b.score - a.score);

    return json({
      environmentId: args.environment_id,
      platform: env.platform,
      installedBinaries: env.installedBinaries.length,
      predictions: actorScores.map(a => ({
        actor: a.actor,
        aliases: a.aliases,
        relevanceScore: a.score,
        platformMatch: a.platformMatch,
        matchedTechniques: a.matchedTechniques.length,
        techniques: a.matchedTechniques,
        missingBinaries: a.missingBinaries,
      })),
    });
  },
};

export const threatActorTools: ToolDef[] = [
  actor_to_techniques,
  technique_to_actors,
  actor_profile,
  campaign_techniques,
  predict_actor_for_env,
];
