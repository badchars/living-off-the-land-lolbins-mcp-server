import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Technique Evolution Data ━━━

interface EvolutionStage {
  period: string;
  usage: string;
  attckIds: string[];
  detectionState: "undetected" | "emerging" | "detected" | "well-detected";
  notes: string;
}

interface BinaryEvolution {
  binary: string;
  platforms: Platform[];
  originalPurpose: string;
  stages: EvolutionStage[];
  currentStatus: "active" | "deprecated" | "restricted";
}

const EVOLUTION_DATA: Map<string, BinaryEvolution> = new Map([
  ["certutil", {
    binary: "certutil",
    platforms: ["windows"] as Platform[],
    originalPurpose: "Certificate management utility for Windows PKI",
    stages: [
      { period: "Pre-2015", usage: "Legitimate certificate enrollment and management", attckIds: [], detectionState: "undetected" as const, notes: "Used exclusively for PKI operations" },
      { period: "2015-2017", usage: "Base64 encode/decode for payload obfuscation (-encode/-decode)", attckIds: ["T1140"], detectionState: "emerging" as const, notes: "Red teamers discovered -encode/-decode for payload obfuscation" },
      { period: "2017-2019", usage: "File download via -urlcache (-urlcache -split -f)", attckIds: ["T1140", "T1105"], detectionState: "detected" as const, notes: "Widely adopted by threat actors for payload download; Sigma rules created" },
      { period: "2019-2022", usage: "Combined download + decode chains, hash verification abuse", attckIds: ["T1140", "T1105", "T1027"], detectionState: "well-detected" as const, notes: "EDR vendors flag certutil download/decode patterns; attackers use obfuscation" },
      { period: "2022-present", usage: "Still used but with evasion (path manipulation, ADS storage)", attckIds: ["T1140", "T1105", "T1027", "T1564.004"], detectionState: "well-detected" as const, notes: "Attackers use full paths, ADS, or chain with other binaries to evade detection" },
    ],
    currentStatus: "active" as const,
  }],
  ["mshta", {
    binary: "mshta",
    platforms: ["windows"] as Platform[],
    originalPurpose: "Microsoft HTML Application Host for running HTA files",
    stages: [
      { period: "Pre-2014", usage: "Legitimate HTA application execution", attckIds: [], detectionState: "undetected" as const, notes: "Used for HTML-based application UIs" },
      { period: "2014-2016", usage: "Execute inline VBScript/JScript for code execution", attckIds: ["T1218.005"], detectionState: "emerging" as const, notes: "Penetration testers began using for AWL bypass" },
      { period: "2016-2018", usage: "Remote HTA payload delivery, spearphishing chain component", attckIds: ["T1218.005", "T1059.005"], detectionState: "detected" as const, notes: "APT groups (FIN7, Cobalt Group) adopted heavily for initial access" },
      { period: "2018-2021", usage: "COM scriptlet execution, polyglot HTA files", attckIds: ["T1218.005", "T1059.005", "T1218.003"], detectionState: "well-detected" as const, notes: "Advanced evasion via COM objects and polyglot file formats" },
      { period: "2021-present", usage: "Still used with obfuscation layers; common in commodity malware", attckIds: ["T1218.005"], detectionState: "well-detected" as const, notes: "Heavily monitored; attackers combine with other proxy execution binaries" },
    ],
    currentStatus: "active" as const,
  }],
  ["powershell", {
    binary: "powershell",
    platforms: ["windows", "linux", "macos"] as Platform[],
    originalPurpose: "Windows task automation and configuration management framework",
    stages: [
      { period: "Pre-2011", usage: "System administration and scripting", attckIds: [], detectionState: "undetected" as const, notes: "PowerShell v1/v2 with minimal logging" },
      { period: "2011-2015", usage: "Offensive frameworks emerge (PowerSploit, Empire, Nishang)", attckIds: ["T1059.001"], detectionState: "emerging" as const, notes: "Constrained language mode introduced; ScriptBlock logging added in v5" },
      { period: "2015-2018", usage: "Encoded commands, download cradles, fileless attacks", attckIds: ["T1059.001", "T1027", "T1105"], detectionState: "detected" as const, notes: "AMSI integration in PS v5; still heavily abused with bypasses" },
      { period: "2018-2021", usage: "AMSI bypass techniques, PS downgrade attacks, CLM bypass", attckIds: ["T1059.001", "T1027", "T1562.001"], detectionState: "well-detected" as const, notes: "Organizations block or constrain PS; attackers use v2 downgrade" },
      { period: "2021-present", usage: "Living-off-the-land via pwsh (PS7), .NET reflection, minimal scripts", attckIds: ["T1059.001", "T1027.010"], detectionState: "well-detected" as const, notes: "Extensive logging available; attackers shift to less-monitored alternatives" },
    ],
    currentStatus: "active" as const,
  }],
  ["rundll32", {
    binary: "rundll32",
    platforms: ["windows"] as Platform[],
    originalPurpose: "Load and run DLL export functions",
    stages: [
      { period: "Pre-2013", usage: "Legitimate DLL function invocation by system and applications", attckIds: [], detectionState: "undetected" as const, notes: "Core Windows component for DLL loading" },
      { period: "2013-2016", usage: "Execute malicious DLL payloads, JavaScript via mshtml", attckIds: ["T1218.011"], detectionState: "emerging" as const, notes: "Red team adoption for AWL bypass and proxy execution" },
      { period: "2016-2019", usage: "DLL side-loading, COM object abuse, inline JS execution", attckIds: ["T1218.011", "T1574.002"], detectionState: "detected" as const, notes: "APT29, APT28 adopt heavily for defense evasion" },
      { period: "2019-present", usage: "Advanced DLL proxying, memory-only execution chains", attckIds: ["T1218.011", "T1574.002", "T1055"], detectionState: "well-detected" as const, notes: "EDRs monitor DLL loads from unusual paths; still effective with legitimate-looking DLLs" },
    ],
    currentStatus: "active" as const,
  }],
  ["regsvr32", {
    binary: "regsvr32",
    platforms: ["windows"] as Platform[],
    originalPurpose: "Register and unregister OLE controls (COM DLLs)",
    stages: [
      { period: "Pre-2016", usage: "Legitimate COM/OLE component registration", attckIds: [], detectionState: "undetected" as const, notes: "Standard Windows component management" },
      { period: "2016-2017", usage: "Squiblydoo technique: /i:URL for remote SCT execution", attckIds: ["T1218.010"], detectionState: "emerging" as const, notes: "Casey Smith published Squiblydoo bypass technique" },
      { period: "2017-2019", usage: "Squiblytwo (COM scriptlet abuse), signed binary proxy", attckIds: ["T1218.010"], detectionState: "detected" as const, notes: "APT28, Cobalt Group adopted for AppLocker bypass" },
      { period: "2019-present", usage: "Variations with local SCT files, DLL sideload chains", attckIds: ["T1218.010", "T1574.002"], detectionState: "well-detected" as const, notes: "regsvr32 with scrobj.dll is heavily flagged; attackers use variations" },
    ],
    currentStatus: "active" as const,
  }],
  ["bitsadmin", {
    binary: "bitsadmin",
    platforms: ["windows"] as Platform[],
    originalPurpose: "Background Intelligent Transfer Service command-line tool",
    stages: [
      { period: "Pre-2016", usage: "Manage Windows Update and legitimate file transfers", attckIds: [], detectionState: "undetected" as const, notes: "Part of standard Windows administration toolkit" },
      { period: "2016-2018", usage: "Download payloads via /transfer, persist via BITS jobs", attckIds: ["T1197", "T1105"], detectionState: "emerging" as const, notes: "Lazarus and other groups discovered download/persistence capability" },
      { period: "2018-2020", usage: "SetNotifyCmdLine for execution on job completion", attckIds: ["T1197", "T1105"], detectionState: "detected" as const, notes: "BITS job persistence survives reboots; increasingly detected" },
      { period: "2020-present", usage: "Still used with obfuscation; BITS COM API preferred by sophisticated actors", attckIds: ["T1197", "T1105"], detectionState: "well-detected" as const, notes: "Command-line bitsadmin well-detected; COM API usage harder to catch" },
    ],
    currentStatus: "active" as const,
  }],
  ["wmic", {
    binary: "wmic",
    platforms: ["windows"] as Platform[],
    originalPurpose: "Windows Management Instrumentation command-line interface",
    stages: [
      { period: "Pre-2015", usage: "System administration and WMI queries", attckIds: [], detectionState: "undetected" as const, notes: "Standard sysadmin tool for WMI operations" },
      { period: "2015-2018", usage: "Remote process execution, XSL script processing", attckIds: ["T1047", "T1220"], detectionState: "emerging" as const, notes: "Used for lateral movement and AWL bypass via XSL" },
      { period: "2018-2021", usage: "WMIC XSL squiblytwo, shadow copy deletion, recon", attckIds: ["T1047", "T1220", "T1490"], detectionState: "detected" as const, notes: "Ransomware groups adopt for shadow copy deletion" },
      { period: "2021-present", usage: "Deprecated by Microsoft; still present on older systems", attckIds: ["T1047", "T1220"], detectionState: "well-detected" as const, notes: "Microsoft deprecated WMIC in Windows 11; transitioning to PowerShell WMI cmdlets" },
    ],
    currentStatus: "deprecated" as const,
  }],
]);

// ━━━ OS Change Data ━━━

interface OSChange {
  os: string;
  version: string;
  releaseYear: string;
  changes: Array<{
    binary: string;
    change: "added" | "modified" | "restricted" | "deprecated" | "removed";
    description: string;
    impact: string;
  }>;
}

const OS_CHANGES: OSChange[] = [
  {
    os: "Windows",
    version: "Windows 10 1709",
    releaseYear: "2017",
    changes: [
      { binary: "powershell", change: "modified", description: "AMSI integration improved, ScriptBlock logging enhanced", impact: "PowerShell obfuscation techniques detected more reliably" },
      { binary: "mshta", change: "modified", description: "Defender ASR rules can block mshta child processes", impact: "Reduced effectiveness of mshta for initial execution" },
    ],
  },
  {
    os: "Windows",
    version: "Windows 10 1903",
    releaseYear: "2019",
    changes: [
      { binary: "powershell", change: "modified", description: "PowerShell v2 can be disabled via features; AMSI v3 improvements", impact: "PS downgrade attack effectiveness reduced" },
      { binary: "certutil", change: "restricted", description: "Defender flags certutil download patterns more aggressively", impact: "certutil -urlcache detections improved" },
    ],
  },
  {
    os: "Windows",
    version: "Windows 11 21H2",
    releaseYear: "2021",
    changes: [
      { binary: "wmic", change: "deprecated", description: "WMIC deprecated and may be removed in future updates", impact: "Attackers must shift to PowerShell WMI cmdlets or COM API" },
      { binary: "powershell", change: "modified", description: "PowerShell 7 available alongside 5.1; enhanced constrained mode", impact: "Dual runtime paths create confusion for defenders" },
    ],
  },
  {
    os: "Windows",
    version: "Windows 11 22H2",
    releaseYear: "2022",
    changes: [
      { binary: "wmic", change: "removed", description: "WMIC removed as optional feature (can be re-added)", impact: "WMIC-based LOL techniques broken by default on new installs" },
      { binary: "certutil", change: "restricted", description: "SmartScreen and Defender improvements target certutil abuse", impact: "Higher detection rates for certutil download chains" },
    ],
  },
  {
    os: "Windows",
    version: "Windows 11 24H2",
    releaseYear: "2024",
    changes: [
      { binary: "mshta", change: "restricted", description: "ASR rules enabled by default for mshta child process blocking", impact: "mshta-based attack chains blocked in default security posture" },
      { binary: "regsvr32", change: "restricted", description: "Enhanced monitoring for regsvr32 network connections", impact: "Squiblydoo remote SCT execution more likely to be blocked" },
    ],
  },
  {
    os: "macOS",
    version: "macOS Ventura 13",
    releaseYear: "2022",
    changes: [
      { binary: "curl", change: "modified", description: "TCC restrictions on curl accessing certain directories", impact: "curl-based download to protected directories requires TCC approval" },
      { binary: "python3", change: "modified", description: "System Python removed; requires Xcode CLT or Homebrew install", impact: "Python-based LOL techniques require additional setup" },
    ],
  },
  {
    os: "macOS",
    version: "macOS Sonoma 14",
    releaseYear: "2023",
    changes: [
      { binary: "osascript", change: "restricted", description: "Increased TCC restrictions on AppleScript automation", impact: "AppleScript-based LOL techniques face more permission prompts" },
      { binary: "curl", change: "modified", description: "Additional code signing requirements for downloaded binaries", impact: "Downloaded payloads face Gatekeeper restrictions" },
    ],
  },
];

// ━━━ Deprecation Data ━━━

interface DeprecatedTechnique {
  binary: string;
  platform: Platform;
  deprecatedInVersion: string;
  removedInVersion: string | null;
  reason: string;
  replacement: string;
  impactOnAttackers: string;
}

const DEPRECATED_TECHNIQUES: DeprecatedTechnique[] = [
  {
    binary: "wmic",
    platform: "windows",
    deprecatedInVersion: "Windows 11 21H2",
    removedInVersion: "Windows 11 22H2 (optional feature)",
    reason: "Microsoft transitioning WMI management to PowerShell cmdlets",
    replacement: "PowerShell Get-WmiObject / Get-CimInstance",
    impactOnAttackers: "WMIC-based XSL execution and remote process creation broken on modern systems",
  },
  {
    binary: "wscript",
    platform: "windows",
    deprecatedInVersion: null as any,
    removedInVersion: null,
    reason: "Not deprecated but increasingly restricted via ASR and WDAC policies",
    replacement: "PowerShell or direct application execution",
    impactOnAttackers: "VBScript/JScript execution blocked in restricted environments",
  },
  {
    binary: "cscript",
    platform: "windows",
    deprecatedInVersion: null as any,
    removedInVersion: null,
    reason: "Not deprecated but restricted alongside wscript via policy",
    replacement: "PowerShell cmdlets",
    impactOnAttackers: "Console scripting host blocked by AppLocker/WDAC in hardened environments",
  },
  {
    binary: "python",
    platform: "macos",
    deprecatedInVersion: "macOS Monterey 12",
    removedInVersion: "macOS Monterey 12",
    reason: "Apple removed system Python 2.x; Python 3 requires separate installation",
    replacement: "Homebrew/pyenv managed Python 3",
    impactOnAttackers: "Python-based LOL techniques no longer available by default on macOS",
  },
  {
    binary: "php",
    platform: "macos",
    deprecatedInVersion: "macOS Monterey 12",
    removedInVersion: "macOS Monterey 12",
    reason: "Apple removed bundled PHP",
    replacement: "Homebrew PHP",
    impactOnAttackers: "PHP-based GTFOBins techniques not available on modern macOS",
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

// ━━━ Tools ━━━

const evolution_history: ToolDef = {
  name: "evolution_history",
  description: "Track how a LOL binary's offensive usage has evolved over time (e.g. certutil evolved from cert management to download/encode tool)",
  schema: {
    binary: z.string().describe("Binary name to track evolution (e.g. certutil, mshta, powershell, rundll32)"),
  },
  async execute(args: { binary: string }, ctx: ToolContext): Promise<ToolResult> {
    const lower = args.binary.toLowerCase();
    let evolution: BinaryEvolution | undefined;

    for (const [key, evo] of EVOLUTION_DATA) {
      if (key.toLowerCase() === lower) {
        evolution = evo;
        break;
      }
    }

    if (!evolution) {
      // Try KB lookup for binaries not in hardcoded data
      const kbEntries = ctx.knowledgeBase.lookupBinary(args.binary);
      if (kbEntries.length > 0) {
        return json({
          binary: args.binary,
          evolutionDataAvailable: false,
          message: `No evolution timeline data available for "${args.binary}", but found ${kbEntries.length} KB entries.`,
          kbEntries: deduplicateByBinary(kbEntries).slice(0, 10).map(summarizeKbEntry),
          trackedBinaries: Array.from(EVOLUTION_DATA.keys()),
        });
      }
      const available = Array.from(EVOLUTION_DATA.keys()).join(", ");
      return text(`No evolution data for "${args.binary}". Tracked binaries: ${available}`);
    }

    // Enrich with KB data
    const kbEntries = ctx.knowledgeBase.lookupBinary(args.binary);

    return json({
      binary: evolution.binary,
      platforms: evolution.platforms,
      originalPurpose: evolution.originalPurpose,
      currentStatus: evolution.currentStatus,
      evolutionTimeline: evolution.stages,
      totalStages: evolution.stages.length,
      currentDetectionState: evolution.stages[evolution.stages.length - 1].detectionState,
      kbEntries: deduplicateByBinary(kbEntries).slice(0, 10).map(summarizeKbEntry),
      totalKBEntries: kbEntries.length,
    });
  },
};

const evolution_os_changes: ToolDef = {
  name: "evolution_os_changes",
  description: "Track OS version changes affecting LOL technique viability (Windows updates, macOS changes)",
  schema: {
    os: z.enum(["windows", "macos", "all"]).optional().describe("Filter by operating system, or 'all' for both"),
    binary: z.string().optional().describe("Filter changes affecting a specific binary"),
  },
  async execute(args: { os?: string; binary?: string }, ctx: ToolContext): Promise<ToolResult> {
    const osFilter = args.os || "all";
    let changes = [...OS_CHANGES];

    if (osFilter !== "all") {
      const osLower = osFilter.toLowerCase();
      changes = changes.filter(c => c.os.toLowerCase().includes(osLower));
    }

    if (args.binary) {
      const binLower = args.binary.toLowerCase();
      changes = changes.map(c => ({
        ...c,
        changes: c.changes.filter(ch => ch.binary.toLowerCase() === binLower),
      })).filter(c => c.changes.length > 0);
    }

    // Enrich with KB data for affected binaries
    const affectedBinaries = new Set<string>();
    for (const c of changes) {
      for (const ch of c.changes) affectedBinaries.add(ch.binary);
    }

    const kbContext: Record<string, Record<string, unknown>[]> = {};
    for (const binary of affectedBinaries) {
      const entries = ctx.knowledgeBase.lookupBinary(binary);
      if (entries.length > 0) {
        kbContext[binary] = deduplicateByBinary(entries).slice(0, 3).map(summarizeKbEntry);
      }
    }

    return json({
      filter: { os: osFilter, binary: args.binary || "all" },
      totalVersions: changes.length,
      osChanges: changes,
      affectedBinaries: Array.from(affectedBinaries),
      kbContext,
    });
  },
};

const evolution_deprecation: ToolDef = {
  name: "evolution_deprecation",
  description: "Find deprecated or removed LOL techniques per OS version, including impact on attackers and replacements",
  schema: {
    platform: z.enum(["windows", "macos", "all"]).optional().describe("Filter by platform, or 'all'"),
    binary: z.string().optional().describe("Check deprecation status of a specific binary"),
  },
  async execute(args: { platform?: string; binary?: string }, ctx: ToolContext): Promise<ToolResult> {
    const platformFilter = args.platform || "all";
    let deprecated = [...DEPRECATED_TECHNIQUES];

    if (platformFilter !== "all") {
      deprecated = deprecated.filter(d => d.platform === platformFilter);
    }

    if (args.binary) {
      const binLower = args.binary.toLowerCase();
      deprecated = deprecated.filter(d => d.binary.toLowerCase() === binLower);
    }

    if (deprecated.length === 0 && args.binary) {
      // Check if binary exists but is not deprecated
      const kbEntries = ctx.knowledgeBase.lookupBinary(args.binary);
      if (kbEntries.length > 0) {
        return json({
          binary: args.binary,
          deprecated: false,
          message: `"${args.binary}" is not deprecated or removed. It remains available and active.`,
          kbEntries: deduplicateByBinary(kbEntries).slice(0, 5).map(summarizeKbEntry),
        });
      }
    }

    // Enrich with KB context
    const enriched = deprecated.map(d => {
      const entries = ctx.knowledgeBase.lookupBinary(d.binary, d.platform);
      return {
        ...d,
        kbEntries: deduplicateByBinary(entries).slice(0, 3).map(summarizeKbEntry),
      };
    });

    return json({
      filter: { platform: platformFilter, binary: args.binary || "all" },
      totalDeprecated: enriched.length,
      deprecatedTechniques: enriched,
    });
  },
};

export const techniqueEvolutionTools: ToolDef[] = [
  evolution_history,
  evolution_os_changes,
  evolution_deprecation,
];
