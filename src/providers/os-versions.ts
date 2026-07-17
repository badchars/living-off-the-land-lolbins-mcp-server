import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ OS Version Data ━━━

const WINDOWS_VERSIONS = ["Windows 7", "Windows 8", "Windows 8.1", "Windows 10", "Windows 11", "Windows Server 2016", "Windows Server 2019", "Windows Server 2022"];
const LINUX_VERSIONS = ["Ubuntu 18.04", "Ubuntu 20.04", "Ubuntu 22.04", "Ubuntu 24.04", "Debian 11", "Debian 12", "RHEL 8", "RHEL 9"];
const MACOS_VERSIONS = ["macOS 12 Monterey", "macOS 13 Ventura", "macOS 14 Sonoma", "macOS 15 Sequoia"];

// Binaries deprecated or changed behavior across versions
const DEPRECATION_MAP: Record<string, { deprecated_in: string; replacement?: string; notes: string }> = {
  "wmic": { deprecated_in: "Windows 11 22H2", replacement: "PowerShell Get-WmiObject / Get-CimInstance", notes: "WMIC deprecated but still available via optional feature" },
  "certutil": { deprecated_in: "", notes: "Still available but increasingly monitored and restricted in newer Windows versions" },
  "mshta": { deprecated_in: "", notes: "Blocked by default in Windows 11 with Smart App Control" },
  "bitsadmin": { deprecated_in: "", notes: "Increasingly blocked by AppLocker/WDAC policies in modern deployments" },
  "ifconfig": { deprecated_in: "Ubuntu 18.04+", replacement: "ip", notes: "Part of net-tools package, not installed by default in modern distros" },
  "iptables": { deprecated_in: "RHEL 9+", replacement: "nftables", notes: "iptables-nft provides backward compatibility" },
};

// New capabilities added in newer versions
const NEW_CAPABILITIES: Record<string, { added_in: string; binary: string; description: string }[]> = {
  windows: [
    { added_in: "Windows 10 1803", binary: "curl.exe", description: "Native curl added to Windows" },
    { added_in: "Windows 10 1803", binary: "tar.exe", description: "Native tar added to Windows" },
    { added_in: "Windows 10 1809", binary: "ssh.exe", description: "OpenSSH client included by default" },
    { added_in: "Windows 11", binary: "winget.exe", description: "Windows Package Manager added" },
  ],
  linux: [
    { added_in: "Ubuntu 22.04+", binary: "snap", description: "Snap package manager with confined execution" },
  ],
  macos: [
    { added_in: "macOS 13+", binary: "networksetup", description: "Enhanced TCC protections for network configuration" },
  ],
};

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

// ━━━ Tools ━━━

const osver_binary_behavior_diff: ToolDef = {
  name: "osver_binary_behavior_diff",
  description: "Compare how a binary's behavior differs across OS versions. Identifies changes in capabilities, restrictions, and security controls.",
  schema: {
    binary: z.string().describe("Binary name to compare across versions"),
    os_versions: z.array(z.string()).optional().describe("Specific OS versions to compare"),
  },
  async execute(args: { binary: string; os_versions?: string[] }, ctx: ToolContext): Promise<ToolResult> {
    const entries = ctx.knowledgeBase.lookupBinary(args.binary);
    if (entries.length === 0) return text(`No entries found for binary: ${args.binary}`);

    const entry = entries[0];
    const deprecation = DEPRECATION_MAP[args.binary.toLowerCase()];
    const platform = entry.platform;

    const versions = args.os_versions || (
      platform === "windows" ? WINDOWS_VERSIONS :
        platform === "linux" ? LINUX_VERSIONS :
          platform === "macos" ? MACOS_VERSIONS : []
    );

    const behaviorDiff = versions.map(version => ({
      osVersion: version,
      available: !deprecation || !deprecation.deprecated_in || !version.includes(deprecation.deprecated_in.split(" ")[0]),
      restrictions: [],
      notes: deprecation?.notes || `${args.binary} behavior consistent across ${version}`,
    }));

    return json({
      binary: args.binary,
      platform,
      functions: entry.functions,
      deprecationInfo: deprecation || null,
      behaviorAcrossVersions: behaviorDiff,
      securityImpact: deprecation
        ? `${args.binary} ${deprecation.deprecated_in ? `deprecated in ${deprecation.deprecated_in}` : "increasingly restricted"}${deprecation.replacement ? `. Replacement: ${deprecation.replacement}` : ""}`
        : `${args.binary} remains functional across tested versions`,
    });
  },
};

const osver_technique_validity: ToolDef = {
  name: "osver_technique_validity",
  description: "Check if a LOL technique is still valid on a specific OS version. Some techniques are patched or restricted in newer versions.",
  schema: {
    binary: z.string().optional().describe("Binary name"),
    technique_id: z.string().optional().describe("LOL technique ID"),
    os_version: z.string().describe("Target OS version to check validity for"),
  },
  async execute(args: { binary?: string; technique_id?: string; os_version: string }, ctx: ToolContext): Promise<ToolResult> {
    let entries: UnifiedLOLEntry[] = [];

    if (args.technique_id) {
      const entry = ctx.knowledgeBase.getById(args.technique_id);
      if (entry) entries = [entry];
    } else if (args.binary) {
      entries = ctx.knowledgeBase.lookupBinary(args.binary);
    }

    if (entries.length === 0) return text("No matching entries found.");

    const validity = entries.slice(0, 10).map(e => {
      const deprecation = DEPRECATION_MAP[e.binary.toLowerCase()];
      const isDeprecated = deprecation?.deprecated_in &&
        args.os_version.toLowerCase().includes(deprecation.deprecated_in.split(" ")[0].toLowerCase());

      const osContexts = e.executionContexts.filter(c =>
        !c.operatingSystem || c.operatingSystem.toLowerCase().includes(args.os_version.split(" ")[0].toLowerCase())
      );

      return {
        binary: e.binary,
        technique: e.id,
        osVersion: args.os_version,
        isValid: !isDeprecated && osContexts.length > 0,
        isDeprecated: !!isDeprecated,
        validContexts: osContexts.length,
        totalContexts: e.executionContexts.length,
        notes: isDeprecated
          ? `${e.binary} deprecated/restricted in ${args.os_version}${deprecation?.replacement ? `. Use ${deprecation.replacement}` : ""}`
          : `${e.binary} remains functional in ${args.os_version}`,
        alternatives: isDeprecated
          ? ctx.knowledgeBase.searchByFunction(e.functions[0] || "command_execution")
            .filter(a => a.id !== e.id && a.platform === e.platform)
            .slice(0, 3)
            .map(a => a.binary)
          : [],
      };
    });

    return json({ techniqueValidity: validity });
  },
};

const osver_deprecation: ToolDef = {
  name: "osver_deprecation",
  description: "List LOL techniques that are deprecated or restricted in newer OS versions. Helps identify techniques that may not work in modern environments.",
  schema: {
    platform: z.string().optional().describe("Platform filter (windows, linux, macos)"),
  },
  async execute(args: { platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const deprecations = Object.entries(DEPRECATION_MAP)
      .map(([binary, info]) => {
        const entries = ctx.knowledgeBase.lookupBinary(binary);
        if (entries.length === 0) return null;
        if (args.platform && entries[0].platform !== args.platform) return null;

        return {
          binary,
          platform: entries[0].platform,
          deprecatedIn: info.deprecated_in || "increasingly restricted",
          replacement: info.replacement || null,
          notes: info.notes,
          functions: entries[0].functions,
          attck: entries[0].attckTechniques,
          impactOnRedTeam: info.deprecated_in
            ? "Technique may fail on updated systems — use alternatives"
            : "Technique still works but more likely to be detected/blocked",
        };
      })
      .filter(Boolean);

    return json({
      deprecatedTechniques: deprecations,
      totalDeprecated: deprecations.length,
      recommendation: "Verify technique availability on target OS version before use. Modern OS versions increasingly restrict LOL binary abuse.",
    });
  },
};

const osver_new_capabilities: ToolDef = {
  name: "osver_new_capabilities",
  description: "Identify new LOL-abusable binaries added in recent OS versions. Newer systems may introduce new attack surface through added utilities.",
  schema: {
    platform: z.string().optional().describe("Platform filter (windows, linux, macos)"),
    since_version: z.string().optional().describe("Show capabilities added since this version"),
  },
  async execute(args: { platform?: string; since_version?: string }, ctx: ToolContext): Promise<ToolResult> {
    const platforms = args.platform ? [args.platform] : ["windows", "linux", "macos"];

    const capabilities = platforms.flatMap(p => {
      const caps = NEW_CAPABILITIES[p] || [];
      return caps.map(c => {
        const entries = ctx.knowledgeBase.lookupBinary(c.binary);
        return {
          ...c,
          platform: p,
          hasLolEntry: entries.length > 0,
          functions: entries.length > 0 ? entries[0].functions : [],
          stealthScore: entries.length > 0 ? entries[0].stealthScore : null,
        };
      });
    });

    return json({
      newCapabilities: capabilities,
      totalNew: capabilities.length,
      withLolEntries: capabilities.filter(c => c.hasLolEntry).length,
      insight: "New binaries in modern OS versions expand LOL attack surface. These are often less monitored by legacy detection rules.",
    });
  },
};

export const osVersionsTools: ToolDef[] = [
  osver_binary_behavior_diff,
  osver_technique_validity,
  osver_deprecation,
  osver_new_capabilities,
];
