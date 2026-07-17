import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform } from "../schema/unified-entry.js";

// ━━━ Helpers ━━━

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
    tactics: e.tactics ?? [],
  };
}

// ━━━ Hardcoded TCC Bypass Technique Data ━━━

interface TccBypassTechnique {
  name: string;
  description: string;
  tccPermission: string;
  binary: string;
  command: string;
  prerequisites: string[];
  cves: string[];
  attck: string[];
  detectionNotes: string;
  stealthScore: number;
}

const TCC_BYPASSES: TccBypassTechnique[] = [
  {
    name: "TCC.db Direct Manipulation",
    description: "Directly modify the TCC.db SQLite database to grant permissions without user consent",
    tccPermission: "Full Disk Access",
    binary: "sqlite3",
    command: "sqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db \"INSERT INTO access VALUES('kTCCServiceAccessibility','com.malicious.app',0,2,4,1,NULL,NULL,0,NULL,NULL,0,0);\"",
    prerequisites: ["Full Disk Access or SIP disabled", "Write access to TCC.db"],
    cves: ["CVE-2020-9934", "CVE-2023-32364"],
    attck: ["T1548", "T1222.002"],
    detectionNotes: "Monitor TCC.db modifications. Audit sqlite3 access to TCC.db path. Endpoint security framework.",
    stealthScore: 2,
  },
  {
    name: "FDA via Terminal Emulator",
    description: "Abuse terminal emulator FDA entitlement to access TCC-protected locations",
    tccPermission: "Full Disk Access (inherited)",
    binary: "Terminal.app",
    command: "# Any command run in a terminal with FDA inherits the permission\ncat ~/Library/Mail/V*/MailData/Accounts.plist",
    prerequisites: ["Terminal app with Full Disk Access granted"],
    cves: [],
    attck: ["T1548"],
    detectionNotes: "Monitor Terminal/iTerm2 accessing TCC-protected paths. Check FDA grants in TCC.db.",
    stealthScore: 1,
  },
  {
    name: "Automation to Accessibility",
    description: "Abuse Automation permission to grant Accessibility permission via AppleScript",
    tccPermission: "Accessibility",
    binary: "osascript",
    command: "osascript -e 'tell application \"System Events\" to keystroke \"hello\"'",
    prerequisites: ["Automation permission for System Events"],
    cves: [],
    attck: ["T1059.002", "T1548"],
    detectionNotes: "Monitor osascript controlling System Events. Audit Automation permission grants.",
    stealthScore: 2,
  },
  {
    name: "Mount Point FDA Bypass",
    description: "Create a synthetic mount point to bypass TCC file access restrictions",
    tccPermission: "Full Disk Access",
    binary: "mount",
    command: "# Create APFS snapshot and mount at alternate path\nmount -t apfs -o nobrowse /dev/disk1s1 /tmp/tcc_bypass",
    prerequisites: ["Root privileges or SIP disabled"],
    cves: ["CVE-2020-9771"],
    attck: ["T1548", "T1006"],
    detectionNotes: "Monitor mount operations with nobrowse. Check for synthetic mount points.",
    stealthScore: 2,
  },
  {
    name: "Finder AppleScript Abuse",
    description: "Use Finder via AppleScript to access TCC-protected files since Finder has implicit FDA",
    tccPermission: "Full Disk Access (via Finder)",
    binary: "osascript",
    command: "osascript -e 'tell application \"Finder\" to duplicate (POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\") to (POSIX file \"/tmp/\")'",
    prerequisites: ["Automation permission for Finder"],
    cves: [],
    attck: ["T1059.002", "T1548"],
    detectionNotes: "Monitor osascript controlling Finder for file operations. Audit Automation grants.",
    stealthScore: 2,
  },
];

interface EntitlementAbuse {
  entitlement: string;
  description: string;
  binary: string;
  abuseScenario: string;
  attck: string[];
  detectionNotes: string;
}

const ENTITLEMENT_ABUSES: EntitlementAbuse[] = [
  {
    entitlement: "com.apple.security.cs.allow-dyld-environment-variables",
    description: "Allows DYLD_INSERT_LIBRARIES injection into the entitled process",
    binary: "(various entitled apps)",
    abuseScenario: "DYLD_INSERT_LIBRARIES=/path/to/malicious.dylib /Applications/EntitledApp.app/Contents/MacOS/EntitledApp",
    attck: ["T1574.006"],
    detectionNotes: "Monitor DYLD_INSERT_LIBRARIES environment variable. Audit dylib loads.",
  },
  {
    entitlement: "com.apple.security.cs.disable-library-validation",
    description: "Allows loading unsigned or non-Apple dylibs into the process",
    binary: "(various entitled apps)",
    abuseScenario: "Inject unsigned dylib into process with this entitlement to inherit TCC permissions",
    attck: ["T1574.006"],
    detectionNotes: "Monitor unsigned dylib loads. Check process entitlements with codesign.",
  },
  {
    entitlement: "com.apple.private.tcc.allow",
    description: "Private Apple entitlement that grants TCC permissions without user consent",
    binary: "Apple system binaries",
    abuseScenario: "Abuse Apple binaries with this entitlement to perform TCC-protected operations",
    attck: ["T1548"],
    detectionNotes: "Audit binaries with private TCC entitlements. Monitor their child processes.",
  },
  {
    entitlement: "com.apple.rootless.install.heritable",
    description: "Heritable SIP exemption that passes to child processes",
    binary: "Installer-related Apple binaries",
    abuseScenario: "Spawn child process from entitled parent to inherit SIP bypass capability",
    attck: ["T1548", "T1068"],
    detectionNotes: "Monitor process trees from SIP-exempt parents. Audit heritable entitlements.",
  },
];

interface SipBypass {
  name: string;
  description: string;
  method: string;
  cves: string[];
  attck: string[];
  detectionNotes: string;
}

const SIP_BYPASSES: SipBypass[] = [
  {
    name: "Installer Package SIP Bypass",
    description: "Abuse Apple signed installer packages with post-install scripts to write to SIP-protected paths",
    method: "Create .pkg with post-install script that runs in SIP-exempt context",
    cves: ["CVE-2022-22583"],
    attck: ["T1548", "T1068"],
    detectionNotes: "Monitor pkg installs and post-install script execution.",
  },
  {
    name: "Migration Assistant Abuse",
    description: "Abuse Migration Assistant process which runs with SIP exemptions",
    method: "Inject into or abuse Migration Assistant's privileged execution context",
    cves: ["CVE-2023-32369"],
    attck: ["T1548", "T1068"],
    detectionNotes: "Monitor Migration Assistant spawning unexpected child processes.",
  },
  {
    name: "systemmigrationd Exploit",
    description: "Abuse systemmigrationd's SIP-exempt entitlements for filesystem manipulation",
    method: "Trigger systemmigrationd with crafted migration data to write SIP-protected files",
    cves: ["CVE-2023-32369"],
    attck: ["T1548"],
    detectionNotes: "Monitor systemmigrationd file operations outside normal migration.",
  },
];

interface GatekeeperBypass {
  name: string;
  description: string;
  method: string;
  command: string;
  attck: string[];
  detectionNotes: string;
}

const GATEKEEPER_BYPASSES: GatekeeperBypass[] = [
  {
    name: "Quarantine Attribute Removal",
    description: "Remove the com.apple.quarantine extended attribute to bypass Gatekeeper checks",
    method: "Strip quarantine xattr from downloaded files",
    command: "xattr -d com.apple.quarantine /path/to/downloaded.app",
    attck: ["T1553.001"],
    detectionNotes: "Monitor xattr removal operations. Audit quarantine attribute changes.",
  },
  {
    name: "Archive/DMG without Quarantine",
    description: "Use archive tools that don't preserve quarantine attributes",
    method: "Extract with tools that strip quarantine (some unzip implementations)",
    command: "# Certain archivers like ditto may not propagate quarantine to extracted files",
    attck: ["T1553.001"],
    detectionNotes: "Monitor extraction tools and check quarantine propagation.",
  },
  {
    name: "Safari Auto-Open Abuse",
    description: "Abuse Safari's auto-open for safe file types to execute without Gatekeeper prompt",
    method: "Deliver payload as a file type Safari considers safe and auto-opens",
    command: "# Package payload in a format Safari auto-opens (e.g., .webarchive, .terminal)",
    attck: ["T1553.001", "T1204.002"],
    detectionNotes: "Monitor Safari auto-open behavior. Audit .terminal and .webarchive file creation.",
  },
  {
    name: "AppleDouble Format Bypass",
    description: "Use AppleDouble file format to deliver payloads that bypass Gatekeeper scanning",
    method: "Create files in AppleDouble format that are not fully scanned by Gatekeeper",
    command: "# Craft AppleDouble file with payload in resource fork",
    attck: ["T1553.001"],
    detectionNotes: "Monitor for AppleDouble file creation. Check resource fork contents.",
  },
];

// ━━━ Tools ━━━

const tcc_bypass_technique: ToolDef = {
  name: "tcc_bypass_technique",
  description: "Find macOS TCC (Transparency, Consent, and Control) bypass techniques for protected resource access",
  schema: {
    permission: z.string().optional()
      .describe("Filter by TCC permission type (e.g. 'Full Disk Access', 'Accessibility', 'Camera')"),
    keyword: z.string().optional()
      .describe("Keyword to search bypass techniques (e.g. 'TCC.db', 'osascript', 'Finder')"),
  },
  async execute(args: { permission?: string; keyword?: string }, ctx: ToolContext): Promise<ToolResult> {
    let bypasses = [...TCC_BYPASSES];

    if (args.permission) {
      const perm = args.permission.toLowerCase();
      bypasses = bypasses.filter(b => b.tccPermission.toLowerCase().includes(perm));
    }
    if (args.keyword) {
      const kw = args.keyword.toLowerCase();
      bypasses = bypasses.filter(b =>
        b.name.toLowerCase().includes(kw) ||
        b.description.toLowerCase().includes(kw) ||
        b.binary.toLowerCase().includes(kw) ||
        b.command.toLowerCase().includes(kw),
      );
    }

    // Search LOOBins catalog for macOS entries
    const loobinEntries = ctx.knowledgeBase.searchByCatalog("loobins");
    const tccRelated = deduplicateByBinary(
      loobinEntries.filter(e =>
        e.description.toLowerCase().includes("tcc") ||
        e.description.toLowerCase().includes("privacy") ||
        (e.tactics ?? []).some((t: string) => t.toLowerCase().includes("defense evasion")),
      ),
    );

    return json({
      total_bypasses: bypasses.length,
      bypasses: bypasses.map(b => ({
        name: b.name,
        description: b.description,
        tcc_permission: b.tccPermission,
        binary: b.binary,
        command: b.command,
        prerequisites: b.prerequisites,
        cves: b.cves,
        attck: b.attck,
        detection_notes: b.detectionNotes,
        stealth_score: b.stealthScore,
      })),
      kb_loobin_matches: tccRelated.slice(0, 10).map(summarizeKbEntry),
      total_kb_matches: tccRelated.length,
    });
  },
};

const tcc_entitlement_abuse: ToolDef = {
  name: "tcc_entitlement_abuse",
  description: "Find macOS entitlement abuse techniques for TCC bypass via dylib injection and library validation",
  schema: {
    entitlement: z.string().optional()
      .describe("Filter by entitlement name keyword (e.g. 'dyld', 'library-validation', 'tcc')"),
  },
  async execute(args: { entitlement?: string }, ctx: ToolContext): Promise<ToolResult> {
    let abuses = [...ENTITLEMENT_ABUSES];

    if (args.entitlement) {
      const ent = args.entitlement.toLowerCase();
      abuses = abuses.filter(a =>
        a.entitlement.toLowerCase().includes(ent) ||
        a.description.toLowerCase().includes(ent),
      );
    }

    // Search KB for dylib injection related entries
    const kbEntries = deduplicateByBinary(
      ctx.knowledgeBase.searchByKeyword("dylib", "macos"),
    );

    return json({
      total_abuses: abuses.length,
      entitlement_abuses: abuses.map(a => ({
        entitlement: a.entitlement,
        description: a.description,
        binary: a.binary,
        abuse_scenario: a.abuseScenario,
        attck: a.attck,
        detection_notes: a.detectionNotes,
      })),
      kb_dylib_matches: kbEntries.slice(0, 10).map(summarizeKbEntry),
    });
  },
};

const tcc_sip_circumvent: ToolDef = {
  name: "tcc_sip_circumvent",
  description: "Find macOS System Integrity Protection (SIP) bypass and circumvention techniques",
  schema: {
    keyword: z.string().optional()
      .describe("Filter SIP bypass techniques by keyword (e.g. 'installer', 'migration', 'pkg')"),
  },
  async execute(args: { keyword?: string }, ctx: ToolContext): Promise<ToolResult> {
    let bypasses = [...SIP_BYPASSES];

    if (args.keyword) {
      const kw = args.keyword.toLowerCase();
      bypasses = bypasses.filter(b =>
        b.name.toLowerCase().includes(kw) ||
        b.description.toLowerCase().includes(kw) ||
        b.method.toLowerCase().includes(kw),
      );
    }

    // Search KB for SIP-related entries
    const kbEntries = deduplicateByBinary(
      ctx.knowledgeBase.searchByKeyword("sip", "macos"),
    );
    const installerEntries = deduplicateByBinary(
      ctx.knowledgeBase.searchByKeyword("installer", "macos"),
    );

    const seen = new Set(kbEntries.map(e => e.id));
    for (const e of installerEntries) {
      if (!seen.has(e.id)) { seen.add(e.id); kbEntries.push(e); }
    }

    return json({
      total_bypasses: bypasses.length,
      sip_bypasses: bypasses.map(b => ({
        name: b.name,
        description: b.description,
        method: b.method,
        cves: b.cves,
        attck: b.attck,
        detection_notes: b.detectionNotes,
      })),
      kb_matches: kbEntries.slice(0, 10).map(summarizeKbEntry),
    });
  },
};

const tcc_gatekeeper_bypass: ToolDef = {
  name: "tcc_gatekeeper_bypass",
  description: "Find macOS Gatekeeper bypass techniques for executing unsigned or unnotarized code",
  schema: {
    keyword: z.string().optional()
      .describe("Filter Gatekeeper bypass techniques by keyword (e.g. 'quarantine', 'xattr', 'safari')"),
  },
  async execute(args: { keyword?: string }, ctx: ToolContext): Promise<ToolResult> {
    let bypasses = [...GATEKEEPER_BYPASSES];

    if (args.keyword) {
      const kw = args.keyword.toLowerCase();
      bypasses = bypasses.filter(b =>
        b.name.toLowerCase().includes(kw) ||
        b.description.toLowerCase().includes(kw) ||
        b.method.toLowerCase().includes(kw) ||
        b.command.toLowerCase().includes(kw),
      );
    }

    // Search KB for Gatekeeper-related entries
    const kbEntries = deduplicateByBinary(
      ctx.knowledgeBase.searchByKeyword("gatekeeper", "macos"),
    );
    const xattrEntries = deduplicateByBinary(
      ctx.knowledgeBase.searchByKeyword("xattr", "macos"),
    );

    const seen = new Set(kbEntries.map(e => e.id));
    for (const e of xattrEntries) {
      if (!seen.has(e.id)) { seen.add(e.id); kbEntries.push(e); }
    }

    return json({
      total_bypasses: bypasses.length,
      gatekeeper_bypasses: bypasses.map(b => ({
        name: b.name,
        description: b.description,
        method: b.method,
        command: b.command,
        attck: b.attck,
        detection_notes: b.detectionNotes,
      })),
      kb_matches: kbEntries.slice(0, 10).map(summarizeKbEntry),
    });
  },
};

export const macosTccTools: ToolDef[] = [
  tcc_bypass_technique,
  tcc_entitlement_abuse,
  tcc_sip_circumvent,
  tcc_gatekeeper_bypass,
];
