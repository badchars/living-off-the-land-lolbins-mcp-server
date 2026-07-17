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

interface AntiforensicTechnique {
  technique: string;
  description: string;
  platform: Platform;
  binary: string;
  command: string;
  cleanup_command: string;
  stealth_score: number;
  attck_ids: string[];
  detection_notes: string;
}

// ── antiforensic_clear_logs ─────────────────────────────────────────────────

const antiforensic_clear_logs: ToolDef = {
  name: "antiforensic_clear_logs",
  description: "Log clearing techniques using native OS tools — wevtutil on Windows, journalctl vacuum on Linux, log command on macOS",
  schema: {
    platform: z.enum(["linux", "windows", "macos"]).default("linux").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const plat: Platform = args.platform;
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1070.001", plat));

    const techniques: AntiforensicTechnique[] = [
      {
        technique: "Windows Event Log clearing via wevtutil",
        description: "Use the built-in wevtutil.exe utility to clear specific Windows Event Log channels, removing forensic evidence of attacker activity",
        platform: "windows", binary: "wevtutil.exe",
        command: "wevtutil cl Security && wevtutil cl System && wevtutil cl Application",
        cleanup_command: "for /f \"tokens=*\" %i in ('wevtutil el') do wevtutil cl \"%i\"",
        stealth_score: 4, attck_ids: ["T1070.001"],
        detection_notes: "Event ID 1102 (Security log cleared) is generated even when logs are cleared. Monitor wevtutil.exe with 'cl' argument. Sysmon Event 1 for process creation.",
      },
      {
        technique: "Linux journal vacuum",
        description: "Use journalctl --vacuum-size or --vacuum-time to reduce systemd journal size, removing older log entries that may contain evidence",
        platform: "linux", binary: "journalctl",
        command: "journalctl --vacuum-size=1M",
        cleanup_command: "journalctl --vacuum-time=1h",
        stealth_score: 3, attck_ids: ["T1070.001", "T1070"],
        detection_notes: "Monitor journalctl execution with --vacuum flags. Audit /var/log/journal/ size changes. File integrity monitoring on journal files.",
      },
      {
        technique: "macOS log erase",
        description: "Use the macOS log command or direct removal of ASL/unified log files to clear system logs",
        platform: "macos", binary: "log",
        command: "sudo log erase --all",
        cleanup_command: "rm -rf /var/log/asl/*.asl",
        stealth_score: 3, attck_ids: ["T1070.001"],
        detection_notes: "Monitor 'log erase' command execution. Endpoint security tools track log deletion. File integrity monitoring on /var/log/.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === plat);

    return json({
      technique: "clear_logs", total_techniques: filtered.length,
      platform: plat, techniques: filtered,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── antiforensic_delete_artifacts ────────────────────────────────────────────

const antiforensic_delete_artifacts: ToolDef = {
  name: "antiforensic_delete_artifacts",
  description: "Artifact deletion techniques — secure file deletion using native tools like shred on Linux, SDelete on Windows, and srm on macOS",
  schema: {
    platform: z.enum(["linux", "windows", "macos"]).default("linux").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const plat: Platform = args.platform;
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1070.004", plat));

    const techniques: AntiforensicTechnique[] = [
      {
        technique: "Linux secure deletion with shred",
        description: "Use the shred utility to overwrite files with random data multiple times before unlinking, preventing data recovery from disk",
        platform: "linux", binary: "shred",
        command: "shred -vfz -n 3 /tmp/malware.bin",
        cleanup_command: "shred -u /tmp/malware.bin",
        stealth_score: 3, attck_ids: ["T1070.004"],
        detection_notes: "Monitor shred process execution. Audit unlink syscalls on sensitive paths. File integrity monitoring detects removals but not overwrites.",
      },
      {
        technique: "Windows SDelete secure deletion",
        description: "Use Sysinternals SDelete to securely overwrite and delete files, compliant with DoD 5220.22-M clearing standard",
        platform: "windows", binary: "sdelete.exe",
        command: "sdelete -p 3 -s C:\\Users\\Public\\evidence\\",
        cleanup_command: "sdelete -c C:",
        stealth_score: 3, attck_ids: ["T1070.004"],
        detection_notes: "Monitor sdelete.exe execution. Sigma rule for SDelete usage. Detect overwrite patterns (repeated writes to same sectors). Sysmon Event 23 (FileDelete).",
      },
      {
        technique: "macOS rm with secure option",
        description: "Use rm -P on macOS for three-pass overwrite before deletion, or use tmutil to manage Time Machine snapshot evidence",
        platform: "macos", binary: "rm",
        command: "rm -Prf /tmp/evidence/",
        cleanup_command: "tmutil deletelocalsnapshots $(date +%Y-%m-%d)",
        stealth_score: 3, attck_ids: ["T1070.004"],
        detection_notes: "Monitor rm with -P flag. Track tmutil snapshot deletion. Endpoint security tools log file deletion events.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === plat);

    return json({
      technique: "delete_artifacts", total_techniques: filtered.length,
      platform: plat, techniques: filtered,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── antiforensic_timestomp ──────────────────────────────────────────────────

const antiforensic_timestomp: ToolDef = {
  name: "antiforensic_timestomp",
  description: "File timestamp manipulation (timestomping) — modify file creation, modification, and access times using native OS tools to blend in with legitimate files",
  schema: {
    platform: z.enum(["linux", "windows", "macos"]).default("linux").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const plat: Platform = args.platform;
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1070.006", plat));

    const techniques: AntiforensicTechnique[] = [
      {
        technique: "Linux touch timestomp",
        description: "Use the touch command to modify file access and modification timestamps to a specific date, blending malicious files with legitimate system files",
        platform: "linux", binary: "touch",
        command: "touch -t 202301011200.00 /tmp/implant.elf",
        cleanup_command: "touch -r /usr/bin/ls /tmp/implant.elf",
        stealth_score: 3, attck_ids: ["T1070.006"],
        detection_notes: "Compare mtime with ctime (ctime cannot be easily modified). Audit touch command execution with -t or -r flags. inode change time reveals the actual modification.",
      },
      {
        technique: "Windows PowerShell timestamp manipulation",
        description: "Use .NET System.IO.File methods in PowerShell to modify CreationTime, LastWriteTime, and LastAccessTime on Windows files",
        platform: "windows", binary: "powershell.exe",
        command: "(Get-Item C:\\payload.exe).CreationTime = '2023-01-01 12:00:00'; (Get-Item C:\\payload.exe).LastWriteTime = '2023-01-01 12:00:00'",
        cleanup_command: "[IO.File]::SetLastAccessTime('C:\\payload.exe', (Get-Date '2023-01-01'))",
        stealth_score: 3, attck_ids: ["T1070.006"],
        detection_notes: "PowerShell Script Block Logging captures timestamp manipulation. Monitor SetCreationTime/SetLastWriteTime calls. NTFS $MFT still holds original timestamps.",
      },
      {
        technique: "macOS touch reference timestamp",
        description: "Use touch -r to copy timestamps from a legitimate macOS system file to a malicious binary, matching its apparent age to surrounding files",
        platform: "macos", binary: "touch",
        command: "touch -r /usr/bin/ssh /tmp/implant",
        cleanup_command: "touch -t 202301011200 /tmp/implant",
        stealth_score: 3, attck_ids: ["T1070.006"],
        detection_notes: "Monitor touch with -r or -t flags. APFS snapshots preserve original timestamps. Endpoint security tracks file metadata changes.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === plat);

    return json({
      technique: "timestomp", total_techniques: filtered.length,
      platform: plat, techniques: filtered,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── antiforensic_disable_logging ────────────────────────────────────────────

const antiforensic_disable_logging: ToolDef = {
  name: "antiforensic_disable_logging",
  description: "Disable logging mechanisms — stop auditd, disable syslog, turn off Windows event logging, or disable macOS unified logging to prevent evidence collection",
  schema: {
    platform: z.enum(["linux", "windows", "macos"]).default("linux").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const plat: Platform = args.platform;
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1562.002", plat));

    const techniques: AntiforensicTechnique[] = [
      {
        technique: "Linux auditd disable",
        description: "Stop the auditd service and disable audit rules to prevent logging of syscalls, file access, and process execution events",
        platform: "linux", binary: "auditctl",
        command: "auditctl -e 0 && systemctl stop auditd",
        cleanup_command: "auditctl -D",
        stealth_score: 2, attck_ids: ["T1562.002", "T1562.001"],
        detection_notes: "Auditd stopping generates its own event. Monitor auditctl -e 0 and service stop commands. Remote syslog servers retain forwarded logs.",
      },
      {
        technique: "Windows disable event logging service",
        description: "Stop the Windows Event Log service to prevent all event logging, or use auditpol to disable specific audit categories",
        platform: "windows", binary: "auditpol.exe",
        command: "auditpol /set /category:* /success:disable /failure:disable",
        cleanup_command: "net stop EventLog",
        stealth_score: 2, attck_ids: ["T1562.002"],
        detection_notes: "Event ID 4719 (audit policy change) is logged before the policy is disabled. Monitor auditpol.exe execution. EDR operates independently of Windows Event Log.",
      },
      {
        technique: "macOS disable unified logging",
        description: "Modify logging configuration profiles or stop syslogd to reduce macOS log collection. Use log config to adjust subsystem log levels",
        platform: "macos", binary: "log",
        command: "sudo log config --mode 'level:off' --subsystem com.apple.security",
        cleanup_command: "sudo log config --reset --subsystem com.apple.security",
        stealth_score: 2, attck_ids: ["T1562.002"],
        detection_notes: "Monitor 'log config' command execution with --mode level:off. Endpoint security detects logging subsystem changes. SIP protects core logging infrastructure.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === plat);

    return json({
      technique: "disable_logging", total_techniques: filtered.length,
      platform: plat, techniques: filtered,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── antiforensic_cover_tracks ───────────────────────────────────────────────

const antiforensic_cover_tracks: ToolDef = {
  name: "antiforensic_cover_tracks",
  description: "General track covering techniques — clear shell history, remove temporary files, unset environment variables that record command history",
  schema: {
    platform: z.enum(["linux", "windows", "macos"]).default("linux").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const plat: Platform = args.platform;
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1070.003", plat));

    const techniques: AntiforensicTechnique[] = [
      {
        technique: "Linux bash history clearing",
        description: "Unset HISTFILE and clear in-memory history to prevent command logging. Remove .bash_history and .zsh_history files",
        platform: "linux", binary: "bash",
        command: "unset HISTFILE && history -c && history -w",
        cleanup_command: "rm -f ~/.bash_history ~/.zsh_history && ln -s /dev/null ~/.bash_history",
        stealth_score: 3, attck_ids: ["T1070.003"],
        detection_notes: "Monitor for unset HISTFILE in process environment. Detect history -c execution. File integrity monitoring on history files. Symlinks to /dev/null are suspicious.",
      },
      {
        technique: "Windows PowerShell history clearing",
        description: "Clear PowerShell command history (PSReadLine) and remove the ConsoleHost_history.txt file that persists command history across sessions",
        platform: "windows", binary: "powershell.exe",
        command: "Remove-Item (Get-PSReadlineOption).HistorySavePath; Clear-History",
        cleanup_command: "Set-PSReadlineOption -HistorySaveStyle SaveNothing",
        stealth_score: 3, attck_ids: ["T1070.003"],
        detection_notes: "Monitor deletion of ConsoleHost_history.txt. PowerShell Script Block Logging captures Clear-History. Event ID 4104 logs the clearing commands themselves.",
      },
      {
        technique: "macOS zsh history clearing",
        description: "Clear zsh history on macOS by removing .zsh_history and unsetting HISTFILE in the current session",
        platform: "macos", binary: "zsh",
        command: "fc -W && rm -f ~/.zsh_history && unset HISTFILE",
        cleanup_command: "ln -sf /dev/null ~/.zsh_history",
        stealth_score: 3, attck_ids: ["T1070.003"],
        detection_notes: "Monitor for .zsh_history deletion. Endpoint security tracks HISTFILE modifications. Audit shell rc file changes for HISTSIZE=0 patterns.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === plat);

    return json({
      technique: "cover_tracks", total_techniques: filtered.length,
      platform: plat, techniques: filtered,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── antiforensic_shadow_copy ────────────────────────────────────────────────

const antiforensic_shadow_copy: ToolDef = {
  name: "antiforensic_shadow_copy",
  description: "Volume Shadow Copy manipulation — delete shadow copies using vssadmin or wmic to prevent forensic recovery of previous file versions on Windows",
  schema: {},
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("vssadmin", "windows"));

    const techniques: AntiforensicTechnique[] = [
      {
        technique: "vssadmin delete shadows",
        description: "Use vssadmin.exe to delete all volume shadow copies, preventing forensic recovery of previous file versions and ransomware decryption via shadow copies",
        platform: "windows", binary: "vssadmin.exe",
        command: "vssadmin delete shadows /all /quiet",
        cleanup_command: "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=0%",
        stealth_score: 4, attck_ids: ["T1070", "T1490"],
        detection_notes: "Monitor vssadmin.exe with 'delete shadows' arguments. Event ID 7036 (VSS service state change). Well-known ransomware indicator. Sigma rule for shadow copy deletion.",
      },
      {
        technique: "wmic shadowcopy delete",
        description: "Use wmic.exe to enumerate and delete shadow copies via WMI, an alternative to vssadmin that may bypass some detection rules",
        platform: "windows", binary: "wmic.exe",
        command: "wmic shadowcopy delete",
        cleanup_command: "wmic shadowcopy list brief",
        stealth_score: 4, attck_ids: ["T1070", "T1490"],
        detection_notes: "Monitor wmic.exe with 'shadowcopy delete' arguments. Some EDRs specifically track WMI shadow copy manipulation. Event ID 7036 for VSS service.",
      },
      {
        technique: "PowerShell shadow copy deletion",
        description: "Use PowerShell Get-WmiObject or Get-CimInstance to enumerate and delete shadow copies, bypassing command-line monitoring of vssadmin and wmic",
        platform: "windows", binary: "powershell.exe",
        command: "Get-CimInstance Win32_ShadowCopy | Remove-CimInstance",
        cleanup_command: "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }",
        stealth_score: 3, attck_ids: ["T1070", "T1490", "T1059.001"],
        detection_notes: "PowerShell Script Block Logging captures Win32_ShadowCopy queries. Monitor Remove-CimInstance and Delete() calls on shadow copy objects. Event 4104.",
      },
    ];

    return json({
      technique: "shadow_copy_manipulation", total_techniques: techniques.length,
      platform: "windows", techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const antiforensicsTools: ToolDef[] = [
  antiforensic_clear_logs,
  antiforensic_delete_artifacts,
  antiforensic_timestomp,
  antiforensic_disable_logging,
  antiforensic_cover_tracks,
  antiforensic_shadow_copy,
];
