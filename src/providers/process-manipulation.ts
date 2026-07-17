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

interface ProcessTechnique {
  technique: string;
  description: string;
  platform: Platform;
  binary: string;
  command_template: string;
  stealth_score: number;
  attck_ids: string[];
  detection_notes: string;
}

// ── proc_parent_spoof ───────────────────────────────────────────────────────

const proc_parent_spoof: ToolDef = {
  name: "proc_parent_spoof",
  description: "Parent PID spoofing techniques — CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS on Windows, fork manipulation on Linux",
  schema: {
    platform: z.enum(["linux", "windows", "macos"]).default("windows").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const plat: Platform = args.platform;
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1134", plat));

    const techniques: ProcessTechnique[] = [
      {
        technique: "PPID Spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
        description: "Use UpdateProcThreadAttribute with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to set an arbitrary parent process, evading parent-child relationship detection",
        platform: "windows", binary: "CreateProcess API",
        command_template: "InitializeProcThreadAttributeList -> UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, hParent) -> CreateProcessW",
        stealth_score: 3, attck_ids: ["T1055", "T1134.004"],
        detection_notes: "Monitor for processes where PPID does not match expected parent. Sysmon Event ID 1 logs parent PID. ETW traces reveal attribute list manipulation.",
      },
      {
        technique: "Linux fork/exec PPID manipulation",
        description: "Use double-fork technique or prctl(PR_SET_PDEATHSIG) to reparent child processes under init/systemd, obscuring true process lineage",
        platform: "linux", binary: "fork",
        command_template: "fork() -> setsid() -> fork() -> exec(target) // orphan reparented to init",
        stealth_score: 2, attck_ids: ["T1055", "T1134"],
        detection_notes: "Audit process trees with auditd. Monitor for double-fork patterns. Check /proc/<pid>/status for PPid mismatches.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === plat);

    return json({
      technique: "parent_pid_spoofing", total_techniques: filtered.length,
      platform: plat, techniques: filtered,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── proc_hollowing ──────────────────────────────────────────────────────────

const proc_hollowing: ToolDef = {
  name: "proc_hollowing",
  description: "Process hollowing techniques — NtUnmapViewOfSection + WriteProcessMemory to replace legitimate process memory with malicious code",
  schema: {
    platform: z.enum(["linux", "windows", "macos"]).default("windows").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const plat: Platform = args.platform;
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1055.012", plat));

    const techniques: ProcessTechnique[] = [
      {
        technique: "Classic Process Hollowing (RunPE)",
        description: "Create a suspended legitimate process (e.g., svchost.exe), unmap its image with NtUnmapViewOfSection, write malicious PE into the hollowed memory, then resume execution",
        platform: "windows", binary: "svchost.exe",
        command_template: "CreateProcess(SUSPENDED) -> NtUnmapViewOfSection -> VirtualAllocEx -> WriteProcessMemory -> SetThreadContext -> ResumeThread",
        stealth_score: 3, attck_ids: ["T1055.012"],
        detection_notes: "Monitor NtUnmapViewOfSection calls. Detect memory region with PAGE_EXECUTE_READWRITE in suspended processes. Sysmon Event 8 (CreateRemoteThread).",
      },
      {
        technique: "Linux ptrace-based hollowing",
        description: "Attach to a running process via ptrace, overwrite its text segment with new executable code, and detach to let it continue with modified instructions",
        platform: "linux", binary: "ptrace",
        command_template: "ptrace(PTRACE_ATTACH) -> PTRACE_POKETEXT (overwrite .text) -> PTRACE_SETREGS -> PTRACE_DETACH",
        stealth_score: 2, attck_ids: ["T1055.012", "T1055.008"],
        detection_notes: "Monitor ptrace syscalls via auditd. Check /proc/<pid>/maps for unexpected memory regions. YAMA ptrace_scope mitigates.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === plat);

    return json({
      technique: "process_hollowing", total_techniques: filtered.length,
      platform: plat, techniques: filtered,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── proc_injection_lol ──────────────────────────────────────────────────────

const proc_injection_lol: ToolDef = {
  name: "proc_injection_lol",
  description: "LOL binary-assisted process injection — using signed Microsoft binaries like mavinject.exe and Register-CimProvider.exe to inject DLLs into running processes",
  schema: {
    platform: z.enum(["linux", "windows", "macos"]).default("windows").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const plat: Platform = args.platform;
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("inject", plat));

    const techniques: ProcessTechnique[] = [
      {
        technique: "mavinject.exe DLL injection",
        description: "Use the signed Microsoft binary mavinject.exe to inject a DLL into a running process, bypassing application whitelisting",
        platform: "windows", binary: "mavinject.exe",
        command_template: "mavinject.exe <PID> /INJECTRUNNING <path\\to\\payload.dll>",
        stealth_score: 4, attck_ids: ["T1055.001", "T1218"],
        detection_notes: "Monitor mavinject.exe execution. Sigma rule: win_susp_mavinject. Sysmon Event ID 7 (DLL load) from injected process.",
      },
      {
        technique: "Register-CimProvider.exe DLL loading",
        description: "Use Register-CimProvider.exe to load an arbitrary DLL as a WMI provider, achieving code execution via a signed binary",
        platform: "windows", binary: "Register-CimProvider.exe",
        command_template: "Register-CimProvider.exe -Path <payload.dll>",
        stealth_score: 4, attck_ids: ["T1055.001", "T1218"],
        detection_notes: "Monitor Register-CimProvider.exe process creation. Unusual DLL paths indicate abuse. Check WMI provider registrations.",
      },
      {
        technique: "Linux LD_PRELOAD injection into process",
        description: "Set LD_PRELOAD before executing a target binary to force-load a shared library containing hook functions into the process address space",
        platform: "linux", binary: "ld.so",
        command_template: "LD_PRELOAD=/path/to/hook.so /usr/bin/target_binary",
        stealth_score: 2, attck_ids: ["T1055.009", "T1574.006"],
        detection_notes: "Monitor /etc/ld.so.preload and LD_PRELOAD env var. Audit library loads via auditd or strace.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === plat);

    return json({
      technique: "lol_binary_injection", total_techniques: filtered.length,
      platform: plat, techniques: filtered,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── proc_doppelganging ──────────────────────────────────────────────────────

const proc_doppelganging: ToolDef = {
  name: "proc_doppelganging",
  description: "Process doppelganging techniques — use NTFS Transactional (TxF) APIs to create a process from a transacted file that is never committed to disk",
  schema: {
    platform: z.enum(["linux", "windows"]).default("windows").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const plat: Platform = args.platform;
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1055.013", plat));

    const techniques: ProcessTechnique[] = [
      {
        technique: "TxF Process Doppelganging",
        description: "Create an NTFS transaction, write malicious payload into the transacted file, create a process section from it, then rollback the transaction so the file never appears on disk",
        platform: "windows", binary: "ntdll.dll",
        command_template: "NtCreateTransaction -> CreateFileTransacted -> WriteFile(payload) -> NtCreateSection(SEC_IMAGE) -> RollbackTransaction -> NtCreateProcessEx",
        stealth_score: 2, attck_ids: ["T1055.013"],
        detection_notes: "Monitor TxF API usage (NtCreateTransaction, CreateFileTransacted). Kernel callbacks for section creation from transacted files. Most EDRs now detect this pattern.",
      },
      {
        technique: "Linux memfd_create process execution",
        description: "Create an anonymous in-memory file via memfd_create, write executable content to it, and execute it via /proc/self/fd/<fd> without touching disk — Linux analog of doppelganging",
        platform: "linux", binary: "memfd_create",
        command_template: "fd = memfd_create('payload', MFD_CLOEXEC) -> write(fd, elf_data) -> execve('/proc/self/fd/<fd>', ...)",
        stealth_score: 2, attck_ids: ["T1055.013", "T1620"],
        detection_notes: "Monitor memfd_create syscall. Detect execve on /proc/self/fd/ paths. Sysmon for Linux tracks fileless execution.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === plat);

    return json({
      technique: "process_doppelganging", total_techniques: filtered.length,
      platform: plat, techniques: filtered,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── proc_herpaderping ───────────────────────────────────────────────────────

const proc_herpaderping: ToolDef = {
  name: "proc_herpaderping",
  description: "Process herpaderping techniques — create a process from a file, then modify the file on disk before security tools can scan it, causing a mismatch between executed code and scanned content",
  schema: {
    platform: z.enum(["windows"]).describe("Target platform (Windows only)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("herpaderping", "windows"));

    const techniques: ProcessTechnique[] = [
      {
        technique: "Process Herpaderping",
        description: "Write malicious PE to a file, create a section and process from it, then overwrite the file on disk with a benign PE before the AV/EDR can scan it. The process runs malicious code but the on-disk file appears clean",
        platform: "windows", binary: "CreateProcess API",
        command_template: "CreateFile -> WriteFile(malicious_pe) -> NtCreateSection -> NtCreateProcessEx -> WriteFile(benign_pe) -> NtCreateThreadEx",
        stealth_score: 2, attck_ids: ["T1055", "T1036.005"],
        detection_notes: "Monitor for file modifications between NtCreateSection and NtCreateThreadEx. Kernel callback PsSetCreateProcessNotifyRoutine sees the modified (benign) file. ETW can correlate file writes with process creation.",
      },
      {
        technique: "Process Ghosting (variant)",
        description: "Mark the file for deletion before creating a process image section from it. The file is deleted but the mapped section remains valid for process creation, leaving no artifact on disk",
        platform: "windows", binary: "NtSetInformationFile",
        command_template: "CreateFile -> WriteFile(payload) -> NtSetInformationFile(FileDispositionInformation, DELETE) -> NtCreateSection -> CloseHandle(file deleted) -> NtCreateProcessEx",
        stealth_score: 1, attck_ids: ["T1055", "T1070.004"],
        detection_notes: "Monitor for delete-on-close followed by section creation. Minifilter drivers can intercept pending-delete state. Windows Defender detects this pattern since late 2021.",
      },
    ];

    return json({
      technique: "process_herpaderping", total_techniques: techniques.length,
      platform: "windows", techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const processManipulationTools: ToolDef[] = [
  proc_parent_spoof,
  proc_hollowing,
  proc_injection_lol,
  proc_doppelganging,
  proc_herpaderping,
];
