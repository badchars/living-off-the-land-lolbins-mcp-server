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

interface DllHijackTechnique {
  technique: string;
  description: string;
  platform: "windows";
  binary: string;
  dll_name: string;
  command: string;
  stealth_score: number;
  attck_ids: string[];
  detection_notes: string;
}

// ── dll_search_order ────────────────────────────────────────────────────────

const dll_search_order: ToolDef = {
  name: "dll_search_order",
  description: "DLL search order hijacking info — explains the Windows DLL search order and how attackers exploit it to load malicious DLLs",
  schema: {
    application: z.string().optional().describe("Target application name to check for DLL search order vulnerabilities"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const app = args.application;
    const kbEntries = deduplicateByBinary(
      app
        ? ctx.knowledgeBase.searchByKeyword(app, "windows")
        : ctx.knowledgeBase.searchByAttck("T1574.001", "windows"),
    );

    const techniques: DllHijackTechnique[] = [
      {
        technique: "Standard DLL search order hijack",
        description: "Windows searches for DLLs in this order: (1) application directory, (2) system directory, (3) 16-bit system directory, (4) Windows directory, (5) current directory, (6) PATH directories. Placing a malicious DLL earlier in the search order hijacks the load",
        platform: "windows", binary: app || "any_application.exe",
        dll_name: "target.dll",
        command: "copy payload.dll <app_directory>\\target.dll",
        stealth_score: 3, attck_ids: ["T1574.001"],
        detection_notes: "Sysmon Event 7 (ImageLoaded) with unsigned DLLs in application directories. Monitor for DLL loads from writable locations. Process Monitor reveals DLL search order.",
      },
      {
        technique: "KnownDLLs bypass",
        description: "The KnownDLLs registry key (HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs) protects certain DLLs from search order hijacking by forcing them to load from System32. DLLs NOT in this list are vulnerable",
        platform: "windows", binary: app || "explorer.exe",
        dll_name: "unlisted.dll",
        command: "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs\"",
        stealth_score: 3, attck_ids: ["T1574.001"],
        detection_notes: "Enumerate KnownDLLs to identify unprotected DLLs. Monitor DLL loads from non-System32 paths for DLLs that should be system-provided.",
      },
    ];

    return json({
      technique: "dll_search_order", total_techniques: techniques.length,
      platform: "windows",
      target_application: app || "generic",
      search_order: [
        "1. Directory of the application",
        "2. C:\\Windows\\System32",
        "3. C:\\Windows\\System (16-bit)",
        "4. C:\\Windows",
        "5. Current working directory",
        "6. Directories in PATH",
      ],
      techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── dll_known_vulnerable ────────────────────────────────────────────────────

const dll_known_vulnerable: ToolDef = {
  name: "dll_known_vulnerable",
  description: "Known DLL hijack-vulnerable applications — returns a catalog of applications with documented DLL hijacking vulnerabilities",
  schema: {
    application: z.string().optional().describe("Filter by specific application name"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const app = args.application;
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1574.001", "windows"));

    const vulnerableApps: DllHijackTechnique[] = [
      {
        technique: "OneDrive DLL hijack (secur32.dll)",
        description: "Microsoft OneDrive's user-space installation loads secur32.dll from its application directory before System32, allowing a user-writable hijack without admin privileges",
        platform: "windows", binary: "OneDrive.exe",
        dll_name: "secur32.dll",
        command: "copy payload.dll \"%LOCALAPPDATA%\\Microsoft\\OneDrive\\secur32.dll\"",
        stealth_score: 3, attck_ids: ["T1574.001", "T1547.001"],
        detection_notes: "Monitor DLL loads by OneDrive.exe from non-System32 paths. Sysmon Event 7. OneDrive runs at logon, providing persistence.",
      },
      {
        technique: "Teams DLL hijack (dbghelp.dll)",
        description: "Microsoft Teams loads dbghelp.dll from its application directory, which is user-writable, enabling user-level DLL hijacking and persistence",
        platform: "windows", binary: "Teams.exe",
        dll_name: "dbghelp.dll",
        command: "copy payload.dll \"%LOCALAPPDATA%\\Microsoft\\Teams\\current\\dbghelp.dll\"",
        stealth_score: 3, attck_ids: ["T1574.001", "T1547.001"],
        detection_notes: "Monitor DLL loads in Teams directory. Signature verification on loaded DLLs. Teams auto-starts providing persistence vector.",
      },
      {
        technique: "BGInfo DLL hijack (various)",
        description: "Sysinternals BGInfo loads multiple DLLs from its current directory. When run from a writable location, multiple DLLs can be hijacked",
        platform: "windows", binary: "bginfo.exe",
        dll_name: "Riched32.dll",
        command: "copy payload.dll <bginfo_dir>\\Riched32.dll",
        stealth_score: 3, attck_ids: ["T1574.001"],
        detection_notes: "Monitor bginfo.exe DLL loads from non-standard paths. Often used in logon scripts, making it a persistence mechanism.",
      },
    ];

    const filtered = app
      ? vulnerableApps.filter(t => t.binary.toLowerCase().includes(app.toLowerCase()))
      : vulnerableApps;

    return json({
      technique: "known_vulnerable_apps", total_techniques: filtered.length,
      platform: "windows",
      filter: app || "all",
      techniques: filtered,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── dll_phantom ─────────────────────────────────────────────────────────────

const dll_phantom: ToolDef = {
  name: "dll_phantom",
  description: "Phantom DLL loading technique — exploit applications that attempt to load DLLs that do not exist on the system, placing a malicious DLL with the expected name",
  schema: {},
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1574.001", "windows"));

    const techniques: DllHijackTechnique[] = [
      {
        technique: "Phantom DLL via missing system DLL",
        description: "Some Windows binaries attempt to load DLLs that do not exist on the system (e.g., removed in newer Windows versions). Placing a malicious DLL with that name in the search path causes it to be loaded",
        platform: "windows", binary: "various",
        dll_name: "phoneinfo.dll",
        command: "copy payload.dll C:\\Windows\\System32\\phoneinfo.dll",
        stealth_score: 2, attck_ids: ["T1574.001"],
        detection_notes: "Monitor for creation of DLLs that do not ship with the OS version. Process Monitor NAME_NOT_FOUND results reveal phantom DLL candidates.",
      },
      {
        technique: "Phantom DLL via optional feature DLL",
        description: "Applications may attempt to load optional extension DLLs. If the DLL does not exist but the application handles the failure gracefully, an attacker can supply the DLL to gain code execution",
        platform: "windows", binary: "various",
        dll_name: "wlanapi.dll",
        command: "copy payload.dll <app_directory>\\wlanapi.dll",
        stealth_score: 2, attck_ids: ["T1574.001"],
        detection_notes: "Use Process Monitor to identify NAME_NOT_FOUND DLL load attempts. These phantom DLLs are high-value hijack targets since no legitimate DLL is displaced.",
      },
    ];

    return json({
      technique: "phantom_dll", total_techniques: techniques.length,
      platform: "windows",
      methodology: "Use Process Monitor filter: Operation=LoadImage, Result=NAME NOT FOUND to discover phantom DLL candidates",
      techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── dll_sideload_candidates ─────────────────────────────────────────────────

const dll_sideload_candidates: ToolDef = {
  name: "dll_sideload_candidates",
  description: "DLL sideloading candidates — lists known signed Microsoft and third-party binaries vulnerable to DLL sideloading for defense evasion",
  schema: {},
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1574.002", "windows"));

    const techniques: DllHijackTechnique[] = [
      {
        technique: "Signed binary DLL sideloading (Notepad++ GUP.exe)",
        description: "GUP.exe (Generic Updater) shipped with Notepad++ is signed and loads libcurl.dll from its directory. Placing a malicious libcurl.dll next to a copy of GUP.exe achieves signed binary sideloading",
        platform: "windows", binary: "GUP.exe",
        dll_name: "libcurl.dll",
        command: "copy GUP.exe C:\\staging\\ && copy payload.dll C:\\staging\\libcurl.dll && C:\\staging\\GUP.exe",
        stealth_score: 2, attck_ids: ["T1574.002", "T1036.005"],
        detection_notes: "Monitor GUP.exe running outside Notepad++ directory. Verify libcurl.dll signature. Sysmon Event 7 with mismatched signatures.",
      },
      {
        technique: "Signed binary DLL sideloading (WinSCP winscpcominterop.dll)",
        description: "WinSCP.exe (signed) loads winscpcominterop.dll from its directory. Copying the signed binary to a writable location with a malicious DLL enables sideloading",
        platform: "windows", binary: "WinSCP.exe",
        dll_name: "winscpcominterop.dll",
        command: "copy WinSCP.exe C:\\staging\\ && copy payload.dll C:\\staging\\winscpcominterop.dll && C:\\staging\\WinSCP.exe",
        stealth_score: 2, attck_ids: ["T1574.002", "T1036.005"],
        detection_notes: "Monitor WinSCP.exe running from non-standard paths. Check loaded DLL signatures. Application whitelisting by path is ineffective.",
      },
      {
        technique: "Signed binary DLL sideloading (Sumatra PDF libmupdf.dll)",
        description: "SumatraPDF.exe is a signed reader that loads libmupdf.dll from its directory, making it a candidate for DLL sideloading via signed binary abuse",
        platform: "windows", binary: "SumatraPDF.exe",
        dll_name: "libmupdf.dll",
        command: "copy SumatraPDF.exe C:\\staging\\ && copy payload.dll C:\\staging\\libmupdf.dll && C:\\staging\\SumatraPDF.exe",
        stealth_score: 2, attck_ids: ["T1574.002"],
        detection_notes: "Monitor SumatraPDF.exe in non-standard directories. Verify DLL signatures match expected publisher. Hash-based whitelisting is more effective.",
      },
    ];

    return json({
      technique: "dll_sideloading", total_techniques: techniques.length,
      platform: "windows", techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── dll_proxying ────────────────────────────────────────────────────────────

const dll_proxying: ToolDef = {
  name: "dll_proxying",
  description: "DLL proxying technique — create a malicious DLL that forwards all exports to the legitimate DLL while executing additional code, maintaining application functionality",
  schema: {},
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByAttck("T1574.002", "windows"));

    const techniques: DllHijackTechnique[] = [
      {
        technique: "DLL export forwarding (linker-based proxy)",
        description: "Create a proxy DLL with a .def file that forwards all exports to the original DLL using #pragma comment(linker, '/export:FuncName=original.FuncName'). The proxy DLL adds malicious code in DllMain while preserving all original functionality",
        platform: "windows", binary: "cl.exe / link.exe",
        dll_name: "proxy_target.dll",
        command: "#pragma comment(linker, \"/export:ExportedFunc=original.ExportedFunc\") // for each export",
        stealth_score: 1, attck_ids: ["T1574.002", "T1574.001"],
        detection_notes: "Monitor DLLs with export forwarding to unexpected paths. Compare DLL exports against known-good baselines. Unsigned proxy DLLs are suspicious.",
      },
      {
        technique: "DLL proxying via LoadLibrary chain",
        description: "The malicious DLL loads the legitimate DLL via LoadLibrary in DllMain, resolves all original exports via GetProcAddress, and provides wrapper functions that call through to the originals while executing malicious code",
        platform: "windows", binary: "any_application.exe",
        dll_name: "proxy_target.dll",
        command: "DllMain: hOriginal = LoadLibrary('original_target.dll'); // resolve + wrap each export",
        stealth_score: 1, attck_ids: ["T1574.002"],
        detection_notes: "Monitor for DLLs that immediately load another DLL with a similar name. Double-DLL load patterns are suspicious. Memory analysis reveals proxy chains.",
      },
    ];

    return json({
      technique: "dll_proxying", total_techniques: techniques.length,
      platform: "windows",
      methodology: "Use dumpbin /exports to enumerate target DLL exports, then generate a proxy .def file forwarding all exports to the renamed original DLL",
      techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── dll_hijack_validate ─────────────────────────────────────────────────────

const dll_hijack_validate: ToolDef = {
  name: "dll_hijack_validate",
  description: "DLL hijack validation methodology — steps to identify and validate DLL hijacking opportunities in a target application",
  schema: {
    application: z.string().optional().describe("Target application to validate for DLL hijack"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const app = args.application;
    const kbEntries = deduplicateByBinary(
      app
        ? ctx.knowledgeBase.searchByKeyword(app, "windows")
        : ctx.knowledgeBase.searchByAttck("T1574.001", "windows"),
    );

    const techniques: DllHijackTechnique[] = [
      {
        technique: "Process Monitor DLL discovery",
        description: "Use Sysinternals Process Monitor to identify DLL load attempts by the target application. Filter for LoadImage operations with NAME NOT FOUND results to find phantom DLLs, and SUCCESS results from writable paths to find hijack candidates",
        platform: "windows", binary: "procmon.exe",
        dll_name: "discovery phase",
        command: "procmon.exe /AcceptEula /Quiet /BackingFile C:\\log.pml -- Filter: Process Name is <app>, Operation is CreateFile, Path contains .dll",
        stealth_score: 1, attck_ids: ["T1574.001", "T1574.002"],
        detection_notes: "Process Monitor is a legitimate admin tool. No detection needed for discovery phase. Validation should be performed in an isolated lab environment.",
      },
      {
        technique: "DLL hijack proof-of-concept validation",
        description: "Create a minimal DLL that writes to a file or shows a MessageBox in DllMain to confirm code execution. Place it in the identified hijack location and launch the target application to verify the hijack",
        platform: "windows", binary: app || "target.exe",
        dll_name: "test_hijack.dll",
        command: "cl.exe /LD test_dll.c /Fe:hijack_target.dll // DllMain writes 'hijacked' to C:\\poc.txt",
        stealth_score: 1, attck_ids: ["T1574.001"],
        detection_notes: "PoC DLL should only perform benign confirmation (file write, MessageBox). Validate in sandbox environment. Document writable paths and loaded DLL list.",
      },
    ];

    return json({
      technique: "dll_hijack_validation", total_techniques: techniques.length,
      platform: "windows",
      target_application: app || "generic",
      validation_steps: [
        "1. Launch Process Monitor and set filter: Process Name = target, Path contains .dll",
        "2. Start the target application and capture DLL load events",
        "3. Identify NAME_NOT_FOUND results (phantom DLLs) and loads from writable paths",
        "4. Check if the application directory is user-writable (icacls <path>)",
        "5. Verify the DLL is not in the KnownDLLs list",
        "6. Create a PoC DLL with DllMain confirmation and place it in the hijack path",
        "7. Restart the application and verify code execution",
        "8. Document the DLL name, path, and execution context",
      ],
      techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const dllHijackTools: ToolDef[] = [
  dll_search_order,
  dll_known_vulnerable,
  dll_phantom,
  dll_sideload_candidates,
  dll_proxying,
  dll_hijack_validate,
];
