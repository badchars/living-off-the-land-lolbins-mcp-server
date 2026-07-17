import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Discovery Technique Data ━━━

interface DiscoveryTechnique {
  name: string;
  description: string;
  binary: string;
  commandTemplate: string;
  detectionPatterns: string[];
  stealthScore: number;
  platforms: Platform[];
  attck: string[];
  outputExample: string;
}

const NATIVE_ENUM_TECHNIQUES: DiscoveryTechnique[] = [
  {
    name: "whoami (Current User)",
    description: "Identify current user, groups, and privileges on Windows",
    binary: "whoami",
    commandTemplate: "whoami /all",
    detectionPatterns: ["whoami execution", "Event 4688 whoami", "Sysmon Event 1 whoami"],
    stealthScore: 2,
    platforms: ["windows"],
    attck: ["T1033"],
    outputExample: "DOMAIN\\username with group memberships and privilege listing",
  },
  {
    name: "whoami (Linux/macOS)",
    description: "Display current effective user ID and name",
    binary: "whoami",
    commandTemplate: "whoami && id",
    detectionPatterns: ["whoami execution", "id command execution", "Audit log exec events"],
    stealthScore: 1,
    platforms: ["linux", "macos"],
    attck: ["T1033"],
    outputExample: "username uid=1000(user) gid=1000(user) groups=...",
  },
  {
    name: "uname System Info",
    description: "Display system information including kernel version and architecture",
    binary: "uname",
    commandTemplate: "uname -a",
    detectionPatterns: ["uname execution", "System information gathering pattern"],
    stealthScore: 1,
    platforms: ["linux", "macos"],
    attck: ["T1082"],
    outputExample: "Linux hostname 5.15.0-generic #1 SMP x86_64 GNU/Linux",
  },
  {
    name: "systeminfo (Windows)",
    description: "Detailed system information including OS version, hotfixes, network configuration",
    binary: "systeminfo.exe",
    commandTemplate: "systeminfo",
    detectionPatterns: ["systeminfo.exe execution", "Event 4688 systeminfo", "WMI queries for system info"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1082"],
    outputExample: "OS Name, Version, Hotfixes, Network Adapters, Domain info",
  },
  {
    name: "hostname",
    description: "Display system hostname",
    binary: "hostname",
    commandTemplate: "hostname",
    detectionPatterns: ["hostname execution"],
    stealthScore: 1,
    platforms: ["linux", "macos", "windows"],
    attck: ["T1082"],
    outputExample: "WORKSTATION-01",
  },
  {
    name: "env / set (Environment Variables)",
    description: "Dump environment variables for sensitive data (paths, tokens, keys)",
    binary: "env",
    commandTemplate: "env",
    detectionPatterns: ["env command execution", "Process accessing environment variables"],
    stealthScore: 1,
    platforms: ["linux", "macos"],
    attck: ["T1082", "T1552.001"],
    outputExample: "PATH=... HOME=... AWS_SECRET_ACCESS_KEY=...",
  },
  {
    name: "set (Windows Environment)",
    description: "Display Windows environment variables",
    binary: "cmd.exe",
    commandTemplate: "set",
    detectionPatterns: ["cmd.exe set command", "Environment variable enumeration"],
    stealthScore: 1,
    platforms: ["windows"],
    attck: ["T1082"],
    outputExample: "COMPUTERNAME=... USERDOMAIN=... PATH=...",
  },
];

const NETWORK_SCAN_TECHNIQUES: DiscoveryTechnique[] = [
  {
    name: "ping Sweep",
    description: "Host discovery via ICMP ping sweep on a subnet",
    binary: "ping",
    commandTemplate: "for i in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$i &>/dev/null && echo \"192.168.1.$i alive\"; done",
    detectionPatterns: ["High-volume ICMP traffic", "Sequential ICMP requests", "Ping sweep pattern", "IDS alert for ICMP scan"],
    stealthScore: 4,
    platforms: ["linux", "macos"],
    attck: ["T1018", "T1046"],
    outputExample: "192.168.1.1 alive\n192.168.1.10 alive\n192.168.1.50 alive",
  },
  {
    name: "arp Table Inspection",
    description: "View ARP table to discover hosts on the local network segment",
    binary: "arp",
    commandTemplate: "arp -a",
    detectionPatterns: ["arp command execution", "ARP table enumeration"],
    stealthScore: 1,
    platforms: ["linux", "macos", "windows"],
    attck: ["T1018", "T1016"],
    outputExample: "192.168.1.1 at aa:bb:cc:dd:ee:ff [ether] on eth0",
  },
  {
    name: "netstat Connections",
    description: "List active network connections and listening ports",
    binary: "netstat",
    commandTemplate: "netstat -tulnp",
    detectionPatterns: ["netstat execution", "Network enumeration commands", "Event 4688 netstat"],
    stealthScore: 2,
    platforms: ["linux", "windows"],
    attck: ["T1049", "T1016"],
    outputExample: "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd",
  },
  {
    name: "ss (Socket Statistics)",
    description: "Display socket statistics and network connections (modern netstat replacement)",
    binary: "ss",
    commandTemplate: "ss -tulnp",
    detectionPatterns: ["ss command execution", "Socket enumeration"],
    stealthScore: 1,
    platforms: ["linux"],
    attck: ["T1049", "T1016"],
    outputExample: "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1234,fd=3))",
  },
  {
    name: "ip / ifconfig (Interface Info)",
    description: "Display network interface configuration and IP addresses",
    binary: "ip",
    commandTemplate: "ip addr show",
    detectionPatterns: ["ip addr execution", "Network interface enumeration"],
    stealthScore: 1,
    platforms: ["linux"],
    attck: ["T1016"],
    outputExample: "eth0: inet 192.168.1.100/24 brd 192.168.1.255",
  },
  {
    name: "ipconfig (Windows)",
    description: "Display Windows network interface configuration",
    binary: "ipconfig.exe",
    commandTemplate: "ipconfig /all",
    detectionPatterns: ["ipconfig execution", "Event 4688 ipconfig", "Network configuration enumeration"],
    stealthScore: 2,
    platforms: ["windows"],
    attck: ["T1016"],
    outputExample: "IPv4 Address: 192.168.1.100, Subnet Mask, Default Gateway, DNS Servers",
  },
  {
    name: "route Table",
    description: "Display routing table to understand network topology",
    binary: "route",
    commandTemplate: "route -n",
    detectionPatterns: ["route command execution", "Routing table enumeration"],
    stealthScore: 1,
    platforms: ["linux", "macos"],
    attck: ["T1016"],
    outputExample: "0.0.0.0 192.168.1.1 0.0.0.0 UG 0 0 0 eth0",
  },
];

const SERVICE_ENUM_TECHNIQUES: DiscoveryTechnique[] = [
  {
    name: "systemctl List Services",
    description: "List all systemd services and their status on Linux",
    binary: "systemctl",
    commandTemplate: "systemctl list-units --type=service --all",
    detectionPatterns: ["systemctl execution", "Service enumeration pattern"],
    stealthScore: 1,
    platforms: ["linux"],
    attck: ["T1007"],
    outputExample: "sshd.service loaded active running OpenSSH Daemon",
  },
  {
    name: "sc query (Windows Services)",
    description: "Query Windows service status and configuration",
    binary: "sc.exe",
    commandTemplate: "sc query state= all",
    detectionPatterns: ["sc.exe query execution", "Event 4688 sc.exe", "Service enumeration"],
    stealthScore: 2,
    platforms: ["windows"],
    attck: ["T1007"],
    outputExample: "SERVICE_NAME: wuauserv STATE: RUNNING",
  },
  {
    name: "launchctl List (macOS)",
    description: "List launchd services on macOS",
    binary: "launchctl",
    commandTemplate: "launchctl list",
    detectionPatterns: ["launchctl execution", "Service enumeration on macOS"],
    stealthScore: 1,
    platforms: ["macos"],
    attck: ["T1007"],
    outputExample: "PID Status Label - com.apple.sshd",
  },
  {
    name: "wmic Service List",
    description: "List services via WMIC on Windows with detailed information",
    binary: "wmic.exe",
    commandTemplate: "wmic service get name,displayname,pathname,startmode",
    detectionPatterns: ["wmic.exe execution", "WMI service queries", "Event 4688 wmic"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1007", "T1047"],
    outputExample: "Name DisplayName PathName StartMode",
  },
  {
    name: "service --status-all",
    description: "List all services and their status on SysVinit-based Linux systems",
    binary: "service",
    commandTemplate: "service --status-all",
    detectionPatterns: ["service command execution", "Init script enumeration"],
    stealthScore: 1,
    platforms: ["linux"],
    attck: ["T1007"],
    outputExample: "[ + ] ssh [ - ] apache2 [ + ] cron",
  },
];

const USER_ENUM_TECHNIQUES: DiscoveryTechnique[] = [
  {
    name: "net user (Windows Local Users)",
    description: "Enumerate local user accounts on Windows",
    binary: "net.exe",
    commandTemplate: "net user",
    detectionPatterns: ["net.exe user execution", "Event 4688 net user", "User enumeration pattern"],
    stealthScore: 2,
    platforms: ["windows"],
    attck: ["T1087.001"],
    outputExample: "Administrator Guest DefaultAccount WDAGUtilityAccount",
  },
  {
    name: "net user /domain (Domain Users)",
    description: "Enumerate domain user accounts on Windows",
    binary: "net.exe",
    commandTemplate: "net user /domain",
    detectionPatterns: ["net.exe user /domain", "LDAP queries", "Domain user enumeration", "Event 4661"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1087.002"],
    outputExample: "Domain users listing from Active Directory",
  },
  {
    name: "net group (Domain Groups)",
    description: "Enumerate domain groups including Domain Admins",
    binary: "net.exe",
    commandTemplate: "net group \"Domain Admins\" /domain",
    detectionPatterns: ["net group execution", "LDAP group query", "Domain admin enumeration", "Event 4661"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1087.002", "T1069.002"],
    outputExample: "Members: Administrator admin.user",
  },
  {
    name: "getent passwd (Linux Users)",
    description: "Enumerate local and LDAP users on Linux via NSS",
    binary: "getent",
    commandTemplate: "getent passwd",
    detectionPatterns: ["getent execution", "passwd database query", "User enumeration on Linux"],
    stealthScore: 1,
    platforms: ["linux"],
    attck: ["T1087.001"],
    outputExample: "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash",
  },
  {
    name: "dscl (macOS Users)",
    description: "Enumerate local users and groups on macOS via Directory Services",
    binary: "dscl",
    commandTemplate: "dscl . -list /Users",
    detectionPatterns: ["dscl execution", "Directory Services query", "User enumeration on macOS"],
    stealthScore: 1,
    platforms: ["macos"],
    attck: ["T1087.001"],
    outputExample: "root daemon _www admin user",
  },
  {
    name: "cat /etc/passwd",
    description: "Read the passwd file to enumerate local user accounts",
    binary: "cat",
    commandTemplate: "cat /etc/passwd",
    detectionPatterns: ["/etc/passwd access", "File read audit event", "Sensitive file access"],
    stealthScore: 1,
    platforms: ["linux", "macos"],
    attck: ["T1087.001", "T1003.008"],
    outputExample: "root:x:0:0:root:/root:/bin/bash",
  },
];

const FILE_ENUM_TECHNIQUES: DiscoveryTechnique[] = [
  {
    name: "find Sensitive Files (Linux)",
    description: "Search for sensitive files like SSH keys, config files, passwords",
    binary: "find",
    commandTemplate: "find / -name '*.key' -o -name '*.pem' -o -name 'id_rsa' -o -name '.env' -o -name 'credentials' 2>/dev/null",
    detectionPatterns: ["find command with sensitive filenames", "Recursive file search", "Broad filesystem traversal"],
    stealthScore: 3,
    platforms: ["linux", "macos"],
    attck: ["T1083", "T1552.001"],
    outputExample: "/home/user/.ssh/id_rsa\n/etc/ssl/private/server.key",
  },
  {
    name: "find SUID Binaries",
    description: "Enumerate SUID/SGID binaries for privilege escalation opportunities",
    binary: "find",
    commandTemplate: "find / -perm -u=s -type f 2>/dev/null",
    detectionPatterns: ["find with -perm SUID search", "SUID binary enumeration", "Filesystem permission scan"],
    stealthScore: 2,
    platforms: ["linux"],
    attck: ["T1083", "T1548.001"],
    outputExample: "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/pkexec",
  },
  {
    name: "dir /s (Windows File Search)",
    description: "Recursively search for files by pattern on Windows",
    binary: "cmd.exe",
    commandTemplate: "dir /s /b C:\\Users\\*.txt C:\\Users\\*.docx C:\\Users\\*.xlsx",
    detectionPatterns: ["dir /s execution", "Recursive file enumeration", "Broad file search pattern"],
    stealthScore: 2,
    platforms: ["windows"],
    attck: ["T1083", "T1119"],
    outputExample: "C:\\Users\\admin\\Documents\\passwords.txt",
  },
  {
    name: "find Writable Directories",
    description: "Enumerate world-writable directories for payload staging",
    binary: "find",
    commandTemplate: "find / -writable -type d 2>/dev/null",
    detectionPatterns: ["find with -writable flag", "Writable directory enumeration"],
    stealthScore: 2,
    platforms: ["linux", "macos"],
    attck: ["T1083"],
    outputExample: "/tmp\n/var/tmp\n/dev/shm",
  },
  {
    name: "locate / mlocate Database Search",
    description: "Fast file search using the locate database (pre-indexed filesystem)",
    binary: "locate",
    commandTemplate: "locate -i password",
    detectionPatterns: ["locate command execution", "mlocate database access"],
    stealthScore: 1,
    platforms: ["linux"],
    attck: ["T1083"],
    outputExample: "/etc/pam.d/common-password\n/home/user/.password-store/",
  },
  {
    name: "PowerShell Get-ChildItem",
    description: "Recursively search for sensitive files using PowerShell",
    binary: "powershell.exe",
    commandTemplate: "Get-ChildItem -Path C:\\Users -Recurse -Include *.txt,*.doc,*.xls,*.config -ErrorAction SilentlyContinue | Select-Object FullName",
    detectionPatterns: ["PowerShell Get-ChildItem recursive", "Script block logging", "File enumeration via PowerShell"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1083", "T1119"],
    outputExample: "C:\\Users\\admin\\Desktop\\credentials.txt",
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

function formatTechnique(t: DiscoveryTechnique): Record<string, unknown> {
  return {
    name: t.name,
    description: t.description,
    binary: t.binary,
    commandTemplate: t.commandTemplate,
    detectionPatterns: t.detectionPatterns,
    stealthScore: t.stealthScore,
    platforms: t.platforms,
    attck: t.attck,
    outputExample: t.outputExample,
  };
}

// ━━━ Tools ━━━

const discover_native_enum: ToolDef = {
  name: "discover_native_enum",
  description: "Native enumeration commands per platform (whoami, id, uname, systeminfo, hostname, env)",
  schema: {
    platform: z.enum(["linux", "windows", "macos", "all"]).optional().default("all")
      .describe("Target platform to filter enumeration commands, or 'all'"),
    category: z.enum(["user", "system", "environment", "all"]).optional().default("all")
      .describe("Category of enumeration: user identity, system info, or environment variables"),
  },
  async execute(args: { platform?: string; category?: string }, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform || "all";
    const category = args.category || "all";
    let techniques = [...NATIVE_ENUM_TECHNIQUES];

    if (platform !== "all") {
      techniques = techniques.filter(t => t.platforms.includes(platform as Platform));
    }

    if (category !== "all") {
      const catMap: Record<string, string[]> = {
        user: ["whoami", "id"],
        system: ["uname", "systeminfo", "hostname"],
        environment: ["env", "set"],
      };
      const keywords = catMap[category] || [];
      if (keywords.length > 0) {
        techniques = techniques.filter(t =>
          keywords.some(kw => t.binary.toLowerCase().includes(kw) || t.name.toLowerCase().includes(kw)),
        );
      }
    }

    // Search KB for reconnaissance-related entries
    const kbEntries = findKBEntries(
      ctx,
      ["whoami", "uname", "systeminfo", "hostname", "id"],
      ["reconnaissance"],
      platform !== "all" ? platform as Platform : undefined,
    );

    return json({
      platform,
      category,
      totalTechniques: techniques.length,
      techniques: techniques.map(formatTechnique),
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

const discover_network_scan: ToolDef = {
  name: "discover_network_scan",
  description: "Network discovery using LOL binaries (ping, arp, netstat, ss, ip, ipconfig, route)",
  schema: {
    platform: z.enum(["linux", "windows", "macos", "all"]).optional().default("all")
      .describe("Target platform to filter network discovery techniques"),
    technique: z.enum(["ping", "arp", "netstat", "ss", "ip", "ipconfig", "route", "all"]).optional().default("all")
      .describe("Specific network technique to look up, or 'all'"),
  },
  async execute(args: { platform?: string; technique?: string }, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform || "all";
    const technique = args.technique || "all";
    let techniques = [...NETWORK_SCAN_TECHNIQUES];

    if (platform !== "all") {
      techniques = techniques.filter(t => t.platforms.includes(platform as Platform));
    }

    if (technique !== "all") {
      techniques = techniques.filter(t =>
        t.binary.toLowerCase().replace(/\.exe$/i, "") === technique.toLowerCase() ||
        t.name.toLowerCase().includes(technique.toLowerCase()),
      );
    }

    // Search KB for network recon entries
    const kbEntries = findKBEntries(
      ctx,
      ["ping", "arp", "netstat", "ss", "ifconfig", "ipconfig", "route", "network"],
      ["reconnaissance"],
      platform !== "all" ? platform as Platform : undefined,
    );

    return json({
      platform,
      technique,
      totalTechniques: techniques.length,
      techniques: techniques.map(formatTechnique),
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

const discover_service_enum: ToolDef = {
  name: "discover_service_enum",
  description: "Service enumeration using native tools (systemctl, sc query, launchctl, wmic, service)",
  schema: {
    platform: z.enum(["linux", "windows", "macos", "all"]).optional().default("all")
      .describe("Target platform to filter service enumeration techniques"),
  },
  async execute(args: { platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform || "all";
    let techniques = [...SERVICE_ENUM_TECHNIQUES];

    if (platform !== "all") {
      techniques = techniques.filter(t => t.platforms.includes(platform as Platform));
    }

    // Search KB for service enumeration entries
    const kbEntries = findKBEntries(
      ctx,
      ["systemctl", "sc", "launchctl", "wmic", "service"],
      ["reconnaissance"],
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

const discover_user_enum: ToolDef = {
  name: "discover_user_enum",
  description: "User enumeration techniques (net user, getent, dscl, /etc/passwd, domain groups)",
  schema: {
    platform: z.enum(["linux", "windows", "macos", "all"]).optional().default("all")
      .describe("Target platform to filter user enumeration techniques"),
    scope: z.enum(["local", "domain", "all"]).optional().default("all")
      .describe("Enumeration scope: local users, domain users, or all"),
  },
  async execute(args: { platform?: string; scope?: string }, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform || "all";
    const scope = args.scope || "all";
    let techniques = [...USER_ENUM_TECHNIQUES];

    if (platform !== "all") {
      techniques = techniques.filter(t => t.platforms.includes(platform as Platform));
    }

    if (scope !== "all") {
      if (scope === "domain") {
        techniques = techniques.filter(t =>
          t.name.toLowerCase().includes("domain") ||
          t.commandTemplate.includes("/domain"),
        );
      } else if (scope === "local") {
        techniques = techniques.filter(t =>
          !t.name.toLowerCase().includes("domain") &&
          !t.commandTemplate.includes("/domain"),
        );
      }
    }

    // Search KB for user enumeration entries
    const kbEntries = findKBEntries(
      ctx,
      ["net", "user", "getent", "dscl", "passwd", "whoami"],
      ["reconnaissance", "credential_access"],
      platform !== "all" ? platform as Platform : undefined,
    );

    return json({
      platform,
      scope,
      totalTechniques: techniques.length,
      techniques: techniques.map(formatTechnique),
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

const discover_file_enum: ToolDef = {
  name: "discover_file_enum",
  description: "File/directory enumeration for sensitive data (SSH keys, configs, passwords, SUID binaries)",
  schema: {
    platform: z.enum(["linux", "windows", "macos", "all"]).optional().default("all")
      .describe("Target platform to filter file enumeration techniques"),
    target: z.enum(["sensitive_files", "suid", "writable", "all"]).optional().default("all")
      .describe("What to enumerate: sensitive files, SUID binaries, writable dirs, or all"),
  },
  async execute(args: { platform?: string; target?: string }, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform || "all";
    const target = args.target || "all";
    let techniques = [...FILE_ENUM_TECHNIQUES];

    if (platform !== "all") {
      techniques = techniques.filter(t => t.platforms.includes(platform as Platform));
    }

    if (target !== "all") {
      const targetMap: Record<string, string[]> = {
        sensitive_files: ["sensitive", "password", "key", "search"],
        suid: ["suid", "sgid"],
        writable: ["writable"],
      };
      const keywords = targetMap[target] || [];
      if (keywords.length > 0) {
        techniques = techniques.filter(t =>
          keywords.some(kw =>
            t.name.toLowerCase().includes(kw) ||
            t.description.toLowerCase().includes(kw),
          ),
        );
      }
    }

    // Search KB for file read/discovery entries
    const kbEntries = findKBEntries(
      ctx,
      ["find", "locate", "dir", "ls", "Get-ChildItem"],
      ["file_read", "reconnaissance"],
      platform !== "all" ? platform as Platform : undefined,
    );

    return json({
      platform,
      target,
      totalTechniques: techniques.length,
      techniques: techniques.map(formatTechnique),
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

export const discoveryTools: ToolDef[] = [
  discover_native_enum,
  discover_network_scan,
  discover_service_enum,
  discover_user_enum,
  discover_file_enum,
];
