import type { ScheduledTask, DriverInfo, EnvironmentState } from "../schema/environment.js";
import { normalizeBinaryName } from "../utils/normalize.js";

/**
 * Parse "whoami /priv" output to extract Windows privilege names.
 *
 * Example input:
 *   PRIVILEGES INFORMATION
 *   ----------------------
 *   Privilege Name                  Description                    State
 *   ============================= ============================== ========
 *   SeImpersonatePrivilege         Impersonate a client after...  Enabled
 *   SeDebugPrivilege               Debug programs                 Enabled
 */
export function parseWhoamiPriv(input: string): string[] {
  const privileges: string[] = [];
  const regex = /^(Se\w+Privilege)\s+/gm;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(input)) !== null) {
    privileges.push(match[1]);
  }

  return privileges;
}

/**
 * Parse scheduled tasks from "schtasks /query /fo CSV" or structured output.
 *
 * CSV format example:
 *   "TaskName","Next Run Time","Status"
 *   "\Microsoft\Windows\Backup","N/A","Ready"
 *
 * Or verbose format:
 *   TaskName:   \MyTask
 *   Task To Run: C:\Windows\System32\cmd.exe /c script.bat
 *   Run As User: SYSTEM
 *   Status:      Ready
 */
export function parseScheduledTasks(input: string): ScheduledTask[] {
  const tasks: ScheduledTask[] = [];

  // Try CSV format first
  if (input.includes('","')) {
    const lines = input.split("\n").filter(l => l.trim().length > 0);
    // Skip header line
    for (let i = 1; i < lines.length; i++) {
      const fields = parseCSVLine(lines[i]);
      if (fields.length >= 3) {
        tasks.push({
          name: fields[0].replace(/^\\/, ""),
          command: fields.length > 6 ? fields[6] : "",
          runAs: fields.length > 7 ? fields[7] : "",
          status: fields[2] || "Unknown",
          writable: false,
        });
      }
    }
    if (tasks.length > 0) return tasks;
  }

  // Try verbose/structured format
  const taskBlocks = input.split(/(?=TaskName:)/gi);
  for (const block of taskBlocks) {
    const nameMatch = block.match(/TaskName:\s*(.+)/i);
    const commandMatch = block.match(/Task To Run:\s*(.+)/i);
    const runAsMatch = block.match(/Run As User:\s*(.+)/i);
    const statusMatch = block.match(/Status:\s*(.+)/i);

    if (nameMatch) {
      tasks.push({
        name: nameMatch[1].trim().replace(/^\\/, ""),
        command: commandMatch?.[1]?.trim() ?? "",
        runAs: runAsMatch?.[1]?.trim() ?? "",
        status: statusMatch?.[1]?.trim() ?? "Unknown",
        writable: false,
      });
    }
  }

  return tasks;
}

/**
 * Parse loaded driver listing.
 *
 * Supports multiple formats:
 *   - "driverquery /v" output
 *   - Simple list of driver filenames
 */
export function parseLoadedDrivers(input: string): DriverInfo[] {
  const drivers: DriverInfo[] = [];

  // Try driverquery-style output (table format)
  const lines = input.split("\n").filter(l => l.trim().length > 0);

  // Detect if it's a table with headers
  const headerLine = lines.find(l =>
    l.toLowerCase().includes("module name") || l.toLowerCase().includes("display name")
  );

  if (headerLine) {
    // Table format: skip header and separator lines
    const startIdx = lines.indexOf(headerLine) + 2; // skip header + separator
    for (let i = startIdx; i < lines.length; i++) {
      const parts = lines[i].split(/\s{2,}/);
      if (parts.length >= 2) {
        const name = parts[0].trim();
        const filename = parts.length > 2 ? parts[2].trim() : `${name}.sys`;
        const isSigned = lines[i].toLowerCase().includes("true") ||
                         lines[i].toLowerCase().includes("microsoft");

        drivers.push({
          name,
          filename,
          signed: isSigned,
          signer: isSigned ? "Microsoft Windows" : undefined,
        });
      }
    }
  } else {
    // Simple format: one driver per line
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.endsWith(".sys") || trimmed.match(/^\w+\s/)) {
        const parts = trimmed.split(/\s+/);
        const name = parts[0];
        const filename = parts.length > 1 ? parts[parts.length - 1] : `${name}.sys`;

        drivers.push({
          name,
          filename,
          signed: true, // Default assumption
        });
      }
    }
  }

  return drivers;
}

/**
 * Parse unquoted service paths from sc query or wmic output.
 */
export function parseUnquotedServicePaths(input: string): string[] {
  const paths: string[] = [];
  const regex = /^\s*(?:BINARY_PATH_NAME|PathName)\s*[:=]\s*(.+)$/gm;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(input)) !== null) {
    const path = match[1].trim();
    // Unquoted if it contains spaces and doesn't start with a quote
    if (!path.startsWith('"') && path.includes(" ") && path.includes("\\")) {
      paths.push(path);
    }
  }

  return paths;
}

/**
 * Main entry point: parse raw Windows enumeration text.
 */
export function parseWindowsEnumeration(rawInput: string): Partial<EnvironmentState> {
  const result: Partial<EnvironmentState> = {
    platform: "windows",
  };

  // Parse token privileges
  if (rawInput.includes("Privilege") || rawInput.match(/Se\w+Privilege/)) {
    result.tokenPrivileges = parseWhoamiPriv(rawInput);
  }

  // Parse scheduled tasks
  if (rawInput.toLowerCase().includes("taskname") || rawInput.toLowerCase().includes("schtasks")) {
    result.scheduledTasks = parseScheduledTasks(rawInput);
  }

  // Parse loaded drivers
  if (rawInput.toLowerCase().includes("driver") || rawInput.includes(".sys")) {
    result.loadedDrivers = parseLoadedDrivers(rawInput);
  }

  // Parse unquoted service paths
  if (rawInput.includes("BINARY_PATH_NAME") || rawInput.includes("PathName")) {
    result.unquotedServicePaths = parseUnquotedServicePaths(rawInput);
  }

  // Detect AMSI status
  if (rawInput.toLowerCase().includes("amsi")) {
    result.amsiEnabled = !rawInput.toLowerCase().includes("amsi disabled") &&
                         !rawInput.toLowerCase().includes("amsi bypassed");
  }

  // Detect AppLocker
  if (rawInput.toLowerCase().includes("applocker")) {
    result.appLockerEnabled = rawInput.toLowerCase().includes("applocker enabled") ||
                              rawInput.toLowerCase().includes("enforcement mode");
  }

  // Extract current user
  const userMatch = rawInput.match(/(?:User Name|USERNAME)\s*[:=]\s*(.+)/i);
  if (userMatch) {
    result.currentUser = userMatch[1].trim();
  }

  // Extract OS info
  const osMatch = rawInput.match(/(?:OS Name|Microsoft Windows[^,\n]*)/i);
  if (osMatch) {
    result.os = osMatch[0].replace(/OS Name\s*[:=]\s*/i, "").trim();
  }

  return result;
}

// ━━━ Internal Helpers ━━━

function parseCSVLine(line: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === "," && !inQuotes) {
      fields.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }
  fields.push(current.trim());

  return fields;
}
