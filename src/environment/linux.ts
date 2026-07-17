import { basename } from "node:path";
import type { SudoEntry, CapabilityEntry, CronJob, EnvironmentState } from "../schema/environment.js";
import { normalizeBinaryName } from "../utils/normalize.js";

/**
 * Parse "sudo -l" output into structured SudoEntry objects.
 *
 * Example input:
 *   User www-data may run the following commands on target:
 *       (ALL) NOPASSWD: /usr/bin/find
 *       (root) /usr/bin/vim
 */
export function parseSudoL(input: string): SudoEntry[] {
  const entries: SudoEntry[] = [];
  const regex = /\((\S+)\)\s+(NOPASSWD:\s+)?(.+)/g;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(input)) !== null) {
    const user = match[1];
    const nopasswd = match[2] !== undefined;
    const cmdPaths = match[3].split(",").map(s => s.trim());

    for (const cmdPath of cmdPaths) {
      // Extract binary path — first word before any arguments
      const binaryPath = cmdPath.split(/\s+/)[0];
      const binary = basename(binaryPath);
      const binaryNormalized = normalizeBinaryName(binary);

      entries.push({
        binary: binaryPath,
        binaryNormalized,
        user,
        nopasswd,
        constraints: nopasswd ? "NOPASSWD" : "",
      });
    }
  }

  return entries;
}

/**
 * Parse SUID binary listing (find output, one path per line starting with /).
 */
export function parseSuidBinaries(input: string): string[] {
  const binaries: string[] = [];
  const lines = input.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("/")) {
      binaries.push(trimmed);
    }
  }

  return binaries;
}

/**
 * Parse getcap output into CapabilityEntry objects.
 *
 * Example input:
 *   /usr/bin/perl cap_setuid+ep
 *   /usr/bin/python3 = cap_net_raw+ep
 */
export function parseCapabilities(input: string): CapabilityEntry[] {
  const entries: CapabilityEntry[] = [];
  const regex = /^(\S+)\s+=?\s*(.+)$/gm;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(input)) !== null) {
    const binaryPath = match[1];
    const capsRaw = match[2].trim();
    const binary = basename(binaryPath);
    const binaryNormalized = normalizeBinaryName(binary);

    // Parse individual capabilities (e.g., "cap_setuid,cap_net_raw+ep")
    const capabilities = capsRaw
      .split(",")
      .map(c => c.trim().replace(/[+=].*$/, ""))
      .filter(c => c.length > 0);

    entries.push({
      binary: binaryPath,
      binaryNormalized,
      capabilities,
    });
  }

  return entries;
}

/**
 * Parse crontab/cron listing output.
 *
 * Example input:
 *   * * * * * root /usr/bin/backup.sh
 *   0 2 * * * www-data /opt/scripts/cleanup.sh
 */
export function parseCronJobs(input: string): CronJob[] {
  const jobs: CronJob[] = [];
  const regex = /^([\d*\/\-,]+\s+[\d*\/\-,]+\s+[\d*\/\-,]+\s+[\d*\/\-,]+\s+[\d*\/\-,]+)\s+(\S+)\s+(.+)$/gm;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(input)) !== null) {
    const schedule = match[1];
    const user = match[2];
    const command = match[3].trim();

    // Extract the script/binary path from the command
    const path = command.split(/\s+/)[0];

    jobs.push({
      schedule,
      user,
      command,
      writable: false, // Default; caller can refine with fs checks
      path,
    });
  }

  return jobs;
}

/**
 * Extract OS and kernel information from uname/os-release text.
 */
export function parseOsInfo(input: string): { os: string; kernel: string } {
  let os = "";
  let kernel = "";

  // Try to extract from /etc/os-release style
  const prettyName = input.match(/PRETTY_NAME="?([^"\n]+)"?/);
  if (prettyName) {
    os = prettyName[1];
  } else {
    // Fallback: first non-empty line as OS identifier
    const nameMatch = input.match(/^NAME="?([^"\n]+)"?/m);
    if (nameMatch) {
      os = nameMatch[1];
    }
  }

  // Kernel version from uname -r style output
  const kernelMatch = input.match(/(\d+\.\d+\.\d+[\w.\-]*)/);
  if (kernelMatch) {
    kernel = kernelMatch[1];
  }

  return { os, kernel };
}

/**
 * Main entry point: parse raw Linux enumeration text by detecting sections.
 *
 * Recognizes section markers:
 *   - "sudo -l" / "User .* may run"
 *   - "perm -4000" / "SUID" / "-perm /4000"
 *   - "getcap"
 *   - "crontab" / "/etc/cron"
 *   - "uname" / "os-release"
 */
export function parseLinuxEnumeration(rawInput: string): Partial<EnvironmentState> {
  const result: Partial<EnvironmentState> = {
    platform: "linux",
  };

  // Split into sections by common delimiters or detect by content
  const sections = splitSections(rawInput);

  for (const section of sections) {
    const content = section.content;
    const header = section.header.toLowerCase();

    if (header.includes("sudo") || content.includes("may run the following commands")) {
      result.sudoEntries = parseSudoL(content);
    } else if (header.includes("suid") || header.includes("perm -4000") || header.includes("-perm /4000")) {
      result.suidBinaries = parseSuidBinaries(content);
    } else if (header.includes("getcap") || header.includes("capabilities")) {
      result.capabilities = parseCapabilities(content);
    } else if (header.includes("crontab") || header.includes("cron")) {
      result.cronJobs = parseCronJobs(content);
    } else if (header.includes("uname") || header.includes("os-release") || header.includes("kernel")) {
      const info = parseOsInfo(content);
      result.os = info.os;
      result.kernel = info.kernel;
    }
  }

  // If no sections detected, try heuristic parsing on the full input
  if (!result.sudoEntries && rawInput.includes("may run the following commands")) {
    result.sudoEntries = parseSudoL(rawInput);
  }
  if (!result.suidBinaries && rawInput.match(/^\/\S+/m)) {
    // Only parse as SUID if the context suggests it (multiple absolute paths)
    const lines = rawInput.split("\n").filter(l => l.trim().startsWith("/"));
    if (lines.length > 2) {
      result.suidBinaries = parseSuidBinaries(rawInput);
    }
  }
  if (!result.capabilities && rawInput.includes("cap_")) {
    result.capabilities = parseCapabilities(rawInput);
  }
  if (!result.cronJobs && rawInput.match(/^[\d*\/\-,]+\s+[\d*\/\-,]+\s+[\d*\/\-,]+\s+[\d*\/\-,]+\s+[\d*\/\-,]+/m)) {
    result.cronJobs = parseCronJobs(rawInput);
  }

  // Detect docker socket
  if (rawInput.includes("/var/run/docker.sock") || rawInput.includes("docker.sock")) {
    result.dockerSocket = true;
  }

  return result;
}

// ━━━ Internal Helpers ━━━

interface Section {
  header: string;
  content: string;
}

function splitSections(input: string): Section[] {
  const sections: Section[] = [];

  // Try splitting by common enumeration script section headers
  // Patterns: "=== SECTION ===" or "[+] Section" or "--- Section ---" or "### Section"
  const sectionRegex = /^(?:={3,}|#{3,}|-{3,}|\[\+\]|\[\*\])\s*(.+?)(?:\s*(?:={3,}|-{3,}))?$/gm;
  const markers: { index: number; header: string }[] = [];
  let sectionMatch: RegExpExecArray | null;

  while ((sectionMatch = sectionRegex.exec(input)) !== null) {
    markers.push({ index: sectionMatch.index, header: sectionMatch[1] });
  }

  if (markers.length === 0) {
    // No structured sections found — return single block with empty header
    sections.push({ header: "", content: input });
    return sections;
  }

  for (let i = 0; i < markers.length; i++) {
    const start = markers[i].index + input.substring(markers[i].index).indexOf("\n") + 1;
    const end = i + 1 < markers.length ? markers[i + 1].index : input.length;
    sections.push({
      header: markers[i].header,
      content: input.substring(start, end).trim(),
    });
  }

  return sections;
}
