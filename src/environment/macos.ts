import type { EnvironmentState } from "../schema/environment.js";

/**
 * Parse "launchctl list" output into service identifiers.
 *
 * Example input:
 *   PID   Status  Label
 *   -     0       com.apple.Spotlight
 *   123   0       com.apple.syslogd
 *   -     0       org.custom.agent
 */
export function parseLaunchctl(input: string): { agents: string[]; daemons: string[] } {
  const agents: string[] = [];
  const daemons: string[] = [];
  const lines = input.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    // Skip header line
    if (trimmed.startsWith("PID") || trimmed.length === 0) continue;

    // Extract the label (last column)
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 3) {
      const label = parts[parts.length - 1];
      if (!label || label === "-") continue;

      // Heuristic: Apple daemons vs. agents
      // Daemons typically run as root and include "daemon" in path context
      // For launchctl list, categorize by common conventions
      if (label.includes("daemon") || label.startsWith("com.apple.") && isDaemonLabel(label)) {
        daemons.push(label);
      } else {
        agents.push(label);
      }
    }
  }

  return { agents, daemons };
}

/**
 * Parse TCC (Transparency, Consent, and Control) database output.
 *
 * Example input (from sqlite3 TCC.db):
 *   client|service|auth_value
 *   com.apple.Terminal|kTCCServiceAccessibility|2
 *   com.googlecode.iterm2|kTCCServiceFullDiskAccess|2
 */
export function parseTccPermissions(input: string): string[] {
  const permissions: string[] = [];
  const lines = input.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("client")) continue;

    // Pipe-delimited or space-delimited
    const parts = trimmed.split("|");
    if (parts.length >= 2) {
      const client = parts[0].trim();
      const service = parts[1].trim();
      const authValue = parts.length > 2 ? parts[2].trim() : "";

      // auth_value of 2 typically means granted
      if (authValue === "2" || authValue === "") {
        permissions.push(`${client}:${service}`);
      }
    }
  }

  return permissions;
}

/**
 * Parse SIP (System Integrity Protection) status from "csrutil status" output.
 *
 * Example input:
 *   System Integrity Protection status: enabled.
 *   System Integrity Protection status: disabled.
 */
export function parseSipStatus(input: string): boolean {
  const match = input.match(/System Integrity Protection status:\s*(\w+)/i);
  if (match) {
    return match[1].toLowerCase() === "enabled";
  }
  // Default to enabled if we can't parse
  return true;
}

/**
 * Parse Gatekeeper status from "spctl --status" output.
 *
 * Example:
 *   assessments enabled
 *   assessments disabled
 */
export function parseGatekeeperStatus(input: string): boolean {
  if (input.toLowerCase().includes("assessments enabled")) {
    return true;
  }
  if (input.toLowerCase().includes("assessments disabled")) {
    return false;
  }
  // Default to enabled
  return true;
}

/**
 * Main entry point: parse raw macOS enumeration text.
 */
export function parseMacosEnumeration(rawInput: string): Partial<EnvironmentState> {
  const result: Partial<EnvironmentState> = {
    platform: "macos",
  };

  // Parse launchctl data
  if (rawInput.includes("launchctl") || rawInput.match(/^\s*-?\d*\s+\d+\s+\S+/m)) {
    const { agents, daemons } = parseLaunchctl(rawInput);
    result.launchAgents = agents;
    result.launchDaemons = daemons;
  }

  // Parse TCC permissions
  if (rawInput.includes("kTCCService") || rawInput.toLowerCase().includes("tcc")) {
    result.tccPermissions = parseTccPermissions(rawInput);
  }

  // Parse SIP status
  if (rawInput.toLowerCase().includes("system integrity protection") || rawInput.toLowerCase().includes("csrutil")) {
    result.sipEnabled = parseSipStatus(rawInput);
  }

  // Parse Gatekeeper status
  if (rawInput.toLowerCase().includes("gatekeeper") || rawInput.toLowerCase().includes("spctl") || rawInput.toLowerCase().includes("assessments")) {
    result.gatekeeperEnabled = parseGatekeeperStatus(rawInput);
  }

  // Extract OS info
  const osMatch = rawInput.match(/(?:macOS|Mac OS X|ProductName:\s*)([^\n]+)/i);
  if (osMatch) {
    result.os = osMatch[0].replace(/ProductName:\s*/i, "").trim();
  }

  // Extract kernel version
  const kernelMatch = rawInput.match(/Darwin Kernel Version\s+([\d.]+)/i);
  if (kernelMatch) {
    result.kernel = kernelMatch[1];
  } else {
    const darwinMatch = rawInput.match(/Darwin\s+([\d.]+)/);
    if (darwinMatch) {
      result.kernel = darwinMatch[1];
    }
  }

  // Extract current user
  const userMatch = rawInput.match(/(?:whoami|USER)\s*[:=]?\s*(\S+)/i);
  if (userMatch) {
    result.currentUser = userMatch[1];
  }

  return result;
}

// ━━━ Internal Helpers ━━━

/**
 * Heuristic to determine if a launchctl label is a daemon.
 * Apple system daemons often include specific keywords.
 */
function isDaemonLabel(label: string): boolean {
  const daemonIndicators = [
    "syslogd", "fseventsd", "configd", "notifyd", "launchd",
    "diskmanagementd", "coreservicesd", "networkd", "securityd",
    "opendirectoryd", "diskarbitrationd",
  ];
  return daemonIndicators.some(d => label.includes(d));
}
