import type { Platform } from "../schema/unified-entry.js";
import type { EnvironmentState } from "../schema/environment.js";
import { emptyEnvironmentState } from "../schema/environment.js";
import { parseLinuxEnumeration } from "./linux.js";
import { parseWindowsEnumeration } from "./windows.js";
import { parseMacosEnumeration } from "./macos.js";

/**
 * Heuristic platform detection from raw enumeration text.
 *
 * Looks for platform-specific markers:
 *   - Linux: "sudo -l", "SUID", "/usr/bin", "getcap", "/etc/", "uname"
 *   - Windows: "SeDebugPrivilege", "schtasks", "C:\\", "HKLM\\", "whoami /priv"
 *   - macOS: "launchctl", "SIP", "/usr/local/Cellar", "csrutil", "kTCCService"
 */
export function detectPlatform(rawInput: string): Platform {
  const input = typeof rawInput === "string" ? rawInput : JSON.stringify(rawInput);

  // Score-based detection for accuracy
  let linuxScore = 0;
  let windowsScore = 0;
  let macosScore = 0;

  // Linux indicators
  if (input.includes("sudo -l")) linuxScore += 3;
  if (input.includes("SUID") || input.includes("-perm -4000") || input.includes("-perm /4000")) linuxScore += 3;
  if (input.includes("/usr/bin")) linuxScore += 2;
  if (input.includes("getcap")) linuxScore += 3;
  if (input.includes("/etc/passwd") || input.includes("/etc/shadow")) linuxScore += 2;
  if (input.includes("cap_setuid") || input.includes("cap_net_raw")) linuxScore += 3;
  if (input.match(/uname\s+-[ar]/)) linuxScore += 2;
  if (input.includes("/etc/cron")) linuxScore += 2;
  if (input.includes("docker.sock")) linuxScore += 1;

  // Windows indicators
  if (input.includes("SeDebugPrivilege") || input.includes("SeImpersonatePrivilege")) windowsScore += 3;
  if (input.match(/Se\w+Privilege/)) windowsScore += 2;
  if (input.includes("schtasks")) windowsScore += 3;
  if (input.includes("C:\\")) windowsScore += 2;
  if (input.includes("HKLM\\") || input.includes("HKCU\\")) windowsScore += 3;
  if (input.includes("whoami /priv")) windowsScore += 3;
  if (input.includes(".exe")) windowsScore += 1;
  if (input.includes("AppLocker") || input.includes("AMSI")) windowsScore += 2;
  if (input.includes("driverquery") || input.includes(".sys")) windowsScore += 1;

  // macOS indicators
  if (input.includes("launchctl")) macosScore += 3;
  if (input.includes("SIP") || input.includes("System Integrity Protection")) macosScore += 3;
  if (input.includes("/usr/local/Cellar")) macosScore += 3;
  if (input.includes("csrutil")) macosScore += 3;
  if (input.includes("kTCCService")) macosScore += 3;
  if (input.includes("Gatekeeper") || input.includes("spctl")) macosScore += 2;
  if (input.includes("LaunchAgent") || input.includes("LaunchDaemon")) macosScore += 2;
  if (input.includes("com.apple.")) macosScore += 2;

  // Return highest scoring platform
  if (windowsScore > linuxScore && windowsScore > macosScore) return "windows";
  if (macosScore > linuxScore && macosScore > windowsScore) return "macos";
  return "linux"; // Default fallback
}

/**
 * Main export: parse raw enumeration input and return a complete EnvironmentState.
 *
 * @param rawInput - Raw text from enumeration tools, or a structured object
 * @param platform - Target platform; "auto" or undefined triggers heuristic detection
 * @returns Complete EnvironmentState with parsed data merged over defaults
 */
export function parseEnumeration(
  rawInput: string | object,
  platform?: Platform | "auto",
): EnvironmentState {
  // Normalize input to string
  const text = typeof rawInput === "string" ? rawInput : JSON.stringify(rawInput, null, 2);

  // Detect platform if not specified or "auto"
  const detectedPlatform: Platform =
    platform && platform !== "auto" ? platform : detectPlatform(text);

  // Dispatch to platform-specific parser
  let partial: Partial<EnvironmentState>;

  switch (detectedPlatform) {
    case "windows":
      partial = parseWindowsEnumeration(text);
      break;
    case "macos":
      partial = parseMacosEnumeration(text);
      break;
    case "linux":
    default:
      partial = parseLinuxEnumeration(text);
      break;
  }

  // Merge partial result with empty state defaults
  const baseState = emptyEnvironmentState(detectedPlatform);

  return {
    ...baseState,
    ...partial,
  };
}
