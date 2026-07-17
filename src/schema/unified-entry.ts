// ━━━ Platform Types ━━━
export type Platform = "linux" | "windows" | "macos" | "esxi" | "cicd" | "network" | "multi";

export type CatalogSource =
  | "gtfobins" | "lolbas" | "loobins" | "loldrivers"
  | "lolrmm" | "lolesxi" | "lotp" | "lolc2"
  | "loflcab" | "wadcoms" | "wtfbins" | "lots" | "malapi";

export type EntryCategory =
  | "binary" | "script" | "library" | "driver" | "api"
  | "service" | "site" | "rmm" | "cert" | "cmdlet" | "mmc" | "wmi";

// ━━━ 28 LOL Function Types ━━━
export type LOLFunction =
  | "shell"
  | "command"
  | "reverse_shell"
  | "bind_shell"
  | "file_read"
  | "file_write"
  | "upload"
  | "download"
  | "library_load"
  | "privilege_escalation"
  | "inherit"
  | "persistence"
  | "lateral_movement"
  | "defense_evasion"
  | "credential_access"
  | "command_execution"
  | "encode_decode"
  | "reconnaissance"
  | "compile"
  | "copy"
  | "ads"
  | "awl_bypass"
  | "dump"
  | "tamper"
  | "conceal"
  | "uac_bypass"
  | "c2"
  | "edr_disable";

export const ALL_LOL_FUNCTIONS: LOLFunction[] = [
  "shell", "command", "reverse_shell", "bind_shell", "file_read", "file_write",
  "upload", "download", "library_load", "privilege_escalation", "inherit",
  "persistence", "lateral_movement", "defense_evasion", "credential_access",
  "command_execution", "encode_decode", "reconnaissance", "compile", "copy",
  "ads", "awl_bypass", "dump", "tamper", "conceal", "uac_bypass", "c2", "edr_disable",
];

// ━━━ Execution Context ━━━
export type ContextType = "sudo" | "suid" | "capabilities" | "unprivileged" | "user" | "admin" | "system" | "kernel";

export interface ExecutionContext {
  context: ContextType;
  prerequisite: string;
  command: string;
  result: string;
  oneLiner: boolean;
  requiredCapabilities?: string[];
  operatingSystem?: string;
  binaryPreservesPriv?: boolean;
}

// ━━━ Detection Info ━━━
export interface DetectionInfo {
  sigmaRules: string[];
  elasticRules: string[];
  splunkRules: string[];
  sysmonEvents: number[];
  blockRules: string[];
  logSources: string[];
  edrCoverage: "none" | "low" | "medium" | "high";
  iocs: string[];
  yaraRules: string[];
  atomicTests: string[];
}

export function emptyDetection(): DetectionInfo {
  return {
    sigmaRules: [],
    elasticRules: [],
    splunkRules: [],
    sysmonEvents: [],
    blockRules: [],
    logSources: [],
    edrCoverage: "none",
    iocs: [],
    yaraRules: [],
    atomicTests: [],
  };
}

// ━━━ Driver-Specific Fields ━━━
export interface DriverSample {
  filename: string;
  md5: string;
  sha1: string;
  sha256: string;
  machineType: string;
  signature: string;
  imphash?: string;
}

// ━━━ Unified LOL Entry ━━━
export interface UnifiedLOLEntry {
  id: string;
  binary: string;
  aliases: string[];
  platform: Platform;
  catalogSource: CatalogSource;
  category: EntryCategory;
  description: string;
  functions: LOLFunction[];
  executionContexts: ExecutionContext[];
  attckTechniques: string[];
  detection: DetectionInfo;
  stealthScore: number;
  stealthNotes: string;
  fullPaths: string[];
  resources: string[];
  relatedEntries: string[];
  chainPotential: string[];
  // Driver-specific
  driverCategory?: "vulnerable" | "malicious";
  driverSamples?: DriverSample[];
  cves?: string[];
  // LOLRMM-specific
  rmmArtifacts?: {
    disk: string[];
    registry: string[];
    network: { domains: string[]; ports: number[] };
    eventLog: string[];
  };
  // LOOBins-specific
  tactics?: string[];
  // Inherit (GTFOBins)
  inheritsFrom?: string;
}
