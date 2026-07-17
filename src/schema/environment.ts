import type { Platform } from "./unified-entry.js";
import type { UnifiedLOLEntry, ExecutionContext } from "./unified-entry.js";

// ━━━ Linux-Specific ━━━
export interface SudoEntry {
  binary: string;
  binaryNormalized: string;
  user: string;
  nopasswd: boolean;
  constraints: string;
}

export interface CapabilityEntry {
  binary: string;
  binaryNormalized: string;
  capabilities: string[];
}

export interface CronJob {
  schedule: string;
  user: string;
  command: string;
  writable: boolean;
  path: string;
}

// ━━━ Windows-Specific ━━━
export interface ScheduledTask {
  name: string;
  command: string;
  runAs: string;
  status: string;
  writable: boolean;
}

export interface DriverInfo {
  name: string;
  filename: string;
  hash?: string;
  signed: boolean;
  signer?: string;
}

// ━━━ Cross-Platform ━━━
export interface NetworkAccess {
  outboundHttp: boolean;
  outboundDns: boolean;
  internalSubnets: string[];
}

export interface FileAccess {
  path: string;
  readable: boolean;
  writable: boolean;
}

// ━━━ Environment State ━━━
export interface EnvironmentState {
  platform: Platform;
  os: string;
  kernel?: string;
  currentUser: string;
  privilegeLevel: string;
  // Linux-specific
  sudoEntries: SudoEntry[];
  suidBinaries: string[];
  sgidBinaries: string[];
  capabilities: CapabilityEntry[];
  cronJobs: CronJob[];
  writablePaths: string[];
  dockerSocket: boolean;
  // Windows-specific
  tokenPrivileges: string[];
  scheduledTasks: ScheduledTask[];
  loadedDrivers: DriverInfo[];
  unquotedServicePaths: string[];
  writableServiceBinaries: string[];
  registryKeys: { path: string; value: string }[];
  amsiEnabled: boolean;
  appLockerEnabled: boolean;
  // macOS-specific
  sipEnabled: boolean;
  gatekeeperEnabled: boolean;
  tccPermissions: string[];
  launchAgents: string[];
  launchDaemons: string[];
  // Cross-platform
  installedBinaries: string[];
  runningServices: string[];
  networkAccess: NetworkAccess;
  edrDetected: string;
  sensitiveFiles: FileAccess[];
  environmentVariables: { key: string; hasSecret: boolean }[];
}

export interface MatchedEntry {
  entry: UnifiedLOLEntry;
  matchReason: string;
  applicableContexts: ExecutionContext[];
  effectiveStealthScore: number;
}

export interface EnvironmentModel {
  id: string;
  state: EnvironmentState;
  matchedEntries: MatchedEntry[];
  createdAt: number;
}

export function emptyEnvironmentState(platform: Platform = "linux"): EnvironmentState {
  return {
    platform,
    os: "",
    currentUser: "",
    privilegeLevel: "unprivileged",
    sudoEntries: [],
    suidBinaries: [],
    sgidBinaries: [],
    capabilities: [],
    cronJobs: [],
    writablePaths: [],
    dockerSocket: false,
    tokenPrivileges: [],
    scheduledTasks: [],
    loadedDrivers: [],
    unquotedServicePaths: [],
    writableServiceBinaries: [],
    registryKeys: [],
    amsiEnabled: true,
    appLockerEnabled: false,
    sipEnabled: true,
    gatekeeperEnabled: true,
    tccPermissions: [],
    launchAgents: [],
    launchDaemons: [],
    installedBinaries: [],
    runningServices: [],
    networkAccess: { outboundHttp: true, outboundDns: true, internalSubnets: [] },
    edrDetected: "none",
    sensitiveFiles: [],
    environmentVariables: [],
  };
}
