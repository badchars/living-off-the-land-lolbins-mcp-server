import type { AttackGraph } from "../schema/graph.js";
import { createEmptyGraph, addNode, addEdge } from "../schema/graph.js";
import type { EnvironmentModel, MatchedEntry } from "../schema/environment.js";
import type { ExecutionContext, LOLFunction } from "../schema/unified-entry.js";
import type { EdgeType } from "../schema/graph.js";

const CERTAINTY_MAP: Record<string, number> = {
  sudo: 1.0,
  suid: 0.95,
  capabilities: 0.9,
  unprivileged: 0.7,
  user: 0.7,
  admin: 0.85,
  system: 0.9,
  kernel: 0.8,
};

const ESCALATION_FUNCTIONS: LOLFunction[] = [
  "shell",
  "command",
  "privilege_escalation",
  "command_execution",
];

const PERSISTENCE_PATH_PATTERNS = [
  /\/etc\/cron/,
  /\/var\/spool\/cron/,
  /\/etc\/systemd/,
  /\/etc\/init\.d/,
  /\/usr\/lib\/systemd/,
  /\.bashrc$/,
  /\.profile$/,
  /\.bash_profile$/,
  /LaunchAgents/,
  /LaunchDaemons/,
];

const WINDOWS_PERSISTENCE_PATTERNS = [
  /\\Tasks\\/i,
  /\\Startup\\/i,
  /\\Start Menu\\/i,
  /HKLM\\.*\\Run/i,
  /HKCU\\.*\\Run/i,
];

function getEscalationTarget(context: string, platform: string): string | null {
  if (platform === "linux" || platform === "macos") {
    if (context === "sudo" || context === "suid" || context === "capabilities" || context === "kernel") {
      return "root";
    }
  }
  if (platform === "windows") {
    if (context === "system" || context === "kernel") {
      return "system";
    }
    if (context === "admin") {
      return "administrator";
    }
  }
  return null;
}

function computeStealthForEdge(matched: MatchedEntry, ctx: ExecutionContext): number {
  // Base stealth from entry, adjusted by context
  let stealth = matched.effectiveStealthScore;
  // sudo/admin are more visible
  if (ctx.context === "sudo" || ctx.context === "admin") {
    stealth = Math.max(0, stealth - 0.1);
  }
  // suid/capabilities are stealthier
  if (ctx.context === "suid" || ctx.context === "capabilities") {
    stealth = Math.min(1, stealth + 0.05);
  }
  return Math.round(stealth * 100) / 100;
}

function hasFunction(matched: MatchedEntry, ...fns: LOLFunction[]): boolean {
  return fns.some((f) => matched.entry.functions.includes(f));
}

function isEscalationContext(ctx: ExecutionContext): boolean {
  return (
    ctx.context === "sudo" ||
    ctx.context === "suid" ||
    ctx.context === "capabilities" ||
    ctx.context === "system" ||
    ctx.context === "kernel" ||
    ctx.context === "admin"
  );
}

export function buildAttackGraph(model: EnvironmentModel): AttackGraph {
  const graph = createEmptyGraph();
  const state = model.state;

  // 1. Create privilege target nodes
  addNode(graph, "current-user", "CurrentUser", state.currentUser, {
    privilegeLevel: state.privilegeLevel,
    platform: state.platform,
  });

  if (state.platform === "linux" || state.platform === "macos") {
    addNode(graph, "root", "TargetPrivilege", "root");
  }
  if (state.platform === "windows") {
    addNode(graph, "system", "TargetPrivilege", "SYSTEM");
    addNode(graph, "administrator", "TargetPrivilege", "Administrator");
  }

  // 2. For each matched entry, create binary node + edges
  for (const matched of model.matchedEntries) {
    const entry = matched.entry;
    const binaryId = `bin-${entry.id}`;

    addNode(graph, binaryId, "Binary", entry.binary, {
      catalogSource: entry.catalogSource,
      category: entry.category,
      functions: entry.functions,
      stealthScore: matched.effectiveStealthScore,
      fullPaths: entry.fullPaths,
    });

    for (const ctx of matched.applicableContexts) {
      const certainty = CERTAINTY_MAP[ctx.context] ?? 0.5;
      const stealth = computeStealthForEdge(matched, ctx);

      // Escalation edges
      if (
        hasFunction(matched, ...ESCALATION_FUNCTIONS) &&
        isEscalationContext(ctx)
      ) {
        const target = getEscalationTarget(ctx.context, state.platform);
        if (target && graph.nodes.has(target)) {
          // Edge from current-user to binary (CanExecuteAs)
          addEdge(graph, {
            type: "CanExecuteAs",
            from: "current-user",
            to: binaryId,
            entryId: entry.id,
            command: ctx.command,
            stealthScore: stealth,
            certainty,
            attckTechniques: entry.attckTechniques,
          });

          // Edge from binary to target (CanEscalateVia)
          addEdge(graph, {
            type: "CanEscalateVia",
            from: binaryId,
            to: target,
            entryId: entry.id,
            command: ctx.command,
            stealthScore: stealth,
            certainty,
            attckTechniques: entry.attckTechniques,
          });
        }
      }

      // Shell spawn edge (unprivileged context)
      if (hasFunction(matched, "shell", "command") && !isEscalationContext(ctx)) {
        addEdge(graph, {
          type: "CanSpawnShell",
          from: "current-user",
          to: binaryId,
          entryId: entry.id,
          command: ctx.command,
          stealthScore: stealth,
          certainty,
          attckTechniques: entry.attckTechniques,
        });
      }

      // File read edges
      if (hasFunction(matched, "file_read")) {
        for (const sf of state.sensitiveFiles) {
          if (sf.readable) {
            const fileNodeId = `file-${sf.path.replace(/[^a-zA-Z0-9]/g, "-")}`;
            addNode(graph, fileNodeId, "File", sf.path, { readable: true, writable: sf.writable });

            addEdge(graph, {
              type: "CanReadFile",
              from: binaryId,
              to: fileNodeId,
              entryId: entry.id,
              command: ctx.command,
              stealthScore: stealth,
              certainty,
              attckTechniques: entry.attckTechniques,
            });
          }
        }
      }

      // File write edges
      if (hasFunction(matched, "file_write")) {
        for (const sf of state.sensitiveFiles) {
          if (sf.writable) {
            const fileNodeId = `file-${sf.path.replace(/[^a-zA-Z0-9]/g, "-")}`;
            addNode(graph, fileNodeId, "File", sf.path, { readable: sf.readable, writable: true });

            addEdge(graph, {
              type: "CanWriteFile",
              from: binaryId,
              to: fileNodeId,
              entryId: entry.id,
              command: ctx.command,
              stealthScore: stealth,
              certainty,
              attckTechniques: entry.attckTechniques,
            });
          }
        }
      }

      // Download edges (only if network access)
      if (hasFunction(matched, "download") && state.networkAccess.outboundHttp) {
        addEdge(graph, {
          type: "CanDownload",
          from: "current-user",
          to: binaryId,
          entryId: entry.id,
          command: ctx.command,
          stealthScore: stealth,
          certainty,
          attckTechniques: entry.attckTechniques,
        });
      }

      // Upload edges (only if network access)
      if (hasFunction(matched, "upload") && state.networkAccess.outboundHttp) {
        addEdge(graph, {
          type: "CanUpload",
          from: "current-user",
          to: binaryId,
          entryId: entry.id,
          command: ctx.command,
          stealthScore: stealth,
          certainty,
          attckTechniques: entry.attckTechniques,
        });
      }
    }

    // 3. Persistence edges: writable paths that match cron/service patterns
    if (hasFunction(matched, "persistence", "file_write")) {
      const patterns =
        state.platform === "windows"
          ? WINDOWS_PERSISTENCE_PATTERNS
          : PERSISTENCE_PATH_PATTERNS;

      for (const wp of state.writablePaths) {
        const matchesPersistence = patterns.some((p) => p.test(wp));
        if (matchesPersistence) {
          const configNodeId = `config-${wp.replace(/[^a-zA-Z0-9]/g, "-")}`;
          addNode(graph, configNodeId, "Configuration", wp, {
            writable: true,
            persistenceTarget: true,
          });

          addEdge(graph, {
            type: "EnablesPersistence",
            from: binaryId,
            to: configNodeId,
            entryId: entry.id,
            command: `write to ${wp}`,
            stealthScore: matched.effectiveStealthScore,
            certainty: CERTAINTY_MAP[matched.applicableContexts[0]?.context ?? "unprivileged"] ?? 0.7,
            attckTechniques: entry.attckTechniques,
          });
        }
      }
    }

    // 5. Driver edges: if category=driver and edr_disable function → CanLoadDriver → CanDisableEDR
    if (entry.category === "driver" && hasFunction(matched, "edr_disable")) {
      const driverNodeId = `driver-${entry.id}`;
      addNode(graph, driverNodeId, "Driver", entry.binary, {
        driverCategory: entry.driverCategory,
        cves: entry.cves,
      });

      addEdge(graph, {
        type: "CanLoadDriver",
        from: "current-user",
        to: driverNodeId,
        entryId: entry.id,
        command: `load driver ${entry.binary}`,
        stealthScore: matched.effectiveStealthScore,
        certainty: CERTAINTY_MAP["admin"] ?? 0.85,
        attckTechniques: entry.attckTechniques,
      });

      // If EDR is detected, add CanDisableEDR edge
      if (state.edrDetected && state.edrDetected !== "none") {
        const edrNodeId = `edr-${state.edrDetected.replace(/[^a-zA-Z0-9]/g, "-")}`;
        addNode(graph, edrNodeId, "Service", state.edrDetected, {
          isEdr: true,
        });

        addEdge(graph, {
          type: "CanDisableEDR",
          from: driverNodeId,
          to: edrNodeId,
          entryId: entry.id,
          command: `disable EDR via ${entry.binary}`,
          stealthScore: matched.effectiveStealthScore * 0.5, // Low stealth — very noisy
          certainty: 0.8,
          attckTechniques: entry.attckTechniques,
        });
      }
    }
  }

  // 4. Network/lateral edges: for internal subnets
  if (state.networkAccess.internalSubnets.length > 0) {
    for (const matched of model.matchedEntries) {
      if (hasFunction(matched, "lateral_movement", "c2", "reverse_shell", "bind_shell")) {
        const binaryId = `bin-${matched.entry.id}`;
        for (const subnet of state.networkAccess.internalSubnets) {
          const netNodeId = `net-${subnet.replace(/[^a-zA-Z0-9]/g, "-")}`;
          addNode(graph, netNodeId, "Network", subnet, { subnet });

          addEdge(graph, {
            type: "CanReach",
            from: binaryId,
            to: netNodeId,
            entryId: matched.entry.id,
            command: `lateral movement to ${subnet}`,
            stealthScore: matched.effectiveStealthScore,
            certainty: CERTAINTY_MAP[matched.applicableContexts[0]?.context ?? "unprivileged"] ?? 0.7,
            attckTechniques: matched.entry.attckTechniques,
          });
        }
      }
    }
  }

  return graph;
}
