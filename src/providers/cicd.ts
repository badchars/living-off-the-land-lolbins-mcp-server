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

// ━━━ Hardcoded CI/CD Abuse Data ━━━

interface CicdTechnique {
  tool: string;
  technique: string;
  description: string;
  command: string;
  tags: string[];
  pipeline: string;
  configFile: string;
  attck: string[];
  detectionNotes: string;
}

const CICD_TECHNIQUES: CicdTechnique[] = [
  {
    tool: "make", technique: "Makefile command injection",
    description: "Abuse Makefile targets to execute arbitrary shell commands during build",
    command: "make -f Makefile target  # where target contains $(shell <cmd>)",
    tags: ["eval-sh", "config-file", "build-plugin"],
    pipeline: "any", configFile: "Makefile",
    attck: ["T1059.004", "T1195.002"],
    detectionNotes: "Monitor for make process spawning unexpected child processes.",
  },
  {
    tool: "npm", technique: "npm lifecycle script injection",
    description: "Abuse npm preinstall/postinstall scripts in package.json for arbitrary code execution",
    command: "npm install  # triggers preinstall/postinstall in package.json",
    tags: ["eval-sh", "config-file", "env-var"],
    pipeline: "github-actions", configFile: "package.json",
    attck: ["T1059.004", "T1195.002"],
    detectionNotes: "Monitor npm install with --ignore-scripts disabled. Check package.json scripts section.",
  },
  {
    tool: "pip", technique: "pip setup.py code execution",
    description: "Abuse setup.py execution during pip install for arbitrary code execution",
    command: "pip install .  # triggers setup.py execution",
    tags: ["eval-sh", "config-file"],
    pipeline: "any", configFile: "setup.py",
    attck: ["T1059.006", "T1195.002"],
    detectionNotes: "Monitor pip install spawning python with setup.py. Use --no-build-isolation carefully.",
  },
  {
    tool: "gradle", technique: "Gradle build script injection",
    description: "Abuse Gradle build.gradle tasks for arbitrary Groovy/shell command execution",
    command: "gradle build  # executes tasks in build.gradle with exec/commandLine",
    tags: ["eval-sh", "config-file", "build-plugin"],
    pipeline: "jenkins", configFile: "build.gradle",
    attck: ["T1059", "T1195.002"],
    detectionNotes: "Monitor gradle/gradlew spawning shell processes. Check build.gradle for exec blocks.",
  },
  {
    tool: "docker", technique: "Docker build RUN injection",
    description: "Abuse Dockerfile RUN directives or docker build args for command execution",
    command: "docker build --build-arg CMD=whoami -t img .  # ARG used in RUN",
    tags: ["eval-sh", "config-file", "env-var"],
    pipeline: "any", configFile: "Dockerfile",
    attck: ["T1059.004", "T1610"],
    detectionNotes: "Monitor docker build with suspicious build-args. Inspect Dockerfile RUN directives.",
  },
  {
    tool: "terraform", technique: "Terraform provisioner abuse",
    description: "Abuse Terraform local-exec/remote-exec provisioners for arbitrary command execution",
    command: 'terraform apply  # triggers provisioner "local-exec" { command = "<cmd>" }',
    tags: ["eval-sh", "config-file"],
    pipeline: "any", configFile: "main.tf",
    attck: ["T1059.004", "T1195.002"],
    detectionNotes: "Monitor terraform apply spawning shell commands. Check .tf files for provisioner blocks.",
  },
  {
    tool: "github-actions", technique: "GitHub Actions expression injection",
    description: "Inject commands via GitHub Actions expressions (${{ }}) in workflow files",
    command: 'run: echo "${{ github.event.pull_request.title }}"  # unsanitized input',
    tags: ["eval-sh", "env-var"],
    pipeline: "github-actions", configFile: ".github/workflows/*.yml",
    attck: ["T1059.004", "T1195.002"],
    detectionNotes: "Audit workflow files for ${{ }} expressions with untrusted input contexts.",
  },
  {
    tool: "gitlab-ci", technique: "GitLab CI variable injection",
    description: "Abuse CI/CD variables and script blocks in .gitlab-ci.yml for code execution",
    command: "script: - eval $CI_VARIABLE  # variable contains malicious command",
    tags: ["eval-sh", "env-var", "config-file"],
    pipeline: "gitlab-ci", configFile: ".gitlab-ci.yml",
    attck: ["T1059.004", "T1195.002"],
    detectionNotes: "Audit .gitlab-ci.yml for eval usage with CI variables.",
  },
  {
    tool: "jenkins", technique: "Jenkins pipeline Groovy execution",
    description: "Abuse Jenkins Pipeline Groovy scripts for arbitrary code execution on controller/agent",
    command: "sh 'whoami'  // in Jenkinsfile pipeline stage",
    tags: ["eval-sh", "config-file", "build-plugin"],
    pipeline: "jenkins", configFile: "Jenkinsfile",
    attck: ["T1059", "T1195.002"],
    detectionNotes: "Monitor Jenkins pipeline execution. Audit Jenkinsfile for sh/bat steps.",
  },
];

const SUPPLY_CHAIN_VECTORS = [
  {
    vector: "Dependency Confusion",
    description: "Register a public package with the same name as an internal package to hijack installs",
    tools: ["npm", "pip", "nuget", "maven"],
    attck: ["T1195.002"],
  },
  {
    vector: "Typosquatting",
    description: "Publish malicious packages with names similar to popular libraries",
    tools: ["npm", "pip", "rubygems"],
    attck: ["T1195.002"],
  },
  {
    vector: "Compromised Maintainer Account",
    description: "Take over a maintainer account to push malicious updates to legitimate packages",
    tools: ["npm", "pip", "crates.io"],
    attck: ["T1195.002", "T1199"],
  },
  {
    vector: "Build System Poisoning",
    description: "Modify CI/CD pipeline configs to inject malicious steps into the build process",
    tools: ["github-actions", "gitlab-ci", "jenkins", "circleci"],
    attck: ["T1195.002"],
  },
  {
    vector: "Malicious GitHub Action",
    description: "Create or compromise a GitHub Action used by target repositories",
    tools: ["github-actions"],
    attck: ["T1195.002", "T1199"],
  },
];

// ━━━ Tools ━━━

const cicd_tool_lookup: ToolDef = {
  name: "cicd_tool_lookup",
  description: "Look up CI/CD build tools from the LOTP catalog for pipeline abuse techniques",
  schema: {
    tool: z.string().describe("CI/CD tool name (e.g. 'make', 'gradle', 'npm', 'pip', 'docker', 'terraform')"),
  },
  async execute(args: { tool: string }, ctx: ToolContext): Promise<ToolResult> {
    const tool = args.tool.toLowerCase().trim();
    const techniques = CICD_TECHNIQUES.filter(t => t.tool.toLowerCase() === tool);

    // Search LOTP catalog
    const lotpEntries = ctx.knowledgeBase.searchByCatalog("lotp");
    const matches = deduplicateByBinary(
      lotpEntries.filter(e =>
        e.binary.toLowerCase().includes(tool) ||
        e.description.toLowerCase().includes(tool),
      ),
    );

    // Also search by keyword across all catalogs
    const kwResults = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword(tool, "cicd"));

    const seen = new Set(matches.map(e => e.id));
    for (const e of kwResults) {
      if (!seen.has(e.id)) { seen.add(e.id); matches.push(e); }
    }

    return json({
      tool: args.tool,
      total_techniques: techniques.length,
      techniques: techniques.map(t => ({
        tool: t.tool,
        technique: t.technique,
        description: t.description,
        command: t.command,
        tags: t.tags,
        pipeline: t.pipeline,
        config_file: t.configFile,
        attck: t.attck,
        detection_notes: t.detectionNotes,
      })),
      kb_matches: matches.slice(0, 10).map(summarizeKbEntry),
      total_kb_matches: matches.length,
    });
  },
};

const cicd_footgun_search: ToolDef = {
  name: "cicd_footgun_search",
  description: "Search CI/CD abuse techniques by tag: eval-sh, config-file, env-var, build-plugin",
  schema: {
    tag: z.enum(["eval-sh", "config-file", "env-var", "build-plugin"]).describe("Tag to search for"),
  },
  async execute(args: { tag: string }, ctx: ToolContext): Promise<ToolResult> {
    const techniques = CICD_TECHNIQUES.filter(t => t.tags.includes(args.tag));

    return json({
      tag: args.tag,
      total: techniques.length,
      techniques: techniques.map(t => ({
        tool: t.tool,
        technique: t.technique,
        description: t.description,
        command: t.command,
        config_file: t.configFile,
        pipeline: t.pipeline,
        attck: t.attck,
        detection_notes: t.detectionNotes,
      })),
    });
  },
};

const cicd_pipeline_poison: ToolDef = {
  name: "cicd_pipeline_poison",
  description: "Find pipeline poisoning techniques for specific CI/CD platforms (GitHub Actions, GitLab CI, Jenkins)",
  schema: {
    pipeline: z.enum(["github-actions", "gitlab-ci", "jenkins", "any"]).describe("CI/CD pipeline platform"),
  },
  async execute(args: { pipeline: string }, ctx: ToolContext): Promise<ToolResult> {
    const techniques = CICD_TECHNIQUES.filter(t =>
      t.pipeline === args.pipeline || t.pipeline === "any",
    );

    // Search KB for pipeline-specific entries
    const kwResults = deduplicateByBinary(
      ctx.knowledgeBase.searchByKeyword(args.pipeline.replace("-", " ")),
    );

    return json({
      pipeline: args.pipeline,
      total_techniques: techniques.length,
      techniques: techniques.map(t => ({
        tool: t.tool,
        technique: t.technique,
        description: t.description,
        command: t.command,
        config_file: t.configFile,
        attck: t.attck,
        detection_notes: t.detectionNotes,
      })),
      kb_matches: kwResults.slice(0, 10).map(summarizeKbEntry),
    });
  },
};

const cicd_config_exploit: ToolDef = {
  name: "cicd_config_exploit",
  description: "Find config file exploitation techniques (Makefile, package.json, Dockerfile, build.gradle, etc.)",
  schema: {
    config_file: z.string().describe("Config file name to search (e.g. 'Makefile', 'package.json', 'Dockerfile')"),
  },
  async execute(args: { config_file: string }, ctx: ToolContext): Promise<ToolResult> {
    const cf = args.config_file.toLowerCase().trim();
    const techniques = CICD_TECHNIQUES.filter(t => t.configFile.toLowerCase().includes(cf));

    if (techniques.length === 0) {
      return json({
        config_file: args.config_file,
        found: false,
        message: "No techniques found for this config file. Try: Makefile, package.json, Dockerfile, build.gradle, main.tf, setup.py",
        available_configs: Array.from(new Set(CICD_TECHNIQUES.map(t => t.configFile))),
      });
    }

    return json({
      config_file: args.config_file,
      total_techniques: techniques.length,
      techniques: techniques.map(t => ({
        tool: t.tool,
        technique: t.technique,
        description: t.description,
        command: t.command,
        tags: t.tags,
        attck: t.attck,
        detection_notes: t.detectionNotes,
      })),
    });
  },
};

const cicd_supply_chain: ToolDef = {
  name: "cicd_supply_chain",
  description: "Find supply chain attack vectors: dependency confusion, typosquatting, build poisoning",
  schema: {
    vector: z.string().optional().describe("Filter by attack vector keyword (e.g. 'dependency', 'typosquat', 'maintainer')"),
    tool: z.string().optional().describe("Filter by package manager or CI tool (e.g. 'npm', 'pip', 'github-actions')"),
  },
  async execute(args: { vector?: string; tool?: string }, ctx: ToolContext): Promise<ToolResult> {
    let vectors = [...SUPPLY_CHAIN_VECTORS];

    if (args.vector) {
      const v = args.vector.toLowerCase();
      vectors = vectors.filter(sv =>
        sv.vector.toLowerCase().includes(v) ||
        sv.description.toLowerCase().includes(v),
      );
    }
    if (args.tool) {
      const t = args.tool.toLowerCase();
      vectors = vectors.filter(sv => sv.tools.some(tool => tool.toLowerCase().includes(t)));
    }

    return json({
      total: vectors.length,
      supply_chain_vectors: vectors,
    });
  },
};

export const cicdTools: ToolDef[] = [
  cicd_tool_lookup,
  cicd_footgun_search,
  cicd_pipeline_poison,
  cicd_config_exploit,
  cicd_supply_chain,
];
