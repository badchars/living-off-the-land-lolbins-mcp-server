<p align="center">
  <a href="README.md">English</a> |
  <strong>简体中文</strong> |
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

<h3 align="center">面向 AI 代理的 Living off the Land 二进制情报。</h3>

<p align="center">
  GTFOBins、LOLBAS、LOOBins、LOLDrivers、LOLRMM、WADComs、LOLC2 等 &mdash; 统一到一个 MCP 服务器中。<br>
  您的 AI 代理可获得 <b>全方位 LOL 二进制情报</b>，用于红队、蓝队和紫队行动。
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Tools">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Sources">
</p>

---

## 概述

**living-off-the-land-lolbins-mcp-server** 通过 [Model Context Protocol](https://modelcontextprotocol.io) 为您的 AI 代理提供 **59 个组合工具**（共 321 个子工具），覆盖 **10 个 LOL 目录**。代理并行查询所有目录，跨平台关联二进制文件，发现提权路径，生成检测规则，并呈现统一的攻防态势。

Living off the Land 二进制情报分散在 GTFOBins、LOLBAS、LOOBins、LOLDrivers 等 10 多个独立目录中，各有不同的格式和架构。本项目将它们统一到一个 MCP 服务器中，让 AI 代理能够同时跨所有目录进行推理，实现攻击规划、防御验证和紫队演练。

所有 10 个目录均为开源数据，无需 API 密钥。一条命令即可启动，零配置。

---

## 快速开始

```bash
npx living-off-the-land-lolbins-mcp-server
```

### Claude Code

```bash
claude mcp add lolbins-mcp-server -- npx living-off-the-land-lolbins-mcp-server
```

### Claude Desktop

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

---

## 数据源 (10)

| 目录 | 平台 | 条目数 | 说明 |
|------|------|--------|------|
| [GTFOBins](https://gtfobins.github.io) | Linux/Unix | 400+ | 可用于提权、文件操作、shell 逃逸的 Unix 二进制文件 |
| [LOLBAS](https://lolbas-project.github.io) | Windows | 250+ | 用于执行、绕过、持久化的 Windows LOL 二进制文件 |
| [LOOBins](https://www.loobins.io) | macOS | 50+ | 可用于攻击操作的 macOS 原生二进制文件 |
| [LOLDrivers](https://www.loldrivers.io) | Windows (内核) | 700+ | 用于 BYOVD 攻击的漏洞内核驱动 |
| [LOLRMM](https://lolrmm.io) | 跨平台 | 100+ | 被滥用于持久化和远程访问的合法 RMM 工具 |
| [LOLESXi](https://lolesxi.com) | VMware ESXi | 30+ | 用于虚拟机逃逸和虚拟化管理程序操控的 ESXi 二进制文件 |
| [LOTP](https://lotp.github.io) | 跨平台 | 40+ | 被滥用于恶意目的的受信任平台和服务 |
| [LOLC2](https://lolc2.github.io) | 跨平台 | 30+ | 被滥用为命令控制通道的合法服务 |
| [LOFLCAB](https://loflcab.github.io) | 跨平台 | 20+ | 固件、BIOS 和 Cabinet 文件利用技术 |
| [WADComs](https://wadcoms.github.io) | Windows AD | 150+ | Active Directory 攻击命令和技术 |

---

> **完整的工具参考、架构详情和使用示例请参阅 [英文 README](README.md)。**

---

<p align="center">
<b>仅用于授权的安全测试和评估。</b><br>
在对任何目标系统使用 LOL 二进制技术之前，请始终确保您拥有适当的授权。
</p>

<p align="center">
  <a href="LICENSE">MIT 许可证</a> &bull; Built with Bun + TypeScript
</p>
