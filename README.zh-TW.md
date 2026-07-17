<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh.md">简体中文</a> |
  <strong>繁體中文</strong> |
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

<h3 align="center">為 AI 代理提供的 Living off the Land 二進位情報。</h3>

<p align="center">
  GTFOBins、LOLBAS、LOOBins、LOLDrivers、LOLRMM、WADComs、LOLC2 等 &mdash; 統一至單一 MCP 伺服器。<br>
  您的 AI 代理可獲得 <b>全方位 LOL 二進位情報</b>，用於紅隊、藍隊和紫隊行動。
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Tools">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Sources">
</p>

---

## 概述

**living-off-the-land-lolbins-mcp-server** 透過 [Model Context Protocol](https://modelcontextprotocol.io) 為您的 AI 代理提供 **59 個組合工具**（共 321 個子工具），涵蓋 **10 個 LOL 目錄**。代理可並行查詢所有目錄、跨平台關聯二進位檔案、發現提權路徑、產生偵測規則，並呈現統一的攻防態勢。

Living off the Land 二進位情報分散在 GTFOBins、LOLBAS、LOOBins、LOLDrivers 等 10 多個獨立目錄中，各有不同的格式與架構。本專案將它們統一至單一 MCP 伺服器，讓 AI 代理能夠同時跨所有目錄進行推理，實現攻擊規劃、防禦驗證和紫隊演練。

所有 10 個目錄均為開源資料，無需 API 金鑰。一條指令即可啟動，零配置。

---

## 快速開始

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

## 資料來源 (10)

| 目錄 | 平台 | 條目數 | 說明 |
|------|------|--------|------|
| [GTFOBins](https://gtfobins.github.io) | Linux/Unix | 400+ | 可用於提權、檔案操作、shell 逃脫的 Unix 二進位檔案 |
| [LOLBAS](https://lolbas-project.github.io) | Windows | 250+ | 用於執行、繞過、持久化的 Windows LOL 二進位檔案 |
| [LOOBins](https://www.loobins.io) | macOS | 50+ | 可用於攻擊操作的 macOS 原生二進位檔案 |
| [LOLDrivers](https://www.loldrivers.io) | Windows (核心) | 700+ | 用於 BYOVD 攻擊的漏洞核心驅動程式 |
| [LOLRMM](https://lolrmm.io) | 跨平台 | 100+ | 被濫用於持久化和遠端存取的合法 RMM 工具 |
| [LOLESXi](https://lolesxi.com) | VMware ESXi | 30+ | 用於虛擬機逃脫和 Hypervisor 操控的 ESXi 二進位檔案 |
| [LOTP](https://lotp.github.io) | 跨平台 | 40+ | 被濫用於惡意目的的受信任平台和服務 |
| [LOLC2](https://lolc2.github.io) | 跨平台 | 30+ | 被濫用為命令與控制通道的合法服務 |
| [LOFLCAB](https://loflcab.github.io) | 跨平台 | 20+ | 韌體、BIOS 和 Cabinet 檔案利用技術 |
| [WADComs](https://wadcoms.github.io) | Windows AD | 150+ | Active Directory 攻擊指令和技術 |

---

> **完整的工具參考、架構詳情和使用範例請參閱 [英文 README](README.md)。**

---

<p align="center">
<b>僅供授權的安全測試和評估使用。</b><br>
在對任何目標系統使用 LOL 二進位技術之前，請務必確保您擁有適當的授權。
</p>

<p align="center">
  <a href="LICENSE">MIT 授權條款</a> &bull; Built with Bun + TypeScript
</p>
