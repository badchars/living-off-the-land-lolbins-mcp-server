<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.zh-TW.md">繁體中文</a> |
  <strong>한국어</strong> |
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

<h3 align="center">AI 에이전트를 위한 Living off the Land 바이너리 인텔리전스.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 등 &mdash; 단일 MCP 서버로 통합.<br>
  AI 에이전트에게 레드팀, 블루팀, 퍼플팀 작전을 위한 <b>풀 스펙트럼 LOL 바이너리 인텔리전스</b>를 제공합니다.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Tools">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Sources">
</p>

---

## 개요

**living-off-the-land-lolbins-mcp-server**는 [Model Context Protocol](https://modelcontextprotocol.io)을 통해 AI 에이전트에게 **59개의 복합 도구**(총 321개 하위 도구)를 제공하며, **10개 LOL 카탈로그**를 통합합니다. 에이전트는 모든 카탈로그를 병렬로 쿼리하고, 크로스 플랫폼 바이너리를 연관시키며, 권한 상승 경로를 발견하고, 탐지 규칙을 생성하여 통합된 공격/방어 현황을 제시합니다.

Living off the Land 바이너리 인텔리전스는 GTFOBins, LOLBAS, LOOBins, LOLDrivers 등 10개 이상의 독립적인 카탈로그에 분산되어 있으며, 각각 고유한 형식과 스키마를 가지고 있습니다. 이 프로젝트는 이를 단일 MCP 서버로 통합하여 AI 에이전트가 모든 카탈로그에 걸쳐 동시에 추론할 수 있도록 합니다.

모든 10개 카탈로그는 오픈소스 데이터이며, API 키가 필요하지 않습니다. 명령어 하나로 시작, 설정 불필요.

---

## 빠른 시작

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

## 데이터 소스 (10)

| 카탈로그 | 플랫폼 | 항목 수 | 설명 |
|----------|--------|---------|------|
| [GTFOBins](https://gtfobins.github.io) | Linux/Unix | 400+ | 권한 상승, 파일 작업, 셸 탈출에 활용 가능한 Unix 바이너리 |
| [LOLBAS](https://lolbas-project.github.io) | Windows | 250+ | 실행, 우회, 지속성을 위한 Windows LOL 바이너리 |
| [LOOBins](https://www.loobins.io) | macOS | 50+ | 공격 작전에 활용 가능한 macOS 기본 바이너리 |
| [LOLDrivers](https://www.loldrivers.io) | Windows (커널) | 700+ | BYOVD 공격을 위한 취약 커널 드라이버 |
| [LOLRMM](https://lolrmm.io) | 크로스 플랫폼 | 100+ | 지속성과 원격 접근에 악용되는 합법적 RMM 도구 |
| [LOLESXi](https://lolesxi.com) | VMware ESXi | 30+ | VM 탈출 및 하이퍼바이저 조작을 위한 ESXi 바이너리 |
| [LOTP](https://lotp.github.io) | 크로스 플랫폼 | 40+ | 악의적 목적으로 악용되는 신뢰 플랫폼 및 서비스 |
| [LOLC2](https://lolc2.github.io) | 크로스 플랫폼 | 30+ | C2 채널로 악용되는 합법적 서비스 |
| [LOFLCAB](https://loflcab.github.io) | 크로스 플랫폼 | 20+ | 펌웨어, BIOS 및 캐비닛 파일 악용 기법 |
| [WADComs](https://wadcoms.github.io) | Windows AD | 150+ | Active Directory 공격 명령 및 기법 |

---

> **전체 도구 레퍼런스, 아키텍처 세부 정보 및 사용 예시는 [영문 README](README.md)를 참조하세요.**

---

<p align="center">
<b>승인된 보안 테스트 및 평가 목적으로만 사용하세요.</b><br>
대상 시스템에서 LOL 바이너리 기법을 사용하기 전에 항상 적절한 권한을 확보하세요.
</p>

<p align="center">
  <a href="LICENSE">MIT License</a> &bull; Built with Bun + TypeScript
</p>
