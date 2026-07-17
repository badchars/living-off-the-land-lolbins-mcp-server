<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.zh-TW.md">繁體中文</a> |
  <a href="README.ko.md">한국어</a> |
  <strong>Deutsch</strong> |
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

<h3 align="center">Living-off-the-Land-Intelligenz fuer KI-Agenten.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 und mehr &mdash; vereint in einem einzigen MCP-Server.<br>
  Ihr KI-Agent erhaelt <b>umfassende LOL-Binaer-Intelligenz</b> fuer Red-Team-, Blue-Team- und Purple-Team-Operationen.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Tools">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Sources">
</p>

---

## Ueberblick

**living-off-the-land-lolbins-mcp-server** stellt Ihrem KI-Agenten ueber das [Model Context Protocol](https://modelcontextprotocol.io) **59 zusammengesetzte Werkzeuge** (321 Gesamt-Werkzeuge) aus **10 LOL-Katalogen** bereit. Der Agent fragt alle Kataloge parallel ab, korreliert Binaerdateien plattformuebergreifend, entdeckt Eskalationspfade, generiert Erkennungsregeln und praesentiert ein einheitliches Angriffs-/Verteidigungsbild.

Living-off-the-Land-Binaer-Intelligenz ist ueber GTFOBins, LOLBAS, LOOBins, LOLDrivers und weitere 10+ unabhaengige Kataloge verstreut, jeder mit eigenem Format und Schema. Dieses Projekt vereint sie in einem einzigen MCP-Server, sodass der KI-Agent gleichzeitig ueber alle Kataloge hinweg schlussfolgern kann — fuer Angriffsplanung, Verteidigungsvalidierung und Purple-Team-Uebungen.

Alle 10 Kataloge sind Open-Source-Daten — keine API-Schluessel erforderlich. Ein Befehl zum Starten, keine Konfiguration.

---

## Schnellstart

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

## Datenquellen (10)

| Katalog | Plattform | Eintraege | Beschreibung |
|---------|-----------|-----------|--------------|
| [GTFOBins](https://gtfobins.github.io) | Linux/Unix | 400+ | Unix-Binaerdateien fuer Privilegieneskalation, Dateioperationen, Shell-Escape |
| [LOLBAS](https://lolbas-project.github.io) | Windows | 250+ | Windows-LOL-Binaerdateien fuer Ausfuehrung, Umgehung, Persistenz |
| [LOOBins](https://www.loobins.io) | macOS | 50+ | macOS-native Binaerdateien fuer offensive Operationen |
| [LOLDrivers](https://www.loldrivers.io) | Windows (Kernel) | 700+ | Verwundbare Kerneltreiber fuer BYOVD-Angriffe |
| [LOLRMM](https://lolrmm.io) | Plattformuebergreifend | 100+ | Legitime RMM-Werkzeuge, missbraucht fuer Persistenz und Fernzugriff |
| [LOLESXi](https://lolesxi.com) | VMware ESXi | 30+ | ESXi-Binaerdateien fuer VM-Escape und Hypervisor-Manipulation |
| [LOTP](https://lotp.github.io) | Plattformuebergreifend | 40+ | Vertrauenswuerdige Plattformen, missbraucht fuer boesartige Zwecke |
| [LOLC2](https://lolc2.github.io) | Plattformuebergreifend | 30+ | Legitime Dienste, missbraucht als C2-Kanaele |
| [LOFLCAB](https://loflcab.github.io) | Plattformuebergreifend | 20+ | Firmware-, BIOS- und Cabinet-Datei-Missbrauchstechniken |
| [WADComs](https://wadcoms.github.io) | Windows AD | 150+ | Active-Directory-Angriffsbefehle und -techniken |

---

> **Vollstaendige Werkzeugreferenz, Architekturdetails und Nutzungsbeispiele finden Sie in der [englischen README](README.md).**

---

<p align="center">
<b>Nur fuer autorisierte Sicherheitstests und -bewertungen.</b><br>
Stellen Sie immer sicher, dass Sie die entsprechende Genehmigung haben, bevor Sie LOL-Binaer-Techniken auf einem Zielsystem einsetzen.
</p>

<p align="center">
  <a href="LICENSE">MIT-Lizenz</a> &bull; Built with Bun + TypeScript
</p>
