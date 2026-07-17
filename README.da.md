<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.zh-TW.md">繁體中文</a> |
  <a href="README.ko.md">한국어</a> |
  <a href="README.de.md">Deutsch</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.fr.md">Français</a> |
  <a href="README.it.md">Italiano</a> |
  <strong>Dansk</strong> |
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

<h3 align="center">Living off the Land-efterretning til AI-agenter.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 og mere &mdash; samlet i en enkelt MCP-server.<br>
  Din AI-agent faar <b>fuld-spektrum LOL-binaer-efterretning</b> til red team-, blue team- og purple team-operationer.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Tools">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Sources">
</p>

---

## Oversigt

**living-off-the-land-lolbins-mcp-server** giver din AI-agent **59 sammensatte vaerktoejer** (321 vaerktoejer i alt) paa tvaers af **10 LOL-kataloger** via [Model Context Protocol](https://modelcontextprotocol.io). Agenten foresoeger alle kataloger parallelt, korrelerer binaere filer paa tvaers af platforme, opdager eskaleringsstier, genererer detektionsregler og praesenterer et samlet angreb/forsvar-billede.

Living off the Land-binaer-efterretning er spredt over mere end 10 uafhaengige kataloger — GTFOBins, LOLBAS, LOOBins, LOLDrivers og flere — hver med sit eget format og skema. Dette projekt samler dem i en enkelt MCP-server, saa AI-agenten kan raesonnere paa tvaers af alle kataloger samtidigt til angrebsplanlaegning, forsvarsvalidering og purple team-oevelser.

Alle 10 kataloger er open source-data — ingen API-noegler kraeves. En enkelt kommando til at starte, ingen konfiguration.

---

## Hurtig start

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

## Datakilder (10)

| Katalog | Platform | Poster | Beskrivelse |
|---------|----------|--------|-------------|
| [GTFOBins](https://gtfobins.github.io) | Linux/Unix | 400+ | Unix-binaere filer til privilegieeskalering, filoperationer, shell-escape |
| [LOLBAS](https://lolbas-project.github.io) | Windows | 250+ | Windows LOL-binaere filer til eksekvering, omgaaelse, persistens |
| [LOOBins](https://www.loobins.io) | macOS | 50+ | macOS-native binaere filer til offensive operationer |
| [LOLDrivers](https://www.loldrivers.io) | Windows (kerne) | 700+ | Saarbare kerne-drivere til BYOVD-angreb |
| [LOLRMM](https://lolrmm.io) | Tvaerplatform | 100+ | Legitime RMM-vaerktoejer misbrugt til persistens og fjernadgang |
| [LOLESXi](https://lolesxi.com) | VMware ESXi | 30+ | ESXi-binaere filer til VM-escape og hypervisor-manipulation |
| [LOTP](https://lotp.github.io) | Tvaerplatform | 40+ | Betroede platforme misbrugt til ondsindede formaal |
| [LOLC2](https://lolc2.github.io) | Tvaerplatform | 30+ | Legitime tjenester misbrugt som C2-kanaler |
| [LOFLCAB](https://loflcab.github.io) | Tvaerplatform | 20+ | Firmware-, BIOS- og cabinet-fil-misbrugsteknikker |
| [WADComs](https://wadcoms.github.io) | Windows AD | 150+ | Active Directory-angrebskommandoer og -teknikker |

---

> **For den fulde vaerktoejsreference, arkitekturdetaljer og brugseksempler, se den [engelske README](README.md).**

---

<p align="center">
<b>Kun til autoriseret sikkerhedstest og -vurdering.</b><br>
Soerg altid for at have korrekt autorisation, foer du bruger LOL-binaer-teknikker paa noget maalsystem.
</p>

<p align="center">
  <a href="LICENSE">MIT-licens</a> &bull; Built with Bun + TypeScript
</p>
