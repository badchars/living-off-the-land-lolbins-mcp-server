<p align="center">
  <a href="README.md">English</a> |
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
  <strong>Norsk</strong> |
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

<h3 align="center">Living off the Land-etterretning for AI-agenter.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 og mer &mdash; samlet i en enkelt MCP-server.<br>
  Din AI-agent far <b>fullspektrum LOL-binar etterretning</b> for red team-, blue team- og purple team-operasjoner.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Lisens"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Verktoy">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Kilder">
</p>

---

## Oversikt

**living-off-the-land-lolbins-mcp-server** gir din AI-agent 59 sammensatte verktoy (321 totalt) pa tvers av 10 LOL-kataloger via [Model Context Protocol](https://modelcontextprotocol.io). Agenten soker i alle kataloger parallelt, korrelerer binarer pa tvers av plattformer, oppdager privilegieeskaleringsveier, genererer deteksjonsregler og presenterer et samlet angreps-/forsvarsbilde &mdash; i en enkelt samtale.

Living off the Land-binaretterretning er dokumentert pa tvers av 10+ kataloger, hver med sitt eget format og plattformfokus. Denne serveren forener GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2, LOLESXi, LOTP og LOFLCAB til et enkelt verktoy for kryssplattform-korrelasjon, deteksjonsingenioring og angrepsgrafanalyse.

Ingen API-nokler kreves &mdash; alle 10 LOL-kataloger er apen kildekode-data.

---

## Hurtigstart

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

## Datakilder

| Katalog | Plattform | Oppforinger | Beskrivelse |
|---------|-----------|-------------|-------------|
| GTFOBins | Linux | 400+ | Unix-binarer som kan utnyttes for privilegieeskalering, filoperasjoner, shell-flukt |
| LOLBAS | Windows | 250+ | Windows LOL-binarer, skript og biblioteker for utforelse, unnvikelse, persistens |
| LOOBins | macOS | 50+ | Innebygde macOS-binarer for offensive operasjoner |
| LOLDrivers | Windows | 700+ | Sarbare og ondsinnede kjernedrivere for BYOVD-angrep |
| LOLRMM | Kryssplattform | 100+ | Legitime RMM-verktoy misbrukt for persistens og fjerntilgang |
| LOLESXi | ESXi | 30+ | ESXi-binarer for VM-flukt, hypervisor-manipulasjon |
| LOTP | Kryssplattform | 40+ | Palitelige plattformer og tjenester misbrukt til ondsinnede formal |
| LOLC2 | Kryssplattform | 30+ | Legitime tjenester misbrukt som kommando-og-kontroll-kanaler |
| LOFLCAB | Kryssplattform | 20+ | Fastvare-, BIOS- og cabinet-filmisbruksteknikker |
| WADComs | Windows AD | 150+ | Active Directory-angrepskommandoer og -teknikker |

---

> **For fullstendig dokumentasjon, se [engelsk README](README.md).**

---

<p align="center">
  <b>Kun for autorisert sikkerhetstesting og vurdering.</b><br>
  Sorg alltid for at du har riktig autorisasjon for du bruker LOL-binarteknikker pa noe malsystem.
</p>

<p align="center">
  <a href="LICENSE">MIT-lisens</a> &bull; Built with Bun + TypeScript
</p>
