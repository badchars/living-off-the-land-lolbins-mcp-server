<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.zh-TW.md">繁體中文</a> |
  <a href="README.ko.md">한국어</a> |
  <a href="README.de.md">Deutsch</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.fr.md">Français</a> |
  <strong>Italiano</strong> |
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

<h3 align="center">Intelligence Living off the Land per agenti IA.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 e altro &mdash; unificati in un unico server MCP.<br>
  Il tuo agente IA ottiene <b>intelligence completa sui binari LOL</b> per operazioni red team, blue team e purple team.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Tools">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Sources">
</p>

---

## Panoramica

**living-off-the-land-lolbins-mcp-server** fornisce al tuo agente IA **59 strumenti compositi** (321 strumenti totali) da **10 cataloghi LOL** tramite il [Model Context Protocol](https://modelcontextprotocol.io). L'agente interroga tutti i cataloghi in parallelo, correla i binari tra piattaforme, scopre percorsi di escalation dei privilegi, genera regole di rilevamento e presenta un quadro unificato attacco/difesa.

L'intelligence sui binari Living off the Land e distribuita in oltre 10 cataloghi indipendenti — GTFOBins, LOLBAS, LOOBins, LOLDrivers e altri — ciascuno con il proprio formato e schema. Questo progetto li unifica in un unico server MCP affinche l'agente IA possa ragionare simultaneamente su tutti i cataloghi per la pianificazione degli attacchi, la validazione delle difese e gli esercizi purple team.

Tutti i 10 cataloghi sono dati open source — nessuna chiave API richiesta. Un solo comando per iniziare, zero configurazione.

---

## Avvio rapido

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

## Fonti dati (10)

| Catalogo | Piattaforma | Voci | Descrizione |
|----------|-------------|------|-------------|
| [GTFOBins](https://gtfobins.github.io) | Linux/Unix | 400+ | Binari Unix per escalation privilegi, operazioni file, escape shell |
| [LOLBAS](https://lolbas-project.github.io) | Windows | 250+ | Binari LOL Windows per esecuzione, evasione, persistenza |
| [LOOBins](https://www.loobins.io) | macOS | 50+ | Binari nativi macOS per operazioni offensive |
| [LOLDrivers](https://www.loldrivers.io) | Windows (kernel) | 700+ | Driver kernel vulnerabili per attacchi BYOVD |
| [LOLRMM](https://lolrmm.io) | Multipiattaforma | 100+ | Strumenti RMM legittimi abusati per persistenza e accesso remoto |
| [LOLESXi](https://lolesxi.com) | VMware ESXi | 30+ | Binari ESXi per escape VM e manipolazione hypervisor |
| [LOTP](https://lotp.github.io) | Multipiattaforma | 40+ | Piattaforme fidate abusate per scopi malevoli |
| [LOLC2](https://lolc2.github.io) | Multipiattaforma | 30+ | Servizi legittimi abusati come canali C2 |
| [LOFLCAB](https://loflcab.github.io) | Multipiattaforma | 20+ | Tecniche di abuso firmware, BIOS e file cabinet |
| [WADComs](https://wadcoms.github.io) | Windows AD | 150+ | Comandi e tecniche di attacco Active Directory |

---

> **Per il riferimento completo degli strumenti, i dettagli dell'architettura e gli esempi d'uso, consulta il [README in inglese](README.md).**

---

<p align="center">
<b>Solo per test e valutazioni di sicurezza autorizzati.</b><br>
Assicurati sempre di avere l'autorizzazione appropriata prima di utilizzare tecniche di binari LOL su qualsiasi sistema target.
</p>

<p align="center">
  <a href="LICENSE">Licenza MIT</a> &bull; Built with Bun + TypeScript
</p>
