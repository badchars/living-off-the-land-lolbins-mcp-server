<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.zh-TW.md">繁體中文</a> |
  <a href="README.ko.md">한국어</a> |
  <a href="README.de.md">Deutsch</a> |
  <a href="README.es.md">Español</a> |
  <strong>Français</strong> |
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

<h3 align="center">Renseignement Living off the Land pour agents IA.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 et plus &mdash; unifies dans un seul serveur MCP.<br>
  Votre agent IA obtient une <b>intelligence complete des binaires LOL</b> pour les operations red team, blue team et purple team.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Tools">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Sources">
</p>

---

## Apercu

**living-off-the-land-lolbins-mcp-server** fournit a votre agent IA **59 outils composites** (321 outils au total) couvrant **10 catalogues LOL** via le [Model Context Protocol](https://modelcontextprotocol.io). L'agent interroge tous les catalogues en parallele, correle les binaires entre plateformes, decouvre les chemins d'escalade de privileges, genere des regles de detection et presente une vision unifiee attaque/defense.

Le renseignement sur les binaires Living off the Land est disperse dans plus de 10 catalogues independants — GTFOBins, LOLBAS, LOOBins, LOLDrivers et autres — chacun avec son propre format et schema. Ce projet les unifie dans un seul serveur MCP pour que l'agent IA puisse raisonner simultanement sur tous les catalogues pour la planification d'attaques, la validation des defenses et les exercices purple team.

Les 10 catalogues sont des donnees open source — aucune cle API requise. Une seule commande pour demarrer, zero configuration.

---

## Demarrage rapide

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

## Sources de donnees (10)

| Catalogue | Plateforme | Entrees | Description |
|-----------|------------|---------|-------------|
| [GTFOBins](https://gtfobins.github.io) | Linux/Unix | 400+ | Binaires Unix pour escalade de privileges, operations fichier, echappement shell |
| [LOLBAS](https://lolbas-project.github.io) | Windows | 250+ | Binaires LOL Windows pour execution, evasion, persistance |
| [LOOBins](https://www.loobins.io) | macOS | 50+ | Binaires natifs macOS pour operations offensives |
| [LOLDrivers](https://www.loldrivers.io) | Windows (noyau) | 700+ | Pilotes noyau vulnerables pour attaques BYOVD |
| [LOLRMM](https://lolrmm.io) | Multiplateforme | 100+ | Outils RMM legitimes detournes pour persistance et acces distant |
| [LOLESXi](https://lolesxi.com) | VMware ESXi | 30+ | Binaires ESXi pour echappement VM et manipulation d'hyperviseur |
| [LOTP](https://lotp.github.io) | Multiplateforme | 40+ | Plateformes de confiance detournees a des fins malveillantes |
| [LOLC2](https://lolc2.github.io) | Multiplateforme | 30+ | Services legitimes detournes comme canaux C2 |
| [LOFLCAB](https://loflcab.github.io) | Multiplateforme | 20+ | Techniques d'abus de firmware, BIOS et fichiers cabinet |
| [WADComs](https://wadcoms.github.io) | Windows AD | 150+ | Commandes et techniques d'attaque Active Directory |

---

> **Pour la reference complete des outils, les details d'architecture et les exemples d'utilisation, consultez le [README en anglais](README.md).**

---

<p align="center">
<b>Uniquement pour les tests et evaluations de securite autorises.</b><br>
Assurez-vous toujours d'avoir l'autorisation appropriee avant d'utiliser des techniques de binaires LOL sur tout systeme cible.
</p>

<p align="center">
  <a href="LICENSE">Licence MIT</a> &bull; Built with Bun + TypeScript
</p>
