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
  <strong>Polski</strong> |
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

<h3 align="center">Wywiad Living off the Land dla agentow AI.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 i wiecej &mdash; zunifikowane w jednym serwerze MCP.<br>
  Twoj agent AI otrzymuje <b>pelne spektrum wywiadu o binarnych LOL</b> do operacji red team, blue team i purple team.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Tools">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Sources">
</p>

---

## Przeglad

**living-off-the-land-lolbins-mcp-server** udostepnia Twojemu agentowi AI **59 zlozonych narzedzi** (321 narzedzi lacznie) z **10 katalogow LOL** za posrednictwem [Model Context Protocol](https://modelcontextprotocol.io). Agent odpytuje wszystkie katalogi rownolegle, koreluje pliki binarne miedzy platformami, odkrywa sciezki eskalacji uprawnien, generuje reguly detekcji i prezentuje zunifikowany obraz ataku/obrony.

Wywiad o binarnych Living off the Land jest rozproszony w ponad 10 niezaleznych katalogach — GTFOBins, LOLBAS, LOOBins, LOLDrivers i innych — kazdy z wlasnym formatem i schematem. Ten projekt unifikuje je w jednym serwerze MCP, aby agent AI mogl jednoczesnie rozumowac na podstawie wszystkich katalogow w celu planowania atakow, walidacji obrony i cwiczen purple team.

Wszystkie 10 katalogow to dane open source — klucze API nie sa wymagane. Jedna komenda do uruchomienia, zero konfiguracji.

---

## Szybki start

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

## Zrodla danych (10)

| Katalog | Platforma | Wpisy | Opis |
|---------|-----------|-------|------|
| [GTFOBins](https://gtfobins.github.io) | Linux/Unix | 400+ | Pliki binarne Unix do eskalacji uprawnien, operacji na plikach, ucieczki z shella |
| [LOLBAS](https://lolbas-project.github.io) | Windows | 250+ | Pliki binarne LOL Windows do wykonywania, omijania, persistencji |
| [LOOBins](https://www.loobins.io) | macOS | 50+ | Natywne pliki binarne macOS do operacji ofensywnych |
| [LOLDrivers](https://www.loldrivers.io) | Windows (jadro) | 700+ | Podatne sterowniki jadra do atakow BYOVD |
| [LOLRMM](https://lolrmm.io) | Wieloplatformowy | 100+ | Legalne narzedzia RMM naduzywane do persistencji i zdalnego dostepu |
| [LOLESXi](https://lolesxi.com) | VMware ESXi | 30+ | Pliki binarne ESXi do ucieczki z VM i manipulacji hypervisorem |
| [LOTP](https://lotp.github.io) | Wieloplatformowy | 40+ | Zaufane platformy naduzywane w zlowrogich celach |
| [LOLC2](https://lolc2.github.io) | Wieloplatformowy | 30+ | Legalne uslugi naduzywane jako kanaly C2 |
| [LOFLCAB](https://loflcab.github.io) | Wieloplatformowy | 20+ | Techniki naduzywania firmware, BIOS i plikow cabinet |
| [WADComs](https://wadcoms.github.io) | Windows AD | 150+ | Komendy i techniki atakow Active Directory |

---

> **Pelna dokumentacja narzedzi, szczegoly architektury i przyklady uzycia znajduja sie w [angielskim README](README.md).**

---

<p align="center">
<b>Wylacznie do autoryzowanych testow i ocen bezpieczenstwa.</b><br>
Zawsze upewnij sie, ze masz odpowiednie uprawnienia przed uzyciem technik binarnych LOL na jakimkolwiek systemie docelowym.
</p>

<p align="center">
  <a href="LICENSE">Licencja MIT</a> &bull; Built with Bun + TypeScript
</p>
