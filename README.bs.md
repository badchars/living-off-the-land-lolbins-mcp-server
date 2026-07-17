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
  <strong>Bosanski</strong> |
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

<h3 align="center">Living off the Land obavještajni podaci za AI agente.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 i drugi &mdash; objedinjeni u jedan MCP server.<br>
  Vaš AI agent dobija <b>potpuni LOL binarni obavještajni spektar</b> za red team, blue team i purple team operacije.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Licenca"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Alata">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Izvora">
</p>

---

## Pregled

**living-off-the-land-lolbins-mcp-server** pruža vašem AI agentu 59 kompozitnih alata (321 ukupno) kroz 10 LOL kataloga putem [Model Context Protocol](https://modelcontextprotocol.io). Agent pretražuje sve kataloge paralelno, korelira binarne datoteke na svim platformama, otkriva puteve eskalacije privilegija, generiše pravila za detekciju i predstavlja objedinjenu sliku napada/odbrane &mdash; sve u jednom razgovoru.

Obavještajni podaci o Living off the Land binarnim datotekama su dokumentovani kroz 10+ kataloga, svaki sa svojim formatom i fokusom na platformu. Ovaj server objedinjuje GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2, LOLESXi, LOTP i LOFLCAB u jedan alat za međuplatformsku korelaciju, inženjering detekcije i analizu grafova napada.

Nijedan API ključ nije potreban &mdash; svih 10 LOL kataloga su podaci otvorenog koda.

---

## Brzi početak

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

## Izvori podataka

| Katalog | Platforma | Unosi | Opis |
|---------|-----------|-------|------|
| GTFOBins | Linux | 400+ | Unix binarni za eskalaciju privilegija, operacije s datotekama, izlaz iz ljuske |
| LOLBAS | Windows | 250+ | Windows LOL binarni, skripte i biblioteke za izvršavanje, izbjegavanje, postojanost |
| LOOBins | macOS | 50+ | macOS izvorne binarne datoteke za ofenzivne operacije |
| LOLDrivers | Windows | 700+ | Ranjivi i zlonamjerni kernel drajveri za BYOVD napade |
| LOLRMM | Višeplatformski | 100+ | Legitimni RMM alati zloupotrijebljeni za postojanost i daljinski pristup |
| LOLESXi | ESXi | 30+ | ESXi binarni za bijeg iz VM-a, manipulaciju hipervizora |
| LOTP | Višeplatformski | 40+ | Pouzdane platforme i servisi zloupotrijebljeni u zlonamjerne svrhe |
| LOLC2 | Višeplatformski | 30+ | Legitimni servisi zloupotrijebljeni kao C2 kanali |
| LOFLCAB | Višeplatformski | 20+ | Tehnike zloupotrebe firmvera, BIOS-a i cabinet datoteka |
| WADComs | Windows AD | 150+ | Active Directory komande i tehnike napada |

---

> **Za kompletnu dokumentaciju, pogledajte [engleski README](README.md).**

---

<p align="center">
  <b>Samo za autorizovano sigurnosno testiranje i procjenu.</b><br>
  Uvijek se pobrinite da imate odgovarajuću autorizaciju prije korištenja LOL binarnih tehnika na bilo kojem ciljnom sistemu.
</p>

<p align="center">
  <a href="LICENSE">MIT Licenca</a> &bull; Built with Bun + TypeScript
</p>
