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
  <a href="README.no.md">Norsk</a> |
  <a href="README.pt-BR.md">Português (Brasil)</a> |
  <a href="README.th.md">ไทย</a> |
  <a href="README.tr.md">Türkçe</a> |
  <strong>Українська</strong> |
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

<h3 align="center">Розвідка Living off the Land для AI-агентів.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 та інші &mdash; об'єднані в одному MCP-сервері.<br>
  Ваш AI-агент отримує <b>повний спектр розвідки LOL-бінарників</b> для операцій red team, blue team та purple team.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Ліцензія"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 інструментів">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 джерел">
</p>

---

## Огляд

**living-off-the-land-lolbins-mcp-server** надає вашому AI-агенту 59 складених інструментів (321 загалом) з 10 LOL-каталогів через [Model Context Protocol](https://modelcontextprotocol.io). Агент запитує всі каталоги паралельно, корелює бінарники між платформами, виявляє шляхи підвищення привілеїв, генерує правила виявлення та представляє об'єднану картину атаки/захисту &mdash; в одній розмові.

Розвідувальна інформація про Living off the Land бінарники задокументована в понад 10 каталогах, кожен з яких має свій формат та фокус на платформу. Цей сервер об'єднує GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2, LOLESXi, LOTP та LOFLCAB в один інструмент для крос-платформної кореляції, інженерії виявлення та аналізу графів атак.

API-ключі не потрібні &mdash; всі 10 LOL-каталогів є даними з відкритим вихідним кодом.

---

## Швидкий старт

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

## Джерела даних

| Каталог | Платформа | Записи | Опис |
|---------|-----------|--------|------|
| GTFOBins | Linux | 400+ | Unix-бінарники для підвищення привілеїв, файлових операцій, втечі з shell |
| LOLBAS | Windows | 250+ | Windows LOL-бінарники, скрипти та бібліотеки для виконання, ухилення, закріплення |
| LOOBins | macOS | 50+ | Нативні бінарники macOS для наступальних операцій |
| LOLDrivers | Windows | 700+ | Вразливі та шкідливі драйвери ядра для атак BYOVD |
| LOLRMM | Крос-платформний | 100+ | Легітимні RMM-інструменти, що зловживаються для закріплення та віддаленого доступу |
| LOLESXi | ESXi | 30+ | Бінарники ESXi для втечі з VM, маніпуляцій з гіпервізором |
| LOTP | Крос-платформний | 40+ | Довірені платформи та сервіси, що зловживаються у зловмисних цілях |
| LOLC2 | Крос-платформний | 30+ | Легітимні сервіси, що зловживаються як канали C2 |
| LOFLCAB | Крос-платформний | 20+ | Техніки зловживання прошивкою, BIOS та cabinet-файлами |
| WADComs | Windows AD | 150+ | Команди та техніки атак на Active Directory |

---

> **Повну документацію дивіться в [англійському README](README.md).**

---

<p align="center">
  <b>Тільки для авторизованого тестування безпеки та оцінки.</b><br>
  Завжди переконуйтеся, що у вас є належна авторизація перед використанням технік LOL-бінарників на будь-якій цільовій системі.
</p>

<p align="center">
  <a href="LICENSE">MIT Ліцензія</a> &bull; Built with Bun + TypeScript
</p>
