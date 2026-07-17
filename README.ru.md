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
  <strong>Русский</strong> |
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

<h3 align="center">Разведка Living off the Land для ИИ-агентов.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 и другие &mdash; объединены в одном MCP-сервере.<br>
  Ваш ИИ-агент получает <b>полный спектр разведки LOL-бинарных файлов</b> для операций красной, синей и пурпурной команд.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Tools">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Sources">
</p>

---

## Обзор

**living-off-the-land-lolbins-mcp-server** предоставляет вашему ИИ-агенту **59 составных инструментов** (всего 321 инструмент) из **10 каталогов LOL** через [Model Context Protocol](https://modelcontextprotocol.io). Агент параллельно запрашивает все каталоги, коррелирует бинарные файлы между платформами, обнаруживает пути повышения привилегий, генерирует правила обнаружения и представляет единую картину атаки/защиты.

Разведка бинарных файлов Living off the Land распределена по более чем 10 независимым каталогам — GTFOBins, LOLBAS, LOOBins, LOLDrivers и другие — каждый со своим форматом и схемой. Этот проект объединяет их в одном MCP-сервере, чтобы ИИ-агент мог одновременно рассуждать по всем каталогам для планирования атак, валидации защиты и учений пурпурной команды.

Все 10 каталогов — это открытые данные. API-ключи не требуются. Одна команда для запуска, без настройки.

---

## Быстрый старт

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

## Источники данных (10)

| Каталог | Платформа | Записей | Описание |
|---------|-----------|---------|----------|
| [GTFOBins](https://gtfobins.github.io) | Linux/Unix | 400+ | Unix-бинарные файлы для повышения привилегий, файловых операций, побега из оболочки |
| [LOLBAS](https://lolbas-project.github.io) | Windows | 250+ | Windows LOL-бинарные файлы для выполнения, обхода, закрепления |
| [LOOBins](https://www.loobins.io) | macOS | 50+ | Нативные бинарные файлы macOS для наступательных операций |
| [LOLDrivers](https://www.loldrivers.io) | Windows (ядро) | 700+ | Уязвимые драйверы ядра для атак BYOVD |
| [LOLRMM](https://lolrmm.io) | Кроссплатформенный | 100+ | Легитимные RMM-инструменты, используемые для закрепления и удаленного доступа |
| [LOLESXi](https://lolesxi.com) | VMware ESXi | 30+ | Бинарные файлы ESXi для побега из VM и манипуляции гипервизором |
| [LOTP](https://lotp.github.io) | Кроссплатформенный | 40+ | Доверенные платформы, используемые в злонамеренных целях |
| [LOLC2](https://lolc2.github.io) | Кроссплатформенный | 30+ | Легитимные сервисы, используемые как каналы C2 |
| [LOFLCAB](https://loflcab.github.io) | Кроссплатформенный | 20+ | Техники злоупотребления прошивкой, BIOS и cabinet-файлами |
| [WADComs](https://wadcoms.github.io) | Windows AD | 150+ | Команды и техники атак на Active Directory |

---

> **Полный справочник инструментов, детали архитектуры и примеры использования см. в [английском README](README.md).**

---

<p align="center">
<b>Только для авторизованного тестирования и оценки безопасности.</b><br>
Всегда убедитесь, что у вас есть соответствующее разрешение, прежде чем использовать техники LOL-бинарных файлов на любой целевой системе.
</p>

<p align="center">
  <a href="LICENSE">Лицензия MIT</a> &bull; Built with Bun + TypeScript
</p>
