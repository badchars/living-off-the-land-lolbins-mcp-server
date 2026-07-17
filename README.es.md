<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.zh-TW.md">繁體中文</a> |
  <a href="README.ko.md">한국어</a> |
  <a href="README.de.md">Deutsch</a> |
  <strong>Español</strong> |
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

<h3 align="center">Inteligencia Living off the Land para agentes de IA.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 y mas &mdash; unificados en un solo servidor MCP.<br>
  Tu agente de IA obtiene <b>inteligencia completa de binarios LOL</b> para operaciones de red team, blue team y purple team.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Tools">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Sources">
</p>

---

## Descripcion general

**living-off-the-land-lolbins-mcp-server** proporciona a tu agente de IA **59 herramientas compuestas** (321 herramientas en total) de **10 catalogos LOL** a traves del [Model Context Protocol](https://modelcontextprotocol.io). El agente consulta todos los catalogos en paralelo, correlaciona binarios entre plataformas, descubre rutas de escalacion de privilegios, genera reglas de deteccion y presenta una vision unificada de ataque/defensa.

La inteligencia de binarios Living off the Land esta dispersa en mas de 10 catalogos independientes — GTFOBins, LOLBAS, LOOBins, LOLDrivers y mas — cada uno con su propio formato y esquema. Este proyecto los unifica en un solo servidor MCP para que el agente de IA pueda razonar simultaneamente a traves de todos los catalogos para planificacion de ataques, validacion de defensas y ejercicios de purple team.

Los 10 catalogos son datos de codigo abierto — no se requieren claves API. Un solo comando para iniciar, sin configuracion.

---

## Inicio rapido

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

## Fuentes de datos (10)

| Catalogo | Plataforma | Entradas | Descripcion |
|----------|------------|----------|-------------|
| [GTFOBins](https://gtfobins.github.io) | Linux/Unix | 400+ | Binarios Unix para escalacion de privilegios, operaciones de archivo, escape de shell |
| [LOLBAS](https://lolbas-project.github.io) | Windows | 250+ | Binarios LOL de Windows para ejecucion, evasion, persistencia |
| [LOOBins](https://www.loobins.io) | macOS | 50+ | Binarios nativos de macOS para operaciones ofensivas |
| [LOLDrivers](https://www.loldrivers.io) | Windows (kernel) | 700+ | Controladores de kernel vulnerables para ataques BYOVD |
| [LOLRMM](https://lolrmm.io) | Multiplataforma | 100+ | Herramientas RMM legitimas abusadas para persistencia y acceso remoto |
| [LOLESXi](https://lolesxi.com) | VMware ESXi | 30+ | Binarios ESXi para escape de VM y manipulacion de hypervisor |
| [LOTP](https://lotp.github.io) | Multiplataforma | 40+ | Plataformas de confianza abusadas con fines maliciosos |
| [LOLC2](https://lolc2.github.io) | Multiplataforma | 30+ | Servicios legitimos abusados como canales C2 |
| [LOFLCAB](https://loflcab.github.io) | Multiplataforma | 20+ | Tecnicas de abuso de firmware, BIOS y archivos cabinet |
| [WADComs](https://wadcoms.github.io) | Windows AD | 150+ | Comandos y tecnicas de ataque a Active Directory |

---

> **Para la referencia completa de herramientas, detalles de arquitectura y ejemplos de uso, consulta el [README en ingles](README.md).**

---

<p align="center">
<b>Solo para pruebas y evaluaciones de seguridad autorizadas.</b><br>
Asegurate siempre de tener la autorizacion adecuada antes de utilizar tecnicas de binarios LOL en cualquier sistema objetivo.
</p>

<p align="center">
  <a href="LICENSE">Licencia MIT</a> &bull; Built with Bun + TypeScript
</p>
