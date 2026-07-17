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
  <strong>Português (Brasil)</strong> |
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
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 e mais &mdash; unificados em um unico servidor MCP.<br>
  Seu agente de IA obtem <b>inteligencia completa sobre binarios LOL</b> para operacoes de red team, blue team e purple team.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Licenca"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Ferramentas">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Fontes">
</p>

---

## Visao Geral

**living-off-the-land-lolbins-mcp-server** fornece ao seu agente de IA 59 ferramentas compostas (321 no total) em 10 catalogos LOL via [Model Context Protocol](https://modelcontextprotocol.io). O agente consulta todos os catalogos em paralelo, correlaciona binarios entre plataformas, descobre caminhos de escalacao de privilegios, gera regras de deteccao e apresenta uma visao unificada de ataque/defesa &mdash; em uma unica conversa.

A inteligencia sobre binarios Living off the Land esta documentada em mais de 10 catalogos, cada um com seu proprio formato e foco de plataforma. Este servidor unifica GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2, LOLESXi, LOTP e LOFLCAB em uma unica ferramenta para correlacao multiplataforma, engenharia de deteccao e analise de grafos de ataque.

Nenhuma chave de API necessaria &mdash; todos os 10 catalogos LOL sao dados de codigo aberto.

---

## Inicio Rapido

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

## Fontes de Dados

| Catalogo | Plataforma | Entradas | Descricao |
|----------|------------|----------|-----------|
| GTFOBins | Linux | 400+ | Binarios Unix exploraveis para escalacao de privilegios, operacoes de arquivo, escape de shell |
| LOLBAS | Windows | 250+ | Binarios LOL do Windows, scripts e bibliotecas para execucao, evasao, persistencia |
| LOOBins | macOS | 50+ | Binarios nativos do macOS para operacoes ofensivas |
| LOLDrivers | Windows | 700+ | Drivers de kernel vulneraveis e maliciosos para ataques BYOVD |
| LOLRMM | Multiplataforma | 100+ | Ferramentas RMM legitimas abusadas para persistencia e acesso remoto |
| LOLESXi | ESXi | 30+ | Binarios ESXi para escape de VM, manipulacao de hypervisor |
| LOTP | Multiplataforma | 40+ | Plataformas e servicos confiaveis abusados para fins maliciosos |
| LOLC2 | Multiplataforma | 30+ | Servicos legitimos abusados como canais de comando e controle |
| LOFLCAB | Multiplataforma | 20+ | Tecnicas de abuso de firmware, BIOS e arquivos cabinet |
| WADComs | Windows AD | 150+ | Comandos e tecnicas de ataque ao Active Directory |

---

> **Para documentacao completa, consulte o [README em ingles](README.md).**

---

<p align="center">
  <b>Apenas para testes e avaliacoes de seguranca autorizados.</b><br>
  Sempre garanta que voce possui autorizacao adequada antes de usar tecnicas de binarios LOL em qualquer sistema alvo.
</p>

<p align="center">
  <a href="LICENSE">Licenca MIT</a> &bull; Built with Bun + TypeScript
</p>
