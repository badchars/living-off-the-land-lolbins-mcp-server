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
  <strong>日本語</strong> |
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

<h3 align="center">AIエージェントのためのLiving off the Landインテリジェンス。</h3>

<p align="center">
  GTFOBins、LOLBAS、LOOBins、LOLDrivers、LOLRMM、WADComs、LOLC2など &mdash; 単一のMCPサーバーに統合。<br>
  AIエージェントにレッドチーム、ブルーチーム、パープルチーム作戦のための<b>フルスペクトラムLOLバイナリインテリジェンス</b>を提供します。
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Tools">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Sources">
</p>

---

## 概要

**living-off-the-land-lolbins-mcp-server**は、[Model Context Protocol](https://modelcontextprotocol.io)を通じて、AIエージェントに**10のLOLカタログ**から**59の複合ツール**（合計321のサブツール）を提供します。エージェントは全カタログを並列にクエリし、クロスプラットフォームでバイナリを関連付け、権限昇格パスを発見し、検出ルールを生成し、統一された攻撃/防御の全体像を提示します。

Living off the Landバイナリインテリジェンスは、GTFOBins、LOLBAS、LOOBins、LOLDriversなど10以上の独立したカタログに分散しており、それぞれ独自のフォーマットとスキーマを持っています。本プロジェクトはこれらを単一のMCPサーバーに統合し、AIエージェントが攻撃計画、防御検証、パープルチーム演習のためにすべてのカタログにわたって同時に推論できるようにします。

10のカタログすべてがオープンソースデータです。APIキー不要。コマンド一つで起動、設定不要。

---

## クイックスタート

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

## データソース (10)

| カタログ | プラットフォーム | エントリ数 | 説明 |
|---------|-----------------|-----------|------|
| [GTFOBins](https://gtfobins.github.io) | Linux/Unix | 400+ | 権限昇格、ファイル操作、シェルエスケープに利用可能なUnixバイナリ |
| [LOLBAS](https://lolbas-project.github.io) | Windows | 250+ | 実行、回避、永続化のためのWindows LOLバイナリ |
| [LOOBins](https://www.loobins.io) | macOS | 50+ | 攻撃作戦に利用可能なmacOSネイティブバイナリ |
| [LOLDrivers](https://www.loldrivers.io) | Windows (カーネル) | 700+ | BYOVD攻撃のための脆弱なカーネルドライバ |
| [LOLRMM](https://lolrmm.io) | クロスプラットフォーム | 100+ | 永続化とリモートアクセスに悪用される正規RMMツール |
| [LOLESXi](https://lolesxi.com) | VMware ESXi | 30+ | VMエスケープとハイパーバイザー操作のためのESXiバイナリ |
| [LOTP](https://lotp.github.io) | クロスプラットフォーム | 40+ | 悪意のある目的で悪用される信頼プラットフォーム |
| [LOLC2](https://lolc2.github.io) | クロスプラットフォーム | 30+ | C2チャネルとして悪用される正規サービス |
| [LOFLCAB](https://loflcab.github.io) | クロスプラットフォーム | 20+ | ファームウェア、BIOS、キャビネットファイルの悪用技術 |
| [WADComs](https://wadcoms.github.io) | Windows AD | 150+ | Active Directory攻撃コマンドと技術 |

---

> **ツールの完全なリファレンス、アーキテクチャの詳細、使用例については[英語版README](README.md)をご覧ください。**

---

<p align="center">
<b>許可されたセキュリティテストおよび評価にのみ使用してください。</b><br>
対象システムでLOLバイナリ技術を使用する前に、必ず適切な許可を得てください。
</p>

<p align="center">
  <a href="LICENSE">MIT License</a> &bull; Built with Bun + TypeScript
</p>
