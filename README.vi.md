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
  <a href="README.uk.md">Українська</a> |
  <a href="README.bn.md">বাংলা</a> |
  <a href="README.el.md">Ελληνικά</a> |
  <strong>Tiếng Việt</strong> |
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

<h3 align="center">Thong tin tinh bao Living off the Land cho AI agent.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 va nhieu hon nua &mdash; thong nhat trong mot may chu MCP duy nhat.<br>
  AI agent cua ban nhan duoc <b>thong tin tinh bao LOL binary toan dien</b> cho cac chien dich red team, blue team va purple team.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Giay phep"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Cong cu">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Nguon">
</p>

---

## Tong quan

**living-off-the-land-lolbins-mcp-server** cung cap cho AI agent cua ban 59 cong cu tong hop (tong cong 321) tren 10 danh muc LOL thong qua [Model Context Protocol](https://modelcontextprotocol.io). Agent truy van tat ca cac danh muc dong thoi, tuong quan binary giua cac nen tang, phat hien duong dan leo thang dac quyen, tao cac quy tac phat hien va trinh bay mot buc tranh thong nhat ve tan cong/phong thu &mdash; trong mot cuoc hoi thoai duy nhat.

Thong tin tinh bao ve Living off the Land binary duoc ghi nhan tren hon 10 danh muc, moi danh muc co dinh dang va trong tam nen tang rieng. May chu nay thong nhat GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2, LOLESXi, LOTP va LOFLCAB thanh mot cong cu duy nhat de tuong quan da nen tang, ky thuat phat hien va phan tich do thi tan cong.

Khong can API key &mdash; tat ca 10 danh muc LOL deu la du lieu ma nguon mo.

---

## Bat dau nhanh

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

## Nguon du lieu

| Danh muc | Nen tang | Muc nhap | Mo ta |
|----------|----------|----------|-------|
| GTFOBins | Linux | 400+ | Binary Unix co the khai thac de leo thang dac quyen, thao tac file, thoat shell |
| LOLBAS | Windows | 250+ | Binary LOL Windows, script va thu vien de thuc thi, tranh ne, duy tri |
| LOOBins | macOS | 50+ | Binary goc macOS cho cac chien dich tan cong |
| LOLDrivers | Windows | 700+ | Driver kernel co lo hong va doc hai cho tan cong BYOVD |
| LOLRMM | Da nen tang | 100+ | Cong cu RMM hop phap bi lam dung de duy tri va truy cap tu xa |
| LOLESXi | ESXi | 30+ | Binary ESXi de thoat VM, thao tung hypervisor |
| LOTP | Da nen tang | 40+ | Nen tang va dich vu dang tin cay bi lam dung cho muc dich doc hai |
| LOLC2 | Da nen tang | 30+ | Dich vu hop phap bi lam dung lam kenh C2 |
| LOFLCAB | Da nen tang | 20+ | Ky thuat lam dung firmware, BIOS va file cabinet |
| WADComs | Windows AD | 150+ | Lenh va ky thuat tan cong Active Directory |

---

> **De xem tai lieu day du, vui long xem [README tieng Anh](README.md).**

---

<p align="center">
  <b>Chi danh cho kiem thu va danh gia bao mat duoc uy quyen.</b><br>
  Luon dam bao ban co su uy quyen phu hop truoc khi su dung cac ky thuat LOL binary tren bat ky he thong muc tieu nao.
</p>

<p align="center">
  <a href="LICENSE">Giay phep MIT</a> &bull; Built with Bun + TypeScript
</p>
