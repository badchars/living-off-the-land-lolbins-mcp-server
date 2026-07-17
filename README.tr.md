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
  <strong>Türkçe</strong> |
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

<h3 align="center">AI ajanlar icin Living off the Land istihbarati.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 ve daha fazlasi &mdash; tek bir MCP sunucusunda birlestirildi.<br>
  AI ajaniniz red team, blue team ve purple team operasyonlari icin <b>tam kapsamli LOL binary istihbarati</b> elde eder.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Lisans"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Arac">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Kaynak">
</p>

---

## Genel Bakis

**living-off-the-land-lolbins-mcp-server**, AI ajaniniza [Model Context Protocol](https://modelcontextprotocol.io) uzerinden 10 LOL katalogu boyunca 59 bilesik arac (toplam 321) saglar. Ajan tum kataloglari paralel olarak sorgular, platformlar arasi binary'leri iliskilendirir, yetki yukseltme yollarini kesfeder, tespit kurallari olusturur ve birlesik bir saldiri/savunma resmi sunar &mdash; tek bir gorusmede.

Living off the Land binary istihbarati 10'dan fazla katalogda belgelenmistir ve her birinin kendi formati ve platform odagi vardir. Bu sunucu GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2, LOLESXi, LOTP ve LOFLCAB'i platformlar arasi korelasyon, tespit muhendisligi ve saldiri grafi analizi icin tek bir aracta birlestirir.

API anahtari gerekmez &mdash; 10 LOL katalogunun tamami acik kaynak verilerdir.

---

## Hizli Baslangic

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

## Veri Kaynaklari

| Katalog | Platform | Giris | Aciklama |
|---------|----------|-------|----------|
| GTFOBins | Linux | 400+ | Yetki yukseltme, dosya islemleri, shell kacisi icin kullanilabilir Unix binary'leri |
| LOLBAS | Windows | 250+ | Calistirma, kacinma, kalicilik icin Windows LOL binary'leri, betikler ve kutuphaneler |
| LOOBins | macOS | 50+ | Saldiri operasyonlari icin macOS yerel binary'leri |
| LOLDrivers | Windows | 700+ | BYOVD saldirilari icin zafiyetli ve zararli kernel suruculeri |
| LOLRMM | Platformlar arasi | 100+ | Kalicilik ve uzaktan erisim icin kotuye kullanilan mesru RMM araclari |
| LOLESXi | ESXi | 30+ | VM kacisi, hypervisor manipulasyonu icin ESXi binary'leri |
| LOTP | Platformlar arasi | 40+ | Kotu amaclarla kotuye kullanilan guvenilir platformlar ve hizmetler |
| LOLC2 | Platformlar arasi | 30+ | Komuta ve kontrol kanali olarak kotuye kullanilan mesru hizmetler |
| LOFLCAB | Platformlar arasi | 20+ | Firmware, BIOS ve cabinet dosyasi kotuye kullanim teknikleri |
| WADComs | Windows AD | 150+ | Active Directory saldiri komutlari ve teknikleri |

---

> **Tam dokumantasyon icin [Ingilizce README](README.md) dosyasina bakin.**

---

<p align="center">
  <b>Yalnizca yetkili guvenlik testleri ve degerlendirmeler icindir.</b><br>
  LOL binary tekniklerini herhangi bir hedef sistemde kullanmadan once uygun yetkilendirmeye sahip oldugunuzdan her zaman emin olun.
</p>

<p align="center">
  <a href="LICENSE">MIT Lisansi</a> &bull; Built with Bun + TypeScript
</p>
