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
  <strong>Ελληνικά</strong> |
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

<h3 align="center">Πληροφορίες Living off the Land για AI agents.</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 και άλλα &mdash; ενοποιημένα σε έναν μόνο MCP server.<br>
  Ο AI agent σας αποκτά <b>πλήρους φάσματος πληροφορίες LOL binary</b> για λειτουργίες red team, blue team και purple team.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Άδεια"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 Εργαλεία">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 Πηγές">
</p>

---

## Επισκόπηση

Το **living-off-the-land-lolbins-mcp-server** παρέχει στον AI agent σας 59 σύνθετα εργαλεία (321 συνολικά) σε 10 καταλόγους LOL μέσω του [Model Context Protocol](https://modelcontextprotocol.io). Ο agent αναζητά σε όλους τους καταλόγους παράλληλα, συσχετίζει binaries μεταξύ πλατφορμών, ανακαλύπτει μονοπάτια κλιμάκωσης δικαιωμάτων, δημιουργεί κανόνες ανίχνευσης και παρουσιάζει μια ενοποιημένη εικόνα επίθεσης/άμυνας &mdash; σε μία μόνο συνομιλία.

Οι πληροφορίες για τα Living off the Land binaries είναι τεκμηριωμένες σε 10+ καταλόγους, καθένας με τη δική του μορφή και εστίαση πλατφόρμας. Αυτός ο server ενοποιεί τα GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2, LOLESXi, LOTP και LOFLCAB σε ένα μόνο εργαλείο για διαπλατφορμική συσχέτιση, μηχανική ανίχνευσης και ανάλυση γράφων επίθεσης.

Δεν απαιτούνται API keys &mdash; και οι 10 κατάλογοι LOL είναι δεδομένα ανοικτού κώδικα.

---

## Γρήγορη Εκκίνηση

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

## Πηγές Δεδομένων

| Κατάλογος | Πλατφόρμα | Εγγραφές | Περιγραφή |
|-----------|-----------|----------|-----------|
| GTFOBins | Linux | 400+ | Unix binaries εκμεταλλεύσιμα για κλιμάκωση δικαιωμάτων, λειτουργίες αρχείων, διαφυγή shell |
| LOLBAS | Windows | 250+ | Windows LOL binaries, scripts και βιβλιοθήκες για εκτέλεση, αποφυγή, μονιμότητα |
| LOOBins | macOS | 50+ | Εγγενή macOS binaries για επιθετικές λειτουργίες |
| LOLDrivers | Windows | 700+ | Ευάλωτοι και κακόβουλοι οδηγοί πυρήνα για επιθέσεις BYOVD |
| LOLRMM | Πολυπλατφορμικό | 100+ | Νόμιμα εργαλεία RMM που κακοποιούνται για μονιμότητα και απομακρυσμένη πρόσβαση |
| LOLESXi | ESXi | 30+ | ESXi binaries για διαφυγή VM, χειρισμό hypervisor |
| LOTP | Πολυπλατφορμικό | 40+ | Αξιόπιστες πλατφόρμες και υπηρεσίες που κακοποιούνται για κακόβουλους σκοπούς |
| LOLC2 | Πολυπλατφορμικό | 30+ | Νόμιμες υπηρεσίες που κακοποιούνται ως κανάλια C2 |
| LOFLCAB | Πολυπλατφορμικό | 20+ | Τεχνικές κακοποίησης firmware, BIOS και αρχείων cabinet |
| WADComs | Windows AD | 150+ | Εντολές και τεχνικές επίθεσης Active Directory |

---

> **Για πλήρη τεκμηρίωση, δείτε το [αγγλικό README](README.md).**

---

<p align="center">
  <b>Μόνο για εξουσιοδοτημένες δοκιμές ασφαλείας και αξιολόγηση.</b><br>
  Πάντα βεβαιωθείτε ότι έχετε κατάλληλη εξουσιοδότηση πριν χρησιμοποιήσετε τεχνικές LOL binary σε οποιοδήποτε σύστημα-στόχο.
</p>

<p align="center">
  <a href="LICENSE">Άδεια MIT</a> &bull; Built with Bun + TypeScript
</p>
