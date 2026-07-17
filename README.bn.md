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
  <strong>বাংলা</strong> |
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

<h3 align="center">AI এজেন্টদের জন্য Living off the Land গোয়েন্দা তথ্য।</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 এবং আরও অনেক কিছু &mdash; একটি একক MCP সার্ভারে একীভূত।<br>
  আপনার AI এজেন্ট red team, blue team এবং purple team অপারেশনের জন্য <b>সম্পূর্ণ LOL বাইনারি গোয়েন্দা তথ্য</b> পায়।
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="লাইসেন্স"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="৫৯ টুল">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="১০ উৎস">
</p>

---

## সংক্ষিপ্ত বিবরণ

**living-off-the-land-lolbins-mcp-server** আপনার AI এজেন্টকে [Model Context Protocol](https://modelcontextprotocol.io)-এর মাধ্যমে ১০টি LOL ক্যাটালগ জুড়ে ৫৯টি সংমিশ্র টুল (মোট ৩২১টি) প্রদান করে। এজেন্ট সমস্ত ক্যাটালগ সমান্তরালভাবে অনুসন্ধান করে, প্ল্যাটফর্ম জুড়ে বাইনারি পারস্পরিক সম্পর্ক স্থাপন করে, বিশেষাধিকার উন্নয়ন পথ আবিষ্কার করে, সনাক্তকরণ নিয়ম তৈরি করে এবং একটি একীভূত আক্রমণ/প্রতিরক্ষা চিত্র উপস্থাপন করে &mdash; একটি একক কথোপকথনে।

Living off the Land বাইনারি গোয়েন্দা তথ্য ১০+ ক্যাটালগে নথিভুক্ত, প্রতিটির নিজস্ব ফরম্যাট এবং প্ল্যাটফর্ম ফোকাস রয়েছে। এই সার্ভারটি GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2, LOLESXi, LOTP এবং LOFLCAB-কে ক্রস-প্ল্যাটফর্ম কোরিলেশন, সনাক্তকরণ প্রকৌশল এবং আক্রমণ গ্রাফ বিশ্লেষণের জন্য একটি একক টুলে একীভূত করে।

কোনো API কী প্রয়োজন নেই &mdash; সমস্ত ১০টি LOL ক্যাটালগ ওপেন সোর্স ডেটা।

---

## দ্রুত শুরু

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

## ডেটা উৎস

| ক্যাটালগ | প্ল্যাটফর্ম | এন্ট্রি | বিবরণ |
|----------|------------|---------|-------|
| GTFOBins | Linux | ৪০০+ | বিশেষাধিকার উন্নয়ন, ফাইল অপারেশন, শেল এস্কেপের জন্য ব্যবহারযোগ্য Unix বাইনারি |
| LOLBAS | Windows | ২৫০+ | এক্সিকিউশন, ইভেশন, পারসিস্টেন্সের জন্য Windows LOL বাইনারি, স্ক্রিপ্ট ও লাইব্রেরি |
| LOOBins | macOS | ৫০+ | আক্রমণাত্মক অপারেশনের জন্য macOS নেটিভ বাইনারি |
| LOLDrivers | Windows | ৭০০+ | BYOVD আক্রমণের জন্য দুর্বল ও ক্ষতিকারক কার্নেল ড্রাইভার |
| LOLRMM | ক্রস-প্ল্যাটফর্ম | ১০০+ | পারসিস্টেন্স ও রিমোট অ্যাক্সেসের জন্য অপব্যবহৃত বৈধ RMM টুল |
| LOLESXi | ESXi | ৩০+ | VM এস্কেপ, হাইপারভাইজার ম্যানিপুলেশনের জন্য ESXi বাইনারি |
| LOTP | ক্রস-প্ল্যাটফর্ম | ৪০+ | ক্ষতিকারক উদ্দেশ্যে অপব্যবহৃত বিশ্বস্ত প্ল্যাটফর্ম ও সেবা |
| LOLC2 | ক্রস-প্ল্যাটফর্ম | ৩০+ | C2 চ্যানেল হিসেবে অপব্যবহৃত বৈধ সেবা |
| LOFLCAB | ক্রস-প্ল্যাটফর্ম | ২০+ | ফার্মওয়্যার, BIOS এবং cabinet ফাইল অপব্যবহার কৌশল |
| WADComs | Windows AD | ১৫০+ | Active Directory আক্রমণ কমান্ড ও কৌশল |

---

> **সম্পূর্ণ ডকুমেন্টেশনের জন্য [ইংরেজি README](README.md) দেখুন।**

---

<p align="center">
  <b>শুধুমাত্র অনুমোদিত নিরাপত্তা পরীক্ষা ও মূল্যায়নের জন্য।</b><br>
  যেকোনো লক্ষ্য সিস্টেমে LOL বাইনারি কৌশল ব্যবহার করার আগে সর্বদা যথাযথ অনুমোদন আছে কিনা নিশ্চিত করুন।
</p>

<p align="center">
  <a href="LICENSE">MIT লাইসেন্স</a> &bull; Built with Bun + TypeScript
</p>
