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
  <strong>العربية</strong> |
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

<h3 align="center" dir="rtl">معلومات استخباراتية عن تقنيات Living off the Land لوكلاء الذكاء الاصطناعي.</h3>

<p align="center" dir="rtl">
  GTFOBins وLOLBAS وLOOBins وLOLDrivers وLOLRMM وWADComs وLOLC2 والمزيد &mdash; موحدة في خادم MCP واحد.<br>
  يحصل وكيل الذكاء الاصطناعي الخاص بك على <b>معلومات استخباراتية شاملة عن ثنائيات LOL</b> لعمليات الفريق الأحمر والفريق الأزرق والفريق الأرجواني.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="الرخصة"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 أداة">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 مصادر">
</p>

---

<div dir="rtl">

## نظرة عامة

يوفر **living-off-the-land-lolbins-mcp-server** لوكيل الذكاء الاصطناعي الخاص بك 59 أداة مركبة (321 أداة إجمالاً) عبر 10 كتالوجات LOL من خلال [بروتوكول سياق النموذج](https://modelcontextprotocol.io). يستعلم الوكيل من جميع الكتالوجات بالتوازي، ويربط الثنائيات عبر المنصات، ويكتشف مسارات تصعيد الامتيازات، وينشئ قواعد الكشف، ويقدم صورة موحدة للهجوم/الدفاع &mdash; في محادثة واحدة.

معلومات استخبارات ثنائيات Living off the Land موثقة عبر أكثر من 10 كتالوجات، لكل منها تنسيقه الخاص وتركيزه على منصة معينة. يوحد هذا الخادم GTFOBins وLOLBAS وLOOBins وLOLDrivers وLOLRMM وWADComs وLOLC2 وLOLESXi وLOTP وLOFLCAB في أداة واحدة للربط عبر المنصات وهندسة الكشف وتحليل مخططات الهجوم.

لا يلزم أي مفتاح API &mdash; جميع كتالوجات LOL العشرة هي بيانات مفتوحة المصدر.

</div>

---

<div dir="rtl">

## البدء السريع

</div>

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

<div dir="rtl">

## مصادر البيانات

</div>

| الكتالوج | المنصة | الإدخالات | الوصف |
|----------|--------|-----------|-------|
| GTFOBins | Linux | +400 | ثنائيات Unix قابلة للاستغلال لتصعيد الامتيازات وعمليات الملفات والهروب من الصدفة |
| LOLBAS | Windows | +250 | ثنائيات Windows LOL والنصوص والمكتبات للتنفيذ والتهرب والاستمرارية |
| LOOBins | macOS | +50 | ثنائيات macOS الأصلية القابلة للاستغلال في العمليات الهجومية |
| LOLDrivers | Windows | +700 | برامج تشغيل نواة ضعيفة وخبيثة لهجمات BYOVD |
| LOLRMM | متعدد المنصات | +100 | أدوات RMM شرعية مستغلة للاستمرارية والوصول عن بُعد |
| LOLESXi | ESXi | +30 | ثنائيات ESXi للهروب من VM والتلاعب بالمشرف الافتراضي |
| LOTP | متعدد المنصات | +40 | منصات وخدمات موثوقة مستغلة لأغراض خبيثة |
| LOLC2 | متعدد المنصات | +30 | خدمات شرعية مستغلة كقنوات قيادة وتحكم |
| LOFLCAB | متعدد المنصات | +20 | تقنيات استغلال البرامج الثابتة وBIOS وملفات cabinet |
| WADComs | Windows AD | +150 | أوامر وتقنيات هجوم Active Directory |

---

<div dir="rtl">

> **للاطلاع على التوثيق الكامل، راجع [ملف README باللغة الإنجليزية](README.md).**

</div>

---

<p align="center" dir="rtl">
  <b>لاختبارات الأمان المصرح بها والتقييم فقط.</b><br>
  تأكد دائماً من حصولك على التصريح المناسب قبل استخدام تقنيات ثنائيات LOL على أي نظام مستهدف.
</p>

<p align="center">
  <a href="LICENSE">MIT License</a> &bull; Built with Bun + TypeScript
</p>
