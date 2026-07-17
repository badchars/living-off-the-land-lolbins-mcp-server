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
  <a href="README.vi.md">Tiếng Việt</a> |
  <strong>हिन्दी</strong>
</p>

<p align="center">
  <br>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/badchars/living-off-the-land-lolbins-mcp-server/main/.github/banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/badchars/living-off-the-land-lolbins-mcp-server/main/.github/banner-light.svg">
    <img alt="living-off-the-land-lolbins-mcp-server" src="https://raw.githubusercontent.com/badchars/living-off-the-land-lolbins-mcp-server/main/.github/banner-dark.svg" width="700">
  </picture>
</p>

<h3 align="center">AI एजेंट के लिए Living off the Land इंटेलिजेंस।</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 और अधिक &mdash; एक ही MCP सर्वर में एकीकृत।<br>
  आपका AI एजेंट red team, blue team और purple team संचालन के लिए <b>पूर्ण-स्पेक्ट्रम LOL बाइनरी इंटेलिजेंस</b> प्राप्त करता है।
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="लाइसेंस"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 टूल">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 स्रोत">
</p>

---

## अवलोकन

**living-off-the-land-lolbins-mcp-server** आपके AI एजेंट को [Model Context Protocol](https://modelcontextprotocol.io) के माध्यम से 10 LOL कैटलॉग में 59 संयुक्त टूल (कुल 321) प्रदान करता है। एजेंट सभी कैटलॉग को समानांतर रूप से क्वेरी करता है, प्लेटफॉर्म भर में बाइनरी को सहसंबंधित करता है, विशेषाधिकार वृद्धि पथ खोजता है, पहचान नियम उत्पन्न करता है और एक एकीकृत हमला/रक्षा चित्र प्रस्तुत करता है &mdash; एक ही बातचीत में।

Living off the Land बाइनरी इंटेलिजेंस 10+ कैटलॉग में प्रलेखित है, प्रत्येक का अपना प्रारूप और प्लेटफॉर्म फोकस है। यह सर्वर GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2, LOLESXi, LOTP और LOFLCAB को क्रॉस-प्लेटफॉर्म सहसंबंध, पहचान इंजीनियरिंग और हमला ग्राफ विश्लेषण के लिए एक ही टूल में एकीकृत करता है।

कोई API कुंजी आवश्यक नहीं &mdash; सभी 10 LOL कैटलॉग ओपन सोर्स डेटा हैं।

---

## त्वरित शुरुआत

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

## डेटा स्रोत

| कैटलॉग | प्लेटफॉर्म | प्रविष्टियां | विवरण |
|---------|-----------|------------|-------|
| GTFOBins | Linux | 400+ | विशेषाधिकार वृद्धि, फ़ाइल संचालन, शेल एस्केप के लिए शोषण योग्य Unix बाइनरी |
| LOLBAS | Windows | 250+ | निष्पादन, बचाव, स्थायित्व के लिए Windows LOL बाइनरी, स्क्रिप्ट और लाइब्रेरी |
| LOOBins | macOS | 50+ | आक्रामक संचालन के लिए macOS मूल बाइनरी |
| LOLDrivers | Windows | 700+ | BYOVD हमलों के लिए कमजोर और दुर्भावनापूर्ण कर्नेल ड्राइवर |
| LOLRMM | क्रॉस-प्लेटफॉर्म | 100+ | स्थायित्व और दूरस्थ पहुंच के लिए दुरुपयोग किए गए वैध RMM टूल |
| LOLESXi | ESXi | 30+ | VM एस्केप, हाइपरवाइजर हेरफेर के लिए ESXi बाइनरी |
| LOTP | क्रॉस-प्लेटफॉर्म | 40+ | दुर्भावनापूर्ण उद्देश्यों के लिए दुरुपयोग किए गए विश्वसनीय प्लेटफॉर्म और सेवाएं |
| LOLC2 | क्रॉस-प्लेटफॉर्म | 30+ | C2 चैनल के रूप में दुरुपयोग की गई वैध सेवाएं |
| LOFLCAB | क्रॉस-प्लेटफॉर्म | 20+ | फर्मवेयर, BIOS और cabinet फ़ाइल दुरुपयोग तकनीकें |
| WADComs | Windows AD | 150+ | Active Directory हमला कमांड और तकनीकें |

---

> **पूर्ण दस्तावेज़ीकरण के लिए [अंग्रेज़ी README](README.md) देखें।**

---

<p align="center">
  <b>केवल अधिकृत सुरक्षा परीक्षण और मूल्यांकन के लिए।</b><br>
  किसी भी लक्ष्य प्रणाली पर LOL बाइनरी तकनीकों का उपयोग करने से पहले हमेशा सुनिश्चित करें कि आपके पास उचित प्राधिकरण है।
</p>

<p align="center">
  <a href="LICENSE">MIT लाइसेंस</a> &bull; Built with Bun + TypeScript
</p>
