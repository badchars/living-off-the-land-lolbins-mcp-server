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
  <strong>ไทย</strong> |
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

<h3 align="center">ข่าวกรอง Living off the Land สำหรับ AI Agent</h3>

<p align="center">
  GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2 และอื่นๆ &mdash; รวมไว้ในเซิร์ฟเวอร์ MCP เดียว<br>
  AI Agent ของคุณจะได้รับ<b>ข่าวกรอง LOL binary แบบครบวงจร</b>สำหรับปฏิบัติการ red team, blue team และ purple team
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/living-off-the-land-lolbins-mcp-server"><img src="https://img.shields.io/npm/v/living-off-the-land-lolbins-mcp-server.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="สัญญาอนุญาต"></a>
  <img src="https://img.shields.io/badge/tools-59-ef4444" alt="59 เครื่องมือ">
  <img src="https://img.shields.io/badge/sources-10-f97316" alt="10 แหล่งข้อมูล">
</p>

---

## ภาพรวม

**living-off-the-land-lolbins-mcp-server** มอบเครื่องมือผสม 59 รายการ (รวม 321 รายการ) จาก 10 แค็ตตาล็อก LOL ให้กับ AI Agent ของคุณผ่าน [Model Context Protocol](https://modelcontextprotocol.io) Agent จะค้นหาแค็ตตาล็อกทั้งหมดพร้อมกัน เชื่อมโยงไบนารีข้ามแพลตฟอร์ม ค้นหาเส้นทางยกระดับสิทธิ์ สร้างกฎการตรวจจับ และนำเสนอภาพรวมการโจมตี/ป้องกันแบบรวมศูนย์ &mdash; ในการสนทนาเดียว

ข่าวกรองเกี่ยวกับ Living off the Land binary ถูกบันทึกไว้ในแค็ตตาล็อกมากกว่า 10 รายการ แต่ละรายการมีรูปแบบและแพลตฟอร์มเฉพาะของตัวเอง เซิร์ฟเวอร์นี้รวม GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, WADComs, LOLC2, LOLESXi, LOTP และ LOFLCAB ไว้ในเครื่องมือเดียวสำหรับการเชื่อมโยงข้ามแพลตฟอร์ม วิศวกรรมการตรวจจับ และการวิเคราะห์กราฟการโจมตี

ไม่ต้องใช้ API key &mdash; แค็ตตาล็อก LOL ทั้ง 10 รายการเป็นข้อมูลโอเพนซอร์ส

---

## เริ่มต้นอย่างรวดเร็ว

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

## แหล่งข้อมูล

| แค็ตตาล็อก | แพลตฟอร์ม | รายการ | คำอธิบาย |
|------------|-----------|--------|----------|
| GTFOBins | Linux | 400+ | ไบนารี Unix ที่สามารถใช้ยกระดับสิทธิ์ จัดการไฟล์ หนีจาก shell |
| LOLBAS | Windows | 250+ | ไบนารี LOL, สคริปต์ และไลบรารีของ Windows สำหรับการดำเนินการ หลบเลี่ยง คงอยู่ |
| LOOBins | macOS | 50+ | ไบนารีดั้งเดิมของ macOS สำหรับปฏิบัติการเชิงรุก |
| LOLDrivers | Windows | 700+ | ไดรเวอร์เคอร์เนลที่มีช่องโหว่และเป็นอันตรายสำหรับการโจมตี BYOVD |
| LOLRMM | ข้ามแพลตฟอร์ม | 100+ | เครื่องมือ RMM ที่ถูกต้องแต่ถูกใช้ในทางที่ผิดเพื่อคงอยู่และเข้าถึงระยะไกล |
| LOLESXi | ESXi | 30+ | ไบนารี ESXi สำหรับหนีจาก VM จัดการ hypervisor |
| LOTP | ข้ามแพลตฟอร์ม | 40+ | แพลตฟอร์มและบริการที่น่าเชื่อถือแต่ถูกใช้ในทางที่ผิด |
| LOLC2 | ข้ามแพลตฟอร์ม | 30+ | บริการที่ถูกต้องแต่ถูกใช้เป็นช่องทาง C2 |
| LOFLCAB | ข้ามแพลตฟอร์ม | 20+ | เทคนิคการใช้เฟิร์มแวร์ BIOS และไฟล์ cabinet ในทางที่ผิด |
| WADComs | Windows AD | 150+ | คำสั่งและเทคนิคการโจมตี Active Directory |

---

> **สำหรับเอกสารฉบับสมบูรณ์ ดูที่ [README ภาษาอังกฤษ](README.md)**

---

<p align="center">
  <b>สำหรับการทดสอบและประเมินความปลอดภัยที่ได้รับอนุญาตเท่านั้น</b><br>
  โปรดตรวจสอบให้แน่ใจว่าคุณมีการอนุญาตที่เหมาะสมก่อนใช้เทคนิค LOL binary กับระบบเป้าหมายใดๆ
</p>

<p align="center">
  <a href="LICENSE">MIT License</a> &bull; Built with Bun + TypeScript
</p>
