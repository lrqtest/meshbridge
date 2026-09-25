# MeshBridge 前端设计准则（强制标准）

> 来源：用户亲自重写的 web/assets 前端（2026-09-25），被定为项目唯一的视觉基准。
> 以后任何前端工作——新页面、新组件、文案改动——都必须遵守本文档。**不要回退到
> "通用 SaaS 深蓝紫渐变"风格。**

## 1. 设计哲学：自然材质，不是科技风模板

- 色系是**亚麻纸 + 森林绿 + 陶土**的大地色系（linen paper / moss / clay / ochre / rust / slate），不是蓝紫渐变。
- 暖色调阴影：阴影带棕褐色偏移 `rgba(51,44,26,…)`，不用冷黑。
- 纸张颗粒纹理（`.grain`，data-URI 噪点）铺底，页面有"纸感"。
- 深色模式是**森林绿深色**（#121410 系），不是纯黑/深蓝。

## 2. 排印（这是整套设计的灵魂）

- 展示字体 **Fraunces**（衬线，可变字重），正文 **Inter**，代码 **JetBrains Mono**，全部自托管 woff2 + CJK 子集化（scripts/fetch-fonts.py）。
- 大标题用衬线（甚至斜体强调，如 hero 的 "Files go direct."），字号大、行高紧（--display-lh 1.04）。
- **分语言排印**：CJK 用户自动切换字距/行高/字重（:lang 规则），zh-TW/ja/ko 各有自己的字形栈（Han unification）。新文本必须走 i18n，不允许硬编码。
- 三层文字色 --ink / --ink-2 / --ink-3 建立信息层级；辅助信息用 mono 小字 + 分隔线（如卡片底部的 `WireGuard · no third parties`）。

## 3. 叙事式布局：每一页都在讲产品

- **登录/注册/向导不是孤零零的表单卡**——统一分屏：左侧表单，右侧是生成式地形艺术 + 一句产品价值主张（如 "The control plane coordinates. Your files travel device to device."）+ 三条 checkmark 卖点。
- 首页结构：pill 徽章 → 衬线大标题（含斜体强调行）→ 副标题（讲场景不讲功能）→ 双 CTA → 三能力卡（图标 chip + 衬线标题 + mono tagline）→ 核心原则区 → 01/02/03 步骤（陶土色编号 + 细线）→ 森林绿面板 finale。
- 步骤指示器、编号、kicker（`— THE CORE PRINCIPLE`）都是陶土色细线风格，贯穿全站。

## 4. 生成式艺术，不要 stock 图片

- 用种子随机（`rng(seed)`）程序化生成 SVG **地形等高线**（`contours()`）和地图（`drawMap`），铺在向导/认证页右栏和 finale 面板。
- 尊重 `prefers-reduced-motion`；窗口 resize 时 debounce 重绘。

## 5. 工程约束（与美观同等重要）

- **严格 CSP**：`script-src 'self'; style-src 'self'`——零内联 script/style。动态值走 CSSOM；DOM 全部用 `h()` 构建器 + `textContent`（永不 innerHTML，XSS 由架构杜绝）。
- **SVG sprite 图标系统**（30+ 手绘 symbol，统一 stroke 风格），`icon(name)` 工厂；logo 是专属的桥形 mark。
- **字体与缓存**：boot.js 在首帧前应用主题/语言（防闪烁）；字体 immutable 缓存一年、shell/app.js 用内容哈希 ETag 协商缓存；`MESH_WEB_DIR` 支持改完即刷新的开发模式。
- **无障碍是默认项**：skip-to-content、aria-live toast、aria-label、focus-visible 环、语义化 `<form>` submit。
- **9 语言 i18n**：JSON 词典按需 fetch（assets/i18n/{lang}.json），`data-i18n` 声明式绑定；新增 UI 文案必须同时补 en.json。

## 6. 修改前自检清单

1. 新颜色/字号是否先加 token？（不允许散落魔法值）
2. 新文案是否进 i18n 词典？
3. 新图标是否进 sprite？
4. 是否用了 innerHTML 或内联样式？（禁止）
5. 深浅两主题都检查过吗？CJK 排版检查过吗？
6. `make i18n-check` + `go test` 过了吗？
