/* MeshBridge web UI.
   Vanilla JS, no build step, no third-party code. All user/server data is
   rendered with textContent (never innerHTML), and nothing here needs
   inline script or style, so the page runs under a strict CSP. */
"use strict";
(() => {
  // ───────────────────────── helpers ─────────────────────────
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const SVGNS = "http://www.w3.org/2000/svg";
  const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)");

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null || v === false) continue;
        if (k === "class") el.className = v;
        else if (k === "text") el.textContent = v;
        else if (k === "i18n") el.dataset.i18n = v;
        else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? "" : v);
      }
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  function svg(tag, attrs) {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v != null) el.setAttribute(k, v);
    return el;
  }
  function icon(name, cls) {
    const s = svg("svg", { class: "icon" + (cls ? " " + cls : ""), "aria-hidden": "true" });
    s.append(svg("use", { href: "#i-" + name }));
    return s;
  }
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch { /* private mode */ } },
  };
  const debounce = (fn, ms) => { let tm; return (...a) => { clearTimeout(tm); tm = setTimeout(() => fn(...a), ms); }; };
  const listeners = {};
  const on = (ev, fn) => (listeners[ev] = listeners[ev] || []).push(fn);
  const emit = (ev, arg) => (listeners[ev] || []).forEach((fn) => { try { fn(arg); } catch (e) { console.error(e); } });

  // ───────────────────────── i18n ─────────────────────────
  const LANGS = [
    { code: "en", name: "English", en: "English" },
    { code: "zh-CN", name: "简体中文", en: "Chinese, Simplified" },
    { code: "zh-TW", name: "繁體中文", en: "Chinese, Traditional" },
    { code: "ja", name: "日本語", en: "Japanese" },
    { code: "ko", name: "한국어", en: "Korean" },
    { code: "es", name: "Español", en: "Spanish" },
    { code: "fr", name: "Français", en: "French" },
    { code: "de", name: "Deutsch", en: "German" },
    { code: "pt-BR", name: "Português", en: "Portuguese" },
    { code: "ru", name: "Русский", en: "Russian" },
  ];
  const dictCache = {};

  function flatten(obj, prefix = "", out = {}) {
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? prefix + "." + k : k;
      if (v && typeof v === "object" && !("other" in v)) flatten(v, key, out);
      else out[key] = v;
    }
    return out;
  }
  async function loadDict(code) {
    if (!dictCache[code]) {
      dictCache[code] = fetch(`/assets/i18n/${code}.json`, { cache: "no-cache" })
        .then((r) => { if (!r.ok) throw new Error("i18n " + r.status); return r.json(); })
        .then((j) => flatten(j))
        .catch((e) => { delete dictCache[code]; throw e; });
    }
    return dictCache[code];
  }
  function matchLang(tag) {
    if (!tag) return null;
    const t = String(tag).toLowerCase();
    const exact = LANGS.find((l) => l.code.toLowerCase() === t);
    if (exact) return exact.code;
    if (t.startsWith("zh")) return /hant|^zh-(tw|hk|mo)/.test(t) ? "zh-TW" : "zh-CN";
    if (t.startsWith("pt")) return "pt-BR";
    const base = t.split(/[-_]/)[0];
    const b = LANGS.find((l) => l.code.split("-")[0].toLowerCase() === base);
    return b ? b.code : null;
  }
  function detectLang() {
    const q = new URLSearchParams(location.search).get("lang");
    for (const cand of [q, store.get("mb_lang"), ...(navigator.languages || [navigator.language])]) {
      const m = matchLang(cand);
      if (m) return m;
    }
    return "en";
  }

  const I18N = {
    lang: "en", dict: {}, base: {}, plural: new Intl.PluralRules("en"),
    async use(code, persist) {
      const [base, dict] = await Promise.all([loadDict("en"), code === "en" ? null : loadDict(code).catch(() => null)]);
      this.base = base;
      this.dict = dict || base;
      this.lang = dict || code === "en" ? code : "en";
      this.plural = new Intl.PluralRules(this.lang);
      if (persist) store.set("mb_lang", this.lang);
      document.documentElement.lang = this.lang;
      this.apply(document);
      const desc = $('meta[name="description"]');
      if (desc) desc.setAttribute("content", t("meta.description"));
      emit("lang", this.lang);
    },
    apply(root) {
      for (const el of $$("[data-i18n]", root)) setRich(el, t(el.dataset.i18n));
      for (const el of $$("[data-i18n-attr]", root)) {
        for (const pair of el.dataset.i18nAttr.split(";")) {
          const i = pair.indexOf(":");
          if (i > 0) el.setAttribute(pair.slice(0, i).trim(), t(pair.slice(i + 1).trim()));
        }
      }
    },
  };
  function t(key, vars) {
    let v = I18N.dict[key];
    if (v == null) v = I18N.base[key];
    if (v == null) return key;
    if (typeof v === "object") v = v[I18N.plural.select(vars && typeof vars.n === "number" ? vars.n : 0)] ?? v.other;
    if (!vars) return v;
    return v.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
  }
  // Translations may mark emphasis with **…**; built as DOM nodes, never HTML.
  function setRich(el, text) {
    if (!text.includes("**")) { el.textContent = text; return; }
    el.textContent = "";
    text.split(/(\*\*[^*]+\*\*)/).forEach((part) => {
      if (part.startsWith("**") && part.endsWith("**")) el.append(h("strong", null, part.slice(2, -2)));
      else if (part) el.append(part);
    });
  }

  // ───────────────────────── formatting ─────────────────────────
  const fmt = {
    num: (n) => new Intl.NumberFormat(I18N.lang).format(n),
    bytes(n) {
      if (n == null || isNaN(n)) return "—";
      const units = ["byte", "kilobyte", "megabyte", "gigabyte", "terabyte", "petabyte"];
      let v = Math.max(0, n), i = 0;
      while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
      return new Intl.NumberFormat(I18N.lang, { style: "unit", unit: units[i], unitDisplay: "short", maximumFractionDigits: i === 0 || v >= 100 ? 0 : 1 }).format(v);
    },
    pct: (x) => new Intl.NumberFormat(I18N.lang, { style: "percent", maximumFractionDigits: 0 }).format(x),
    abs(ts) {
      if (!ts) return "—";
      return new Intl.DateTimeFormat(I18N.lang, { dateStyle: "medium", timeStyle: "short" }).format(new Date(ts * 1000));
    },
    rel(ts) {
      if (!ts) return t("common.never");
      const s = Math.round(Date.now() / 1000 - ts);
      if (Math.abs(s) < 45) return t("common.justNow");
      const rtf = new Intl.RelativeTimeFormat(I18N.lang, { numeric: "auto" });
      if (Math.abs(s) < 3600) return rtf.format(-Math.round(s / 60), "minute");
      if (Math.abs(s) < 86400) return rtf.format(-Math.round(s / 3600), "hour");
      if (Math.abs(s) < 86400 * 30) return rtf.format(-Math.round(s / 86400), "day");
      return new Intl.DateTimeFormat(I18N.lang, { dateStyle: "medium" }).format(new Date(ts * 1000));
    },
  };
  const short = (id) => (id ? String(id).slice(0, 8) : "—");

  // ───────────────────────── theme ─────────────────────────
  const Theme = {
    get: () => store.get("mb_theme") || "system",
    effective() {
      const m = this.get();
      return m !== "system" ? m : matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    },
    set(mode) {
      store.set("mb_theme", mode === "system" ? null : mode);
      if (mode === "system") document.documentElement.removeAttribute("data-theme");
      else document.documentElement.setAttribute("data-theme", mode);
      emit("theme", mode);
    },
    toggle() { this.set(this.effective() === "dark" ? "light" : "dark"); },
  };

  // ───────────────────────── toasts ─────────────────────────
  function toast(msg, kind = "ok") {
    const el = h("div", { class: "toast " + kind }, icon(kind === "err" ? "alert" : kind === "info" ? "info" : "check"), h("div", null, msg));
    $("#toasts").append(el);
    const kill = () => { el.classList.add("out"); setTimeout(() => el.remove(), 320); };
    const timer = setTimeout(kill, kind === "err" ? 6500 : 4200);
    el.addEventListener("click", () => { clearTimeout(timer); kill(); });
  }

  // ───────────────────────── API ─────────────────────────
  class ApiError extends Error {
    constructor(status, code, message) { super(message); this.status = status; this.code = code; }
  }
  const Session = {
    token: () => store.get("mb_token") || "",
    set(tok) { store.set("mb_token", tok || null); this._me = undefined; },
    clear() { this.set(null); },
    _me: undefined,
    async me() {
      if (!this.token()) return null;
      if (this._me !== undefined) return this._me;
      try { this._me = await api("GET", "/api/v1/me", null, { quiet401: true }); }
      catch (e) { if (e.status === 401) this.clear(); this._me = null; }
      return this._me;
    },
    expired() {
      if (!this.token()) return;
      this.clear();
      flash = { panel: "login", text: t("auth.sessionExpired") };
      go("#/login");
    },
  };
  let flash = null;

  async function api(method, path, body, opts = {}) {
    const headers = {};
    const tok = Session.token();
    if (tok && opts.auth !== false) headers.Authorization = "Bearer " + tok;
    const init = { method, headers, cache: "no-store" };
    if (body != null) { headers["Content-Type"] = "application/json"; init.body = JSON.stringify(body); }
    let r;
    try { r = await fetch(path, init); } catch (e) { throw new ApiError(0, "network", e.message); }
    let data = {};
    try { data = await r.json(); } catch { /* empty body */ }
    if (!r.ok) {
      const err = new ApiError(r.status, data.code || "", data.error || "HTTP " + r.status);
      if (r.status === 401 && tok && opts.auth !== false && !opts.quiet401) Session.expired();
      throw err;
    }
    return data;
  }

  // Server errors are English strings + a code; map the known ones.
  function errText(err, ctx) {
    const m = String(err.message || "").toLowerCase();
    const c = err.code;
    if (err.status === 0) return t("err.network");
    if (c === "rate_limited" || err.status === 429) {
      const s = /wait (\d+)s/.exec(m);
      if (s) return t("err.waitSeconds", { s: s[1] });
      if (m.includes("daily")) return t("err.dailyLimit");
      if (m.includes("busy")) return t("err.busy");
      return t("err.tooMany");
    }
    if (c === "bad_code") return t("err.badCode");
    if (c === "conflict") return m.includes("email") ? t("err.emailTaken") : t("err.projectExists");
    if (c === "forbidden") {
      if (m.includes("registration")) return t("err.regClosed");
      if (m.includes("setup")) return t("err.setupDone");
      if (m.includes("admin")) return t("err.adminOnly");
    }
    if (c === "mailer") return t("err.mailerOff");
    if (c === "mail_send_failed") {
      if (m.includes("smtp not configured")) return t("err.smtpMissing");
      if (m.includes("invalid email")) return t("err.badEmail");
      return t("err.mailFailed", { detail: err.message });
    }
    if (c === "unauthorized") return ctx === "login" ? t("err.badCredentials") : t("err.unauthorized");
    if (c === "bad_request") {
      if (m.includes("password must be")) return t("err.passwordShort");
      if (m.includes("hostname")) return t("err.badHostname");
      if (m.includes("must differ")) return t("err.sameDevice");
      if (m.includes("relative")) return t("err.badPath");
      if (m.includes("host, port and username")) return t("err.smtpRequired");
      if (m.includes("none stored")) return t("err.smtpPassRequired");
      if (m.includes("port must be")) return t("err.smtpPort");
      if (m.includes("no valid target")) return t("err.noAdminEmail");
      if (m.includes("src/dst")) return t("err.pickDevices");
      if (m.includes("name required")) return t("err.projectName");
    }
    if (err.status >= 500) return t("err.server");
    return err.message;
  }

  function showErr(scope, msg) {
    const box = $('[data-role="err"]', scope);
    if (!box) { toast(msg, "err"); return; }
    if (!msg) { box.hidden = true; return; }
    $('[data-role="err-text"]', box).textContent = msg;
    box.hidden = false;
  }
  async function busy(btn, fn) {
    if (!btn) return fn();
    btn.classList.add("is-busy");
    btn.setAttribute("aria-busy", "true");
    try { return await fn(); } finally { btn.classList.remove("is-busy"); btn.removeAttribute("aria-busy"); }
  }
  async function clip(text) {
    try { await navigator.clipboard.writeText(text); }
    catch {
      const ta = h("textarea", { class: "sr-only", readonly: true });
      ta.value = text; document.body.append(ta); ta.select();
      try { document.execCommand("copy"); } finally { ta.remove(); }
    }
  }
  async function copyText(text, btn) {
    await clip(text);
    if (!btn) { toast(t("common.copied")); return; }
    btn.classList.add("is-done");
    const label = $("span[data-i18n]", btn);
    if (label) label.textContent = t("common.copied");
    setTimeout(() => { btn.classList.remove("is-done"); if (label) label.textContent = t("common.copy"); }, 1600);
  }

  // ───────────────────────── setup status ─────────────────────────
  const Status = {
    _v: null, _at: 0,
    async get(force) {
      if (!force && this._v && Date.now() - this._at < 20000) return this._v;
      try { this._v = await api("GET", "/api/v1/setup/status", null, { auth: false }); this._at = Date.now(); }
      catch { /* keep the last known value */ }
      return this._v;
    },
    invalidate() { this._at = 0; },
  };

  // ───────────────────────── language pickers ─────────────────────────
  function mountLangPickers() {
    for (const host of $$("[data-lang-picker]")) {
      const btn = h("button", { class: "lp-btn", type: "button", "aria-haspopup": "listbox", "aria-expanded": "false" },
        icon("globe"), h("span", { class: "lp-cur" }), icon("chevron", "chev"));
      const menu = h("ul", { class: "lp-menu" + ("up" in host.dataset ? " up" : ""), role: "listbox", tabindex: "-1", hidden: true });
      for (const l of LANGS) {
        menu.append(h("li", { class: "lp-opt", role: "option", "data-lang": l.code, lang: l.code, "aria-selected": "false" },
          h("span", null, l.name), h("span", { class: "lp-en" }, l.en)));
      }
      host.append(btn, menu);
      let active = -1;
      const opts = () => $$(".lp-opt", menu);
      const highlight = (i) => {
        const list = opts();
        active = (i + list.length) % list.length;
        list.forEach((o, j) => o.classList.toggle("is-active", j === active));
        list[active].scrollIntoView({ block: "nearest" });
      };
      const close = () => { menu.hidden = true; btn.setAttribute("aria-expanded", "false"); };
      const open = () => {
        $$(".lp-menu").forEach((m) => { if (m !== menu) m.hidden = true; });
        menu.hidden = false; btn.setAttribute("aria-expanded", "true");
        highlight(LANGS.findIndex((l) => l.code === I18N.lang));
        menu.focus();
      };
      const pick = async (code) => { close(); btn.focus(); if (code !== I18N.lang) await I18N.use(code, true); };
      btn.addEventListener("click", (e) => { e.stopPropagation(); menu.hidden ? open() : close(); });
      menu.addEventListener("click", (e) => { const o = e.target.closest(".lp-opt"); if (o) pick(o.dataset.lang); });
      menu.addEventListener("keydown", (e) => {
        if (e.key === "ArrowDown") { e.preventDefault(); highlight(active + 1); }
        else if (e.key === "ArrowUp") { e.preventDefault(); highlight(active - 1); }
        else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(opts()[active].dataset.lang); }
        else if (e.key === "Escape" || e.key === "Tab") { close(); btn.focus(); }
      });
      document.addEventListener("click", (e) => { if (!host.contains(e.target)) close(); });
      const sync = () => {
        const cur = LANGS.find((l) => l.code === I18N.lang) || LANGS[0];
        $(".lp-cur", btn).textContent = cur.name;
        btn.setAttribute("aria-label", t("common.language") + ": " + cur.name);
        opts().forEach((o) => o.setAttribute("aria-selected", String(o.dataset.lang === cur.code)));
      };
      on("lang", sync);
    }
    for (const b of $$("[data-theme-toggle]")) b.addEventListener("click", () => Theme.toggle());
  }

  // ───────────────────────── terrain (contour lines) ─────────────────────────
  // A seeded height field → marching squares → joined polylines → Catmull-Rom
  // curves. Deterministic per seed, sized to the element, no assets.
  function rng(seed) {
    let a = seed >>> 0;
    return () => {
      a = (a + 0x6d2b79f5) | 0;
      let x = Math.imul(a ^ (a >>> 15), 1 | a);
      x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x;
      return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
    };
  }
  function contours(w, hgt, seed, opts = {}) {
    const rnd = rng(seed);
    const span = Math.max(w, hgt);
    const hills = [];
    for (let i = 0; i < (opts.hills || 7); i++) {
      hills.push({ x: rnd() * w, y: rnd() * hgt, r: (0.16 + rnd() * 0.3) * span, a: (rnd() < 0.3 ? -0.7 : 1) * (0.55 + rnd() * 0.8) });
    }
    const fx = (2 * Math.PI) / (span * (0.5 + rnd() * 0.4)), fy = (2 * Math.PI) / (span * (0.45 + rnd() * 0.4)), ph = rnd() * 6.28;
    const field = (x, y) => {
      let v = 0.2 * Math.sin(x * fx + ph) * Math.cos(y * fy - ph);
      for (const k of hills) { const dx = (x - k.x) / k.r, dy = (y - k.y) / k.r; v += k.a * Math.exp(-(dx * dx + dy * dy)); }
      return v;
    };
    const step = opts.step || Math.max(8, span / 100);
    const nx = Math.ceil(w / step) + 3, ny = Math.ceil(hgt / step) + 3, ox = -step, oy = -step;
    const g = new Float64Array(nx * ny);
    let min = Infinity, max = -Infinity;
    for (let j = 0; j < ny; j++) for (let i = 0; i < nx; i++) {
      const v = field(ox + i * step, oy + j * step);
      g[j * nx + i] = v; if (v < min) min = v; if (v > max) max = v;
    }
    const levels = opts.levels || 18, out = [];
    for (let L = 1; L < levels; L++) {
      const th = min + ((max - min) * L) / levels;
      const pts = new Map(), adj = new Map();
      const link = (a, b) => { (adj.get(a) || adj.set(a, []).get(a)).push(b); (adj.get(b) || adj.set(b, []).get(b)).push(a); };
      const hp = (i, j) => { const id = (j * nx + i) * 2; if (!pts.has(id)) { const a = g[j * nx + i], b = g[j * nx + i + 1]; pts.set(id, [ox + (i + (th - a) / (b - a)) * step, oy + j * step]); } return id; };
      const vp = (i, j) => { const id = (j * nx + i) * 2 + 1; if (!pts.has(id)) { const a = g[j * nx + i], b = g[(j + 1) * nx + i]; pts.set(id, [ox + i * step, oy + (j + (th - a) / (b - a)) * step]); } return id; };
      for (let j = 0; j < ny - 1; j++) for (let i = 0; i < nx - 1; i++) {
        const code = (g[j * nx + i] > th ? 8 : 0) | (g[j * nx + i + 1] > th ? 4 : 0) | (g[(j + 1) * nx + i + 1] > th ? 2 : 0) | (g[(j + 1) * nx + i] > th ? 1 : 0);
        switch (code) {
          case 1: case 14: link(vp(i, j), hp(i, j + 1)); break;
          case 2: case 13: link(hp(i, j + 1), vp(i + 1, j)); break;
          case 3: case 12: link(vp(i, j), vp(i + 1, j)); break;
          case 4: case 11: link(hp(i, j), vp(i + 1, j)); break;
          case 5: link(vp(i, j), hp(i, j)); link(hp(i, j + 1), vp(i + 1, j)); break;
          case 6: case 9: link(hp(i, j), hp(i, j + 1)); break;
          case 7: case 8: link(vp(i, j), hp(i, j)); break;
          case 10: link(hp(i, j), vp(i + 1, j)); link(vp(i, j), hp(i, j + 1)); break;
          default: break;
        }
      }
      const seen = new Set(), lines = [];
      const walk = (start) => {
        const ids = [start]; seen.add(start);
        let prev = -1, cur = start;
        for (;;) {
          const nb = (adj.get(cur) || []).find((x) => x !== prev && !seen.has(x));
          if (nb == null) return { ids, closed: ids.length > 2 && (adj.get(cur) || []).includes(start) };
          ids.push(nb); seen.add(nb); prev = cur; cur = nb;
        }
      };
      for (const [id, nbs] of adj) if (nbs.length === 1 && !seen.has(id)) lines.push(walk(id));
      for (const id of adj.keys()) if (!seen.has(id)) lines.push(walk(id));
      let d = "";
      for (const ln of lines) {
        const p = ln.ids.filter((_, k) => k % 2 === 0 || k === ln.ids.length - 1).map((id) => pts.get(id));
        if (p.length > 2) d += curve(p, ln.closed);
      }
      out.push({ d, idx: L % 5 === 0 });
    }
    return out;
  }
  function curve(p, closed) {
    const n = p.length, r = (v) => Math.round(v * 10) / 10;
    const at = (i) => (closed ? p[(i + n) % n] : p[Math.max(0, Math.min(n - 1, i))]);
    let d = "M" + r(p[0][0]) + " " + r(p[0][1]);
    for (let i = 0; i < (closed ? n : n - 1); i++) {
      const p0 = at(i - 1), p1 = at(i), p2 = at(i + 1), p3 = at(i + 2);
      d += "C" + r(p1[0] + (p2[0] - p0[0]) / 6) + " " + r(p1[1] + (p2[1] - p0[1]) / 6) + " " +
        r(p2[0] - (p3[0] - p1[0]) / 6) + " " + r(p2[1] - (p3[1] - p1[1]) / 6) + " " + r(p2[0]) + " " + r(p2[1]);
    }
    return closed ? d + "Z" : d;
  }

  const TERRAIN = {
    hero: { seed: 23, levels: 20, hills: 8 },
    closing: { seed: 5, levels: 16, hills: 6 },
    auth: { seed: 41, levels: 18, hills: 7 },
  };
  function drawTerrain(el, force) {
    const conf = TERRAIN[el.dataset.terrain] || { seed: Number(el.dataset.seed) || 9, levels: 10, hills: 5 };
    const box = el.getBoundingClientRect();
    const w = Math.round(box.width), hgt = Math.round(box.height);
    if (!w || !hgt) return;
    const key = w + "x" + hgt;
    if (!force && el.dataset.drawn === key) return;
    el.dataset.drawn = key;
    el.setAttribute("viewBox", `0 0 ${w} ${hgt}`);
    const g = svg("g", { class: "contours" });
    for (const c of contours(w, hgt, conf.seed, conf)) if (c.d) g.append(svg("path", { d: c.d, class: c.idx ? "idx" : null }));
    el.replaceChildren(g);
    if (el.dataset.terrain === "hero") drawMap(el, w, hgt);
  }
  // drawTerrain skips zero-sized (hidden) elements; SVG has no offsetParent.
  const drawVisibleTerrain = () => $$("[data-terrain]").forEach((el) => drawTerrain(el));
  window.addEventListener("resize", debounce(drawVisibleTerrain, 180));

  // Nodes of the hero illustration in normalized coordinates, per shape.
  const MAP = {
    wide: {
      nas: [0.15, 0.62, "below"], laptop: [0.47, 0.24, "right"], studio: [0.84, 0.5, "below"], control: [0.55, 0.82, "right"],
    },
    tall: {
      nas: [0.2, 0.38, "below"], laptop: [0.62, 0.15, "left"], studio: [0.8, 0.6, "below"], control: [0.3, 0.8, "right"],
    },
  };
  function drawMap(svgEl, w, hgt) {
    const layout = w / hgt > 1.25 ? MAP.wide : MAP.tall;
    const P = (k) => [layout[k][0] * w, layout[k][1] * hgt];
    const arc = (a, b, bend) => {
      const [x1, y1] = P(a), [x2, y2] = P(b);
      const mx = (x1 + x2) / 2, my = (y1 + y2) / 2, dx = x2 - x1, dy = y2 - y1;
      const cx = mx + dy * bend, cy = my - dx * bend;
      return `M${x1.toFixed(1)} ${y1.toFixed(1)}Q${cx.toFixed(1)} ${cy.toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}`;
    };
    const links = svg("g", { class: "links" });
    const direct = arc("nas", "studio", 0.2);
    links.append(
      svg("path", { d: arc("control", "nas", 0.08), class: "l-signal" }),
      svg("path", { d: arc("control", "laptop", -0.06), class: "l-signal" }),
      svg("path", { d: arc("control", "studio", -0.08), class: "l-signal" }),
      svg("path", { d: arc("nas", "laptop", 0.12), class: "l-mesh" }),
      svg("path", { d: arc("laptop", "studio", 0.12), class: "l-mesh" }),
      svg("path", { d: direct, class: "l-glow" }),
      svg("path", { d: direct, class: "l-direct" }),
    );
    const nodes = svg("g", { class: "nodes" });
    for (const k of ["nas", "laptop", "studio"]) {
      const [x, y] = P(k);
      nodes.append(svg("circle", { cx: x, cy: y, r: 11, class: "n-halo" }), svg("circle", { cx: x, cy: y, r: 9, class: "n-ring" }), svg("circle", { cx: x, cy: y, r: 3.8, class: "n-core" }));
    }
    const [cx, cy] = P("control");
    nodes.append(svg("circle", { cx, cy, r: 10, class: "n-ctrl" }), svg("circle", { cx, cy, r: 3, class: "n-ctrl-core" }));
    const packets = svg("g", { class: "packets" });
    if (!reduceMotion.matches) {
      const pkt = (d, cls, dur, begin, reverse) => {
        const c = svg("circle", { r: cls === "p-clay" ? 4.2 : 3.2, class: cls, opacity: 0 });
        const m = svg("animateMotion", { dur, begin, repeatCount: "indefinite", path: d, calcMode: "linear" });
        if (reverse) { m.setAttribute("keyPoints", "1;0"); m.setAttribute("keyTimes", "0;1"); }
        const o = svg("animate", { attributeName: "opacity", values: "0;1;1;0", keyTimes: "0;0.08;0.9;1", dur, begin, repeatCount: "indefinite" });
        c.append(m, o);
        return c;
      };
      packets.append(
        pkt(direct, "p-clay", "3.4s", "0s"), pkt(direct, "p-clay", "3.4s", "1.13s"), pkt(direct, "p-clay", "3.4s", "2.26s"),
        pkt(direct, "p-sage", "4.2s", "0.6s", true),
        pkt(arc("nas", "laptop", 0.12), "p-sage", "3.8s", "1.4s"),
      );
    }
    svgEl.append(links, packets, nodes);
    for (const lab of $$(".map-label", svgEl.parentNode)) {
      const spec = layout[lab.dataset.node];
      if (!spec) continue;
      lab.style.left = spec[0] * 100 + "%";
      lab.style.top = spec[1] * 100 + "%";
      lab.classList.remove("left", "below", "above");
      if (spec[2] !== "right") lab.classList.add(spec[2]);
    }
  }

  // ───────────────────────── views ─────────────────────────
  const VIEWS = ["landing", "auth", "app"];
  let currentView = null;
  function showView(name) {
    if (currentView !== name) {
      for (const v of VIEWS) $("#view-" + v).hidden = v !== name;
      currentView = name;
      window.scrollTo(0, 0);
    }
    requestAnimationFrame(drawVisibleTerrain);
    document.body.classList.add("ready");
  }

  // ── landing
  let landingReady = false;
  function initLanding() {
    if (landingReady) return;
    landingReady = true;
    const nav = $("#site-nav");
    const onScroll = () => nav.classList.toggle("is-scrolled", window.scrollY > 12);
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    for (const a of $$("[data-scroll]")) {
      a.addEventListener("click", (e) => { e.preventDefault(); scrollToSection(a.dataset.scroll); });
    }
    for (const group of [".facts", ".cards", ".steps"]) {
      $$(group + " > .reveal").forEach((el, i) => el.style.setProperty("--d", i * 90 + "ms"));
    }
    const io = "IntersectionObserver" in window
      ? new IntersectionObserver((entries) => {
        for (const en of entries) if (en.isIntersecting) { en.target.classList.add("is-in"); io.unobserve(en.target); }
      }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 })
      : null;
    $$("#view-landing .reveal").forEach((el) => (io ? io.observe(el) : el.classList.add("is-in")));
  }
  function scrollToSection(id) {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: reduceMotion.matches ? "auto" : "smooth", block: "start" });
  }
  function applyRegistrationGate(st) {
    const open = !st || st.allow_registration !== false;
    for (const a of $$("[data-cta='register']")) {
      a.setAttribute("href", open ? "#/register" : "#/login");
      const label = a.dataset.i18n ? a : $("[data-i18n]", a);
      if (!label.dataset.i18nOpen) label.dataset.i18nOpen = label.dataset.i18n;
      label.dataset.i18n = open ? label.dataset.i18nOpen : "common.signIn";
      setRich(label, t(label.dataset.i18n));
    }
    $$("[data-reg-link]").forEach((el) => (el.hidden = !open));
  }
  async function showLanding(anchor) {
    initLanding();
    showView("landing");
    document.title = t("meta.title");
    applyRegistrationGate(await Status.get());
    if (anchor) setTimeout(() => scrollToSection(anchor), 60);
  }

  // ── auth panels
  const ART = {
    auth: ["auth.panelTitle", "auth.panelP1", "auth.panelP2", "auth.panelP3"],
    setup: ["setup.panelTitle", "setup.panelP1", "setup.panelP2", "setup.panelP3"],
  };
  let currentPanel = null;
  function setArt(kind) {
    const keys = ART[kind];
    const [title, p1, p2, p3] = ["title", "p1", "p2", "p3"].map((k) => $(`[data-art="${k}"]`));
    [title, p1, p2, p3].forEach((el, i) => { el.dataset.i18n = keys[i]; setRich(el, t(keys[i])); });
  }
  async function showAuth(panel) {
    const st = await Status.get();
    showView("auth");
    for (const sec of $$("[data-panel]")) sec.hidden = sec.dataset.panel !== panel;
    setArt(panel === "setup" ? "setup" : "auth");
    currentPanel = panel;
    const sec = $(`[data-panel="${panel}"]`);
    document.title = $(".auth-title", sec).textContent + " · MeshBridge";
    if (panel === "register") {
      const closed = st && st.allow_registration === false;
      $('[data-role="closed"]', sec).hidden = !closed;
      $$("input, button", $("#form-register")).forEach((el) => (el.disabled = !!closed));
    }
    if (panel === "login") {
      applyRegistrationGate(st);
      const note = $('[data-role="notice"]', sec);
      if (flash && flash.panel === "login") { $('[data-role="notice-text"]', note).textContent = flash.text; note.hidden = false; flash = null; }
      else note.hidden = true;
    }
    if (panel === "setup") setupGoto(setupStep);
    const first = $("input:not([disabled])", sec);
    if (first && matchMedia("(min-width: 720px)").matches) first.focus({ preventScroll: true });
  }

  const emailOK = (e) => /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(e) && e.length <= 254;

  function initPasswordFields() {
    document.addEventListener("click", (e) => {
      const b = e.target.closest("[data-pw-toggle]");
      if (!b) return;
      const input = $("input", b.parentNode);
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      b.setAttribute("aria-pressed", String(show));
      b.dataset.i18nAttr = "aria-label:" + (show ? "common.hidePassword" : "common.showPassword");
      b.setAttribute("aria-label", t(show ? "common.hidePassword" : "common.showPassword"));
    });
    const levels = ["", "auth.strength.weak", "auth.strength.fair", "auth.strength.good", "auth.strength.strong"];
    const score = (p) => {
      if (!p) return 0;
      if (p.length < 12) return 1;
      const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
      return Math.min(4, 2 + (kinds >= 3 ? 1 : 0) + (p.length >= 16 ? 1 : 0));
    };
    const update = (m) => {
      const input = $("input[type=password], input[name=password]", m.closest(".field"));
      const s = score(input.value);
      m.dataset.level = String(s);
      $(".meter-label", m).textContent = s ? t(levels[s]) : "";
    };
    for (const m of $$("[data-meter]")) {
      const input = $("input[name=password]", m.closest(".field"));
      input.addEventListener("input", () => update(m));
      on("lang", () => update(m));
    }
  }

  // Send-code buttons (register / reset / setup) with a live cooldown.
  function initSendCode() {
    for (const btn of $$("[data-send-code]")) {
      const form = btn.closest("form");
      let timer = null;
      const cooldown = (sec) => {
        clearInterval(timer);
        const end = Date.now() + sec * 1000;
        const tick = () => {
          const left = Math.ceil((end - Date.now()) / 1000);
          if (left <= 0) { clearInterval(timer); timer = null; btn.disabled = false; btn.textContent = t("auth.sendCode"); return; }
          btn.disabled = true; btn.textContent = t("auth.resendIn", { s: left });
        };
        tick(); timer = setInterval(tick, 250);
      };
      on("lang", () => { if (!timer) btn.textContent = t("auth.sendCode"); });
      btn.addEventListener("click", async () => {
        showErr(form, "");
        const nomail = $('[data-role="nomail"]', form);
        if (nomail) nomail.hidden = true;
        const email = form.email.value.trim().toLowerCase();
        if (!emailOK(email)) { showErr(form, t("err.badEmail")); form.email.focus(); return; }
        await busy(btn, async () => {
          try {
            const d = await api("POST", "/api/v1/auth/send-code", { email, purpose: btn.dataset.sendCode }, { auth: false });
            toast(t("auth.codeSent", { email }));
            cooldown(d.cooldown_seconds || 60);
            form.code.focus();
          } catch (err) {
            const wait = /wait (\d+)s/.exec(String(err.message));
            if (wait) cooldown(Number(wait[1]));
            // Setup without mail: the CLI hint replaces the generic error.
            if (nomail && (err.code === "mailer" || /smtp not configured/i.test(err.message))) nomail.hidden = false;
            else showErr(form, errText(err));
          }
        });
      });
    }
  }

  function initAuthForms() {
    $("#form-login").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.currentTarget, btn = $("[type=submit]", f);
      showErr(f, "");
      const username = f.username.value.trim(), password = f.password.value;
      if (!username || !password) { showErr(f, t("err.fillAll")); return; }
      await busy(btn, async () => {
        try {
          const d = await api("POST", "/api/v1/auth/login", { username, password }, { auth: false });
          Session.set(d.token);
          f.reset();
          go("#/app/overview");
        } catch (err) { showErr(f, errText(err, "login")); }
      });
    });

    $("#form-register").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.currentTarget, btn = $("[type=submit]", f);
      showErr(f, "");
      const body = { email: f.email.value.trim().toLowerCase(), code: f.code.value.trim(), password: f.password.value, username: f.username.value.trim() };
      const bad = validateAccount(body);
      if (bad) { showErr(f, bad); return; }
      await busy(btn, async () => {
        try {
          const d = await api("POST", "/api/v1/auth/register", body, { auth: false });
          Session.set(d.token);
          f.reset();
          toast(t("auth.register.success"));
          go("#/app/overview");
        } catch (err) { showErr(f, errText(err)); }
      });
    });

    $("#form-forgot").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.currentTarget, btn = $("[type=submit]", f);
      showErr(f, "");
      const body = { email: f.email.value.trim().toLowerCase(), code: f.code.value.trim(), new_password: f.password.value };
      const bad = validateAccount({ email: body.email, code: body.code, password: body.new_password });
      if (bad) { showErr(f, bad); return; }
      await busy(btn, async () => {
        try {
          await api("POST", "/api/v1/auth/password-reset", body, { auth: false });
          f.reset();
          flash = { panel: "login", text: t("auth.forgot.success") };
          go("#/login");
        } catch (err) { showErr(f, errText(err)); }
      });
    });

    $("#form-setup").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.currentTarget, btn = $("[type=submit]", f);
      showErr(f, "");
      const body = { email: f.email.value.trim().toLowerCase(), code: f.code.value.trim(), password: f.password.value, username: f.username.value.trim() };
      const bad = validateAccount(body);
      if (bad) { showErr(f, bad); return; }
      await busy(btn, async () => {
        try {
          const d = await api("POST", "/api/v1/setup/initial", body, { auth: false });
          Session.set(d.token);
          Status.invalidate();
          toast(t("setup.s1Created", { name: d.username }));
          setupGoto(2);
        } catch (err) { showErr(f, errText(err)); }
      });
    });

    for (const input of $$("input.code")) {
      input.addEventListener("input", () => { input.value = input.value.replace(/\D/g, "").slice(0, 6); });
    }
  }
  function validateAccount({ email, code, password }) {
    if (!emailOK(email)) return t("err.badEmail");
    if (!/^\d{6}$/.test(code)) return t("err.codeFormat");
    if (password.length < 12) return t("err.passwordShort");
    if (password.length > 128) return t("err.passwordLong");
    return "";
  }

  // ── setup wizard
  let setupStep = 1, setupMounted = false;
  function setupGoto(n) {
    setupStep = n;
    for (const li of $$("#stepper li")) {
      const s = Number(li.dataset.step);
      li.classList.toggle("is-current", s === n);
      li.classList.toggle("is-done", s < n);
      if (s < n) $(".st-n", li).replaceChildren(icon("check", "icon-sm"));
      else $(".st-n", li).textContent = String(s);
    }
    for (const el of $$("[data-setup-step]")) el.hidden = Number(el.dataset.setupStep) !== n;
    if (n >= 2 && !setupMounted) {
      setupMounted = true;
      mountSmtp($('[data-mount="smtp-setup"]'), "setup");
      mountEnroll($('[data-mount="enroll-setup"]'));
    }
  }

  // ───────────────────────── SMTP component ─────────────────────────
  const SMTP_PRESETS = [
    { id: "qq", key: "smtp.pQQ", host: "smtp.qq.com", port: 465, hint: "smtp.hintQQ" },
    { id: "163", key: "smtp.p163", host: "smtp.163.com", port: 465, hint: "smtp.hint163" },
    { id: "exmail", key: "smtp.pExmail", host: "smtp.exmail.qq.com", port: 465, hint: "smtp.hintExmail" },
    { id: "gmail", key: "smtp.pGmail", host: "smtp.gmail.com", port: 587, hint: "smtp.hintGmail" },
    { id: "custom", key: "smtp.custom", host: "", port: 465, hint: "" },
  ];
  const smtpForms = [];
  function mountSmtp(host, mode) {
    host.replaceChildren($("#tpl-smtp").content.cloneNode(true));
    const f = $("form", host);
    const opts = $$("option", f.port);
    ["smtp.port465", "smtp.port587", "smtp.port25"].forEach((k, i) => (opts[i].dataset.i18n = k));
    const chips = $('[data-role="presets"]', f);
    for (const p of SMTP_PRESETS) chips.append(h("button", { class: "chip", type: "button", "data-preset": p.id, "aria-pressed": "false", i18n: p.key }));
    const hint = $('[data-role="provider-hint"]', f);
    const actions = $('[data-role="actions"]', f);
    const primary = h("button", { class: "btn btn-primary", type: "submit", i18n: mode === "setup" ? "common.continue" : "common.save" });
    const test = h("button", { class: "btn btn-outline", type: "button", i18n: "smtp.saveTest" });
    actions.append(primary, test);
    let skip = null;
    if (mode === "setup") { skip = h("button", { class: "btn btn-quiet", type: "button", i18n: "common.skip" }); actions.append(skip); }
    I18N.apply(host);
    const state = { configured: false };
    const selectPreset = (id) => {
      for (const c of $$(".chip", chips)) c.setAttribute("aria-pressed", String(c.dataset.preset === id));
      const p = SMTP_PRESETS.find((x) => x.id === id);
      hint.hidden = !(p && p.hint);
      if (p && p.hint) { hint.dataset.i18n = p.hint; hint.textContent = t(p.hint); }
    };
    const detectPreset = () => {
      const p = SMTP_PRESETS.find((x) => x.host && x.host === f.host.value.trim().toLowerCase());
      selectPreset(p ? p.id : f.host.value.trim() ? "custom" : "");
    };
    chips.addEventListener("click", (e) => {
      const c = e.target.closest(".chip");
      if (!c) return;
      const p = SMTP_PRESETS.find((x) => x.id === c.dataset.preset);
      if (p.host) { f.host.value = p.host; f.port.value = String(p.port); }
      selectPreset(p.id);
      (p.host ? f.username : f.host).focus();
    });
    f.host.addEventListener("input", detectPreset);
    const payload = () => ({ host: f.host.value.trim(), port: parseInt(f.port.value, 10), username: f.username.value.trim(), password: f.password.value, from: f.from.value.trim() });
    const filled = () => !!(f.host.value.trim() || f.username.value.trim() || f.password.value);
    const save = async () => {
      const p = payload();
      if (!p.host || !p.port || !p.username || (!p.password && !state.configured)) throw new ApiError(400, "local", t("smtp.required"));
      if (!p.password) delete p.password;
      await api("POST", "/api/v1/setup/smtp", p);
      state.configured = true;
      f.password.value = "";
      setPlaceholder();
      emit("smtp", true);
    };
    const setPlaceholder = () => { f.password.placeholder = state.configured ? t("smtp.passKeep") : t("smtp.passNone"); };
    on("lang", setPlaceholder);
    setPlaceholder();
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      showErr(f, "");
      if (mode === "setup" && !filled()) { setupGoto(3); return; }
      await busy(primary, async () => {
        try {
          await save();
          toast(t("smtp.saved"));
          if (mode === "setup") setupGoto(3);
        } catch (err) { showErr(f, err.code === "local" ? err.message : errText(err)); }
      });
    });
    test.addEventListener("click", async () => {
      showErr(f, "");
      await busy(test, async () => {
        try {
          await save();
          await api("POST", "/api/v1/setup/smtp/test", {});
          const me = await Session.me();
          toast(me && me.email ? t("smtp.testSentTo", { email: me.email }) : t("smtp.testSent"));
        } catch (err) { showErr(f, err.code === "local" ? err.message : errText(err)); }
      });
    });
    if (skip) skip.addEventListener("click", () => setupGoto(3));
    const api_ = {
      fill(d) {
        if (!d) return;
        f.host.value = d.host || "";
        f.port.value = String(d.port || 465);
        f.username.value = d.username || "";
        f.from.value = d.from || "";
        state.configured = !!d.configured;
        setPlaceholder();
        detectPreset();
      },
    };
    smtpForms.push(api_);
    return api_;
  }

  // ───────────────────────── enrollment component ─────────────────────────
  function enrollLines(os, r) {
    const origin = location.origin, key = r.preauth_key || "<PREAUTH_KEY>";
    const tok = r.agent_token, id = r.device_id, host = r.hostname;
    const c = (n, k) => ["c", `# ${n}) ${t(k)}`];
    if (os === "windows") {
      return [
        c(1, "enroll.c1"),
        ["", "winget install -e --id tailscale.tailscale"],
        ["", `& "$env:ProgramFiles\\Tailscale\\tailscale.exe" up --login-server ${origin} --hostname ${host} --authkey ${key}`],
        ["", ""], c(2, "enroll.c2win"),
        ["", '$dir = "$env:ProgramData\\meshbridge"'],
        ["", "New-Item -ItemType Directory -Force -Path $dir | Out-Null"],
        ["", `Set-Content -NoNewline -Path "$dir\\agent.token" -Value '${tok}'`],
        ["", 'icacls "$dir\\agent.token" /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null'],
        ["", ""], c(3, "enroll.c3"),
        ["", 'New-Item -ItemType Directory -Force -Path "$env:ProgramFiles\\MeshBridge" | Out-Null'],
        ["", 'Copy-Item .\\meshbridge-agent.exe "$env:ProgramFiles\\MeshBridge\\"'],
        ["", ""], c(4, "enroll.c4"),
        ["", `& "$env:ProgramFiles\\MeshBridge\\meshbridge-agent.exe" --controller ${origin} --device-id ${id} --token-file "$dir\\agent.token"`],
      ];
    }
    const ts = os === "macos"
      ? [["", "brew install tailscale"], ["", "sudo brew services start tailscale"]]
      : [["", "curl -fsSL https://tailscale.com/install.sh | sh"]];
    const bin = os === "macos" ? [["", "sudo install -d /usr/local/bin"]] : [];
    return [
      c(1, "enroll.c1"), ...ts,
      ["", `sudo tailscale up --login-server ${origin} --hostname ${host} --authkey ${key}`],
      ["", ""], c(2, "enroll.c2"),
      ["", "sudo install -d -m 700 /etc/meshbridge"],
      ["", `printf '%s\\n' '${tok}' | sudo tee /etc/meshbridge/agent.token >/dev/null`],
      ["", "sudo chmod 600 /etc/meshbridge/agent.token"],
      ["", ""], c(3, "enroll.c3"), ...bin,
      ["", "sudo install -m 755 meshbridge-agent /usr/local/bin/"],
      ["", ""], c(4, "enroll.c4"),
      ["", `sudo meshbridge-agent --controller ${origin} --device-id ${id} --token-file /etc/meshbridge/agent.token`],
    ];
  }
  const HOST_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  const enrollers = [];
  function mountEnroll(host) {
    host.replaceChildren($("#tpl-enroll").content.cloneNode(true));
    I18N.apply(host);
    const f = $("form", host), out = $('[data-role="out"]', host), btn = $("[type=submit]", f);
    let result = null, os = /Win/.test(navigator.platform) ? "windows" : /Mac/.test(navigator.platform) ? "macos" : "linux";
    const pre = $('[data-role="cmd"]', host);
    const copyCmd = h("button", { class: "copy-btn", type: "button" }, icon("copy"), h("span", { i18n: "common.copy" }, t("common.copy")));
    const render = () => {
      if (!result) return;
      $('[data-role="reg"]', out).textContent = t("enroll.registered", { name: result.hostname });
      $('[data-role="id"]', out).textContent = "ID " + result.device_id;
      $('[data-role="preauth"]', out).textContent = result.preauth_key || "—";
      $('[data-role="preauth-block"]', out).hidden = !result.preauth_key;
      $('[data-role="token"]', out).textContent = result.agent_token;
      const hs = $('[data-role="hs"]', out);
      hs.hidden = !!result.preauth_key;
      $('[data-role="hs-text"]', hs).textContent = result.headscale_error ? t("enroll.hsError", { err: result.headscale_error }) : t("enroll.hsMissing");
      for (const b of $$("[data-os]", out)) b.setAttribute("aria-pressed", String(b.dataset.os === os));
      pre.replaceChildren(...enrollLines(os, result).flatMap(([cls, text]) => [cls ? h("span", { class: cls }, text) : text, "\n"]).slice(0, -1));
    };
    pre.parentNode.append(copyCmd);
    copyCmd.addEventListener("click", () => copyText(enrollLines(os, result).map((l) => l[1]).join("\n"), copyCmd));
    $('[data-role="os"]', out).addEventListener("click", (e) => { const b = e.target.closest("[data-os]"); if (b) { os = b.dataset.os; render(); } });
    out.addEventListener("click", (e) => {
      const b = e.target.closest("[data-copy]");
      if (b) copyText($(`[data-role="${b.dataset.copy}"]`, out).textContent, b);
    });
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      showErr(f, "");
      const hostname = f.host.value.trim().toLowerCase();
      if (!HOST_RE.test(hostname)) { showErr(f, t("err.badHostname")); f.host.focus(); return; }
      await busy(btn, async () => {
        try {
          const d = await api("POST", "/api/v1/devices/enroll", { hostname });
          result = { ...d, hostname };
          render();
          out.hidden = false;
          toast(t("enroll.success"));
          emit("devices-changed");
        } catch (err) { showErr(f, errText(err)); }
      });
    });
    on("lang", render);
    const ctl = { reset() { result = null; out.hidden = true; f.reset(); showErr(f, ""); }, focus() { f.host.focus(); } };
    enrollers.push(ctl);
    return ctl;
  }

  // ───────────────────────── modals ─────────────────────────
  let modalReturn = null;
  const focusables = (root) => $$('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea, [tabindex]:not([tabindex="-1"])', root).filter((el) => el.offsetParent !== null);
  function openModal(id) {
    const m = $("#" + id);
    modalReturn = document.activeElement;
    m.hidden = false;
    document.body.classList.add("modal-open");
    const first = focusables($(".modal-card", m)).find((el) => el.tagName === "INPUT" || el.tagName === "SELECT") || focusables(m)[0];
    if (first) setTimeout(() => first.focus(), 30);
  }
  function closeModal(m) {
    if (!m || m.hidden) return;
    m.hidden = true;
    document.body.classList.remove("modal-open");
    if (modalReturn && modalReturn.focus) modalReturn.focus();
    emit("modal-closed", m.id);
  }
  document.addEventListener("click", (e) => {
    const c = e.target.closest("[data-close-modal]");
    if (c) closeModal(c.closest(".modal"));
    const o = e.target.closest("[data-open]");
    if (o) { e.preventDefault(); openFeature(o.dataset.open); }
  });
  document.addEventListener("keydown", (e) => {
    const m = $$(".modal").find((x) => !x.hidden);
    if (!m) return;
    if (e.key === "Escape") { e.preventDefault(); closeModal(m); return; }
    if (e.key === "Tab") {
      const els = focusables(m);
      if (!els.length) return;
      const first = els[0], last = els[els.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });
  let modalEnroll = null;
  function openFeature(name) {
    if (name === "enroll") {
      if (!modalEnroll) modalEnroll = mountEnroll($('[data-mount="enroll-modal"]'));
      modalEnroll.reset();
      openModal("modal-enroll");
    } else if (name === "transfer") openTransferModal();
  }

  // ───────────────────────── console data ─────────────────────────
  const D = { devices: null, transfers: null, relays: null, audit: [], auditPage: 0, auditDone: false, health: null, healthErr: false, projects: null, smtp: null };
  const ACTIVE = new Set(["QUEUED", "PROBING", "WAITING_FOR_ROUTE", "TRANSFERRING", "PAUSED", "VERIFYING"]);
  const load = {
    async devices() { D.devices = (await api("GET", "/api/v1/devices?limit=200")).items || []; updateCounts(); return D.devices; },
    async transfers() { D.transfers = (await api("GET", "/api/v1/transfers?limit=200")).items || []; updateCounts(); return D.transfers; },
    async relays() { D.relays = (await api("GET", "/api/v1/relays")).items || []; return D.relays; },
    async projects() { D.projects = (await api("GET", "/api/v1/projects?limit=200")).items || []; return D.projects; },
    async health() {
      try { D.health = await api("GET", "/api/v1/health", null, { auth: false }); D.healthErr = false; }
      catch { D.healthErr = true; }
      renderHealth();
    },
    async audit(reset) {
      if (reset) { D.audit = []; D.auditPage = 0; D.auditDone = false; }
      const page = D.auditPage + 1, limit = 50;
      const items = (await api("GET", `/api/v1/audit?limit=${limit}&page=${page}`)).items || [];
      D.audit = D.audit.concat(items); D.auditPage = page; D.auditDone = items.length < limit;
      return D.audit;
    },
    async smtp() { D.smtp = await api("GET", "/api/v1/setup/smtp"); return D.smtp; },
  };
  const hostOf = (id) => { const d = (D.devices || []).find((x) => x.id === id); return d ? d.hostname : short(id); };
  function updateCounts() {
    const dc = $('[data-count="devices"]'), tc = $('[data-count="transfers"]');
    if (D.devices) dc.textContent = D.devices.length ? fmt.num(D.devices.length) : "";
    if (D.transfers) { const n = D.transfers.filter((x) => ACTIVE.has(x.state)).length; tc.textContent = n ? fmt.num(n) : ""; }
  }
  function renderHealth() {
    const box = $("#health"), txt = $('[data-role="text"]', box);
    box.classList.remove("ok", "bad");
    let key = "app.health.checking";
    if (D.healthErr) { box.classList.add("bad"); key = "app.health.offline"; }
    else if (D.health) { const ok = D.health.headscale === "ok"; box.classList.add(ok ? "ok" : "bad"); key = ok ? "app.health.ok" : "app.health.hsDown"; }
    txt.dataset.i18n = key; txt.textContent = t(key);
  }
  const deviceState = (d) => (!d.last_seen ? "pending" : d.online ? "online" : "offline");
  function statePill(state) {
    const cls = { COMPLETED: "ok", TRANSFERRING: "ok live", VERIFYING: "ok live", FAILED: "err", CANCELLED: "", PAUSED: "warn", WAITING_FOR_ROUTE: "warn", QUEUED: "info", PROBING: "info live" }[state] ?? "";
    return h("span", { class: "pill " + cls }, h("span", { class: "dot" }), t("state." + state) === "state." + state ? state : t("state." + state));
  }
  function devicePill(d) {
    const s = deviceState(d);
    return h("span", { class: "pill " + (s === "online" ? "ok live" : s === "pending" ? "info" : "") }, h("span", { class: "dot" }), t("status." + s));
  }
  function routeLabel(r) { const k = "route." + (r || "none"); const v = t(k); return v === k ? r : v; }
  function progress(x) {
    const total = x.bytes_total || 0, done = Math.min(x.bytes_done || 0, total || Infinity);
    const ratio = total ? done / total : x.state === "COMPLETED" ? 1 : 0;
    const bar = h("div", { class: "progress" + (x.state === "FAILED" ? " err" : x.state === "PAUSED" || x.state === "WAITING_FOR_ROUTE" ? " warn" : x.state === "TRANSFERRING" ? " live" : "") }, h("i"));
    bar.firstChild.style.setProperty("--p", (ratio * 100).toFixed(1) + "%");
    const meta = h("div", { class: "prog-meta" },
      h("span", null, total ? t("app.transfers.progressOf", { done: fmt.bytes(done), total: fmt.bytes(total) }) : t("app.transfers.sizePending")),
      h("span", null, total ? fmt.pct(ratio) : ""));
    return h("div", { class: "prog" }, bar, meta);
  }
  function inlineCopy(text, labelKey) {
    const b = h("button", { class: "inline-copy", type: "button", "aria-label": t(labelKey), title: t(labelKey) }, icon("copy"));
    b.addEventListener("click", async (e) => {
      e.stopPropagation();
      await clip(text);
      b.classList.add("is-done"); b.replaceChildren(icon("check"));
      setTimeout(() => { b.classList.remove("is-done"); b.replaceChildren(icon("copy")); }, 1400);
    });
    return b;
  }
  function emptyState({ icon: ic, title, text, action, seed }) {
    const art = h("div", { class: "empty-art" });
    const ter = svg("svg", { class: "terrain-svg", "data-seed": String(seed || 7), preserveAspectRatio: "none", "aria-hidden": "true" });
    art.append(ter, icon(ic));
    const box = h("div", { class: "empty" }, art, h("h3", { class: "display empty-title" }, title), h("p", { class: "empty-text" }, text), action || null);
    requestAnimationFrame(() => drawTerrain(ter, true));
    return box;
  }
  function table(cols, rows) {
    const thead = h("thead", null, h("tr", null, cols.map((c) => h("th", { scope: "col", class: c.cls || null }, c.label))));
    const tbody = h("tbody");
    for (const r of rows) {
      tbody.append(h("tr", null, r.map((cell, i) => {
        const td = h("td", { class: [cols[i].cls, i === 0 ? "cell-main" : null].filter(Boolean).join(" ") || null, "data-label": cols[i].label });
        td.append(...(Array.isArray(cell) ? cell : [cell]).filter((x) => x != null));
        return td;
      })));
    }
    return h("table", { class: "data" }, thead, tbody);
  }
  const loadingRows = (n) => h("div", null, Array.from({ length: n }, () => h("div", { class: "skeleton" })));

  // ───────────────────────── console pages ─────────────────────────
  const App = { page: null, me: null, filters: { dev: "all", tr: "all" } };
  const isAdmin = () => App.me && App.me.role === "admin";

  const PAGES = {
    overview: {
      title() {
        const hr = new Date().getHours();
        const k = hr >= 5 && hr < 12 ? "titleMorning" : hr >= 12 && hr < 18 ? "titleAfternoon" : "titleEvening";
        return t("app.overview." + k, { name: App.me ? App.me.username : "" });
      },
      async refresh() {
        const jobs = [load.health(), load.devices(), load.transfers(), load.relays(), load.audit(true)];
        if (isAdmin()) jobs.push(load.smtp().catch(() => null));
        await Promise.allSettled(jobs);
        this.render();
      },
      render() {
        const devs = D.devices || [], trs = D.transfers || [], rel = D.relays || [];
        const online = devs.filter((d) => d.online).length;
        const stat = (id, value, small, note, cls) => {
          const el = $("#" + id);
          el.classList.remove("ok", "bad");
          if (cls) el.classList.add(cls);
          const v = $('[data-role="v"]', el);
          v.replaceChildren(value, small ? h("small", null, " / " + small) : "");
          $('[data-role="n"]', el).textContent = note;
        };
        if (D.devices) stat("st-devices", fmt.num(online), devs.length ? fmt.num(devs.length) : "", devs.length ? t("app.overview.devicesNote", { n: devs.length, count: fmt.num(devs.length) }) : t("app.overview.noDevices"));
        if (D.transfers) { const act = trs.filter((x) => ACTIVE.has(x.state)).length; stat("st-transfers", fmt.num(act), "", t("app.overview.transfersNote", { n: trs.length, count: fmt.num(trs.length) })); }
        if (D.relays) {
          const ok = rel.filter((r) => r.healthy).length;
          if (rel.length) stat("st-relays", fmt.num(ok), fmt.num(rel.length), t("app.overview.relaysNote"));
          else stat("st-relays", "—", "", t("app.overview.relaysNone"));
        }
        if (D.healthErr) stat("st-control", t("app.overview.controlDown"), "", t("app.health.offline"), "bad");
        else if (D.health) {
          const ok = D.health.headscale === "ok";
          stat("st-control", t(ok ? "app.overview.controlOk" : "app.overview.controlBad"), "", t(ok ? "app.health.hsOk" : "app.health.hsDown"), ok ? "ok" : "bad");
        }
        // recent transfers
        const tl = $("#ov-transfers");
        tl.replaceChildren();
        if (!trs.length) tl.append(h("li", { class: "list-empty" }, t("app.overview.noTransfers")));
        for (const x of trs.slice(0, 5)) {
          const ratio = x.bytes_total ? Math.min(1, x.bytes_done / x.bytes_total) : x.state === "COMPLETED" ? 1 : 0;
          const tone = x.state === "FAILED" ? "clay" : x.state === "COMPLETED" ? "moss" : "slate";
          tl.append(h("li", null,
            h("span", { class: "feed-dot " + tone }, icon("transfer")),
            h("div", { class: "li-main" }, h("div", { class: "li-title" }, hostOf(x.src) + "  →  " + hostOf(x.dst)),
              h("div", { class: "li-sub" }, t("state." + x.state) + " · " + routeLabel(x.route))),
            h("span", { class: "li-end" }, x.bytes_total ? fmt.pct(ratio) : "")));
        }
        // activity
        const al = $("#ov-activity");
        al.replaceChildren();
        if (!D.audit.length) al.append(h("li", { class: "list-empty" }, t("app.overview.noActivity")));
        for (const a of D.audit.slice(0, 6)) {
          const ev = eventInfo(a.event);
          al.append(h("li", null,
            h("span", { class: "feed-dot " + ev.tone }, icon(ev.icon)),
            h("div", { class: "li-main" }, h("div", { class: "li-title" }, ev.label), h("div", { class: "li-sub" }, [a.actor, eventDetail(a)].filter(Boolean).join(" · "))),
            h("span", { class: "li-end", title: fmt.abs(a.ts) }, fmt.rel(a.ts))));
        }
        // getting started (admins only)
        const cl = $("#checklist");
        if (isAdmin() && D.devices && D.transfers) {
          const done = { mail: !!(D.smtp && D.smtp.configured), device: devs.length > 0, transfer: trs.length > 0 };
          const n = Object.values(done).filter(Boolean).length;
          cl.hidden = n === 3;
          for (const [k, v] of Object.entries(done)) $(`[data-check="${k}"]`, cl).classList.toggle("done", v);
          $$(".check-item .btn", cl).forEach((b) => (b.hidden = b.closest(".check-item").classList.contains("done")));
          const tb = $('[data-check="transfer"] .btn', cl);
          if (tb) tb.disabled = devs.length < 2;
          $("#check-progress").textContent = t("app.start.progress", { done: n, total: 3 });
        } else cl.hidden = true;
      },
    },

    devices: {
      async refresh(quiet) {
        const host = $("#dev-table");
        if (!quiet && !D.devices) host.replaceChildren(loadingRows(4));
        try { await load.devices(); } catch (e) { if (!quiet) toast(errText(e), "err"); }
        this.render();
      },
      render() {
        const host = $("#dev-table");
        const all = D.devices || [];
        if (!all.length) {
          host.replaceChildren(emptyState({
            icon: "device", seed: 3, title: t("app.devices.emptyTitle"),
            text: isAdmin() ? t("app.devices.emptyText") : t("app.devices.emptyMember"),
            action: isAdmin() ? h("button", { class: "btn btn-primary", type: "button", "data-open": "enroll" }, icon("plus"), t("app.devices.add")) : null,
          }));
          return;
        }
        const q = $("#dev-q").value.trim().toLowerCase(), f = App.filters.dev;
        const rows = all.filter((d) => (f === "all" || deviceState(d) === f) && (!q || [d.hostname, d.tailscale_ip, d.id].some((v) => String(v || "").toLowerCase().includes(q))));
        if (!rows.length) { host.replaceChildren(h("div", { class: "empty" }, h("p", { class: "empty-text" }, t("common.noMatch")))); return; }
        host.replaceChildren(table(
          [{ label: t("app.devices.colDevice") }, { label: t("app.devices.colIp") }, { label: t("app.devices.colStatus") }, { label: t("app.devices.colSeen") }],
          rows.map((d) => [
            [h("div", { class: "primary" }, d.hostname), h("div", { class: "sub" }, h("span", { class: "mono" }, d.id), inlineCopy(d.id, "app.devices.copyId"))],
            d.tailscale_ip ? h("span", { class: "mono" }, d.tailscale_ip) : h("span", { class: "faint" }, "—"),
            devicePill(d),
            h("span", { title: fmt.abs(d.last_seen), class: d.last_seen ? null : "faint" }, fmt.rel(d.last_seen)),
          ])));
      },
    },

    transfers: {
      interval() { return (D.transfers || []).some((x) => ACTIVE.has(x.state)) ? 5000 : 15000; },
      async refresh(quiet) {
        const host = $("#tr-table");
        if (!quiet && !D.transfers) host.replaceChildren(loadingRows(4));
        try { await Promise.all([load.transfers(), D.devices ? null : load.devices()]); } catch (e) { if (!quiet) toast(errText(e), "err"); }
        this.render();
      },
      render() {
        const host = $("#tr-table");
        const all = D.transfers || [];
        if (!all.length) {
          const can = (D.devices || []).length >= 2;
          host.replaceChildren(emptyState({
            icon: "transfer", seed: 8, title: t("app.transfers.emptyTitle"),
            text: can ? t("app.transfers.emptyText") : t("app.transfers.emptyNeedDevices"),
            action: h("button", { class: "btn btn-primary", type: "button", "data-open": "transfer" }, icon("plus"), t("app.transfers.new")),
          }));
          return;
        }
        const f = App.filters.tr;
        const rows = all.filter((x) => f === "all" || (f === "active" && ACTIVE.has(x.state)) || (f === "done" && x.state === "COMPLETED") || (f === "failed" && (x.state === "FAILED" || x.state === "CANCELLED")));
        if (!rows.length) { host.replaceChildren(h("div", { class: "empty" }, h("p", { class: "empty-text" }, t("common.noMatch")))); return; }
        host.replaceChildren(table(
          [{ label: t("app.transfers.colJob") }, { label: t("app.transfers.colRoute") }, { label: t("app.transfers.colState") }, { label: t("app.transfers.colProgress") }],
          rows.map((x) => [
            [h("div", { class: "primary route" }, hostOf(x.src), h("span", { class: "arrow" }, "→"), hostOf(x.dst)), h("div", { class: "sub" }, h("span", { class: "mono" }, x.id), inlineCopy(x.id, "app.transfers.copyId"))],
            h("span", { class: "tag-mono" }, routeLabel(x.route)),
            [statePill(x.state), x.error ? h("div", { class: "err-text", title: x.error }, x.error) : null],
            progress(x),
          ])));
      },
    },

    relays: {
      interval: () => 30000,
      async refresh(quiet) {
        const host = $("#relay-list");
        if (!quiet && !D.relays) host.replaceChildren(loadingRows(3));
        try { await load.relays(); } catch (e) { if (!quiet) toast(errText(e), "err"); }
        this.render();
      },
      render() {
        const host = $("#relay-list"), rel = D.relays || [];
        if (!rel.length) {
          host.replaceChildren(h("div", { class: "panel" }, emptyState({ icon: "relay", seed: 12, title: t("app.relays.emptyTitle"), text: t("app.relays.emptyText") })));
          return;
        }
        host.replaceChildren(h("div", { class: "relay-grid" }, rel.map((r) => {
          const ratio = r.quota ? Math.min(1, r.bytes_out_month / r.quota) : 0;
          const bar = h("div", { class: "progress" + (ratio > 0.95 ? " err" : ratio > 0.8 ? " warn" : "") }, h("i"));
          bar.firstChild.style.setProperty("--p", (ratio * 100).toFixed(1) + "%");
          return h("div", { class: "panel relay" },
            h("div", { class: "relay-top" }, h("h3", { class: "display relay-name" }, r.name), h("span", { class: "pill " + (r.healthy ? "ok live" : "err") }, h("span", { class: "dot" }), t(r.healthy ? "app.relays.healthy" : "app.relays.unhealthy"))),
            h("div", { class: "relay-meta" }, h("span", { class: "tag-mono" }, r.region || "—"), h("span", null, t("app.relays.port", { port: r.udp_port })), h("span", { title: fmt.abs(r.last_seen) }, t("app.relays.seen", { time: fmt.rel(r.last_seen) }))),
            h("div", { class: "relay-quota" },
              h("div", { class: "prog-meta" }, h("span", null, t("app.relays.month")), h("span", null, r.quota ? t("app.relays.quota", { used: fmt.bytes(r.bytes_out_month), quota: fmt.bytes(r.quota) }) : t("app.relays.noQuota", { used: fmt.bytes(r.bytes_out_month) }))),
              r.quota ? bar : null));
        })));
      },
    },

    audit: {
      interval: () => 60000,
      async refresh(quiet) {
        const host = $("#audit-table");
        if (!quiet && !D.audit.length) host.replaceChildren(loadingRows(6));
        try { await load.audit(true); } catch (e) { if (!quiet) toast(errText(e), "err"); }
        this.render();
      },
      render() {
        const host = $("#audit-table");
        $("#audit-more-row").hidden = D.auditDone || !D.audit.length;
        if (!D.audit.length) {
          host.replaceChildren(emptyState({ icon: "audit", seed: 17, title: t("app.audit.emptyTitle"), text: t("app.audit.emptyText") }));
          return;
        }
        const q = $("#audit-q").value.trim().toLowerCase();
        const rows = D.audit.filter((a) => !q || [a.actor, a.event, eventInfo(a.event).label, a.detail, a.device_id, a.job_id].some((v) => String(v || "").toLowerCase().includes(q)));
        if (!rows.length) { host.replaceChildren(h("div", { class: "empty" }, h("p", { class: "empty-text" }, t("common.noMatch")))); return; }
        host.replaceChildren(table(
          [{ label: t("app.audit.colEvent") }, { label: t("app.audit.colActor") }, { label: t("app.audit.colDetail") }, { label: t("app.audit.colTime") }],
          rows.map((a) => {
            const ev = eventInfo(a.event);
            const ids = [a.device_id && h("span", { class: "tag-mono", title: a.device_id }, "dev " + short(a.device_id)), a.job_id && h("span", { class: "tag-mono", title: a.job_id }, "job " + short(a.job_id))].filter(Boolean);
            return [
              h("div", { class: "primary", title: a.event }, ev.label),
              h("span", null, a.actor || "—"),
              h("div", { class: "sub" }, eventDetail(a) || (ids.length ? null : "—"), ...ids),
              h("span", { class: "nowrap", title: fmt.abs(a.ts) }, fmt.rel(a.ts)),
            ];
          })));
      },
    },

    settings: {
      interval: () => 0,
      async refresh() {
        this.render();
        if (!isAdmin()) return;
        if (!this.smtp) this.smtp = mountSmtp($('[data-mount="smtp-settings"]'), "settings");
        const [smtp, st] = await Promise.all([load.smtp().catch(() => null), Status.get(true)]);
        if (smtp) this.smtp.fill(smtp);
        setSmtpPill(smtp && smtp.configured);
        if (st) $("#set-reg").setAttribute("aria-checked", String(!!st.allow_registration));
      },
      render() {
        const me = App.me || {};
        $("#acc-name").textContent = me.username || "—";
        $("#acc-email").textContent = me.email || "—";
        $("#acc-role").textContent = me.role === "admin" ? t("common.admin") : t("common.member");
        const sel = $("#set-lang");
        if (!sel.options.length) for (const l of LANGS) sel.append(h("option", { value: l.code, lang: l.code }, l.name));
        sel.value = I18N.lang;
        for (const b of $$("#set-theme button")) b.setAttribute("aria-pressed", String(b.dataset.v === Theme.get()));
      },
    },
  };
  function setSmtpPill(on_) {
    const p = $("#smtp-status");
    p.className = "pill " + (on_ ? "ok" : "warn");
    p.replaceChildren(h("span", { class: "dot" }), h("span", { i18n: on_ ? "smtp.statusOn" : "smtp.statusOff" }, t(on_ ? "smtp.statusOn" : "smtp.statusOff")));
  }
  on("smtp", () => { setSmtpPill(true); if (D.smtp) D.smtp.configured = true; });

  const EVENTS = {
    "login": ["event.login", "user", "slate"],
    "setup admin created": ["event.setupAdmin", "shield", "moss"],
    "user registered": ["event.userRegistered", "user", "moss"],
    "password reset": ["event.passwordReset", "lock", "clay"],
    "smtp configured": ["event.smtp", "mail", "slate"],
    "registration toggled": ["event.registration", "settings", "clay"],
    "device registered": ["event.deviceRegistered", "device", "moss"],
    "device enrolled": ["event.deviceEnrolled", "key", "moss"],
    "transfer created": ["event.transferCreated", "transfer", "slate"],
    "project created": ["event.projectCreated", "folder", "slate"],
  };
  function eventInfo(ev) {
    const e = EVENTS[ev];
    return e ? { label: t(e[0]), icon: e[1], tone: e[2] } : { label: ev, icon: "activity", tone: "" };
  }
  function eventDetail(a) {
    if (a.event === "registration toggled") return t(a.detail === "1" ? "app.audit.regOpened" : "app.audit.regClosed");
    if (a.event === "login" && a.detail === "login ok") return "";
    return a.detail || "";
  }

  // ── console shell
  let consoleReady = false, pollTimer = null;
  function initConsole() {
    if (consoleReady) return;
    consoleReady = true;
    const view = $("#view-app");
    $("#btn-menu").addEventListener("click", () => view.classList.add("nav-open"));
    $$("[data-nav-close]").forEach((el) => el.addEventListener("click", () => view.classList.remove("nav-open")));
    const top = $("#app-top");
    window.addEventListener("scroll", () => top.classList.toggle("is-scrolled", window.scrollY > 4), { passive: true });
    const logout = async () => {
      try { await api("POST", "/api/v1/auth/logout", {}, { quiet401: true }); } catch { /* already gone */ }
      Session.clear();
      Object.assign(D, { devices: null, transfers: null, relays: null, audit: [], projects: null, smtp: null });
      go("#/");
    };
    $("#btn-logout").addEventListener("click", logout);
    $$("[data-logout]").forEach((b) => b.addEventListener("click", logout));
    $("#dev-q").addEventListener("input", () => PAGES.devices.render());
    $("#audit-q").addEventListener("input", () => PAGES.audit.render());
    $("#audit-refresh").addEventListener("click", (e) => busy(e.currentTarget, () => PAGES.audit.refresh()));
    $("#audit-more").addEventListener("click", (e) => busy(e.currentTarget, async () => { try { await load.audit(); } catch (err) { toast(errText(err), "err"); } PAGES.audit.render(); }));
    const seg = (id, key, page) => $("#" + id).addEventListener("click", (e) => {
      const b = e.target.closest("button[data-f]");
      if (!b) return;
      App.filters[key] = b.dataset.f;
      for (const x of $$("button", e.currentTarget)) x.setAttribute("aria-pressed", String(x === b));
      PAGES[page].render();
    });
    seg("dev-filter", "dev", "devices");
    seg("tr-filter", "tr", "transfers");
    $("#set-lang").addEventListener("change", (e) => I18N.use(e.target.value, true));
    $("#set-theme").addEventListener("click", (e) => { const b = e.target.closest("button[data-v]"); if (b) Theme.set(b.dataset.v); });
    on("theme", () => { if (App.page === "settings") PAGES.settings.render(); });
    $("#set-reg").addEventListener("click", async (e) => {
      const sw = e.currentTarget, next = sw.getAttribute("aria-checked") !== "true";
      sw.classList.add("is-busy");
      try {
        await api("POST", "/api/v1/setup/registration", { allow: next });
        sw.setAttribute("aria-checked", String(next));
        Status.invalidate();
        toast(t(next ? "app.settings.regOn" : "app.settings.regOff"));
      } catch (err) { toast(errText(err), "err"); }
      finally { sw.classList.remove("is-busy"); }
    });
    on("devices-changed", () => { D.devices = null; });
    on("modal-closed", (id) => { if (id === "modal-enroll" && App.page) PAGES[App.page].refresh(true); });
    document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible" && currentView === "app") poll(0); });
    initTransferModal();
  }
  function poll(delay) {
    clearTimeout(pollTimer);
    const page = PAGES[App.page];
    if (!page) return;
    const every = page.interval ? page.interval() : 15000;
    if (!every) return;
    pollTimer = setTimeout(async () => {
      if (document.visibilityState === "visible" && currentView === "app" && $$(".modal").every((m) => m.hidden)) {
        try { await page.refresh(true); } catch { /* next tick */ }
        load.health();
      }
      poll();
    }, delay ?? every);
  }
  function setPageTitle() {
    const page = PAGES[App.page];
    const title = page.title ? page.title() : t(`app.${App.page}.title`);
    $("#page-title").textContent = title;
    $("#page-sub").textContent = t(`app.${App.page}.sub`);
    document.title = (App.page === "overview" ? t("app.nav.overview") : title) + " · MeshBridge";
  }
  async function showApp(page, me) {
    if (!PAGES[page]) { go("#/app/overview", true); return; }
    initConsole();
    App.me = me;
    showView("app");
    $("#view-app").classList.remove("nav-open");
    $("#u-name").textContent = me.username;
    $("#u-role").textContent = me.role === "admin" ? t("common.admin") : t("common.member");
    $("#u-avatar").textContent = (me.username || "?").slice(0, 1);
    $$("[data-admin]").forEach((el) => (el.hidden = !isAdmin()));
    for (const a of $$("[data-nav]")) {
      if (a.dataset.nav === page) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
    const changed = App.page !== page;
    App.page = page;
    for (const sec of $$("[data-page]")) sec.hidden = sec.dataset.page !== page;
    setPageTitle();
    if (changed) window.scrollTo(0, 0);
    load.health();
    await PAGES[page].refresh(false);
    poll();
  }
  on("lang", () => {
    if (currentView === "app" && App.page) {
      setPageTitle();
      $("#u-role").textContent = App.me && App.me.role === "admin" ? t("common.admin") : t("common.member");
      PAGES[App.page].render();
      renderHealth();
      updateCounts();
    }
    if (currentView === "auth") document.title = $(`[data-panel="${currentPanel}"] .auth-title`).textContent + " · MeshBridge";
    if (currentView === "landing") document.title = t("meta.title");
  });

  // ───────────────────────── new-transfer modal ─────────────────────────
  function initTransferModal() {
    const f = $("#form-transfer");
    const pick = $('[data-role="project-pick"]', f), make = $('[data-role="project-create"]', f);
    let dstTouched = false;
    f.srcPath.addEventListener("input", () => { if (!dstTouched) f.dstPath.value = f.srcPath.value; });
    f.dstPath.addEventListener("input", () => { dstTouched = f.dstPath.value !== f.srcPath.value; });
    $('[data-role="project-new"]', f).addEventListener("click", () => { make.hidden = false; f.projectName.focus(); });
    $('[data-role="project-create-btn"]', f).addEventListener("click", async (e) => {
      showErr(f, "");
      const name = f.projectName.value.trim();
      if (!name) { showErr(f, t("err.projectName")); f.projectName.focus(); return; }
      await busy(e.currentTarget, async () => {
        try {
          const d = await api("POST", "/api/v1/projects", { name });
          await load.projects();
          fillProjects(d.id);
          f.projectName.value = "";
          make.hidden = true;
          toast(t("tf.projectCreated", { name }));
        } catch (err) { showErr(f, errText(err)); }
      });
    });
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      showErr(f, "");
      const body = { project_id: f.project.value, src_device_id: f.src.value, dst_device_id: f.dst.value, src_path: f.srcPath.value.trim(), dst_path: f.dstPath.value.trim() };
      if (!body.project_id) { showErr(f, t("err.pickProject")); return; }
      if (!body.src_device_id || !body.dst_device_id) { showErr(f, t("err.pickDevices")); return; }
      if (body.src_device_id === body.dst_device_id) { showErr(f, t("err.sameDevice")); return; }
      if (!pathOK(body.src_path) || !pathOK(body.dst_path)) { showErr(f, t("err.badPath")); return; }
      await busy($("[type=submit]", f), async () => {
        try {
          await api("POST", "/api/v1/transfers", body);
          closeModal($("#modal-transfer"));
          toast(t("tf.created"));
          if (App.page === "transfers" || App.page === "overview") PAGES[App.page].refresh(true);
        } catch (err) { showErr(f, errText(err)); }
      });
    });
    const resetDst = () => { dstTouched = false; };
    on("tf-open", resetDst);
  }
  function pathOK(p) {
    if (!p || p.startsWith("/") || p.startsWith("\\") || /^[A-Za-z]:/.test(p)) return false;
    return p.replace(/\\/g, "/").split("/").every((seg) => seg && seg !== "..");
  }
  function fillProjects(selectId) {
    const f = $("#form-transfer"), list = D.projects || [];
    const cur = selectId || f.project.value;
    f.project.replaceChildren(...list.map((p) => h("option", { value: p.id }, p.name)));
    if (cur && list.some((p) => p.id === cur)) f.project.value = cur;
    $('[data-role="project-pick"]', f).hidden = !list.length;
    const make = $('[data-role="project-create"]', f);
    if (!list.length) make.hidden = false;
    $('[data-role="project-none"]', f).hidden = !!list.length;
  }
  async function openTransferModal() {
    const f = $("#form-transfer");
    f.reset();
    showErr(f, "");
    emit("tf-open");
    $('[data-role="project-create"]', f).hidden = true;
    openModal("modal-transfer");
    try { await Promise.all([load.devices(), load.projects()]); } catch (e) { showErr(f, errText(e)); return; }
    fillProjects();
    const devs = D.devices || [];
    const opt = (d) => h("option", { value: d.id }, d.hostname + (d.tailscale_ip ? "  ·  " + d.tailscale_ip : "") + (d.online ? "" : "  ·  " + t("status.offline")));
    const placeholder = () => h("option", { value: "", disabled: true, selected: true }, t("tf.pickDevice"));
    f.src.replaceChildren(placeholder(), ...devs.map(opt));
    f.dst.replaceChildren(placeholder(), ...devs.map(opt));
    const enough = devs.length >= 2;
    $('[data-role="need"]', f).hidden = enough;
    $("[type=submit]", f).disabled = !enough;
  }

  // ───────────────────────── router ─────────────────────────
  function go(hash, replace) {
    if (location.hash === hash) { route(); return; }
    if (replace) location.replace(hash); else location.hash = hash;
  }
  const DEEP = ["/login", "/register", "/forgot", "/setup", "/app"];
  async function route() {
    const path = location.pathname.replace(/\/+$/, "");
    if (DEEP.includes(path)) { history.replaceState(null, "", "/#" + path + location.search); }
    const hash = location.hash;
    if (hash && !hash.startsWith("#/")) { await showLanding(hash.slice(1)); return; }
    const [top = "", sub = ""] = hash.replace(/^#\/?/, "").split("/");
    const st = await Status.get();
    if (st && st.setup_required) {
      if (top !== "setup") { go("#/setup", true); return; }
      await showAuth("setup");
      return;
    }
    if (top === "setup" && !(currentView === "auth" && currentPanel === "setup" && setupStep > 1)) { go(Session.token() ? "#/app/overview" : "#/login", true); return; }
    if (top === "setup") return;
    const me = await Session.me();
    switch (top) {
      case "": if (me) go("#/app/overview", true); else await showLanding(); return;
      case "login": case "register": case "forgot":
        if (me) go("#/app/overview", true); else await showAuth(top);
        return;
      case "app":
        if (!me) { go("#/login", true); return; }
        await showApp(sub || "overview", me);
        return;
      default: go("#/", true);
    }
  }

  // ───────────────────────── boot ─────────────────────────
  async function boot() {
    $$("[data-year]").forEach((el) => (el.textContent = String(new Date().getFullYear())));
    $("[data-skip]").addEventListener("click", (e) => {
      e.preventDefault();
      const main = $(`#view-${currentView} main`);
      if (main) { main.setAttribute("tabindex", "-1"); main.focus(); }
    });
    mountLangPickers();
    initPasswordFields();
    initSendCode();
    initAuthForms();
    try { await I18N.use(detectLang(), false); }
    catch (e) { console.error("i18n failed", e); }
    window.addEventListener("hashchange", route);
    await route();
  }
  boot();
})();
