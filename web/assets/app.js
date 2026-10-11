/* MeshBridge web UI.
   Vanilla JS, no build step, no third-party code. All user/server data is
   rendered with textContent (never innerHTML), and nothing here needs
   inline script or style, so the page runs under a strict CSP. */
"use strict";
(() => {
  // Kit supplies the shared DOM, storage, events, locale, theme and UI
  // runtime. data-app="mb" preserves the existing mb_* storage namespace.
  const K = window.Kit;
  const { $, $$, h, icon, store, debounce, on, emit, LANGS, t, setRich,
    detectLang, fmt, toast, ApiError, reduceMotion } = K;
  const I18N = K.i18n, Theme = K.theme;
  const { busy, clip, inlineCopy, emptyState, loadingRows } = K.ui;
  // Mesh tables retain their existing outer table-wrap containers.
  const table = (cols, rows) => K.ui.table(cols, rows, { wrap: false });
  const drawTerrain = K.terrain.draw, drawVisibleTerrain = K.terrain.drawVisible;
  const short = (id) => (id ? String(id).slice(0, 8) : "—");
  const Rules = window.MeshRules;
  // The server decides which product this origin is (GET /api/v1/surface, read
  // from the Host header). "platform" is MineAI: project navigation and the
  // platform account. "project" is MeshBridge: sign-in and the console. A
  // standalone install has one project surface. The shell never makes one look
  // like the other, and never shares a session between them.
  const Surface = {
    loaded: false, kind: "project", split: false, platformURL: "", projectURL: "", baseURL: "", sso: false,
    get isPlatform() { return this.kind === "platform"; },
    get name() { return !this.loaded ? "" : this.isPlatform ? "MineAI" : "MeshBridge"; },
    get info() { return { kind: this.kind, split: this.split, platformURL: this.platformURL, projectURL: this.projectURL }; },
    // Headscale, agent downloads and tunnel URLs are routed on the platform
    // origin only, so the console must not derive them from its own.
    get serviceOrigin() { return this.baseURL || location.origin; },
    // t-<slug>.<domain> tunnel hosts live beside the service origin too.
    tunnelHost(sub) { const u = new URL(this.serviceOrigin); return u.protocol + "//" + sub + (u.port ? ":" + u.port : ""); },
    async load() {
      const s = await api("GET", "/api/v1/surface", null, { auth: false });
      Object.assign(this, { loaded: true, kind: s.kind === "platform" ? "platform" : "project", split: !!s.split, platformURL: s.platform_url || "",
        projectURL: s.project_url || "", baseURL: s.base_url || "", sso: !!s.sso });
    },
  };

  // Where to go after signing in. Kept for this tab only, and only for a short
  // while, so a reload on the sign-in page keeps it but a stale target never
  // surprises a later visit.
  const Resume = {
    key: "mb_resume", ttl: 30 * 60 * 1000,
    get() {
      try { const v = JSON.parse(sessionStorage.getItem(this.key) || "null"); return v && Date.now() - v.t < this.ttl ? String(v.h || "") : ""; }
      catch { return ""; }
    },
    set(hash) {
      try { if (hash) sessionStorage.setItem(this.key, JSON.stringify({ h: hash, t: Date.now() })); else sessionStorage.removeItem(this.key); }
      catch { /* storage is optional */ }
    },
    take() { const v = this.get(); this.set(""); return v; },
  };
  // The destination after a successful sign-in, validated for this surface.
  const afterSignIn = () => {
    const r = Resume.take();
    return Surface.isPlatform ? (Rules.safePlatformResume(r) || "#/") : (Rules.safeResume(r) || "#/app/overview");
  };
  const Queries = K.createQueryCache({ maxEntries: 64 });
  const cancelledQuery = () => Object.assign(new Error("Identity changed"), { name: "AbortError" });

  // Mesh keeps its API/session/hash router adapters: its /me response and
  // setup/auth flow differ from kit accounts. No Kit.start or account router.
  const Session = {
    _knownToken: store.get("token") || "", epoch: 0,
    token() {
      const token = store.get("token") || "";
      if (token !== this._knownToken) this.reset(token);
      return token;
    },
    reset(token) {
      this._knownToken = token; this.epoch++;
      this._me = undefined; this._pending = null;
      Queries.clear(); resetConsoleData();
    },
    set(tok) { store.set("token", tok || null); this.reset(store.get("token") || ""); },
    clear() { this.set(null); },
    _me: undefined,
    async me() {
      if (!this.token()) return null;
      if (this._me !== undefined) return this._me;
      if (this._pending) return this._pending;
      const epoch = this.epoch;
      const pending = (async () => {
        try {
          const me = await api("GET", "/api/v1/me", null, { quiet401: true });
          if (this.token() === "" || this.epoch !== epoch) throw cancelledQuery();
          this._me = me;
        }
        catch (e) { if (e.status !== 401) throw e; this.clear(); this._me = null; }
        return this._me;
      })();
      this._pending = pending;
      try { return await pending; }
      finally { if (this.epoch === epoch && this._pending === pending) this._pending = null; }
    },
    expired() {
      if (!this.token()) return;
      this.clear();
      Resume.set(Rules.safeResume(location.hash)); // come back to the page that expired
      flash = { panel: "login", text: t("auth.sessionExpired") };
      go("#/login", true);
    },
  };
  let flash = null;

  async function api(method, path, body, opts = {}) {
    const headers = {};
    const tok = Session.token(), epoch = Session.epoch;
    if (tok && opts.auth !== false) headers.Authorization = "Bearer " + tok;
    const init = { method, headers, cache: "no-store", signal: opts.signal };
    if (body != null) { headers["Content-Type"] = "application/json"; init.body = JSON.stringify(body); }
    let r;
    try { r = await fetch(path, init); }
    catch (e) {
      if (K.isQueryCancelled(e) || Session.token() !== tok || Session.epoch !== epoch || opts.signal?.aborted) throw cancelledQuery();
      throw new ApiError(0, "network", e.message);
    }
    let data = {};
    try { data = await r.json(); } catch { /* empty body */ }
    // An old response (including a 401) must not update or sign out a new
    // identity. Query invalidation separately handles writes in the same scope.
    if (Session.token() !== tok || Session.epoch !== epoch || opts.signal?.aborted) throw cancelledQuery();
    if (!r.ok) {
      const err = new ApiError(r.status, data.code || "", data.error || "HTTP " + r.status);
      if (r.status === 401 && tok && opts.auth !== false && !opts.quiet401) Session.expired();
      throw err;
    }
    if (method !== "GET" && method !== "HEAD") {
      // Conservative dependency invalidation: writes may affect counts,
      // audit and related lists. Keep displayed values until fresh data lands.
      Queries.invalidate((key) => key !== "health" && key !== "status");
      auditGeneration++; auditPending = null;
      if (path.startsWith("/api/v1/setup/") && !path.endsWith("/test")) Status.invalidate();
    }
    return data;
  }

  // Server errors are English strings + a code; rules.js maps them to wording.
  function errText(err, ctx) {
    const hit = Rules.errorKey(err, ctx);
    return hit ? t(hit.key, hit.params) : err.message;
  }

  function showErr(scope, msg) {
    const box = $('[data-role="err"]', scope);
    if (!box) { toast(msg, "err"); return; }
    if (!msg) { box.hidden = true; return; }
    $('[data-role="err-text"]', box).textContent = msg;
    box.hidden = false;
  }

  // ───────────────────────── Google sign-in ─────────────────────────
  // Optional and additive. The Web client ID comes from setup/status, so
  // saving it in Settings applies to the next page view without a restart; the
  // credential is verified server-side before any session exists. The block is
  // hidden when Google is not configured, and visible-but-explained when the
  // Google script cannot be reached (blocked network, offline).
  const Google = {
    cid: "", tag: null, loading: null, handler: null, prompted: false,
    ready: () => !!(window.google && google.accounts && google.accounts.id),
    load() {
      if (this.ready()) return Promise.resolve(true);
      if (this.loading) return this.loading;
      this.loading = new Promise((resolve, reject) => {
        let done = false;
        const fail = () => {
          if (done) return;
          done = true;
          this.loading = null; if (this.tag) this.tag.remove(); this.tag = null;
          reject(new Error("Google sign-in unavailable"));
        };
        if (!this.tag || !this.tag.isConnected) {
          this.tag = h("script", { src: "https://accounts.google.com/gsi/client", async: true });
          this.tag.addEventListener("error", fail, { once: true });
          document.head.append(this.tag);
        }
        const started = Date.now();
        const poll = () => {
          if (done) return;
          if (this.ready()) { done = true; resolve(true); return; }
          if (Date.now() - started > 8000) { fail(); return; }
          setTimeout(poll, 100);
        };
        poll();
      });
      return this.loading;
    },
    theme() {
      const mode = Theme.get();
      return mode === "dark" || (mode !== "light" && matchMedia("(prefers-color-scheme: dark)").matches) ? "filled_black" : "outline";
    },
    // One initialize per client ID; whichever page owns the button owns the callback.
    init(cid) {
      if (this.cid === cid) return;
      google.accounts.id.initialize({ client_id: cid, callback: (resp) => { if (this.handler) this.handler(resp); }, use_fedcm_for_prompt: true });
      this.cid = cid;
    },
    render(host) {
      const w = host.clientWidth;
      host.replaceChildren();
      google.accounts.id.renderButton(host, { theme: this.theme(), size: "large", shape: "pill", text: "signin_with", logo_alignment: "center", width: w >= 200 ? Math.min(w, 400) : undefined });
    },
    // One Tap is offered once per visit to the sign-in page, never on a re-render.
    prompt() {
      if (this.prompted) return;
      this.prompted = true;
      try { google.accounts.id.prompt(); } catch { /* One Tap is optional */ }
    },
    leave() { this.prompted = false; try { if (this.ready()) google.accounts.id.cancel(); } catch { /* optional */ } },
    signedOut() { try { if (this.ready()) google.accounts.id.disableAutoSelect(); } catch { /* optional */ } },
  };
  const gsignBox = () => $("#mb-gsign");
  function clearGoogleError() {
    const err = $('[data-role="gsign-err"]', gsignBox());
    if (err) err.hidden = true;
  }
  function googleError(err) {
    const callout = $('[data-role="gsign-err"]', gsignBox());
    if (!callout) return;
    $('[data-role="gsign-err-text"]', callout).textContent = errText(err, "google");
    callout.hidden = false;
  }
  async function onGoogleLogin(resp) {
    clearGoogleError();
    try {
      const d = await api("POST", "/api/v1/auth/google", { credential: resp.credential }, { auth: false });
      Session.set(d.token);
      go(afterSignIn());
    } catch (err) { googleError(err); }
  }
  // Re-draw only the button (theme or width changed); never prompts again.
  function redrawGoogle() {
    const box = gsignBox();
    if (!Google.ready() || !Google.cid || box.hidden || currentView !== "auth" || currentPanel !== "login") return;
    const host = $('[data-role="gsign-btn"]', box);
    if (!host.hidden) Google.render(host);
  }
  let altSeq = 0;
  // The "or continue with" block of the sign-in form: the platform account
  // (project origin only) and Google. Hidden entirely when neither applies.
  async function mountAltAuth() {
    const seq = ++altSeq, box = $("#alt-auth"), sso = $("#mb-sso"), g = gsignBox();
    const st = await Status.get();
    let ssoOn = false;
    if (Surface.sso) { try { ssoOn = !!(await K.sso.status()).enabled; } catch { /* the password form still works */ } }
    if (seq !== altSeq || currentPanel !== "login") return;
    const cid = st && st.google_client_id ? String(st.google_client_id).trim() : "";
    sso.hidden = !ssoOn;
    g.hidden = !cid;
    box.hidden = !(ssoOn || cid);
    clearGoogleError();
    if (!cid) { Google.leave(); return; }
    const host = $('[data-role="gsign-btn"]', g), unreachable = $('[data-role="gsign-load"]', g);
    unreachable.hidden = true; host.hidden = false;
    Google.handler = onGoogleLogin;
    try {
      await Google.load();
      if (seq !== altSeq || currentPanel !== "login") return;
      Google.init(cid);
      Google.render(host);
      Google.prompt();
    } catch {
      host.hidden = true; unreachable.hidden = false;
    }
  }
  on("theme", redrawGoogle);
  let gsiResize = null;
  window.addEventListener("resize", () => { clearTimeout(gsiResize); gsiResize = setTimeout(redrawGoogle, 250); });
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
    async get(force) {
      Session.token();
      try { return await Queries.get("status", (signal) => api("GET", "/api/v1/setup/status", null, { auth: false, signal }), { ttl: 20000, force }); }
      catch (err) { if (K.isQueryCancelled(err)) throw err; return Queries.peek("status") || null; }
    },
    invalidate() { Queries.invalidate("status"); },
  };

  // Shared chrome is used in the portal, auth/setup and Mesh console.
  // Language changes remain local; Mesh has no kit PATCH /me locale contract.
  function mountSharedChrome() {
    for (const host of $$("[data-lang-picker]"))
      host.replaceWith(K.chrome.langPicker({ up: "up" in host.dataset }));
    for (const b of $$("[data-theme-toggle]")) b.replaceWith(K.chrome.themeToggle());
    for (const tools of $$(".nav-tools,.auth-tools,.app-tools"))
      tools.prepend(K.chrome.projectMenu({ current: () => Surface.isPlatform ? "mineai" : "mb" }));
  }

  // ───────────────────────── views ─────────────────────────
  const VIEWS = ["landing", "auth", "app", "service"];
  let currentView = null, currentPanel = null;
  function showView(name) {
    if (currentView !== name) {
      if (name !== "app") { clearTimeout(pollTimer); pageGeneration++; }
      if (currentView === "auth") Google.leave(); // One Tap must not float over another view
      for (const v of VIEWS) $("#view-" + v).hidden = v !== name;
      currentView = name;
      window.scrollTo(0, 0);
    }
    requestAnimationFrame(drawVisibleTerrain);
    document.body.classList.add("ready");
  }
  // One place decides the tab title, so a language switch can never leave a
  // title from another product or another view behind.
  function renderTitle() {
    if (currentView === "landing") document.title = t("portal.pageTitle");
    else if (currentView === "auth") {
      const el = $(`[data-panel="${currentPanel}"] .auth-title`);
      document.title = [el ? el.textContent : "", Surface.name].filter(Boolean).join(" · ");
    } else if (currentView === "app" && App.page) setPageTitle();
    else if (currentView === "service") document.title = [t("service.title"), Surface.name].filter(Boolean).join(" · ");
  }

  // The surface decides copy, brand and the way back to the platform. Applied
  // once the server has answered, before anything is routed.
  function applySurface() {
    document.documentElement.dataset.surface = Surface.kind;
    for (const el of $$("[data-surface-brand]")) el.textContent = Surface.name;
    for (const el of $$("[data-i18n-platform]")) el.dataset.i18n = Surface.isPlatform ? el.dataset.i18nPlatform : el.dataset.i18nProject;
    const back = Surface.split && !Surface.isPlatform && Surface.platformURL;
    for (const a of $$("[data-platform-home]")) { a.hidden = !back; if (back) a.href = Surface.platformURL + "/"; }
    for (const a of $$("[data-project-link='mb']")) if (Surface.projectURL) a.href = Surface.projectURL + "/";
    // The footer of the sign-in pages: home on the platform, the platform from
    // the project, nothing on a standalone install.
    const foot = $("#auth-foot-link");
    foot.hidden = !Surface.isPlatform && !back;
    foot.href = Surface.isPlatform ? "#/" : back ? Surface.platformURL + "/" : "#/";
    foot.dataset.i18n = Surface.isPlatform ? "common.backHome" : "mb.backToPlatform";
    I18N.apply(document);
    describeSite();
  }
  // The search-engine description names the product of this origin.
  function describeSite() {
    const desc = $('meta[name="description"]');
    if (desc) desc.setAttribute("content", t(Surface.isPlatform ? "portal.lede" : "meta.description"));
  }

  // ── platform landing: project navigation and the platform account only
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
  }
  function scrollToSection(id) {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: reduceMotion.matches ? "auto" : "smooth", block: "start" });
  }
  async function platformSignOut() {
    try { await api("POST", "/api/v1/auth/logout", {}, { quiet401: true }); }
    catch (err) { if (err.status !== 401) { toast(errText(err), "err"); return; } }
    Google.signedOut();
    Session.clear(); Resume.set("");
    void renderAccount();
  }
  // Sign in, or who is signed in with a way out. A fault shows neither: the
  // visitor is not told they are signed out when the server merely stumbled.
  async function renderAccount() {
    const host = $("#acct");
    const token = Session.token(), epoch = Session.epoch;
    let me = null, fault = false;
    if (token) {
      try { me = await Session.me(); }
      catch (e) { if (K.isQueryCancelled(e)) return; fault = true; }
    }
    if (currentView !== "landing" || Session.token() !== token || Session.epoch !== epoch) return;
    if (me) {
      const out = h("button", { class: "icon-btn", type: "button", "data-i18n-attr": "aria-label:common.signOut;title:common.signOut" }, icon("logout"));
      out.addEventListener("click", platformSignOut);
      host.replaceChildren(
        h("span", { class: "acct-chip", title: me.username }, h("span", { class: "avatar sm" }, (me.username || "?").slice(0, 1)), h("span", { class: "acct-name" }, me.username)),
        out);
      I18N.apply(host);
    } else if (fault) {
      const retry = h("button", { class: "btn btn-quiet btn-sm", type: "button" }, icon("refresh"), h("span", { i18n: "common.retry" }));
      retry.addEventListener("click", () => { Session._me = undefined; void renderAccount(); });
      host.replaceChildren(retry);
    } else {
      host.replaceChildren(h("a", { class: "btn btn-outline btn-sm", href: "#/login" }, icon("user"), h("span", { class: "acct-label", i18n: "common.signIn" })));
    }
  }
  function applyRegistrationGate(st) {
    const open = !st || st.allow_registration !== false;
    $$("[data-reg-link]").forEach((el) => (el.hidden = !open));
  }
  async function showLanding(anchor) {
    initLanding();
    showView("landing");
    currentPanel = null;
    renderTitle();
    void renderAccount();
    if (anchor) setTimeout(() => scrollToSection(anchor), 60);
  }

  // ── a server that cannot answer: retryable, and never a sign-out
  function showFault(error) {
    showView("service");
    currentPanel = null;
    K.tl($("#service-text"), error && (error.status === 0 || error.code === "network") ? "service.textNetwork" : "service.text");
    renderTitle();
  }

  // ── auth panels
  const ART = {
    platform: { kicker: "art.kickerPlatform", title: "auth.panelTitle", p: ["auth.panelP1", "auth.panelP2", "auth.panelP3"] },
    project: { kicker: "art.kickerProject", title: "mb.art.title", p: ["mb.art.p1", "mb.art.p2", "mb.art.p3"] },
    setup: { kicker: "art.kickerProject", title: "setup.panelTitle", p: ["setup.panelP1", "setup.panelP2", "setup.panelP3"] },
  };
  function setArt(kind) {
    const art = ART[kind];
    ["kicker", "title", "p1", "p2", "p3"].forEach((slot, i) => K.tl($(`[data-art="${slot}"]`), [art.kicker, art.title, ...art.p][i]));
  }
  async function showAuth(panel) {
    const st = await Status.get();
    showView("auth");
    for (const sec of $$("[data-panel]")) sec.hidden = sec.dataset.panel !== panel;
    setArt(panel === "setup" ? "setup" : Surface.isPlatform ? "platform" : "project");
    currentPanel = panel;
    const sec = $(`[data-panel="${panel}"]`);
    renderTitle();
    if (panel !== "login") { altSeq++; Google.leave(); }
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
      showErr($("#form-login"), "");
      void mountAltAuth();
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
          go(afterSignIn());
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
          go(afterSignIn());
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
    const origin = Surface.serviceOrigin, key = r.preauth_key || "<PREAUTH_KEY>";
    const tok = r.agent_token, id = r.device_id, host = r.hostname;
    const dl = origin + "/dl";
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
        ["", `Invoke-WebRequest -Uri "${dl}/meshbridge-agent-windows-amd64.exe" -OutFile "meshbridge-agent.exe"`],
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
    const sum = os === "macos" ? "shasum -a 256 -c -" : "sha256sum -c -";
    return [
      c(1, "enroll.c1"), ...ts,
      ["", `sudo tailscale up --login-server ${origin} --hostname ${host} --authkey ${key}`],
      ["", ""], c(2, "enroll.c2"),
      ["", "sudo install -d -m 700 /etc/meshbridge"],
      ["", `printf '%s\\n' '${tok}' | sudo tee /etc/meshbridge/agent.token >/dev/null`],
      ["", "sudo chmod 600 /etc/meshbridge/agent.token"],
      ["", ""], c(3, "enroll.c3"),
      ["", 'ARCH=$(uname -m); case "$ARCH" in x86_64) A=amd64;; aarch64|arm64) A=arm64;; *) echo "unsupported: $ARCH"; exit 1;; esac'],
      ["", `curl -fL -o "meshbridge-agent-${os}-$A" "${dl}/meshbridge-agent-${os}-$A"`],
      ["", `grep "meshbridge-agent-${os}-$A" <(curl -fsSL "${dl}/SHA256SUMS") | ${sum}`],
      ...bin,
      ["", `sudo install -m 755 "meshbridge-agent-${os}-$A" /usr/local/bin/meshbridge-agent`],
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
    const copyCmd = h("button", { class: "copy-btn", type: "button" }, icon("copy"), h("span", { i18n: "common.copy" }));
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
    const ctl = { reset() {
      result = null; out.hidden = true; f.reset(); showErr(f, "");
      for (const role of ["token", "preauth", "cmd", "id", "reg"]) $('[data-role="' + role + '"]', host).textContent = "";
    }, focus() { f.host.focus(); } };
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
  let modalEnroll = null, modalTunnel = null;
  function openFeature(name) {
    if (name === "enroll") {
      if (!modalEnroll) modalEnroll = mountEnroll($('[data-mount="enroll-modal"]'));
      modalEnroll.reset();
      openModal("modal-enroll");
    } else if (name === "transfer") openTransferModal();
    else if (name === "tunnel") {
      if (!modalTunnel) modalTunnel = mountTunnel();
      modalTunnel.reset();
      openModal("modal-tunnel");
    }
  }

  // ── tunnel create modal ──
  function mountTunnel() {
    const m = $("#modal-tunnel");
    const f = $("#form-tunnel"), out = $('[data-role="tun-out"]', m), need = $('[data-role="need"]', f), btn = $("[type=submit]", f);
    const fillDevices = () => {
      const devs = D.devices || [];
      need.hidden = !!devs.length;
      const sel = f.elements.device;
      sel.replaceChildren(...devs.map((d) => h("option", { value: d.id }, d.hostname)));
      if (devs.length === 1) sel.value = devs[0].id;
    };
    out.addEventListener("click", (e) => {
      const c = e.target.closest("[data-copy]");
      if (c) copyText($(`[data-role="${c.dataset.copy}"]`, out).textContent, c);
    });
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      showErr(f, "");
      const el = f.elements;
      const port = parseInt(el.port.value, 10);
      if (!el.device.value) { showErr(f, t("err.pickDevices")); return; }
      if (!Number.isInteger(port) || port < 1 || port > 65535) { showErr(f, t("tun.badPort")); el.port.focus(); return; }
      await busy(btn, async () => {
        try {
          const d = await api("POST", "/api/v1/tunnels", {
            device_id: el.device.value,
            name: el.name.value.trim(),
            target_scheme: el.scheme.value,
            target_host: el.host.value.trim() || "127.0.0.1",
            target_port: port,
            key_required: el.keyRequired.value === "1",
            sandbox: el.sandbox.value === "1",
          });
          const tun = d.tunnel;
          const pathEl = $('[data-role="url-path"]', out);
          pathEl.href = Surface.serviceOrigin + tun.url_path;
          pathEl.textContent = Surface.serviceOrigin + tun.url_path;
          const subEl = $('[data-role="url-sub"]', out);
          const subBlock = $('[data-role="sub-block"]', out);
          if (tun.url_subdomain) {
            const sub = Surface.tunnelHost(tun.url_subdomain);
            subBlock.hidden = false;
            subEl.href = sub;
            subEl.textContent = sub;
          } else subBlock.hidden = true;
          $('[data-role="key"]', out).textContent = d.access_key || "—";
          out.hidden = false;
          f.hidden = true;
          toast(t("tun.success"));
          D.tunnels = null;
        } catch (err) { showErr(f, errText(err)); }
      });
    });
    return {
      reset() {
        f.reset(); f.hidden = false; out.hidden = true; showErr(f, "");
        fillDevices();
        const firstInput = $("input,select", f);
        if (firstInput) setTimeout(() => firstInput.focus(), 30);
      },
    };
  }

  // ───────────────────────── console data ─────────────────────────
  const freshData = () => ({ devices: null, transfers: null, tunnels: null, relays: null, audit: [], auditPage: 0, auditDone: false, health: null, healthErr: false, projects: null, smtp: null, pendingKey: null });
  const D = freshData(), dataVersions = {}, dataErrors = {}, renderKeys = new Map();
  let auditPending = null, auditGeneration = 0, pageGeneration = 0;
  function resetConsoleData() {
    Object.assign(D, freshData());
    for (const key of Object.keys(dataVersions)) delete dataVersions[key];
    for (const key of Object.keys(dataErrors)) delete dataErrors[key];
    renderKeys.clear(); auditPending = null; auditGeneration++; pageGeneration++;
    clearTimeout(pollTimer);
    App.me = null; App.page = null; App.filters = { dev: "all", tr: "all" };
    for (const form of $$("form", $("#view-app"))) form.reset();
    if (currentView === "app") { $("#view-app").hidden = true; currentView = null; }
    for (const selector of [...Object.values(LIST_HOSTS), "#ov-transfers", "#ov-activity"]) $(selector).replaceChildren();
    for (const selector of ["#dev-q", "#audit-q"]) $(selector).value = "";
    for (const button of $$("#dev-filter button,#tr-filter button")) button.setAttribute("aria-pressed", String(button.dataset.f === "all"));
    for (const enroller of enrollers) enroller.reset();
    for (const modal of $$(".modal")) {
      modal.hidden = true;
      for (const form of $$("form", modal)) form.reset();
      for (const secret of $$('[data-role="key"]', modal)) secret.textContent = "";
    }
    document.body.classList.remove("modal-open"); modalReturn = null;
  }
  function assignData(key, value) {
    if (JSON.stringify(D[key]) !== JSON.stringify(value)) {
      D[key] = value; dataVersions[key] = (dataVersions[key] || 0) + 1;
    }
    return D[key];
  }
  function shouldPaint(key, values) {
    const signature = JSON.stringify([I18N.lang, ...values]);
    if (renderKeys.get(key) === signature) return false;
    renderKeys.set(key, signature); return true;
  }
  async function readQuery(key, path, ttl, force = false, auth = true, commit = (data) => data) {
    Session.token();
    const epoch = Session.epoch;
    const data = await Queries.get(key, (signal) => api("GET", path, null, { signal, auth }), { ttl, force });
    Session.token();
    if (Session.epoch !== epoch || Queries.peek(key) !== data) throw cancelledQuery();
    // Commit in this same turn: even the microtask gap between two awaits
    // could otherwise let a just-resolved old response cross an account switch.
    return commit(data);
  }
  const ACTIVE = new Set(["QUEUED", "PROBING", "WAITING_FOR_ROUTE", "TRANSFERRING", "PAUSED", "VERIFYING"]);
  const load = {
    devices(force) { return readQuery("devices", "/api/v1/devices?limit=200", 15000, force, true, (data) => { assignData("devices", data.items || []); updateCounts(); return D.devices; }); },
    transfers(force) { return readQuery("transfers", "/api/v1/transfers?limit=200", 5000, force, true, (data) => { assignData("transfers", data.items || []); updateCounts(); return D.transfers; }); },
    tunnels(force) { return readQuery("tunnels", "/api/v1/tunnels", 30000, force, true, (data) => assignData("tunnels", data.items || [])); },
    relays(force) { return readQuery("relays", "/api/v1/relays", 30000, force, true, (data) => assignData("relays", data.items || [])); },
    projects(force) { return readQuery("projects", "/api/v1/projects?limit=200", 30000, force, true, (data) => assignData("projects", data.items || [])); },
    async health() {
      Session.token(); const epoch = Session.epoch;
      try { await readQuery("health", "/api/v1/health", 15000, false, false, (data) => { assignData("health", data); D.healthErr = false; renderHealth(); }); }
      catch (err) { if (K.isQueryCancelled(err) || Session.epoch !== epoch) throw cancelledQuery(); D.healthErr = true; renderHealth(); }
    },
    async audit(reset = false, force = false) {
      Session.token();
      if (auditPending && (!reset || auditPending.reset)) return auditPending.promise;
      if (!reset && D.auditDone) return D.audit;
      if (reset && auditPending) Queries.invalidate((key) => key.startsWith("audit:"));
      const generation = ++auditGeneration, epoch = Session.epoch;
      const page = reset ? 1 : D.auditPage + 1, limit = 50;
      const pending = { reset };
      pending.promise = readQuery("audit:" + page, `/api/v1/audit?limit=${limit}&page=${page}`, 15000, force, true, (data) => {
        const items = data.items || [];
        if (epoch !== Session.epoch || generation !== auditGeneration) throw cancelledQuery();
        // A no-change poll keeps expanded pages, instead of collapsing the
        // reader back to page one. Failed refreshes also keep the old list.
        if (reset && D.auditPage > 1 && JSON.stringify(D.audit.slice(0, limit)) === JSON.stringify(items)) return D.audit;
        assignData("audit", reset ? items : D.audit.concat(items));
        D.auditPage = page; D.auditDone = items.length < limit;
        if (reset) Queries.invalidate((key) => key.startsWith("audit:") && key !== "audit:1");
        return D.audit;
      });
      auditPending = pending;
      try { return await pending.promise; }
      finally { if (auditPending === pending) auditPending = null; }
    },
    smtp(force) { return readQuery("smtp", "/api/v1/setup/smtp", 15000, force, true, (data) => assignData("smtp", data)); },
  };
  const hostOf = (id) => { const d = (D.devices || []).find((x) => x.id === id); return d ? d.hostname : short(id); };
  function updateCounts() {
    const dc = $('[data-count="devices"]'), tc = $('[data-count="transfers"]');
    dc.textContent = D.devices && D.devices.length ? fmt.num(D.devices.length) : "";
    const n = (D.transfers || []).filter((x) => ACTIVE.has(x.state)).length;
    tc.textContent = n ? fmt.num(n) : "";
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
  function tunnelPill(x) {
    if (x.status === "disabled") return h("span", { class: "pill" }, h("span", { class: "dot" }), t("app.tunnels.statusDisabled"));
    if (x.status === "quota_exceeded") return h("span", { class: "pill warn" }, h("span", { class: "dot" }), t("app.tunnels.statusQuota"));
    if (x.online) return h("span", { class: "pill ok live" }, h("span", { class: "dot" }), t("status.online"));
    return h("span", { class: "pill info" }, h("span", { class: "dot" }), t("status.pending"));
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
  // ───────────────────────── console pages ─────────────────────────
  const App = { page: null, me: null, filters: { dev: "all", tr: "all" } };
  const isAdmin = () => App.me && App.me.role === "admin";
  const LIST_HOSTS = { devices: "#dev-table", transfers: "#tr-table", tunnels: "#tu-table", relays: "#relay-list", audit: "#audit-table" };
  const hasPageData = (name) => name === "audit" ? D.auditPage > 0 : D[name] !== null;
  const pageCurrent = (name, generation, epoch) => currentView === "app" && App.page === name && pageGeneration === generation && Session.epoch === epoch;
  async function refreshList(name, keys, quiet = false, force = false) {
    const generation = pageGeneration, epoch = Session.epoch;
    const current = () => pageCurrent(name, generation, epoch);
    // Paint a previously loaded list synchronously, before any network wait.
    if (current()) PAGES[name].render();
    await Promise.allSettled(keys.map(async (key) => {
      try {
        await (key === "audit" ? load.audit(true, force) : load[key](key === name && force));
        if (Session.epoch !== epoch) return;
        delete dataErrors[key];
      } catch (err) {
        if (K.isQueryCancelled(err) || !current()) return;
        dataErrors[key] = errText(err);
        if (!quiet && hasPageData(name)) toast(dataErrors[key], "err");
      }
      if (current()) PAGES[name].render();
    }));
  }

  const PAGES = {
    overview: {
      title() {
        const hr = new Date().getHours();
        const k = hr >= 5 && hr < 12 ? "titleMorning" : hr >= 12 && hr < 18 ? "titleAfternoon" : "titleEvening";
        return t("app.overview." + k, { name: App.me ? App.me.username : "" });
      },
      async refresh(quiet = false, force = false) {
        const generation = pageGeneration, epoch = Session.epoch;
        const current = () => pageCurrent("overview", generation, epoch);
        if (current()) this.render();
        const keys = ["health", "devices", "transfers", "relays", "audit"];
        if (isAdmin()) keys.push("smtp");
        await Promise.allSettled(keys.map(async (key) => {
          try { await (key === "audit" ? load.audit(true, force) : load[key](force)); if (Session.epoch !== epoch) return; delete dataErrors[key]; }
          catch (err) { if (K.isQueryCancelled(err) || !current()) return; dataErrors[key] = errText(err); }
          // Each module can update while unrelated slow requests are pending.
          if (current()) this.render();
        }));
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
        else stat("st-devices", "—", "", dataErrors.devices || t("common.loading"));
        if (D.transfers) { const act = trs.filter((x) => ACTIVE.has(x.state)).length; stat("st-transfers", fmt.num(act), "", t("app.overview.transfersNote", { n: trs.length, count: fmt.num(trs.length) })); }
        else stat("st-transfers", "—", "", dataErrors.transfers || t("common.loading"));
        if (D.relays) {
          const ok = rel.filter((r) => r.healthy).length;
          if (rel.length) stat("st-relays", fmt.num(ok), fmt.num(rel.length), t("app.overview.relaysNote"));
          else stat("st-relays", "—", "", t("app.overview.relaysNone"));
        }
        else stat("st-relays", "—", "", dataErrors.relays || t("common.loading"));
        if (D.healthErr) stat("st-control", t("app.overview.controlDown"), "", t("app.health.offline"), "bad");
        else if (D.health) {
          const ok = D.health.headscale === "ok";
          stat("st-control", t(ok ? "app.overview.controlOk" : "app.overview.controlBad"), "", t(ok ? "app.health.hsOk" : "app.health.hsDown"), ok ? "ok" : "bad");
        }
        else stat("st-control", "—", "", t("app.health.checking"));
        // recent transfers
        if (shouldPaint("ov-transfers", [dataVersions.transfers, dataVersions.devices, dataErrors.transfers])) {
        const tl = $("#ov-transfers");
        tl.replaceChildren();
        if (!trs.length) tl.append(h("li", { class: "list-empty" }, D.transfers ? t("app.overview.noTransfers") : dataErrors.transfers || t("common.loading")));
        for (const x of trs.slice(0, 5)) {
          const ratio = x.bytes_total ? Math.min(1, x.bytes_done / x.bytes_total) : x.state === "COMPLETED" ? 1 : 0;
          const tone = x.state === "FAILED" ? "clay" : x.state === "COMPLETED" ? "moss" : "slate";
          tl.append(h("li", null,
            h("span", { class: "feed-dot " + tone }, icon("transfer")),
            h("div", { class: "li-main" }, h("div", { class: "li-title" }, hostOf(x.src) + "  →  " + hostOf(x.dst)),
              h("div", { class: "li-sub" }, t("state." + x.state) + " · " + routeLabel(x.route))),
            h("span", { class: "li-end" }, x.bytes_total ? fmt.pct(ratio) : "")));
        }
        }
        // activity
        if (shouldPaint("ov-activity", [dataVersions.audit, D.auditPage, dataErrors.audit, Math.floor(Date.now() / 60000)])) {
        const al = $("#ov-activity");
        al.replaceChildren();
        if (!D.audit.length) al.append(h("li", { class: "list-empty" }, D.auditPage ? t("app.overview.noActivity") : dataErrors.audit || t("common.loading")));
        for (const a of D.audit.slice(0, 6)) {
          const ev = eventInfo(a.event);
          al.append(h("li", null,
            h("span", { class: "feed-dot " + ev.tone }, icon(ev.icon)),
            h("div", { class: "li-main" }, h("div", { class: "li-title" }, ev.label), h("div", { class: "li-sub" }, [a.actor, eventDetail(a)].filter(Boolean).join(" · "))),
            h("span", { class: "li-end", title: fmt.abs(a.ts) }, fmt.rel(a.ts))));
        }
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
      refresh(quiet, force) { return refreshList("devices", ["devices"], quiet, force); },
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
      refresh(quiet, force) { return refreshList("transfers", ["transfers", "devices"], quiet, force); },
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

    tunnels: {
      interval: () => 30000,
      refresh(quiet, force) { return refreshList("tunnels", ["tunnels", "devices"], quiet, force); },
      render() {
        const host = $("#tu-table"), all = D.tunnels || [];
        host.replaceChildren();
        if (D.pendingKey) {
          const dismiss = h("button", { class: "btn btn-quiet btn-xs", type: "button" }, t("common.close"));
          dismiss.addEventListener("click", () => { D.pendingKey = null; PAGES.tunnels.render(); });
          host.append(h("div", { class: "panel" },
            h("div", { class: "kv-block" },
              h("span", { class: "label" }, t("app.tunnels.newKeyNote")),
              h("div", { class: "secret-row" },
                h("span", { class: "mono hot" }, D.pendingKey.key),
                inlineCopy(D.pendingKey.key, "common.copy"),
                dismiss))));
        }
        if (!all.length) {
          const can = (D.devices || []).length >= 1;
          host.append(emptyState({
            icon: "globe", seed: 21, title: t("app.tunnels.emptyTitle"),
            text: can ? t("app.tunnels.emptyText") : t("app.tunnels.emptyNeedDevice"),
            action: can ? h("button", { class: "btn btn-primary", type: "button", "data-open": "tunnel" }, icon("plus"), t("app.tunnels.new")) : null,
          }));
          return;
        }
        host.append(table(
          [{ label: t("app.tunnels.colTunnel") }, { label: t("app.tunnels.colUrl") }, { label: t("app.tunnels.colStatus") }, { label: t("app.tunnels.colTraffic") }, { label: t("common.actions"), cls: "nowrap" }],
          all.map((x) => {
            const ratio = x.monthly_quota_bytes ? Math.min(1, x.bytes_in_month / x.monthly_quota_bytes) : 0;
            const bar = h("div", { class: "progress" + (ratio > 0.95 ? " err" : ratio > 0.8 ? " warn" : "") }, h("i"));
            bar.firstChild.style.setProperty("--p", (ratio * 100).toFixed(1) + "%");
            const url = Surface.serviceOrigin + x.url_path;
            const toggle = h("button", { class: "btn btn-outline btn-xs", type: "button" }, t(x.status === "disabled" ? "app.tunnels.actionEnable" : "app.tunnels.actionDisable"));
            toggle.addEventListener("click", () => busy(toggle, async () => {
              try {
                await api("PATCH", "/api/v1/tunnels/" + x.id, { status: x.status === "disabled" ? "active" : "disabled" });
                toast(t("app.tunnels.updated")); await load.tunnels(); this.render();
              } catch (err) { toast(errText(err), "err"); }
            }));
            const rotate = h("button", { class: "btn btn-outline btn-xs", type: "button" }, t("app.tunnels.actionRotate"));
            rotate.addEventListener("click", () => busy(rotate, async () => {
              try {
                const d = await api("POST", `/api/v1/tunnels/${x.id}/rotate-key`);
                D.pendingKey = { key: d.access_key }; await load.tunnels(); this.render();
              } catch (err) { toast(errText(err), "err"); }
            }));
            const del = h("button", { class: "btn btn-quiet btn-xs", type: "button" }, t("app.tunnels.actionDelete"));
            del.addEventListener("click", () => {
              if (!window.confirm(t("app.tunnels.deleteConfirm", { name: x.name || x.slug.slice(0, 8) }))) return;
              busy(del, async () => {
                try {
                  await api("DELETE", "/api/v1/tunnels/" + x.id);
                  toast(t("app.tunnels.deleted")); await load.tunnels(); this.render();
                } catch (err) { toast(errText(err), "err"); }
              });
            });
            return [
              [h("div", { class: "primary" }, x.name || t("app.tunnels.unnamed")), h("div", { class: "sub" }, h("span", { class: "tag-mono" }, x.device_hostname || short(x.device_id)), " · ", h("span", { class: "mono" }, x.target))],
              [h("a", { class: "mono link", href: url, target: "_blank", rel: "noopener" }, x.url_path), inlineCopy(url, "app.tunnels.copyUrl"),
                x.url_subdomain ? h("div", { class: "sub" }, h("a", { class: "mono link", href: Surface.tunnelHost(x.url_subdomain), target: "_blank", rel: "noopener" }, Surface.tunnelHost(x.url_subdomain))) : null],
              [tunnelPill(x), x.key_required ? h("div", { class: "sub" }, icon("key"), " ", t("app.tunnels.keyOn")) : h("div", { class: "sub" }, t("app.tunnels.keyOff"))],
              h("div", { class: "prog" }, bar, h("div", { class: "prog-meta" }, h("span", null, t("app.tunnels.usageOf", { used: fmt.bytes(x.bytes_in_month), quota: fmt.bytes(x.monthly_quota_bytes) })))),
              h("div", { class: "row-actions" }, toggle, rotate, del),
            ];
          })));
      },
    },

    relays: {
      interval: () => 30000,
      refresh(quiet, force) { return refreshList("relays", ["relays"], quiet, force); },
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
      refresh(quiet, force) { return refreshList("audit", ["audit"], quiet, force); },
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
        const generation = pageGeneration, epoch = Session.epoch;
        this.render();
        void loadGoogleLink(generation, epoch);
        if (!isAdmin()) return;
        void loadGoogleSettings(generation, epoch);
        if (!this.smtp) this.smtp = mountSmtp($('[data-mount="smtp-settings"]'), "settings");
        const [smtp, st, tun] = await Promise.all([
          load.smtp().catch(() => null),
          Status.get(true),
          readQuery("tunnel-settings", "/api/v1/tunnels/settings", 30000).catch(() => null),
        ]);
        if (!pageCurrent("settings", generation, epoch)) return;
        if (smtp) this.smtp.fill(smtp);
        setSmtpPill(smtp && smtp.configured);
        if (st) $("#set-reg").setAttribute("aria-checked", String(!!st.allow_registration));
        if (tun) {
          $("#set-tunnels").setAttribute("aria-checked", String(!!tun.enabled));
          $("#set-tun-budget").value = tun.global_monthly_bytes || "";
          $("#set-tun-rate").value = tun.rate_per_min || "";
        }
      },
      render() {
        const me = App.me || {};
        $("#acc-name").textContent = me.username || "—";
        $("#acc-email").textContent = me.email || "—";
        $("#acc-role").textContent = me.role === "admin" ? t("common.admin") : t("common.member");
        $("#logout-platform").hidden = !me.sso;
        renderGoogleSettings();
        const sel = $("#set-lang");
        if (!sel.options.length) for (const l of LANGS) sel.append(h("option", { value: l.code, lang: l.code }, l.name));
        sel.value = I18N.lang;
        for (const b of $$("#set-theme button")) b.setAttribute("aria-pressed", String(b.dataset.v === Theme.get()));
      },
    },
  };
  // Keep table nodes (and their focus/selection) when a refresh contains no
  // changes. Locale, filters, dependency changes and relative-time ticks still
  // repaint. Initial errors stay distinguishable from genuinely empty lists.
  for (const [name, selector] of Object.entries(LIST_HOSTS)) {
    const page = PAGES[name], render = page.render;
    const deps = name === "transfers" || name === "tunnels" ? [name, "devices"] : [name];
    page.render = function () {
      const query = name === "devices" ? $("#dev-q").value : name === "audit" ? $("#audit-q").value : "";
      if (!shouldPaint(name, [deps.map((key) => dataVersions[key]), dataErrors[name], hasPageData(name),
        App.me && App.me.role, App.filters, query, D.pendingKey && D.pendingKey.key,
        name === "audit" ? [D.auditPage, D.auditDone] : null, Math.floor(Date.now() / 60000)])) return;
      const host = $(selector);
      if (!hasPageData(name)) {
        if (!dataErrors[name]) { host.replaceChildren(loadingRows(name === "audit" ? 6 : 4)); return; }
        const retry = h("button", { class: "btn btn-outline", type: "button" }, t("common.retry"));
        retry.addEventListener("click", () => busy(retry, () => page.refresh(false, true)));
        host.replaceChildren(emptyState({ icon: "alert", title: dataErrors[name], action: retry }));
        return;
      }
      render.call(this);
    };
  }
  function setSmtpPill(on_) {
    const p = $("#smtp-status");
    p.className = "pill " + (on_ ? "ok" : "warn");
    p.replaceChildren(h("span", { class: "dot" }), h("span", { i18n: on_ ? "smtp.statusOn" : "smtp.statusOff" }));
  }
  on("smtp", () => { setSmtpPill(true); if (D.smtp) assignData("smtp", { ...D.smtp, configured: true }); });

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
    "tunnel created": ["event.tunnelCreated", "globe", "moss"],
    "tunnel updated": ["event.tunnelUpdated", "settings", "slate"],
    "tunnel deleted": ["event.tunnelDeleted", "globe", "clay"],
    "tunnel key rotated": ["event.tunnelKeyRotated", "key", "slate"],
    "tunnel agent online": ["event.tunnelAgentOnline", "globe", "moss"],
    "tunnel agent offline": ["event.tunnelAgentOffline", "globe", "slate"],
    "tunnel quota warning": ["event.tunnelQuotaWarn", "alert", "clay"],
    "tunnel quota exceeded": ["event.tunnelQuotaExceeded", "alert", "clay"],
    "tunnel global budget exceeded": ["event.tunnelBudget", "alert", "clay"],
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

  // ── Google: the administrator's configuration and the member's own link
  // The configuration card reports where the client ID comes from, whether a
  // change applies at once, and which origins Google Cloud must authorize.
  const GoogleCfg = { cfg: null };
  async function loadGoogleSettings(generation, epoch) {
    let cfg;
    try { cfg = await api("GET", "/api/v1/setup/google"); } catch { return; }
    if (!pageCurrent("settings", generation, epoch)) return;
    GoogleCfg.cfg = cfg;
    renderGoogleSettings();
  }
  function renderGoogleSettings() {
    const cfg = GoogleCfg.cfg;
    if (!cfg) return;
    const input = $("#set-google-client");
    if (document.activeElement !== input) input.value = cfg.client_id || "";
    const pill = $("#gset-status");
    pill.className = "pill " + (cfg.configured ? "ok" : "warn");
    pill.replaceChildren(h("span", { class: "dot" }), h("span", { i18n: cfg.configured ? "gset.on" : "gset.off" }));
    const source = cfg.source === "settings" ? (cfg.configured ? "gset.srcSettings" : cfg.env_set ? "gset.srcDisabled" : "gset.srcNone")
      : cfg.source === "environment" ? "gset.srcEnv" : "gset.srcNone";
    K.tl($("#gset-source"), source);
    const origins = cfg.origins || [];
    $("#gset-origins").replaceChildren(...origins.map((o) => h("li", null, h("code", { class: "mono" }, o), inlineCopy(o, "common.copy"))));
    $("#gset-origins-block").hidden = !origins.length;
  }

  const GLink = { linked: false, configured: false };
  async function loadGoogleLink(generation, epoch) {
    let st;
    try { st = await api("GET", "/api/v1/me/google"); } catch { $("#glink-row").hidden = true; return; }
    if (!pageCurrent("settings", generation, epoch)) return;
    Object.assign(GLink, { linked: !!st.linked, configured: !!st.configured });
    await renderGoogleLink();
  }
  function glinkError(err) {
    const box = $("#glink-err");
    box.hidden = !err;
    if (err) $("#glink-err-text").textContent = errText(err, "google");
  }
  async function onGoogleLink(resp) {
    glinkError(null);
    try {
      await api("PUT", "/api/v1/me/google", { credential: resp.credential });
      GLink.linked = true;
      toast(t("glink.done"));
      await renderGoogleLink();
    } catch (err) { glinkError(err); }
  }
  async function renderGoogleLink() {
    const row = $("#glink-row"), host = $('[data-role="glink-btn"]', row), unlink = $("#glink-unlink");
    row.hidden = !(GLink.configured || GLink.linked);
    if (row.hidden) return;
    K.tl($("#glink-state"), GLink.linked ? "glink.linked" : "glink.desc");
    unlink.hidden = !GLink.linked;
    host.hidden = GLink.linked || !GLink.configured;
    if (host.hidden) return;
    try {
      await Google.load();
      const st = await Status.get(), cid = st && st.google_client_id ? String(st.google_client_id).trim() : "";
      if (!cid || currentView !== "app" || App.page !== "settings") return;
      Google.init(cid);
      Google.handler = onGoogleLink;
      Google.render(host);
    } catch { glinkError({ status: 0, code: "google_unreachable", message: "" }); $("#glink-err-text").textContent = t("err.google.load"); }
  }

  // ── console shell
  let consoleReady = false, pollTimer = null, closeDrawer = () => {};
  function initConsole() {
    if (consoleReady) return;
    consoleReady = true;
    const view = $("#view-app"), menuBtn = $("#btn-menu");
    // The mobile drawer: Esc and the scrim close it, focus follows, the page
    // behind does not scroll, and resizing to desktop releases all of it.
    const drawer = (open) => {
      view.classList.toggle("nav-open", open);
      document.body.classList.toggle("nav-lock", open);
      menuBtn.setAttribute("aria-expanded", String(open));
      if (open) { const first = $("#sidebar .sb-nav a[aria-current]") || $("#sidebar .sb-nav a"); if (first) first.focus(); }
      else if ($("#sidebar").contains(document.activeElement)) menuBtn.focus();
    };
    closeDrawer = () => { if (view.classList.contains("nav-open")) drawer(false); };
    menuBtn.setAttribute("aria-controls", "sidebar");
    menuBtn.setAttribute("aria-expanded", "false");
    menuBtn.addEventListener("click", () => drawer(true));
    $$("[data-nav-close]").forEach((el) => el.addEventListener("click", () => drawer(false)));
    $("#sidebar").addEventListener("click", (e) => { if (e.target.closest("a[href]")) drawer(false); });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && view.classList.contains("nav-open") && $$(".modal").every((m) => m.hidden)) { e.preventDefault(); drawer(false); }
    });
    matchMedia("(min-width: 981px)").addEventListener("change", (e) => { if (e.matches) closeDrawer(); });
    const top = $("#app-top");
    window.addEventListener("scroll", () => top.classList.toggle("is-scrolled", window.scrollY > 4), { passive: true });
    const logout = async () => {
      try { await api("POST", "/api/v1/auth/logout", {}, { quiet401: true }); }
      catch (err) { if (err.status !== 401) { toast(errText(err), "err"); return; } }
      Google.signedOut();
      Resume.set("");
      Session.clear();
      go("#/", true);
    };
    $("#btn-logout").addEventListener("click", logout);
    $$("[data-logout]").forEach((b) => b.addEventListener("click", logout));
    // A session that came from the platform may also end the platform session:
    // revoke this project session first, then continue to the platform sign-out.
    $("#logout-platform").addEventListener("click", (e) => busy(e.currentTarget, async () => {
      try { Google.signedOut(); Resume.set(""); await K.sso.signOut(); }
      catch (err) { toast(errText(err), "err"); }
    }));
    $("#glink-unlink").addEventListener("click", (e) => {
      if (!window.confirm(t("glink.unlinkConfirm"))) return;
      busy(e.currentTarget, async () => {
        glinkError(null);
        try { await api("DELETE", "/api/v1/me/google"); GLink.linked = false; toast(t("glink.removed")); await renderGoogleLink(); }
        catch (err) { glinkError(err); }
      });
    });
    $("#dev-q").addEventListener("input", () => PAGES.devices.render());
    $("#audit-q").addEventListener("input", () => PAGES.audit.render());
    $("#audit-refresh").addEventListener("click", (e) => busy(e.currentTarget, () => PAGES.audit.refresh(false, true)));
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
    $("#set-google-save").addEventListener("click", (e) => busy(e.currentTarget, async () => {
      const clientID = $("#set-google-client").value.trim();
      try {
        await api("PUT", "/api/v1/setup/google", { client_id: clientID });
        Status.invalidate();
        toast(t("gset.saved"));
        await loadGoogleSettings(pageGeneration, Session.epoch);
      } catch (err) { toast(errText(err), "err"); }
    }));
    $("#set-tunnels").addEventListener("click", async (e) => {
      const sw = e.currentTarget, next = sw.getAttribute("aria-checked") !== "true";
      sw.classList.add("is-busy");
      try {
        const st = await api("PUT", "/api/v1/tunnels/settings", { enabled: next });
        sw.setAttribute("aria-checked", String(!!st.enabled));
        toast(t(next ? "app.settings.tunOn" : "app.settings.tunOff"));
      } catch (err) { toast(errText(err), "err"); }
      finally { sw.classList.remove("is-busy"); }
    });
    $("#set-tun-save").addEventListener("click", (e) => busy(e.currentTarget, async () => {
      const budget = parseInt($("#set-tun-budget").value, 10);
      const rate = parseInt($("#set-tun-rate").value, 10);
      const body = {};
      if (Number.isInteger(budget) && budget >= 0) body.global_monthly_bytes = budget;
      if (Number.isInteger(rate) && rate >= 10) body.rate_per_min = rate;
      if (!Object.keys(body).length) { toast(t("err.fillAll"), "err"); return; }
      try {
        const st = await api("PUT", "/api/v1/tunnels/settings", body);
        $("#set-tun-budget").value = st.global_monthly_bytes;
        $("#set-tun-rate").value = st.rate_per_min;
        toast(t("app.settings.tunSaved"));
      } catch (err) { toast(errText(err), "err"); }
    }));
    on("devices-changed", () => { Queries.invalidate("devices"); });
    on("modal-closed", (id) => {
      if (App.page && (id === "modal-enroll" || id === "modal-tunnel")) PAGES[App.page].refresh(true);
    });
    document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible" && currentView === "app") poll(0); });
    initTransferModal();
  }
  function poll(delay) {
    clearTimeout(pollTimer);
    const name = App.page, page = PAGES[name], generation = pageGeneration, epoch = Session.epoch;
    if (!page) return;
    const every = page.interval ? page.interval() : 15000;
    if (!every) return;
    pollTimer = setTimeout(async () => {
      if (!pageCurrent(name, generation, epoch)) return;
      if (document.visibilityState === "visible" && currentView === "app" && $$(".modal").every((m) => m.hidden)) {
        await Promise.allSettled([page.refresh(true), name === "overview" ? null : load.health()]);
      }
      if (pageCurrent(name, generation, epoch)) poll();
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
    clearTimeout(pollTimer);
    const generation = ++pageGeneration, epoch = Session.epoch;
    App.me = me;
    showView("app");
    closeDrawer();
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
    if (page !== "overview") void load.health().catch(() => {});
    await PAGES[page].refresh(false);
    if (pageCurrent(page, generation, epoch)) poll();
  }
  on("lang", () => {
    describeSite();
    if (currentView === "app" && App.page) {
      setPageTitle();
      $("#u-role").textContent = App.me && App.me.role === "admin" ? t("common.admin") : t("common.member");
      PAGES[App.page].render();
      renderHealth();
      updateCounts();
    }
    renderTitle();
    if (currentView === "landing") void renderAccount();
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
  // What a hash means on this surface is decided by rules.js (a pure table,
  // tested in Node). This part only gathers the facts it asks for and carries
  // the decision out.
  let ssoRunning = null, ssoAuthorized = null, callbackRunning = null;

  // Platform origin: a project asked for a sign-in (authorize), or the
  // platform session ends (logout).
  async function routeSSO(hash) {
    if (ssoRunning || ssoAuthorized === hash) return ssoRunning;
    ssoRunning = (async () => {
      const panel = $('[data-panel="sso"]');
      await showAuth("sso");
      showErr(panel, "");
      K.tl($("#sso-message"), "sso.working");
      try {
        if (hash === "#/sso/logout") {
          try { await api("POST", "/api/v1/auth/logout", {}, { quiet401: true }); }
          catch (err) { if (err.status !== 401) throw err; }
          Session.clear(); Resume.set("");
          go("#/", true);
          return;
        }
        const metadata = await api("GET", "/api/v1/sso/status", null, { auth: false });
        if (!metadata.enabled) { K.tl($("#sso-message"), "sso.disabled"); return; }
        const body = K.sso.authorization(hash, metadata);
        Resume.set(hash);
        const me = await Session.me();
        if (!me) {
          await showAuth("login");
          const note = $('[data-role="notice"]', $('[data-panel="login"]'));
          $('[data-role="notice-text"]', note).textContent = t("sso.loginContinue");
          note.hidden = false;
          return;
        }
        const data = await api("POST", "/api/v1/sso/authorize", body, { quiet401: true });
        const destination = K.sso.redirect(data.redirect_url, body, metadata);
        ssoAuthorized = hash; Resume.set("");
        location.assign(destination);
      } catch (err) {
        if (K.isQueryCancelled(err)) return;
        if (err.status === 401) {
          Session.clear(); await showAuth("login");
          showErr($("#form-login"), t("auth.sessionExpired"));
        } else {
          await showAuth("sso"); K.tl($("#sso-message"), "sso.failed");
          showErr(panel, errText(err));
        }
      }
    })();
    try { await ssoRunning; } finally { ssoRunning = null; }
  }

  // Project origin: the platform sent the browser back with a single-use code.
  // The code and state live only in memory (kit sso.js removed them from the
  // URL before anything else ran); the server redeems them with its own PKCE
  // verifier and answers with this origin's own session.
  async function routeCallback() {
    if (callbackRunning) return callbackRunning;
    callbackRunning = (async () => {
      await showAuth("callback");
      const panel = $('[data-panel="callback"]'), actions = $("#callback-actions");
      showErr(panel, ""); actions.hidden = true;
      K.tl($("#callback-message"), "mb.sso.working");
      try {
        const data = await K.sso.complete();
        if (!data || !data.token) throw new ApiError(401, "sso_invalid", "invalid sign-in");
        Session.set(data.token);
        go(Rules.safeResume(data.next) || Rules.safeResume(Resume.take()) || "#/app/overview", true);
      } catch (err) {
        if (K.isQueryCancelled(err)) return;
        K.tl($("#callback-message"), "mb.sso.failed");
        showErr(panel, errText(err));
        actions.hidden = false;
      }
    })();
    try { await callbackRunning; } finally { callbackRunning = null; }
  }

  function go(hash, replace) {
    if (location.hash === hash) { route(); return; }
    if (replace) location.replace(hash); else location.hash = hash;
  }
  const DEEP = ["/login", "/register", "/forgot", "/setup", "/app"];
  let routeGeneration = 0;
  async function route() {
    const generation = ++routeGeneration;
    try { await routeCurrent(generation); }
    catch (err) { if (!K.isQueryCancelled(err) && generation === routeGeneration) { console.error(err); showFault(err); } }
  }
  async function routeCurrent(generation) {
    const path = location.pathname.replace(/\/+$/, "");
    if (DEEP.includes(path)) { history.replaceState(null, "", "/#" + path + location.search); }
    const hash = location.hash;
    const current = () => generation === routeGeneration && location.hash === hash;
    // Facts are fetched only when a decision needs them. A server that cannot
    // answer rejects (a fault), which the planner turns into the service view:
    // it is never mistaken for "not signed in".
    const facts = {
      setupRequired: async () => {
        const st = await Status.get();
        if (!st) throw new ApiError(0, "network", "setup status unavailable");
        return !!st.setup_required;
      },
      session: async () => ((await Session.me()) ? "valid" : "none"),
    };
    const decision = await Rules.plan({
      surface: Surface.info, hash, resume: Resume.get(),
      wizard: currentView === "auth" && currentPanel === "setup" && setupStep > 1, facts,
    });
    if (!current()) return;
    switch (decision.type) {
      case "navigate": location.replace(decision.url); return;
      case "replace":
        if (decision.resume) Resume.set(decision.resume);
        go(decision.hash, true);
        return;
      case "fault":
        if (!K.isQueryCancelled(decision.error)) showFault(decision.error);
        return;
      default:
    }
    switch (decision.view) {
      case "landing": Resume.set(""); await showLanding(decision.anchor); return;
      case "auth": await showAuth(decision.panel); return;
      case "app": {
        const me = await Session.me();
        if (!me || !current()) return;
        Resume.set("");
        await showApp(decision.page, me);
        return;
      }
      case "sso":
        if (decision.mode === "callback") await routeCallback(); else await routeSSO(hash);
        return;
      default:
    }
  }

  // ───────────────────────── boot ─────────────────────────
  // A fault is retried from scratch: forget what was cached while the server
  // could not answer, keep the session.
  function forgetFaults() { Session.reset(store.get("token") || ""); Status.invalidate(); }
  let wired = false;
  async function start() {
    try { await Surface.load(); }
    catch (err) { showFault(err); return; }
    applySurface();
    if (!wired) {
      wired = true;
      window.addEventListener("hashchange", route);
      window.addEventListener("storage", (event) => {
        if (event.key !== null && event.key !== document.documentElement.dataset.app + "_token") return;
        const epoch = Session.epoch;
        Session.token();
        if (Session.epoch !== epoch) void route();
      });
    }
    await route();
  }
  async function boot() {
    $$("[data-year]").forEach((el) => (el.textContent = String(new Date().getFullYear())));
    $("[data-skip]").addEventListener("click", (e) => {
      e.preventDefault();
      const main = $(`#view-${currentView} main`);
      if (main) { main.setAttribute("tabindex", "-1"); main.focus(); }
    });
    mountSharedChrome();
    await K.loadSprite("/assets/kit/icons.svg", { missingOnly: true });
    initPasswordFields();
    initSendCode();
    initAuthForms();
    $("#sso-retry").addEventListener("click", () => busy($("#sso-retry"), () => routeSSO(location.hash)));
    $("#callback-retry").addEventListener("click", (e) => busy(e.currentTarget, async () => {
      try { await K.sso.start(Rules.safeResume(Resume.get()) || "#/app/overview"); }
      catch (err) { showErr($('[data-panel="callback"]'), errText(err)); }
    }));
    $("#mb-sso").addEventListener("click", (e) => busy(e.currentTarget, async () => {
      showErr($("#form-login"), "");
      try { await K.sso.start(Rules.safeResume(Resume.get()) || "#/app/overview"); }
      catch (err) { showErr($("#form-login"), errText(err)); }
    }));
    $('[data-role="gsign-retry"]', gsignBox()).addEventListener("click", () => { if (currentPanel === "login") void mountAltAuth(); });
    $("#service-retry").addEventListener("click", (e) => busy(e.currentTarget, async () => {
      if (!Surface.loaded) { await start(); return; }
      forgetFaults();
      await route();
    }));
    try { await I18N.use(detectLang(), false); }
    catch (e) { console.error("i18n failed", e); }
    await start();
  }
  boot();
})();
