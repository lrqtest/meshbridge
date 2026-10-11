/* MeshBridge UI rules — pure decisions, no DOM, no network, no storage.
   Which view a hash shows on which surface, where a stale link is sent, which
   resume target is safe, and how a server error is worded all live here so one
   table can be tested in Node (scripts/rules_test.cjs) and then trusted in the
   browser. app.js only carries the decisions out.

   A "surface" is the product a request is addressed to:
     platform — the MineAI origin: project navigation and the platform account.
     project  — the MeshBridge origin (or a standalone install): sign-in and
                the console.
   The server resolves it from the Host header (GET /api/v1/surface). */
"use strict";
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.MeshRules = api;
})(typeof self !== "undefined" ? self : this, function () {
  const PAGES = ["overview", "devices", "transfers", "tunnels", "relays", "audit", "settings"];
  const AUTH_PANELS = ["login", "register", "forgot"];
  const HOME = "#/", CONSOLE = "#/app/overview";

  /* ───────────────────────── hashes ───────────────────────── */

  // parse turns a location hash into a route. Anything that is not a "#/…"
  // route is an in-page anchor ("#projects"), never a destination.
  function parse(hash) {
    const raw = typeof hash === "string" ? hash : "";
    if (raw === "" || raw === "#" || raw === "#/") return { kind: "home", raw };
    if (!raw.startsWith("#/")) return { kind: "anchor", anchor: raw.slice(1), raw };
    const path = raw.slice(2).split(/[?#]/)[0].replace(/\/+$/, "");
    const parts = path.split("/");
    const top = parts[0];
    if (top === "") return { kind: "home", raw };
    if (AUTH_PANELS.includes(top) && parts.length === 1) return { kind: "auth", panel: top, raw };
    if (top === "setup" && parts.length === 1) return { kind: "setup", raw };
    if (top === "app") {
      const page = parts[1] || "overview";
      return { kind: "app", page, known: PAGES.includes(page), raw };
    }
    if (top === "sso") {
      if (parts.length === 1 && raw.startsWith("#/sso?")) return { kind: "sso-authorize", raw };
      if (parts.length === 2 && parts[1] === "callback") return { kind: "sso-callback", raw };
      if (parts.length === 2 && parts[1] === "logout") return { kind: "sso-logout", raw };
    }
    return { kind: "unknown", raw };
  }

  // appHash is the canonical, injection-proof form of a console route.
  // Unknown pages fall back to the overview; nothing else of the input survives.
  function appHash(page) { return "#/app/" + (PAGES.includes(page) ? page : "overview"); }

  // safeResume admits only console routes as a post-sign-in destination.
  function safeResume(hash) {
    const r = parse(hash);
    return r.kind === "app" && r.known ? appHash(r.page) : "";
  }

  // safePlatformResume admits only a pending platform authorization.
  function safePlatformResume(hash) {
    return typeof hash === "string" && /^#\/sso\?[A-Za-z0-9_\-.~%=&]{1,2000}$/.test(hash) ? hash : "";
  }

  // legacyProject maps an old platform-origin console link (the console used to
  // live under mineai.top/#/app/…) to the same page on the project origin.
  function legacyProject(route) {
    return route.kind === "setup" ? "#/setup" : appHash(route.page);
  }

  /* ───────────────────────── planning ───────────────────────── */

  // plan decides what a hash means on a surface. ctx:
  //   surface  { kind, split, platformURL, projectURL }
  //   hash     location.hash
  //   resume   a pending post-sign-in destination (unvalidated)
  //   wizard   true while the first-run wizard continues after the admin exists
  //   facts    { setupRequired(): Promise<bool>, session(): Promise<"valid"|"none"> }
  //            Lookups run only when the decision needs them. A fault (anything
  //            but "no session") rejects and yields {type:"fault"}: a server
  //            that cannot answer must never look like a signed-out user.
  // Results:
  //   {type:"show", view:"landing"|"auth"|"app"|"sso", …}
  //   {type:"replace", hash, resume?}   in-app redirect, no history entry
  //   {type:"navigate", url}            cross-origin redirect, no history entry
  //   {type:"fault", error}
  async function plan(ctx) {
    const route = parse(ctx.hash);
    try {
      return ctx.surface.kind === "platform" ? await planPlatform(route, ctx) : await planProject(route, ctx);
    } catch (error) {
      return { type: "fault", error };
    }
  }

  async function planPlatform(route, ctx) {
    const { surface, facts } = ctx;
    switch (route.kind) {
      case "home": return { type: "show", view: "landing" };
      case "anchor": return { type: "show", view: "landing", anchor: route.anchor };
      case "auth":
        if (await facts.session() === "valid") return { type: "replace", hash: safePlatformResume(ctx.resume) || HOME };
        return { type: "show", view: "auth", panel: route.panel };
      case "app": case "setup":
        // The console is a project of its own. Old bookmarks keep working.
        return surface.projectURL
          ? { type: "navigate", url: surface.projectURL + "/" + legacyProject(route) }
          : { type: "replace", hash: HOME };
      case "sso-authorize": return { type: "show", view: "sso", mode: "authorize" };
      case "sso-logout": return { type: "show", view: "sso", mode: "logout" };
      default: return { type: "replace", hash: HOME };
    }
  }

  async function planProject(route, ctx) {
    const { surface, facts } = ctx;
    const setup = () => facts.setupRequired();
    switch (route.kind) {
      case "home": case "anchor":
        if (await setup()) return { type: "replace", hash: "#/setup" };
        return await facts.session() === "valid" ? { type: "replace", hash: CONSOLE } : { type: "show", view: "auth", panel: "login" };
      case "auth":
        if (await setup()) return { type: "replace", hash: "#/setup" };
        if (await facts.session() === "valid") return { type: "replace", hash: safeResume(ctx.resume) || CONSOLE };
        return { type: "show", view: "auth", panel: route.panel };
      case "setup":
        if (await setup()) return { type: "show", view: "auth", panel: "setup" };
        // After the admin exists the wizard continues (SMTP, first device) but
        // only inside the session that created it.
        if (await facts.session() === "valid") return ctx.wizard ? { type: "show", view: "auth", panel: "setup" } : { type: "replace", hash: CONSOLE };
        return { type: "replace", hash: "#/login" };
      case "app":
        if (await setup()) return { type: "replace", hash: "#/setup" };
        if (!route.known) return { type: "replace", hash: CONSOLE };
        if (await facts.session() !== "valid") return { type: "replace", hash: "#/login", resume: appHash(route.page) };
        return { type: "show", view: "app", page: route.page };
      case "sso-callback": return { type: "show", view: "sso", mode: "callback" };
      case "sso-authorize": case "sso-logout":
        // Authorizing a project sign-in is the platform's job.
        return surface.split && surface.platformURL
          ? { type: "navigate", url: surface.platformURL + "/" + route.raw }
          : { type: "show", view: "sso", mode: route.kind === "sso-logout" ? "logout" : "authorize" };
      default: return { type: "replace", hash: HOME };
    }
  }

  /* ───────────────────────── errors ───────────────────────── */

  // errorKey classifies an API failure into a dictionary key (and its
  // parameters). It returns null for anything it does not recognise, so the
  // caller can show the server's own wording instead of a wrong guess.
  // ctx "login" distinguishes a wrong password from an expired session.
  function errorKey(err, ctx) {
    const status = err && typeof err.status === "number" ? err.status : -1;
    const code = (err && err.code) || "";
    const m = String((err && err.message) || "").toLowerCase();
    const k = (key, params) => ({ key, params: params || {} });
    if (status === 0 || code === "network") return k("err.network");
    switch (code) {
      case "sso_invalid": return k("sso.invalid");
      case "sso_unavailable": case "sso_busy": return k("sso.unavailable");
      case "google_not_configured": return k("err.google.notConfigured");
      case "google_unavailable": return k("err.google.unavailable");
      case "google_invalid": return k("err.google.invalid");
      case "google_email_unverified": return k("err.google.unverified");
      case "google_link_required": return k("err.google.linkRequired");
      case "google_already_linked": return k("err.google.alreadyLinked");
      case "google_last_login": return k("err.google.lastLogin");
      case "account_disabled": return k("err.accountDisabled");
      case "registration_closed": return k("err.regClosed");
      case "origin": return k("err.origin");
      default:
    }
    if (code === "rate_limited" || status === 429) {
      const s = /wait (\d+)s/.exec(m);
      if (s) return k("err.waitSeconds", { s: s[1] });
      if (m.includes("daily")) return k("err.dailyLimit");
      if (m.includes("busy")) return k("err.busy");
      return k("err.tooMany");
    }
    if (code === "bad_code") return k("err.badCode");
    if (code === "conflict") return k(m.includes("email") ? "err.emailTaken" : "err.projectExists");
    if (code === "forbidden") {
      if (m.includes("registration")) return k("err.regClosed");
      if (m.includes("setup")) return k("err.setupDone");
      if (m.includes("admin")) return k("err.adminOnly");
    }
    if (code === "mailer") return k("err.mailerOff");
    if (code === "mail_send_failed") {
      if (m.includes("smtp not configured")) return k("err.smtpMissing");
      if (m.includes("invalid email")) return k("err.badEmail");
      return k("err.mailFailed", { detail: err.message });
    }
    if (code === "unauthorized" || status === 401) return k(ctx === "login" ? "err.badCredentials" : "err.unauthorized");
    if (code === "bad_request") {
      const table = [
        ["password must be", "err.passwordShort"], ["hostname", "err.badHostname"], ["must differ", "err.sameDevice"],
        ["relative", "err.badPath"], ["host, port and username", "err.smtpRequired"], ["none stored", "err.smtpPassRequired"],
        ["port must be", "err.smtpPort"], ["no valid target", "err.noAdminEmail"], ["src/dst", "err.pickDevices"],
        ["name required", "err.projectName"], ["google client id", "err.google.badClientId"],
      ];
      for (const [needle, key] of table) if (m.includes(needle)) return k(key);
    }
    if (status === 403) return k("err.forbidden");
    if (status === 503) return k("err.unavailable");
    if (status >= 500) return k("err.server");
    return null;
  }

  // isFault: the server could not answer (network, 5xx). A fault is retryable
  // and never means "signed out"; 401 is the only status that does.
  function isFault(err) {
    const status = err && typeof err.status === "number" ? err.status : -1;
    return status === 0 || status >= 500 || Boolean(err && err.code === "network");
  }

  return { PAGES, parse, appHash, safeResume, safePlatformResume, legacyProject, plan, errorKey, isFault };
});
