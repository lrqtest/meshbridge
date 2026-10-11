// Table tests for web/assets/rules.js — the platform/project boundary, legacy
// link migration, safe resume targets and error wording. No DOM, no network.
// Run: node scripts/rules_test.cjs   (part of `make runtime-check`)
const assert = require("node:assert/strict");
const path = require("node:path");
const R = require(path.join(__dirname, "../web/assets/rules.js"));

const PLATFORM_URL = "https://mineai.top", PROJECT_URL = "https://meshbridge.mineai.top";
const surfaces = {
  platform: { kind: "platform", split: true, platformURL: PLATFORM_URL, projectURL: PROJECT_URL },
  project: { kind: "project", split: true, platformURL: PLATFORM_URL, projectURL: PROJECT_URL },
  standalone: { kind: "project", split: false, platformURL: "", projectURL: "" },
};
function facts({ setup = false, session = "none", fault = null } = {}) {
  const calls = { setup: 0, session: 0 };
  return {
    calls,
    setupRequired: async () => { calls.setup++; if (fault) throw fault; return setup; },
    session: async () => { calls.session++; if (fault) throw fault; return session; },
  };
}
const plan = (surface, hash, f = {}, extra = {}) => { const fx = facts(f); return R.plan({ surface: surfaces[surface], hash, facts: fx, ...extra }).then((d) => ({ d, fx })); };

(async () => {
  let n = 0;
  const is = async (surface, hash, f, want, extra) => {
    const { d } = await plan(surface, hash, f, extra);
    n++;
    assert.deepEqual(d, want, `${surface} ${JSON.stringify(hash)} ${JSON.stringify(f)} -> ${JSON.stringify(d)}`);
  };

  /* ── hash parsing ── */
  for (const [hash, want] of [
    ["", { kind: "home" }], ["#", { kind: "home" }], ["#/", { kind: "home" }],
    ["#projects", { kind: "anchor", anchor: "projects" }],
    ["#/login", { kind: "auth", panel: "login" }], ["#/register/", { kind: "auth", panel: "register" }], ["#/forgot?x=1", { kind: "auth", panel: "forgot" }],
    ["#/setup", { kind: "setup" }],
    ["#/app", { kind: "app", page: "overview", known: true }], ["#/app/devices", { kind: "app", page: "devices", known: true }],
    ["#/app/settings/", { kind: "app", page: "settings", known: true }], ["#/app/nope", { kind: "app", page: "nope", known: false }],
    ["#/sso?client_id=x", { kind: "sso-authorize" }], ["#/sso/callback", { kind: "sso-callback" }], ["#/sso/logout", { kind: "sso-logout" }],
    ["#/sso", { kind: "unknown" }], ["#/sso/other", { kind: "unknown" }], ["#/whatever", { kind: "unknown" }], ["#//evil.example", { kind: "home" }],
    [undefined, { kind: "home" }], [null, { kind: "home" }], [42, { kind: "home" }],
  ]) { const got = R.parse(hash); n++; for (const [k, v] of Object.entries(want)) assert.equal(got[k], v, `parse(${JSON.stringify(hash)}).${k}`); }

  /* ── platform origin: navigation and account only ── */
  await is("platform", "", {}, { type: "show", view: "landing" });
  await is("platform", "#/", {}, { type: "show", view: "landing" });
  await is("platform", "#projects", {}, { type: "show", view: "landing", anchor: "projects" });
  await is("platform", "#/login", { session: "none" }, { type: "show", view: "auth", panel: "login" });
  await is("platform", "#/register", {}, { type: "show", view: "auth", panel: "register" });
  await is("platform", "#/forgot", {}, { type: "show", view: "auth", panel: "forgot" });
  await is("platform", "#/login", { session: "valid" }, { type: "replace", hash: "#/" });
  await is("platform", "#/login", { session: "valid" }, { type: "replace", hash: "#/sso?client_id=meshbridge&state=abc" }, { resume: "#/sso?client_id=meshbridge&state=abc" });
  await is("platform", "#/login", { session: "valid" }, { type: "replace", hash: "#/" }, { resume: "#/app/devices" }); // a console route is not a platform destination
  await is("platform", "#/login", { session: "valid" }, { type: "replace", hash: "#/" }, { resume: "https://evil.example" });
  await is("platform", "#/sso?client_id=folio", {}, { type: "show", view: "sso", mode: "authorize" });
  await is("platform", "#/sso/logout", {}, { type: "show", view: "sso", mode: "logout" });
  await is("platform", "#/sso/callback", {}, { type: "replace", hash: "#/" });
  await is("platform", "#/unknown/route", {}, { type: "replace", hash: "#/" });

  /* ── legacy console links on the platform origin land on the project ── */
  for (const [hash, to] of [
    ["#/app/overview", "#/app/overview"], ["#/app/devices", "#/app/devices"], ["#/app/transfers", "#/app/transfers"],
    ["#/app/tunnels", "#/app/tunnels"], ["#/app/relays", "#/app/relays"], ["#/app/audit", "#/app/audit"], ["#/app/settings", "#/app/settings"],
    ["#/app", "#/app/overview"], ["#/app/", "#/app/overview"], ["#/app/devices/", "#/app/devices"], ["#/app/devices?x=1", "#/app/devices"],
    ["#/app/unknown", "#/app/overview"], ["#/app/../../evil", "#/app/overview"], ["#/app/%2e%2e", "#/app/overview"],
    ["#/setup", "#/setup"],
  ]) await is("platform", hash, {}, { type: "navigate", url: PROJECT_URL + "/" + to });
  // The destination is never built from the input beyond the allow-list.
  for (const hash of ["#/app/devices\\evil", "#/app/devices%0d%0a", "#/app/<script>", "#/app/javascript:alert(1)"]) {
    const { d } = await plan("platform", hash); n++;
    assert.equal(d.type, "navigate"); assert.ok(/^https:\/\/meshbridge\.mineai\.top\/#\/app\/[a-z]+$/.test(d.url), d.url);
  }
  { // no lookups are needed to decide on the platform landing or a legacy link
    const { fx } = await plan("platform", "#/app/devices"); n++;
    assert.deepEqual(fx.calls, { setup: 0, session: 0 });
    const { fx: fx2 } = await plan("platform", "#/"); n++;
    assert.deepEqual(fx2.calls, { setup: 0, session: 0 });
  }

  /* ── project origin: sign-in and console ── */
  for (const s of ["project", "standalone"]) {
    await is(s, "", { session: "none" }, { type: "show", view: "auth", panel: "login" });
    await is(s, "#/", { session: "valid" }, { type: "replace", hash: "#/app/overview" });
    await is(s, "#projects", { session: "valid" }, { type: "replace", hash: "#/app/overview" });
    await is(s, "#/", { setup: true }, { type: "replace", hash: "#/setup" });
    await is(s, "#/login", { session: "none" }, { type: "show", view: "auth", panel: "login" });
    await is(s, "#/register", { session: "none" }, { type: "show", view: "auth", panel: "register" });
    await is(s, "#/forgot", { session: "none" }, { type: "show", view: "auth", panel: "forgot" });
    await is(s, "#/login", { session: "valid" }, { type: "replace", hash: "#/app/overview" });
    await is(s, "#/login", { session: "valid" }, { type: "replace", hash: "#/app/audit" }, { resume: "#/app/audit" });
    await is(s, "#/login", { session: "valid" }, { type: "replace", hash: "#/app/overview" }, { resume: "https://evil.example/" });
    await is(s, "#/login", { session: "valid" }, { type: "replace", hash: "#/app/overview" }, { resume: "#/sso?client_id=x" });
    await is(s, "#/login", { setup: true }, { type: "replace", hash: "#/setup" });
    await is(s, "#/setup", { setup: true }, { type: "show", view: "auth", panel: "setup" });
    await is(s, "#/setup", { setup: false, session: "none" }, { type: "replace", hash: "#/login" });
    await is(s, "#/setup", { setup: false, session: "valid" }, { type: "replace", hash: "#/app/overview" });
    await is(s, "#/setup", { setup: false, session: "valid" }, { type: "show", view: "auth", panel: "setup" }, { wizard: true });
    await is(s, "#/setup", { setup: false, session: "none" }, { type: "replace", hash: "#/login" }, { wizard: true });
    await is(s, "#/app/overview", { session: "valid" }, { type: "show", view: "app", page: "overview" });
    await is(s, "#/app", { session: "valid" }, { type: "show", view: "app", page: "overview" });
    await is(s, "#/app/settings", { session: "valid" }, { type: "show", view: "app", page: "settings" });
    await is(s, "#/app/devices", { session: "none" }, { type: "replace", hash: "#/login", resume: "#/app/devices" });
    await is(s, "#/app/audit?q=1", { session: "none" }, { type: "replace", hash: "#/login", resume: "#/app/audit" });
    await is(s, "#/app/nope", { session: "valid" }, { type: "replace", hash: "#/app/overview" });
    await is(s, "#/app/devices", { setup: true }, { type: "replace", hash: "#/setup" });
    await is(s, "#/sso/callback", { session: "none" }, { type: "show", view: "sso", mode: "callback" });
    await is(s, "#/unknown", {}, { type: "replace", hash: "#/" });
  }
  // The platform's authorization routes belong to the platform ...
  await is("project", "#/sso?client_id=meshbridge&state=s", {}, { type: "navigate", url: PLATFORM_URL + "/#/sso?client_id=meshbridge&state=s" });
  await is("project", "#/sso/logout", {}, { type: "navigate", url: PLATFORM_URL + "/#/sso/logout" });
  // ... unless this single origin is the issuer itself (a standalone control plane).
  await is("standalone", "#/sso?client_id=folio", {}, { type: "show", view: "sso", mode: "authorize" });
  await is("standalone", "#/sso/logout", {}, { type: "show", view: "sso", mode: "logout" });
  // A project never shows the platform landing, whatever the hash.
  for (const hash of ["", "#/", "#projects", "#/portal", "#/landing"]) {
    const { d } = await plan("project", hash, { session: "none" }); n++;
    assert.notEqual(d.view, "landing", hash);
  }

  /* ── faults are not sign-outs ── */
  for (const hash of ["#/", "#/login", "#/app/devices", "#/setup"]) {
    const boom = Object.assign(new Error("HTTP 503"), { status: 503 });
    const { d } = await plan("project", hash, { fault: boom }); n++;
    assert.equal(d.type, "fault", hash); assert.equal(d.error, boom);
  }
  { const boom = new Error("network"); const { d } = await plan("platform", "#/login", { fault: boom }); n++; assert.equal(d.type, "fault"); }

  /* ── resume validation ── */
  for (const [input, want] of [
    ["#/app/devices", "#/app/devices"], ["#/app", "#/app/overview"], ["#/app/devices?x=1", "#/app/devices"],
    ["#/app/nope", ""], ["#/login", ""], ["#/", ""], ["", ""], ["https://evil.example", ""], ["javascript:alert(1)", ""], [null, ""], [undefined, ""],
  ]) { n++; assert.equal(R.safeResume(input), want, "safeResume " + input); }
  for (const [input, want] of [
    ["#/sso?client_id=meshbridge&state=abc-DEF_123", "#/sso?client_id=meshbridge&state=abc-DEF_123"],
    ["#/sso", ""], ["#/sso?<script>", ""], ["#/sso?x=" + "a".repeat(2100), ""], ["#/app/devices", ""], [null, ""],
  ]) { n++; assert.equal(R.safePlatformResume(input), want, "safePlatformResume " + input); }

  /* ── error wording ── */
  const err = (status, code = "", message = "") => ({ status, code, message });
  for (const [e, ctx, key, params] of [
    [err(0, "network", "x"), "", "err.network"],
    [err(401, "unauthorized", "bad credentials"), "login", "err.badCredentials"],
    [err(401, "unauthorized", "invalid bearer token"), "", "err.unauthorized"],
    [err(401, "", ""), "login", "err.badCredentials"],
    [err(403, "forbidden", "admin only"), "", "err.adminOnly"],
    [err(403, "forbidden", "registration is disabled"), "", "err.regClosed"],
    [err(403, "forbidden", "setup already completed"), "", "err.setupDone"],
    [err(403, "", "nope"), "", "err.forbidden"],
    [err(429, "rate_limited", "too many attempts; retry later"), "login", "err.tooMany"],
    [err(429, "rate_limited", "please wait 42s before requesting another code"), "", "err.waitSeconds", { s: "42" }],
    [err(429, "rate_limited", "daily limit reached"), "", "err.dailyLimit"],
    [err(500, "server", "internal error"), "", "err.server"],
    [err(502, "mail_send_failed", "dial tcp: refused"), "", "err.mailFailed", { detail: "dial tcp: refused" }],
    [err(503, "unavailable", "login temporarily unavailable"), "login", "err.unavailable"],
    [err(503, "sso_unavailable", "platform SSO temporarily unavailable"), "", "sso.unavailable"],
    [err(503, "sso_busy", "capacity"), "", "sso.unavailable"],
    [err(401, "sso_invalid", "invalid"), "", "sso.invalid"],
    [err(503, "google_not_configured", ""), "login", "err.google.notConfigured"],
    [err(503, "google_unavailable", ""), "login", "err.google.unavailable"],
    [err(401, "google_invalid", ""), "login", "err.google.invalid"],
    [err(403, "google_email_unverified", ""), "login", "err.google.unverified"],
    [err(403, "account_disabled", ""), "login", "err.accountDisabled"],
    [err(403, "registration_closed", ""), "login", "err.regClosed"],
    [err(409, "google_link_required", ""), "login", "err.google.linkRequired"],
    [err(409, "google_already_linked", ""), "login", "err.google.alreadyLinked"],
    [err(409, "google_last_login", ""), "", "err.google.lastLogin"],
    [err(400, "bad_request", "google client id looks wrong"), "", "err.google.badClientId"],
    [err(409, "conflict", "this email is already registered"), "", "err.emailTaken"],
    [err(400, "bad_code", ""), "", "err.badCode"],
  ]) {
    const got = R.errorKey(e, ctx); n++;
    assert.ok(got, JSON.stringify(e)); assert.equal(got.key, key, JSON.stringify(e)); if (params) assert.deepEqual(got.params, params);
  }
  assert.equal(R.errorKey(err(418, "teapot", "short and stout"), ""), null); n++; // unknown: show the server's own words
  // A generic 503 must never be worded as a platform sign-in fault.
  assert.notEqual(R.errorKey(err(503, "", "x"), "").key, "sso.unavailable"); n++;

  for (const [e, want] of [[err(0, "network"), true], [err(500), true], [err(503), true], [err(502), true], [err(401), false], [err(403), false], [err(404), false], [err(429), false], [{ code: "network" }, true], [null, false]]) {
    n++; assert.equal(R.isFault(e), want, JSON.stringify(e));
  }
  console.log(`Rules: ${n} checks passed (route table for platform/project/standalone, legacy link migration, safe resume, faults, error wording).`);
})().catch((e) => { console.error(e); process.exit(1); });
