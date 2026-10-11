// Exercise the actual app's data/refresh paths with real kit DOM primitives.
// Boot is replaced only in this test, so no test hooks ship to the browser.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { runtime } = require("../../kit/web/runtime_test.cjs");
const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };
const turn = () => new Promise((resolve) => setImmediate(resolve));
const response = (data, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => data });

async function harness() {
  let handler = async (url) => response(url.endsWith("/health") ? { headscale: "ok" } : { items: [] });
  const calls = [];
  const rt = runtime("mb", { mb_token: "user-a" }, { location: { hostname: "meshbridge.mineai.top", origin: "https://meshbridge.mineai.top" },
    fetch: (url, init) => { calls.push({ url, init }); return handler(url, init); } });
  const { K, document, context } = rt;
  context.AbortController = AbortController;
  context.self = context.window;
  Object.defineProperty(context.Element.prototype, "firstChild", { get() { return this.children[0]; } });
  context.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
  context.window.scrollTo = () => {};
  const nodes = new Map(), nested = new WeakMap();
  const node = (selector, root) => {
    let map = nodes;
    if (root) { if (!nested.has(root)) nested.set(root, new Map()); map = nested.get(root); }
    if (!map.has(selector)) {
      const el = document.createElement("div"); el.value = ""; el.options = [];
      el.reset = () => {}; map.set(selector, el);
    }
    return map.get(selector);
  };
  K.$ = node; K.$$ = () => [];
  await K.i18n.use("en", false);
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../../kit/web/assets/kit/cache.js"), "utf8"), context);
  if (fs.existsSync(path.join(__dirname, "../web/assets/rules.js"))) vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/assets/rules.js"), "utf8"), context);
  const source = fs.readFileSync(path.join(__dirname, "../web/assets/app.js"), "utf8");
  const end = /  boot\(\);\s*\}\)\(\);\s*$/;
  assert.ok(end.test(source), "test must replace only boot, not production logic");
  vm.runInContext(source.replace(end, `
    window.MeshTest = { D, App, Session, Status, Queries, load, api, PAGES, showApp,
      activate(name) { consoleReady = true; currentView = "app"; App.page = name; App.me = { username: "A", role: "member" }; pageGeneration++; },
      stop() { clearTimeout(pollTimer); currentView = null; }
    };
  })();`), context, { filename: "app.js" });
  return { ...rt, app: context.window.MeshTest, calls, node, serve(fn) { handler = fn; } };
}

(async () => {
  const rt = await harness(), { app: A, K } = rt;
  const devices = [{ id: "d1", hostname: "NAS", online: true, last_seen: 1 }];
  rt.serve(async () => response({ items: devices }));
  await Promise.all([A.load.devices(), A.load.devices()]);
  await A.load.devices();
  assert.equal(rt.calls.length, 1, "concurrent and fresh list reads should use one request");
  assert.equal(rt.calls[0].init.cache, "no-store", "private HTTP caching must remain disabled");
  const oldList = A.D.devices;
  await A.load.devices(true);
  assert.equal(A.D.devices, oldList, "identical payloads keep their data identity");

  A.activate("devices"); await A.PAGES.devices.refresh(false);
  const table = rt.node("#dev-table").children[0];
  await A.PAGES.devices.refresh(true);
  assert.equal(rt.node("#dev-table").children[0], table, "unchanged polling must keep table nodes");
  rt.node("#dev-q").value = "missing"; A.PAGES.devices.render();
  assert.notEqual(rt.node("#dev-table").children[0], table, "filter changes must repaint");
  rt.node("#dev-q").value = "";
  const slow = deferred(); rt.serve(() => slow.promise);
  A.Queries.invalidate("devices");
  const refresh = A.PAGES.devices.refresh(false);
  assert.match(rt.node("#dev-table").textContent, /NAS/, "stale list paints before network finishes");
  await turn(); slow.resolve(response({ items: devices })); await refresh;

  const before = rt.calls.length;
  rt.serve(async () => response({})); await A.api("POST", "/api/v1/projects", { name: "project" });
  rt.serve(async () => response({ items: devices })); await A.load.devices();
  assert.equal(rt.calls.length, before + 2, "writes invalidate related list caches");

  const late = deferred(); A.Queries.invalidate("devices"); rt.serve(() => late.promise);
  const oldRead = A.load.devices(), oldCancelled = assert.rejects(oldRead, K.isQueryCancelled);
  await turn(); rt.document.body.classList.add("modal-open"); A.Session.set("user-b"); await oldCancelled;
  assert.equal(rt.document.body.classList.contains("modal-open"), false, "identity reset must release modal scroll lock");
  assert.equal(rt.node("#dev-table").children.length, 0, "old private DOM must be cleared as well as memory");
  assert.equal(A.D.devices, null); assert.equal(A.App.me, null); assert.equal(A.D.pendingKey, null);
  late.resolve(response({ items: devices })); await turn();
  assert.equal(A.D.devices, null, "old user response cannot repopulate console data");

  let meCalls = 0;
  rt.serve(async (url) => { assert.equal(url, "/api/v1/me"); meCalls++; return response({ username: "B", role: "member" }); });
  await Promise.all([A.Session.me(), A.Session.me()]);
  assert.equal(meCalls, 1, "parallel session lookups coalesce");
  const old401 = deferred(); rt.serve(() => old401.promise);
  const staleAuth = A.api("GET", "/api/v1/devices"), staleAuthCancelled = assert.rejects(staleAuth, K.isQueryCancelled);
  A.Session.set("user-c"); old401.resolve(response({ code: "unauthorized" }, 401)); await staleAuthCancelled;
  assert.equal(A.Session.token(), "user-c", "old 401 must not sign out the new account");

  A.activate("devices"); rt.serve(async () => { throw new Error("offline"); });
  await A.PAGES.devices.refresh(false);
  assert.match(rt.node("#dev-table").textContent, /Try again/, "initial failures must expose retry, not fake an empty list");
  rt.serve(async () => response({ items: devices })); await A.PAGES.devices.refresh(false, true);
  rt.serve(async () => { throw new Error("offline"); }); await A.PAGES.devices.refresh(true, true);
  assert.match(rt.node("#dev-table").textContent, /NAS/, "background failure must preserve visible data");

  A.Session.set("audit-user");
  const firstPage = Array.from({ length: 50 }, (_, i) => ({ id: i })), secondPage = [{ id: 50 }];
  rt.serve(async (url) => response({ items: url.includes("page=1") ? firstPage : secondPage }));
  await A.load.audit(true);
  await Promise.all([A.load.audit(), A.load.audit()]);
  assert.equal(A.D.audit.length, 51, "coalesced pagination cannot append twice");
  await A.load.audit(true, true);
  assert.equal(A.D.audit.length, 51, "unchanged first-page refresh keeps expanded pages");

  A.Session.set("write-race-user");
  const beforeWrite = deferred();
  rt.serve((url, init) => init.method === "GET" ? beforeWrite.promise : Promise.resolve(response({})));
  const outdated = A.load.devices(), outdatedCancelled = assert.rejects(outdated, K.isQueryCancelled);
  await turn(); await A.api("POST", "/api/v1/devices/enroll", {}); await outdatedCancelled;
  beforeWrite.resolve(response({ items: devices })); await turn();
  assert.equal(A.D.devices, null, "pre-write response cannot refill after mutation");
  rt.serve(async () => response({ items: devices })); await A.load.devices();

  A.Session.set("microtask-race-user");
  const commitRace = deferred(); rt.serve(() => commitRace.promise);
  const committing = A.load.devices();
  const switched = A.Queries.get("devices", () => assert.fail("must coalesce")).then(() => A.Session.set("after-commit-user"));
  commitRace.resolve(response({ items: devices })); await Promise.all([committing, switched]);
  assert.equal(A.D.devices, null, "just-resolved old response cannot cross a microtask identity change");

  let statusCalls = 0;
  rt.serve(async () => { statusCalls++; return response({ setup_required: false }); });
  await Promise.all([A.Status.get(), A.Status.get(true)]); await A.Status.get();
  assert.equal(statusCalls, 1, "status consumers coalesce and reuse their short TTL");
  A.Status.invalidate(); await A.Status.get(); assert.equal(statusCalls, 2);

  A.Session.set("overview-user"); A.activate("overview");
  const delayed = deferred();
  rt.serve((url) => url.includes("/relays") ? delayed.promise : Promise.resolve(response(url.endsWith("/health") ? { headscale: "ok" } : { items: devices })));
  const overview = A.PAGES.overview.refresh(false); await turn();
  assert.equal(A.D.devices.length, 1);
  assert.equal(rt.node('[data-role="v"]', rt.node("#st-devices")).textContent, "1 / 1", "overview renders fast modules before slow ones");
  delayed.resolve(response({ items: [] })); await overview;
  assert.equal(rt.calls.filter((x) => x.url.endsWith("/health")).length, 1);

  A.Session.set("page-race-user"); A.activate("devices");
  const oldPageData = deferred();
  const timers = [], realSetTimeout = rt.context.setTimeout, realClearTimeout = rt.context.clearTimeout;
  rt.context.setTimeout = (_, delay) => { timers.push(delay); return timers.length; };
  rt.context.clearTimeout = () => {};
  rt.serve((url) => url.includes("/devices") ? oldPageData.promise : Promise.resolve(response(url.endsWith("/health") ? { headscale: "ok" } : { items: [] })));
  const oldPage = A.showApp("devices", { username: "race", role: "member" }); await turn();
  const oldPlaceholder = rt.node("#dev-table").children[0];
  await A.showApp("relays", { username: "race", role: "member" });
  const scheduled = timers.length;
  oldPageData.resolve(response({ items: devices })); await oldPage;
  assert.equal(A.App.page, "relays");
  assert.equal(rt.node("#dev-table").children[0], oldPlaceholder, "old route must not repaint its hidden page");
  assert.equal(timers.length, scheduled, "old route must not restart the current poller");
  assert.equal(timers.at(-1), 30000);
  A.stop();
  rt.context.setTimeout = realSetTimeout; rt.context.clearTimeout = realClearTimeout;
  console.log("Mesh cache: request counts, no-store, unchanged DOM, stale-first pages, write/identity/microtask races, session dedupe, old 401, failures, pagination, progressive overview and stale route/poller guards passed.");
})().catch((error) => { console.error(error); process.exitCode = 1; });
