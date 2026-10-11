// Read-only smoke against a running server. Defaults to an isolated local port.
// No login, writes, production credentials or load generation.
const assert = require("node:assert/strict");
const base = new URL(process.argv[2] || "http://127.0.0.1:18761/");
const immutable = "public, max-age=31536000, immutable";
const request = (path, headers) => fetch(new URL(path, base), { headers });

(async () => {
  const index = await request("/"); assert.equal(index.status, 200);
  assert.equal(index.headers.get("cache-control"), "no-cache");
  const html = await index.text();
  const version = /<meta name="asset-v" content="([0-9a-f]{16})">/.exec(html);
  assert.ok(version, "embedded shell must publish its asset version");
  const refs = [...new Set(Array.from(html.matchAll(/(?:src|href)="(\/assets\/[^"?]+\?v=[0-9a-f]{16})"/g), (match) => match[1]))];
  assert.ok(refs.length > 0);
  for (const path of [...refs, "/assets/kit/i18n/en.json?v=" + version[1], "/assets/i18n/en.json?v=" + version[1]]) {
    const asset = await request(path);
    assert.equal(asset.status, 200, path); assert.equal(asset.headers.get("cache-control"), immutable, path);
    assert.ok(asset.headers.get("etag"), path);
    await asset.arrayBuffer();
  }
  assert.equal((await request("/", { "If-None-Match": index.headers.get("etag") })).status, 304);
  for (const path of ["/assets/app.js", "/assets/app.js?v=old", "/assets/kit/core.js?v=old"]) {
    const asset = await request(path); assert.equal(asset.status, 200); assert.equal(asset.headers.get("cache-control"), "no-cache"); await asset.arrayBuffer();
  }
  for (const path of ["/assets/missing.js", "/assets/kit/missing.js", "/dl/missing-agent", "/api/missing"]) {
    const missing = await request(path); assert.equal(missing.status, 404, path); await missing.arrayBuffer();
  }
  console.log(`HTTP cache smoke: ${refs.length} versioned shell assets + 2 dynamic dictionaries immutable; HTML 304, stale-version revalidation and real 404 passed.`);
})().catch((error) => { console.error(error); process.exitCode = 1; });
