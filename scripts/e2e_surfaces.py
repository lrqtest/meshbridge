#!/usr/bin/env python3
"""Real-browser checks of the platform / project boundary.

One server process, two browser origins -- http://localhost:PORT is the MineAI
platform, http://127.0.0.1:PORT is the MeshBridge project -- exactly the split
mineai.top / meshbridge.mineai.top has in production (separate localStorage,
separate cookies, same API). Each case asserts what a person would see.

  python3 scripts/e2e_surfaces.py            # all cases
  python3 scripts/e2e_surfaces.py -k sso     # cases whose name contains "sso"
  E2E_EMBED=1 python3 scripts/e2e_surfaces.py   # serve the embedded UI (release binary path)
  E2E_SHOTS=dir ...                          # also write a screenshot per case

Needs Go, Playwright for Python (+ Chromium). Credentials are random per run,
live only in a temporary directory and are never printed.
"""
import argparse
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
KIT_WEB = ROOT.parent / "kit" / "web" / "assets" / "kit"
PAGES = ["overview", "devices", "transfers", "tunnels", "relays", "audit", "settings"]
LANGS = ["en", "zh-CN", "zh-TW", "ja", "ko", "es", "fr", "de", "pt-BR", "ru"]

# A stand-in for Google Identity Services: records what the page asks of it.
GIS_STUB = """
window.__g = { init: [], render: 0, prompt: 0, cancel: 0, disable: 0, themes: [], cb: null };
window.google = { accounts: { id: {
  initialize(o) { __g.init.push(o.client_id); __g.cb = o.callback; },
  renderButton(el, o) { __g.render++; __g.themes.push(o.theme); el.textContent = ""; const b = document.createElement("button"); b.className = "fake-google"; b.type = "button"; b.textContent = "Sign in with Google"; el.append(b); },
  prompt() { __g.prompt++; }, cancel() { __g.cancel++; }, disableAutoSelect() { __g.disable++; },
} } };
"""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    """A throw-away MeshBridge with platform and project origins on one port."""

    def __init__(self, workdir, port=None, admin=True):
        self.port = port or free_port()
        self.dir = Path(workdir)
        self.data = self.dir / "data"
        self.data.mkdir(parents=True, exist_ok=True)
        self.password = secrets.token_urlsafe(18)
        self.member_password = secrets.token_urlsafe(18)
        self.binary = self.dir / "server"
        self.plat = f"http://localhost:{self.port}"
        self.proj = f"http://127.0.0.1:{self.port}"
        self.log = open(self.dir / "server.log", "wb")
        self.proc = None
        self.env = dict(os.environ)
        p = self.port
        self.env.update({
            "MESH_ENV": "dev", "MESH_LISTEN": f"127.0.0.1:{p}", "MESH_GATEWAY_LISTEN": f"127.0.0.1:{free_port()}",
            "MESH_DATA_DIR": str(self.data), "MESH_MASTER_KEY_PATH": str(self.dir / "master.key"),
            "MESH_HEADSCALE_URL": "http://127.0.0.1:1", "MESH_BASE_URL": self.plat, "MESH_PROJECT_URL": self.proj,
            "MESH_SSO_ENABLED": "true", "MESH_SSO_DEV": "true", "MESH_SSO_ISSUER": self.plat,
            "MESH_SSO_CLIENTS": json.dumps({a: f"http://localhost:{p + 10 + i}/sso/callback" for i, a in enumerate(
                ["folio", "inkwell", "parley", "codebench", "echo", "hearthvale"])}),
        })
        if not os.environ.get("E2E_EMBED"):
            self.env["MESH_WEB_DIR"] = str(ROOT / "web")
            self.env["KIT_WEB_DIR"] = str(KIT_WEB)
        for k in ("MESH_GOOGLE_CLIENT_ID", "MESH_PROJECT_SSO"):
            self.env.pop(k, None)
        self.build()
        if admin:
            self.create_user("admin", self.password, admin=True)
            self.create_user("member", self.member_password, admin=False)

    def build(self):
        if os.environ.get("E2E_BINARY"):
            self.binary = Path(os.environ["E2E_BINARY"])
            return
        if os.environ.get("E2E_EMBED"):
            subprocess.run(["make", "sync-web"], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["go", "build", "-o", str(self.binary), "./cmd/meshbridge-server"], cwd=ROOT, check=True)

    def create_user(self, name, password, admin):
        subprocess.run([str(self.binary), "--data-dir", str(self.data), "--migrations", str(ROOT / "migrations"), "--create-admin", name],
                       input=password + "\n", text=True, env=self.env, cwd=ROOT, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not admin:
            con = sqlite3.connect(self.data / "meshbridge.sqlite", timeout=10)
            con.execute("UPDATE users SET role='user', email=?, email_verified=1 WHERE username=?", (f"{name}@example.test", name))
            con.commit()
            con.close()

    def start(self):
        self.proc = subprocess.Popen([str(self.binary), "--data-dir", str(self.data), "--migrations", str(ROOT / "migrations")],
                                     env=self.env, cwd=ROOT, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                self.call("GET", "/api/v1/surface")
                return self
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("server did not start; see " + str(self.dir / "server.log"))

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.log.close()

    def call(self, method, path, body=None, token=None, origin=None):
        req = urllib.request.Request((origin or self.plat) + path, method=method,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        if origin == self.proj or origin is None:
            req.add_header("Origin", origin or self.plat)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def token(self, user="admin"):
        status, out = self.call("POST", "/api/v1/auth/login", {"username": user, "password": self.password if user == "admin" else self.member_password})
        assert status == 200, (status, out)
        return out["token"]


# ───────────────────────── tiny harness ─────────────────────────
CASES = []


def case(fn):
    CASES.append(fn)
    return fn


class Env:
    def __init__(self, browser, server):
        self.b, self.s = browser, server
        self.contexts = []

    def page(self, scheme="light", width=1280, height=800, lang="en", gis=False, block_google=False):
        """`lang` is the app language (mb_lang); the app ignores the browser locale and defaults to Chinese."""
        # Idle keep-alive connections of forgotten contexts would exhaust the
        # server's 64-socket API limit; a case never revisits a page it left
        # more than a few pages ago.
        while len(self.contexts) >= 3:
            self.contexts.pop(0).close()
        ctx = self.b.new_context(viewport={"width": width, "height": height}, color_scheme=scheme, locale={"en": "en-US"}.get(lang, lang))
        ctx.add_init_script(f"try {{ if (!localStorage.getItem('mb_lang')) localStorage.setItem('mb_lang', {json.dumps(lang)}); }} catch (e) {{ /* about:blank has no storage */ }}")
        self.contexts.append(ctx)
        page = ctx.new_page()
        page.errors = []
        page.on("pageerror", lambda e: page.errors.append(str(e)))
        page.on("console", lambda m: page.errors.append("console: " + m.text) if m.type == "error" and "Failed to load resource" not in m.text else None)
        if gis:
            ctx.route("https://accounts.google.com/gsi/client", lambda r: r.fulfill(status=200, content_type="text/javascript", body=GIS_STUB))
        elif block_google:
            ctx.route("https://accounts.google.com/**", lambda r: r.abort())
        else:
            ctx.route("https://accounts.google.com/**", lambda r: r.abort())
        return page

    def release(self, page):
        """Close a page's browser context now (its keep-alive sockets count against the server)."""
        ctx = page.context
        if ctx in self.contexts:
            self.contexts.remove(ctx)
        ctx.close()

    def close(self):
        for c in self.contexts:
            try:
                c.close()
            except Exception:  # noqa: BLE001 - already closed
                pass
        self.contexts = []


def view(page):
    for name in ("landing", "auth", "app", "service"):
        if page.locator(f"#view-{name}").is_visible():
            return name
    return None


def panel(page):
    el = page.locator("#view-auth [data-panel]:not([hidden])")
    return el.first.get_attribute("data-panel") if el.count() else None


def wait_view(page, name, timeout=8000):
    page.wait_for_selector(f"#view-{name}:not([hidden])", timeout=timeout)


def wait_panel(page, name, timeout=8000):
    page.wait_for_selector(f'#view-auth [data-panel="{name}"]:not([hidden])', timeout=timeout)


def until(page, expr, arg=None, timeout=8000):
    """Poll a page expression. wait_for_function would eval() the predicate in the page,
    which the strict CSP (correctly) refuses."""
    end = time.time() + timeout / 1000
    while time.time() < end:
        if page.evaluate(expr, arg) if arg is not None else page.evaluate(expr):
            return
        page.wait_for_timeout(80)
    raise AssertionError(f"timed out waiting for: {expr}")


def settle(page, ms=250):
    page.wait_for_load_state("domcontentloaded")
    page.wait_for_timeout(ms)


def sign_in_form(page, user, password):
    page.fill('#form-login [name="username"]', user)
    page.fill('#form-login [name="password"]', password)
    page.click('#form-login [type="submit"]')


def seed_session(page, origin, token, lang=None):
    """Plant a session the way the page itself would, on one origin only."""
    page.goto(origin + "/#/login")
    page.evaluate("([t, l]) => { localStorage.setItem('mb_token', t); if (l) localStorage.setItem('mb_lang', l); }", [token, lang])


def token_of(page):
    return page.evaluate("localStorage.getItem('mb_token') || ''")


def check(cond, message):
    if not cond:
        raise AssertionError(message)


def eq(got, want, what):
    if got != want:
        raise AssertionError(f"{what}: got {got!r}, want {want!r}")


def has(text, needle, what):
    if needle not in text:
        raise AssertionError(f"{what}: {needle!r} not in {text!r}")


def set_google(server, client_id):
    status, _ = server.call("PUT", "/api/v1/setup/google", {"client_id": client_id}, token=server.token())
    assert status == 200, status


def route_json(page, pattern, status, code="", message="", method=None):
    def handler(route):
        if method and route.request.method != method:
            return route.continue_()
        route.fulfill(status=status, content_type="application/json", body=json.dumps({"code": code, "error": message}))
    page.route(pattern, handler)


# ───────────────────────── platform origin ─────────────────────────
@case
def platform_home_is_the_mineai_platform(E):
    p = E.page()
    p.goto(E.s.plat + "/")
    wait_view(p, "landing")
    has(p.title(), "MineAI", "platform title")
    check("MeshBridge" not in p.title(), "platform title must not carry the project brand: " + p.title())
    eq(p.locator("#view-landing .wordmark").first.inner_text(), "MineAI", "platform brand")
    check(p.locator("#view-app").is_hidden() and p.locator("#sidebar").is_hidden(), "no console shell on the platform origin")
    cards = p.locator(".project-card")
    eq(cards.count(), 8, "project cards")
    nav = p.locator("#site-nav").inner_text()
    check("MeshBridge" not in nav and "Manage" not in nav, "platform nav must not offer MeshBridge management: " + nav)
    foot = p.locator(".site-footer").inner_text()
    check("MeshBridge" not in foot and "Manage" not in foot, "platform footer must stay neutral: " + foot)
    for word in ("Devices", "Transfers", "Tunnels", "Relays", "Audit"):
        check(word not in p.locator("#view-landing").inner_text(), f"console feature {word!r} leaked onto the platform home")
    eq(p.locator("#acct a").first.get_attribute("href"), "#/login", "sign-in entry")
    check(not p.errors, f"page errors: {p.errors}")


@case
def platform_mesh_card_opens_the_project_origin(E):
    p = E.page()
    p.goto(E.s.plat + "/")
    wait_view(p, "landing")
    card = p.locator('.project-card[data-project-link="mb"]')
    eq(card.get_attribute("href"), E.s.proj + "/", "MeshBridge card target")
    for href in p.locator(".project-card").evaluate_all("els => els.map(e => e.getAttribute('href'))"):
        check("#/app" not in href and "/#/" not in href, "no card may point at a hash route: " + href)
    others = p.locator(".project-card:not([data-project-link])").evaluate_all("els => els.map(e => e.getAttribute('href'))")
    eq(sorted(others), sorted(f"https://{n}.mineai.top/" for n in ["folio", "inkwell", "parley", "codebench", "echo", "hearthvale", "toolshed"]), "other project links")
    with p.expect_navigation():
        card.click()
    eq(p.url.split("#")[0], E.s.proj + "/", "after clicking the MeshBridge card")
    wait_view(p, "auth")
    eq(panel(p), "login", "project without a session shows its own sign-in")


@case
def platform_project_menu_marks_the_right_project(E):
    for url, current in ((E.s.plat + "/", "MineAI"), (E.s.plat + "/#/login", "MineAI")):
        p = E.page()
        p.goto(url)
        settle(p, 400)
        p.locator('.nav-tools button[aria-haspopup="menu"]:visible, .auth-tools button[aria-haspopup="menu"]:visible').first.click()
        marked = p.locator('.pop [aria-current="page"]').all_inner_texts()
        check(len(marked) == 1 and marked[0].startswith("MineAI"), f"the platform must be the marked project on {url}: {marked}")
        links = p.locator(".pop a").evaluate_all("els => els.map(e => [e.textContent.trim(), e.getAttribute('href')])")
        d = dict(links)
        eq(d.get("MeshBridge"), "https://meshbridge.mineai.top/", "MeshBridge menu link")
        check(all(not h.startswith("https://mineai.top/#") for h in d.values()), "no menu link may point at a platform hash route")
        eq(d.get("MineAI platform"), "https://mineai.top/", "platform menu link")
    p = E.page()
    p.goto(E.s.proj + "/")
    wait_view(p, "auth")
    p.locator('#view-auth .auth-tools button[aria-haspopup="menu"]').click()
    eq(p.locator('.pop [aria-current="page"]').all_inner_texts(), ["MeshBridge"], "current project in menu on the project origin")


@case
def platform_login_is_the_platform_login(E):
    p = E.page()
    p.goto(E.s.plat + "/#/login")
    wait_panel(p, "login")
    eq(p.locator("#view-auth .wordmark").inner_text(), "MineAI", "brand on the platform sign-in")
    eq(p.locator('[data-panel="login"] .auth-title').inner_text(), "Welcome back", "platform sign-in title")
    has(p.title(), "· MineAI", "platform sign-in tab title")
    check("MeshBridge" not in p.title(), "platform sign-in title leaks the project: " + p.title())
    eq(p.locator('[data-art="kicker"]').inner_text().upper(), "MINEAI", "art kicker")
    check("≠" not in p.locator("#view-auth .auth-art").inner_text(), "the MeshBridge motto belongs to the project page")
    check(p.locator("#mb-sso").is_hidden(), "the platform must not offer to continue with itself")
    check(p.locator('[data-platform-home]').first.is_hidden(), "no way-back-to-platform link on the platform itself")
    eq(p.locator("#auth-foot-link").get_attribute("href"), "#/", "platform sign-in footer link")


@case
def platform_sign_in_and_out(E):
    p = E.page()
    p.goto(E.s.plat + "/#/login")
    wait_panel(p, "login")
    sign_in_form(p, "admin", E.s.password)
    wait_view(p, "landing")
    eq(p.url, E.s.plat + "/#/", "back on the platform home after signing in")
    p.wait_for_selector("#acct .acct-chip")
    has(p.locator("#acct").inner_text(), "admin", "account chip")
    check(token_of(p) != "", "platform session stored on the platform origin")
    # the project origin knows nothing about it
    q = E.page()
    q.goto(E.s.proj + "/")
    wait_view(q, "auth")
    eq(token_of(q), "", "project origin must not see the platform session")
    # visiting the sign-in page while signed in goes home
    p.goto(E.s.plat + "/#/login")
    wait_view(p, "landing")
    p.locator('#acct button[aria-label], #acct .icon-btn').first.click()
    p.wait_for_selector('#acct a[href="#/login"]')
    eq(token_of(p), "", "sign-out clears the platform session")
    st, _ = E.s.call("GET", "/api/v1/me", token=E.s.token())
    eq(st, 200, "other sessions of the same user are unaffected")


@case
def platform_legacy_console_links_move_to_the_project(E):
    token = E.s.token()
    for page_name in PAGES:
        p = E.page()
        seed_session(p, E.s.proj, token)
        p.goto("about:blank")
        p.goto(f"{E.s.plat}/#/app/{page_name}", wait_until="commit")
        wait_view(p, "app")
        eq(p.url, f"{E.s.proj}/#/app/{page_name}", f"legacy #/app/{page_name}")
        eq(p.locator(f'[data-page="{page_name}"]').is_visible(), True, f"{page_name} page visible")
        check(token_of(p) == token, "the project session is its own")
        check(p.locator("#sidebar").is_visible() or p.viewport_size["width"] < 981, "console shell on the project origin")
        p.go_back()
        eq(p.url, "about:blank", f"back from the project must not return to the legacy platform link ({page_name})")
        E.release(p)
    # without a session: the target survives the sign-in
    p = E.page()
    p.goto(E.s.plat + "/#/app/devices", wait_until="commit")
    wait_panel(p, "login")
    eq(p.url, E.s.proj + "/#/login", "legacy link without a session")
    sign_in_form(p, "admin", E.s.password)
    wait_view(p, "app")
    eq(p.url, E.s.proj + "/#/app/devices", "the legacy target is resumed after signing in")
    # odd forms are normalised, never echoed into the destination
    for odd, want in (("#/app", "#/app/overview"), ("#/app/", "#/app/overview"), ("#/app/nope", "#/app/overview"), ("#/app/devices?x=1", "#/app/devices"), ("#/setup", "#/app/overview")):
        q = E.page()
        seed_session(q, E.s.proj, token)
        q.goto("about:blank")
        q.goto(E.s.plat + "/" + odd, wait_until="commit")
        wait_view(q, "app" if "app" in want else "auth")
        eq(q.url, E.s.proj + "/" + want, f"legacy {odd}")
        E.release(q)


@case
def platform_old_path_deep_links(E):
    p = E.page()
    p.goto(E.s.plat + "/app", wait_until="commit")
    wait_panel(p, "login")
    eq(p.url.split("#")[0], E.s.proj + "/", "/app on the platform origin goes to the project")


# ───────────────────────── project origin ─────────────────────────
@case
def project_signed_out_shows_the_meshbridge_sign_in(E):
    p = E.page()
    p.goto(E.s.proj + "/")
    wait_panel(p, "login")
    check(p.url in (E.s.proj + "/", E.s.proj + "/#/", E.s.proj + "/#/login"), "project root stays on its own origin: " + p.url)
    eq(p.locator("#view-auth .wordmark").inner_text(), "MeshBridge", "project brand")
    eq(p.locator('[data-panel="login"] .auth-title').inner_text(), "Sign in to MeshBridge", "project sign-in title")
    has(p.title(), "· MeshBridge", "project tab title")
    check(view(p) == "auth" and p.locator("#view-landing").is_hidden(), "the project origin never shows the platform home")
    back = p.locator("#view-auth .back-link")
    eq(back.get_attribute("href"), E.s.plat + "/", "way back to the platform")
    check("MineAI" in back.inner_text(), "back link names the platform")
    check(p.locator("#mb-sso").is_visible(), "continue with MineAI is offered")
    check("≠" in p.locator('[data-art="kicker"]').inner_text(), "project art keeps the control/data motto")
    for field in ("username", "password"):
        check(p.locator(f'#form-login [name="{field}"]').is_visible(), f"{field} field")
    check(p.locator('[data-reg-link]').is_visible(), "registration link when sign-up is open")
    check(not p.errors, f"page errors: {p.errors}")
    p.goto(E.s.proj + "/#/projects")  # an in-page anchor is not a route on the project
    wait_panel(p, "login")


@case
def project_password_sign_in_enters_the_console(E):
    p = E.page()
    p.goto(E.s.proj + "/")
    wait_panel(p, "login")
    sign_in_form(p, "admin", E.s.password)
    wait_view(p, "app")
    eq(p.url, E.s.proj + "/#/app/overview", "console after sign-in")
    check(p.title().endswith("· MeshBridge"), "console title " + p.title())
    eq(p.locator("#sidebar .wordmark").inner_text(), "MeshBridge", "console brand")
    eq(p.locator("#sidebar [data-platform-home]").get_attribute("href"), E.s.plat + "/", "return to the platform")
    check("Overview" in p.locator("#sidebar").inner_text(), "console navigation")
    nav = p.locator("#sidebar .sb-nav a").evaluate_all("els => els.map(e => e.getAttribute('href'))")
    eq(nav, [f"#/app/{n}" for n in PAGES], "console routes stay project-internal hashes")
    p.reload()
    wait_view(p, "app")
    eq(p.url, E.s.proj + "/#/app/overview", "refresh keeps the console")
    # a signed-in visit to the sign-in route returns to the console
    p.goto(E.s.proj + "/#/login")
    wait_view(p, "app")
    eq(p.url, E.s.proj + "/#/app/overview", "sign-in route while signed in")
    # an ordinary member sees no administrator settings
    q = E.page()
    q.goto(E.s.proj + "/#/login")
    wait_panel(q, "login")
    sign_in_form(q, "member", E.s.member_password)
    wait_view(q, "app")
    q.goto(E.s.proj + "/#/app/settings")
    q.wait_for_selector('[data-page="settings"]:not([hidden])')
    check(q.locator('[data-page="settings"] [data-admin]').evaluate_all("els => els.every(e => e.hidden)"), "administrator settings hidden from members")


@case
def project_failed_sign_in_keeps_the_target(E):
    p = E.page()
    p.goto(E.s.proj + "/#/app/audit")
    wait_panel(p, "login")
    sign_in_form(p, "admin", "definitely-not-the-password")
    p.wait_for_selector('#form-login [data-role="err"]:not([hidden])')
    eq(p.locator('#form-login [data-role="err-text"]').inner_text(), "Incorrect email, username or password.", "wrong password wording")
    eq(panel(p), "login", "still on the sign-in")
    p.fill('#form-login [name="password"]', E.s.password)
    p.click('#form-login [type="submit"]')
    wait_view(p, "app")
    eq(p.url, E.s.proj + "/#/app/audit", "the target survived a failed attempt")
    # a reload on the sign-in page keeps the target too
    q = E.page()
    q.goto(E.s.proj + "/#/app/relays")
    wait_panel(q, "login")
    q.reload()
    wait_panel(q, "login")
    sign_in_form(q, "admin", E.s.password)
    wait_view(q, "app")
    eq(q.url, E.s.proj + "/#/app/relays", "target survives a reload of the sign-in page")


@case
def project_expired_session_returns_to_the_same_page(E):
    p = E.page()
    seed_session(p, E.s.proj, E.s.token())
    p.goto(E.s.proj + "/#/app/transfers")
    wait_view(p, "app")
    p.evaluate("localStorage.setItem('mb_token', 'revoked-or-expired')")
    p.goto(E.s.proj + "/#/app/devices")
    wait_panel(p, "login")
    eq(p.url, E.s.proj + "/#/login", "expired session lands on the sign-in")
    sign_in_form(p, "admin", E.s.password)
    wait_view(p, "app")
    eq(p.url, E.s.proj + "/#/app/devices", "back on the page that was open")
    # expiry noticed mid-session by an API call
    q = E.page()
    t = E.s.token()
    seed_session(q, E.s.proj, t)
    q.goto(E.s.proj + "/#/app/audit")
    wait_view(q, "app")
    E.s.call("POST", "/api/v1/auth/logout", {}, token=t)
    q.click('#sidebar a[data-nav="devices"]')
    wait_panel(q, "login")
    has(q.locator('[data-panel="login"] [data-role="notice-text"]').inner_text(), "expired", "expiry notice")
    sign_in_form(q, "admin", E.s.password)
    wait_view(q, "app")
    eq(q.url, E.s.proj + "/#/app/devices", "resumed after mid-session expiry")


@case
def project_sign_out_leaves_nothing_behind(E):
    p = E.page()
    seed_session(p, E.s.proj, E.s.token())
    p.goto(E.s.proj + "/#/app/settings")
    wait_view(p, "app")
    p.click('[data-page="settings"] [data-logout]')
    wait_panel(p, "login")
    eq(token_of(p), "", "token cleared")
    eq(p.evaluate("sessionStorage.getItem('mb_resume')"), None, "no stale resume target")
    p.go_back()
    p.wait_for_timeout(500)
    check(view(p) != "app", "back after sign-out must not show the console")
    p.goto(E.s.proj + "/#/app/devices")
    wait_panel(p, "login")
    p.reload()
    wait_panel(p, "login")
    eq(p.evaluate("typeof google !== 'undefined'"), False, "no Google client loaded when Google is off")


@case
def project_routes_do_not_loop_between_register_forgot_login(E):
    p = E.page()
    p.goto(E.s.proj + "/#/login")
    wait_panel(p, "login")
    seen = []
    p.on("framenavigated", lambda f: seen.append(f.url))
    for target, want in (("#/register", "register"), ("#/forgot", "forgot"), ("#/login", "login"), ("#/register", "register"), ("#/login", "login")):
        p.evaluate("h => { location.hash = h }", target)
        wait_panel(p, want)
        eq(p.url, E.s.proj + "/" + target, f"hash for {want}")
    p.click('[data-panel="login"] a[href="#/register"]')
    wait_panel(p, "register")
    p.click('[data-panel="register"] a[href="#/login"]')
    wait_panel(p, "login")
    p.click('[data-panel="login"] a[href="#/forgot"]')
    wait_panel(p, "forgot")
    p.click('[data-panel="forgot"] a[href="#/login"]')
    wait_panel(p, "login")
    check(len(seen) < 40, f"navigation churn suggests a loop: {len(seen)}")


@case
def project_back_and_forward_keep_view_and_hash_in_step(E):
    p = E.page()
    seed_session(p, E.s.proj, E.s.token())
    p.goto(E.s.proj + "/#/app/overview")
    wait_view(p, "app")
    order = ["devices", "audit", "settings", "tunnels"]
    for name in order:
        p.click(f'#sidebar a[data-nav="{name}"]')
        p.wait_for_selector(f'[data-page="{name}"]:not([hidden])')
    for name in ["settings", "audit", "devices", "overview"]:
        p.go_back()
        p.wait_for_selector(f'[data-page="{name}"]:not([hidden])')
        eq(p.url, f"{E.s.proj}/#/app/{name}", f"hash after back to {name}")
        eq(p.locator(".sb-nav a[aria-current='page']").get_attribute("data-nav"), name, "highlighted nav item")
        check(p.title().endswith("· MeshBridge"), "title after back: " + p.title())
    for name in order[:2]:
        p.go_forward()
        p.wait_for_selector(f'[data-page="{name}"]:not([hidden])')
        eq(p.url, f"{E.s.proj}/#/app/{name}", f"hash after forward to {name}")
    check(not p.errors, f"page errors: {p.errors}")


@case
def project_mobile_drawer(E):
    p = E.page(width=375, height=800)
    seed_session(p, E.s.proj, E.s.token())
    p.goto(E.s.proj + "/#/app/overview")
    wait_view(p, "app")
    check(p.locator("#sidebar").bounding_box()["x"] < 0, "sidebar starts off-screen on a phone")
    eq(p.get_attribute("#btn-menu", "aria-expanded"), "false", "menu button state")
    p.click("#btn-menu")
    p.wait_for_timeout(450)
    eq(p.get_attribute("#btn-menu", "aria-expanded"), "true", "menu button state when open")
    check(p.locator("#sidebar").bounding_box()["x"] >= -1, "sidebar visible when open")
    check(p.evaluate("document.body.classList.contains('nav-lock')"), "page behind does not scroll")
    check(p.evaluate("document.activeElement.closest('#sidebar') !== null"), "focus moves into the drawer")
    p.keyboard.press("Escape")
    p.wait_for_timeout(450)
    eq(p.get_attribute("#btn-menu", "aria-expanded"), "false", "Escape closes")
    check(p.evaluate("!document.body.classList.contains('nav-lock')"), "scroll lock released")
    check(p.evaluate("document.activeElement.id") == "btn-menu", "focus returns to the menu button")
    p.click("#btn-menu")
    p.wait_for_timeout(450)
    p.mouse.click(350, 400)  # the dimmed page
    p.wait_for_timeout(450)
    eq(p.get_attribute("#btn-menu", "aria-expanded"), "false", "scrim closes")
    p.click("#btn-menu")
    p.wait_for_timeout(450)
    p.click('#sidebar a[data-nav="devices"]')
    p.wait_for_selector('[data-page="devices"]:not([hidden])')
    p.wait_for_timeout(450)
    eq(p.get_attribute("#btn-menu", "aria-expanded"), "false", "choosing a page closes the drawer")
    p.click("#btn-menu")
    p.wait_for_timeout(450)
    p.click('#sidebar a[data-nav="devices"]')  # the current page: no hashchange, must still close
    p.wait_for_timeout(450)
    eq(p.get_attribute("#btn-menu", "aria-expanded"), "false", "choosing the current page closes the drawer")
    p.go_back()
    p.wait_for_selector('[data-page="overview"]:not([hidden])')
    eq(p.get_attribute("#btn-menu", "aria-expanded"), "false", "browser back leaves the drawer closed")
    p.click("#btn-menu")
    p.set_viewport_size({"width": 1280, "height": 800})
    p.wait_for_timeout(450)
    check(p.evaluate("!document.body.classList.contains('nav-lock')"), "resizing to desktop releases the lock")
    check(p.locator("#sidebar").bounding_box()["x"] >= 0, "desktop sidebar is in place")


# ───────────────────────── faults and wording ─────────────────────────
@case
def faults_are_never_sign_outs(E):
    token = E.s.token()
    for label, handler in (("503", lambda r: r.fulfill(status=503, content_type="application/json", body='{"code":"unavailable","error":"x"}')),
                           ("500", lambda r: r.fulfill(status=500, content_type="application/json", body='{"code":"server","error":"boom"}')),
                           ("network", lambda r: r.abort())):
        p = E.page()
        seed_session(p, E.s.proj, token)
        p.route("**/api/v1/me", handler)
        p.goto(E.s.proj + "/#/app/devices")
        wait_view(p, "service")
        check(view(p) == "service" and p.locator("#view-auth").is_hidden(), f"{label}: a fault must not show the sign-in")
        eq(token_of(p), token, f"{label}: the session is kept")
        txt = p.locator("#service-text").inner_text()
        if label == "network":
            has(txt, "reach the server", "network wording")
        else:
            has(txt, "Nothing was signed out", f"{label} wording")
        check("MeshBridge" in p.title() or "unavailable" in p.title().lower(), "service title " + p.title())
        p.unroute("**/api/v1/me")
        p.click("#service-retry")
        wait_view(p, "app")
        eq(p.url, E.s.proj + "/#/app/devices", f"{label}: retry returns to the page")
    # the platform's account chip behaves the same
    q = E.page()
    seed_session(q, E.s.plat, token)
    q.route("**/api/v1/me", lambda r: r.fulfill(status=503, content_type="application/json", body='{"code":"unavailable","error":"x"}'))
    q.goto(E.s.plat + "/")
    wait_view(q, "landing")
    q.wait_for_selector("#acct .btn-quiet")
    check(q.locator('#acct a[href="#/login"]').count() == 0, "a fault must not claim the visitor is signed out")
    eq(token_of(q), token, "platform session kept through a fault")
    # no surface answer at all
    r = E.page()
    r.route("**/api/v1/surface", lambda route: route.fulfill(status=502, content_type="application/json", body='{"code":"bad_gateway","error":"x"}'))
    r.goto(E.s.proj + "/")
    wait_view(r, "service")
    r.unroute("**/api/v1/surface")
    r.click("#service-retry")
    wait_panel(r, "login")
    # no setup status and nothing cached: a fault, not a login page
    s = E.page()
    s.route("**/api/v1/setup/status", lambda route: route.abort())
    s.goto(E.s.proj + "/")
    wait_view(s, "service")


@case
def sign_in_errors_are_worded_per_status(E):
    cases = [
        (401, "unauthorized", "bad credentials", "Incorrect email, username or password."),
        (403, "forbidden", "nope", "You don't have permission to do that."),
        (429, "rate_limited", "too many attempts; retry later", "Too many attempts. Please wait a few minutes."),
        (500, "server", "internal error", "The server hit an error. Please try again."),
        (503, "unavailable", "login temporarily unavailable", "The service is temporarily unavailable. Please try again shortly."),
    ]
    for status, code, message, want in cases:
        p = E.page()
        p.goto(E.s.proj + "/#/login")
        wait_panel(p, "login")
        route_json(p, "**/api/v1/auth/login", status, code, message)
        sign_in_form(p, "admin", "irrelevant-password")
        p.wait_for_selector('#form-login [data-role="err"]:not([hidden])')
        eq(p.locator('#form-login [data-role="err-text"]').inner_text(), want, f"HTTP {status}")
        eq(panel(p), "login", f"HTTP {status} keeps the sign-in")
    p = E.page()
    p.goto(E.s.proj + "/#/login")
    wait_panel(p, "login")
    p.route("**/api/v1/auth/login", lambda r: r.abort())
    sign_in_form(p, "admin", "irrelevant-password")
    p.wait_for_selector('#form-login [data-role="err"]:not([hidden])')
    eq(p.locator('#form-login [data-role="err-text"]').inner_text(), "Can't reach the server. Check your connection and try again.", "network failure")
    p.unroute("**/api/v1/auth/login")
    sign_in_form(p, "admin", E.s.password)
    wait_view(p, "app")


# ───────────────────────── Google ─────────────────────────
@case
def google_hidden_when_not_configured(E):
    set_google(E.s, "")
    for origin, hash_ in ((E.s.plat, "#/login"), (E.s.proj, "#/login")):
        p = E.page(gis=True)
        p.goto(f"{origin}/{hash_}")
        wait_panel(p, "login")
        settle(p, 400)
        check(p.locator("#mb-gsign").is_hidden(), f"{origin}: Google block must be hidden")
        eq(p.evaluate("typeof window.__g"), "undefined", f"{origin}: the Google script must not even load")
    p = E.page(gis=True)
    p.goto(E.s.plat + "/#/login")
    wait_panel(p, "login")
    check(p.locator("#alt-auth").is_hidden(), "platform: no alternative methods block at all")
    sign_in_form(p, "admin", E.s.password)
    wait_view(p, "landing")  # password sign-in is unaffected


@case
def google_shown_once_when_configured(E):
    cid = "1234567890-abcdef.apps.googleusercontent.com"
    set_google(E.s, cid)
    try:
        for origin in (E.s.plat, E.s.proj):
            p = E.page(gis=True)
            p.goto(f"{origin}/#/login")
            wait_panel(p, "login")
            p.wait_for_selector(".gsign-btn .fake-google")
            g = p.evaluate("window.__g")
            eq(g["init"], [cid], f"{origin}: one initialize with the configured client")
            eq(g["render"], 1, f"{origin}: one button")
            eq(g["prompt"], 1, f"{origin}: one One Tap prompt")
            check(p.locator("#mb-gsign").is_visible() and p.locator("#alt-auth").is_visible(), f"{origin}: block visible")
            eq(p.locator(".gsign-btn .fake-google").count(), 1, f"{origin}: exactly one button in the DOM")
            # theme and language changes redraw the button but never prompt again
            before = p.evaluate("window.__g.prompt")
            for _ in range(3):
                p.click("#view-auth .theme-toggle")
                p.wait_for_timeout(150)
            g = p.evaluate("window.__g")
            eq(g["prompt"], before, f"{origin}: theme switches must not re-prompt")
            eq(p.locator(".gsign-btn .fake-google").count(), 1, f"{origin}: no duplicate buttons after theme switches")
            check(g["render"] >= 2 and len(set(g["themes"])) == 2, f"{origin}: the button follows the theme: {g['themes']}")
            eq(g["init"], [cid], f"{origin}: still a single initialize")
            # leaving the sign-in page withdraws One Tap
            p.evaluate("location.hash = '#/register'")
            wait_panel(p, "register")
            check(p.evaluate("window.__g.cancel") >= 1, f"{origin}: leaving the sign-in cancels One Tap")
            p.evaluate("location.hash = '#/login'")
            wait_panel(p, "login")
            until(p, "window.__g.prompt === 2")
    finally:
        set_google(E.s, "")


@case
def google_unreachable_is_explained_and_password_still_works(E):
    set_google(E.s, "1234567890-abcdef.apps.googleusercontent.com")
    try:
        p = E.page(block_google=True)
        p.goto(E.s.proj + "/#/login")
        wait_panel(p, "login")
        p.wait_for_selector('[data-role="gsign-load"]:not([hidden])', timeout=15000)
        has(p.locator('[data-role="gsign-load"]').inner_text(), "Google sign-in couldn't load", "unreachable wording")
        check(p.locator('[data-role="gsign-retry"]').is_visible(), "retry offered")
        sign_in_form(p, "admin", E.s.password)
        wait_view(p, "app")
    finally:
        set_google(E.s, "")


@case
def google_refusals_are_explained(E):
    cid = "1234567890-abcdef.apps.googleusercontent.com"
    set_google(E.s, cid)
    try:
        wanted = [
            (503, "google_not_configured", "Google sign-in isn't set up on this server."),
            (503, "google_unavailable", "Google sign-in is temporarily unavailable. Try again in a moment, or use your password."),
            (401, "google_invalid", "We couldn't verify that Google sign-in. Please try again."),
            (403, "google_email_unverified", "Your Google account's email isn't verified. Verify it with Google, or sign in with your password."),
            (403, "account_disabled", "This account has been disabled. Contact an administrator."),
            (403, "registration_closed", "Public sign-up is closed on this server."),
            (409, "google_link_required", "An account with this email already exists. Sign in with its password, then link Google in Settings."),
            (409, "google_already_linked", "This account, or this Google account, is already linked to another one."),
            (429, "rate_limited", "Too many attempts. Please wait a few minutes."),
        ]
        for status, code, text in wanted:
            p = E.page(gis=True)
            route_json(p, "**/api/v1/auth/google", status, code, "x")
            p.goto(E.s.proj + "/#/login")
            wait_panel(p, "login")
            p.wait_for_selector(".gsign-btn .fake-google")
            p.evaluate("window.__g.cb({credential: 'forged.credential.value'})")
            p.wait_for_selector('[data-role="gsign-err"]:not([hidden])')
            eq(p.locator('[data-role="gsign-err-text"]').inner_text(), text, f"{code}")
            eq(panel(p), "login", f"{code}: stays on the sign-in")
        # the real server: a forged credential is refused as invalid, never signs in
        p = E.page(gis=True)
        p.goto(E.s.proj + "/#/login")
        wait_panel(p, "login")
        p.wait_for_selector(".gsign-btn .fake-google")
        p.evaluate("window.__g.cb({credential: 'forged.credential.value'})")
        p.wait_for_selector('[data-role="gsign-err"]:not([hidden])')
        has(p.locator('[data-role="gsign-err-text"]').inner_text(), "couldn't verify", "real server, forged credential")
        eq(token_of(p), "", "a forged credential must not create a session")
    finally:
        set_google(E.s, "")


@case
def google_sign_in_resumes_the_target(E):
    cid = "1234567890-abcdef.apps.googleusercontent.com"
    set_google(E.s, cid)
    try:
        def serve_session(page):
            tok = E.s.token()
            page.route("**/api/v1/auth/google", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps({"token": tok, "expires_at": int(time.time()) + 3600})))
        # the page that was asked for survives a Google sign-in
        p = E.page(gis=True)
        serve_session(p)
        p.goto(E.s.proj + "/#/app/audit")
        wait_panel(p, "login")
        p.wait_for_selector(".gsign-btn .fake-google")
        p.evaluate("window.__g.cb({credential: 'stand-in'})")
        wait_view(p, "app")
        eq(p.url, E.s.proj + "/#/app/audit", "Google sign-in resumes the requested page")
        E.release(p)
        # a project waiting for the platform is continued after signing in to the platform with Google
        q = E.page(gis=True)
        serve_session(q)
        q.goto(E.s.proj + "/")
        wait_panel(q, "login")
        q.click("#mb-sso")
        q.wait_for_url(re.compile(re.escape(E.s.plat) + r"/#/sso\?"))
        wait_panel(q, "login")
        q.wait_for_selector(".gsign-btn .fake-google")
        q.evaluate("window.__g.cb({credential: 'stand-in'})")
        q.wait_for_url(re.compile(re.escape(E.s.proj) + r"/#/app/overview"), timeout=15000)
        wait_view(q, "app")
        st, me = E.s.call("GET", "/api/v1/me", token=token_of(q))
        eq((st, me.get("sso")), (200, True), "the project session came from the platform sign-in")
    finally:
        set_google(E.s, "")


@case
def project_console_and_platform_round_trip(E):
    p = E.page()
    token = E.s.token()
    seed_session(p, E.s.proj, token)
    p.goto(E.s.proj + "/#/app/tunnels")
    wait_view(p, "app")
    p.click("#sidebar [data-platform-home]")
    p.wait_for_url(E.s.plat + "/")
    wait_view(p, "landing")
    eq(token_of(p), "", "the platform origin holds no project session")
    p.click('.project-card[data-project-link="mb"]')
    p.wait_for_url(re.compile(re.escape(E.s.proj)))
    wait_view(p, "app")  # the project's own session is still there
    eq(p.url, E.s.proj + "/#/app/overview", "back in the console")
    eq(token_of(p), token, "the project session survived the visit to the platform")
    # a refresh on each surface keeps its own view
    p.reload()
    wait_view(p, "app")
    p.goto(E.s.plat + "/")
    wait_view(p, "landing")
    p.reload()
    wait_view(p, "landing")
    p.goto(E.s.plat + "/#/login")
    wait_panel(p, "login")
    p.reload()
    wait_panel(p, "login")


@case
def google_sign_out_withdraws_auto_select(E):
    set_google(E.s, "1234567890-abcdef.apps.googleusercontent.com")
    try:
        p = E.page(gis=True)
        p.goto(E.s.proj + "/#/login")
        wait_panel(p, "login")
        p.wait_for_selector(".gsign-btn .fake-google")
        sign_in_form(p, "admin", E.s.password)
        wait_view(p, "app")
        p.goto(E.s.proj + "/#/app/settings")
        p.wait_for_selector('[data-page="settings"]:not([hidden])')
        eq(p.evaluate("window.__g.disable"), 0, "not before sign-out")
        p.click('[data-page="settings"] [data-logout]')
        wait_panel(p, "login")
        check(p.evaluate("window.__g.disable") >= 1, "sign-out must call disableAutoSelect")
        # the platform sign-out does the same
        q = E.page(gis=True)
        seed_session(q, E.s.plat, E.s.token())
        q.goto(E.s.plat + "/#/login")
        wait_view(q, "landing")
        q.goto(E.s.plat + "/#/login")  # signed in: goes home
        q.evaluate(GIS_STUB)
        q.click("#acct .icon-btn")
        q.wait_for_selector('#acct a[href="#/login"]')
        check(q.evaluate("window.__g.disable") >= 1, "platform sign-out must call disableAutoSelect")
    finally:
        set_google(E.s, "")


@case
def settings_report_google_source_and_origins(E):
    token = E.s.token()
    p = E.page()
    seed_session(p, E.s.proj, token)
    set_google(E.s, "")
    p.goto(E.s.proj + "/#/app/settings")
    p.wait_for_selector('[data-page="settings"]:not([hidden])')
    p.wait_for_selector("#gset-origins li")
    origins = p.locator("#gset-origins code").all_inner_texts()
    eq(origins, [E.s.plat, E.s.proj], "origins to authorize in Google Cloud")
    has(p.locator("#gset-source").inner_text(), "Not configured", "source when unset (explicit disable here)")
    p.fill("#set-google-client", "not-a-client-id")
    p.click("#set-google-save")
    p.wait_for_selector(".toast, .toasts > *")
    check("Google client ID" in p.locator(".toasts").inner_text() or "looks" in p.locator(".toasts").inner_text() or "Google" in p.locator(".toasts").inner_text(), "bad client id is refused with a reason")
    cid = "9876543210-zyxwvu.apps.googleusercontent.com"
    p.fill("#set-google-client", cid)
    p.click("#set-google-save")
    until(p, "document.querySelector('#gset-status').textContent.includes('On')")
    has(p.locator("#gset-source").inner_text(), "Saved here", "source after saving")
    st, body = E.s.call("GET", "/api/v1/setup/status")
    eq(body.get("google_client_id"), cid, "a saved client id is live without a restart")
    set_google(E.s, "")
    # a member only sees their own Google link row, never the configuration
    q = E.page()
    seed_session(q, E.s.proj, E.s.token("member"))
    q.goto(E.s.proj + "/#/app/settings")
    q.wait_for_selector('[data-page="settings"]:not([hidden])')
    check(q.locator("#gset-origins").is_hidden() or not q.locator("#set-google-client").is_visible(), "configuration is administrator-only")


# ───────────────────────── languages, themes, titles ─────────────────────────
@case
def language_switch_keeps_brand_and_titles(E):
    token = E.s.token()
    brands = {"platform": "MineAI", "project": "MeshBridge"}
    for lang in LANGS:
        try:
            language_case(E, lang)
        except Exception as exc:  # noqa: BLE001 - name the language that failed
            raise AssertionError(f"[{lang}] {exc}") from exc
    # signed-in console titles follow the language too
    p = E.page()
    seed_session(p, E.s.proj, token)
    p.goto(E.s.proj + "/#/app/devices")
    wait_view(p, "app")
    has(p.title(), "Devices · MeshBridge", "console title (en)")
    p.evaluate("localStorage.setItem('mb_lang', 'zh-CN')")
    p.reload()
    wait_view(p, "app")
    eq(p.title(), "设备 · MeshBridge", "console title (zh-CN)")


def language_case(E, lang):
    brands = {"platform": "MineAI", "project": "MeshBridge"}
    if True:
        p = E.page(lang=lang)
        for surface, origin, hash_, view_name in (("platform", E.s.plat, "#/", "landing"), ("platform", E.s.plat, "#/login", "auth"),
                                                  ("project", E.s.proj, "#/login", "auth")):
            p.goto(origin + "/" + hash_)
            p.reload()
            wait_view(p, view_name)
            settle(p, 250)
            title = p.title()
            check(title.strip() != "" and "undefined" not in title, f"{lang}: title {title!r}")
            if view_name == "auth":
                has(title, brands[surface], f"{lang}/{surface} auth title brand")
                other = brands["project" if surface == "platform" else "platform"]
                check(other not in title.replace(brands[surface], ""), f"{lang}/{surface}: title carries the other product: {title}")
                eq(p.locator("#view-auth .wordmark").inner_text(), brands[surface], f"{lang}/{surface} brand text")
            else:
                has(title, "MineAI", f"{lang} platform home title")
            eq(p.evaluate("document.documentElement.lang"), lang, f"{lang}: html lang")
            check(not re.search(r"\b(auth|portal|mb|gset|glink|err|service|art|common)\.[A-Za-z]+\b", p.locator("body").inner_text()), f"{lang}/{surface}: untranslated key visible")
        # a live switch from the picker re-renders the title in place
        p.goto(E.s.proj + "/#/login")
        wait_panel(p, "login")
        before = p.title()
        other_lang = "en" if lang != "en" else "de"
        p.click("#view-auth .lp-btn")
        p.click(f'#view-auth .lp-opt[data-lang="{other_lang}"]')
        until(p, "t => document.documentElement.lang === t", other_lang)
        after = p.title()
        has(after, "· MeshBridge", f"live switch {lang}->{other_lang}")
        check(after != before or lang == other_lang, "title follows the language")
        check(not p.errors, f"{lang}: page errors {p.errors}")
        E.release(p)


@case
def theme_switch_is_stable_on_every_view(E):
    token = E.s.token()
    for url, view_name in ((E.s.plat + "/", "landing"), (E.s.plat + "/#/login", "auth"), (E.s.proj + "/#/login", "auth")):
        p = E.page()
        p.goto(url)
        wait_view(p, view_name)
        for _ in range(3):
            p.click(f"#view-{view_name} .theme-toggle")
            p.wait_for_timeout(100)
        check(p.evaluate("document.documentElement.getAttribute('data-theme')") in ("dark", "light"), f"{url}: theme attribute")
        eq(p.locator(f"#view-{view_name} .theme-toggle").count(), 1, f"{url}: one theme toggle")
    for scheme in ("light", "dark"):
        p = E.page(scheme=scheme)
        p.goto(E.s.plat + "/")
        wait_view(p, "landing")
        bg = p.evaluate("getComputedStyle(document.body).backgroundColor")
        check(bg != "rgba(0, 0, 0, 0)", "body background is explicit")
        eq(p.evaluate("matchMedia('(prefers-color-scheme: dark)').matches"), scheme == "dark", "scheme emulation")


# ───────────────────────── platform sign-in for the project (PKCE) ─────────────────────────
@case
def sso_continue_with_mineai_end_to_end(E):
    s = E.s
    p = E.page()
    urls = []
    p.on("framenavigated", lambda f: urls.append(f.url) if f == p.main_frame else None)
    p.goto(s.proj + "/")
    wait_panel(p, "login")
    p.click("#mb-sso")
    p.wait_for_url(re.compile(re.escape(s.plat) + r"/#/sso\?"))
    q = p.url
    for key in ("client_id=meshbridge", "code_challenge_method=S256", "state=", "code_challenge="):
        has(q, key, "authorize URL")
    for secret_word in ("verifier", "token", "password"):
        check(secret_word not in q.lower(), f"the authorize URL must not carry {secret_word}: {q}")
    wait_panel(p, "login")  # not signed in on the platform: sign in there, then continue
    has(p.locator('[data-panel="login"] [data-role="notice-text"]').inner_text(), "MineAI", "continue notice")
    eq(p.locator("#view-auth .wordmark").inner_text(), "MineAI", "the platform asks, in its own brand")
    sign_in_form(p, "admin", s.password)
    p.wait_for_url(re.compile(re.escape(s.proj) + r"/#/app/overview"))
    wait_view(p, "app")
    proj_token = token_of(p)
    check(proj_token != "", "the project session exists on the project origin")
    st, me = s.call("GET", "/api/v1/me", token=proj_token)
    eq((st, me.get("sso"), me.get("role")), (200, True, "admin"), "project session came from the platform")
    # the platform's own session is a different credential on a different origin
    other = p.context.new_page()
    other.goto(s.plat + "/")
    wait_view(other, "landing")
    plat_token = token_of(other)
    check(plat_token and plat_token != proj_token, "separate credentials per origin")
    check(plat_token not in p.url and proj_token not in other.url, "no credential in any URL")
    other.close()
    # no credential ever travels in a URL, and the code is gone from the address bar
    for u in urls:
        check(proj_token not in u, "project token leaked into a URL: " + u.split("?")[0])
        check("access_token" not in u, "grant leaked into a URL")
    check("code=" not in p.url and "state=" not in p.url, "single-use parameters removed from the final URL: " + p.url)
    # cookies never carry a session
    cookies = p.context.cookies()
    check(all(proj_token not in c["value"] for c in cookies), "no cookie carries a session token")
    check(not [c for c in cookies if c["name"].startswith("mb_") or "token" in c["name"].lower()], f"unexpected session cookies: {[c['name'] for c in cookies]}")
    for c in cookies:
        if "sso" in c["name"]:
            check(c["httpOnly"], "the flow cookie must be HttpOnly")
    # second time: the platform session now exists in this browser, so no password is asked
    p.goto(s.proj + "/#/app/settings")
    p.wait_for_selector('[data-page="settings"]:not([hidden])')
    p.wait_for_selector("#logout-platform:not([hidden])")  # a platform-derived session may end the platform session too
    p.click('[data-page="settings"] [data-logout]')
    wait_panel(p, "login")
    eq(token_of(p), "", "project sign-out clears the project session")
    p.click("#mb-sso")
    p.wait_for_url(re.compile(re.escape(s.proj) + r"/#/app/overview"), timeout=15000)
    wait_view(p, "app")
    second = token_of(p)
    check(second and second != proj_token, "a fresh project session, no password prompt")
    # "also sign out of MineAI": revokes the project session, then the platform's
    p.goto(s.proj + "/#/app/settings")
    p.wait_for_selector("#logout-platform:not([hidden])")
    p.click("#logout-platform")
    p.wait_for_url(re.compile(re.escape(s.plat)), timeout=15000)
    wait_view(p, "landing")
    p.wait_for_selector('#acct a[href="#/login"]')
    eq(s.call("GET", "/api/v1/me", token=second)[0], 401, "project session ended")
    eq(token_of(p), "", "platform session cleared")


@case
def sso_platform_logout_ends_the_project_session_at_once(E):
    s = E.s
    p = E.page()
    p.goto(s.plat + "/#/login")
    wait_panel(p, "login")
    sign_in_form(p, "admin", s.password)
    wait_view(p, "landing")
    plat_token = token_of(p)
    # the same browser continues into the project
    p.goto(s.proj + "/")
    wait_panel(p, "login")
    p.click("#mb-sso")
    p.wait_for_url(re.compile(re.escape(s.proj) + r"/#/app/overview"), timeout=15000)
    proj_token = token_of(p)
    check(proj_token and proj_token != plat_token, "separate credentials per origin")
    eq(s.call("GET", "/api/v1/me", token=proj_token)[0], 200, "project session works")
    # platform sign-out (from the platform origin) revokes the derived session
    p.goto(s.plat + "/")
    wait_view(p, "landing")
    p.click("#acct .icon-btn")
    p.wait_for_selector('#acct a[href="#/login"]')
    eq(s.call("GET", "/api/v1/me", token=proj_token)[0], 401, "the project session died with the platform session")
    p.goto(s.proj + "/#/app/devices")
    wait_panel(p, "login")
    eq(token_of(p), "", "the project drops the dead session")


@case
def sso_callback_garbage_is_explained_and_scrubbed(E):
    s = E.s
    for qs in ("?code=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&state=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&iss=" + s.plat, "?code=x", "", "?code=a&code=b&state=c&iss=d&extra=1"):
        p = E.page()
        seen = []
        p.on("framenavigated", lambda f: seen.append(f.url) if f == p.main_frame else None)
        p.goto(s.proj + "/sso/callback" + qs)
        wait_panel(p, "callback")
        p.wait_for_selector('#callback-actions:not([hidden])')
        has(p.locator("#callback-message").inner_text(), "couldn't be completed", "callback failure wording")
        check("code=" not in p.url and "state=" not in p.url and "iss=" not in p.url and "/sso/callback" not in p.url.split("#")[0], "callback parameters scrubbed from the address bar: " + p.url)
        check(all("code=" not in u.split("#")[1] if "#" in u else True for u in seen[1:]), "no later URL carries the code")
        eq(token_of(p), "", "garbage must not create a session")
        p.click('#callback-actions a[href="#/login"]')
        wait_panel(p, "login")
        p.go_back()
        p.wait_for_timeout(300)
    # the callback belongs to the project: on the platform it is just the home page
    q = E.page()
    q.goto(s.plat + "/sso/callback?code=a&state=b&iss=c")
    wait_view(q, "landing")


@case
def sso_platform_rejects_malformed_authorizations(E):
    s = E.s
    token = s.token()
    bad = [
        "#/sso?client_id=unknown&redirect_uri=x&state=aaaaaaaaaaaaaaaaaaaaaaaa&code_challenge=" + "A" * 43 + "&code_challenge_method=S256",
        f"#/sso?client_id=meshbridge&redirect_uri=https%3A%2F%2Fevil.example%2Fsso%2Fcallback&state=aaaaaaaaaaaaaaaaaaaaaaaa&code_challenge={'A' * 43}&code_challenge_method=S256",
        f"#/sso?client_id=meshbridge&redirect_uri={s.proj}%2Fsso%2Fcallback&state=aaaaaaaaaaaaaaaaaaaaaaaa&code_challenge={'A' * 43}&code_challenge_method=plain",
        "#/sso?client_id=meshbridge",
    ]
    for h in bad:
        p = E.page()
        seed_session(p, s.plat, token)
        p.goto(s.plat + "/" + h)
        wait_panel(p, "sso")
        p.wait_for_selector('[data-panel="sso"] [data-role="err"]:not([hidden])')
        check(p.url.startswith(s.plat), "a malformed request never redirects off the platform: " + p.url)
    # the project origin forwards the platform's routes to the platform
    q = E.page()
    q.goto(s.proj + "/#/sso/logout")
    q.wait_for_url(re.compile(re.escape(s.plat)))


# ───────────────────────── first run, layout, accessibility ─────────────────────────
@case
def first_run_setup_belongs_to_the_project(E):
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Server(tmp, admin=False).start()
        try:
            p = E.page()
            p.goto(fresh.proj + "/")
            wait_panel(p, "setup")
            eq(p.url, fresh.proj + "/#/setup", "first run on the project")
            p.goto(fresh.proj + "/#/login")
            wait_panel(p, "setup")
            p.goto(fresh.proj + "/#/app/overview")
            wait_panel(p, "setup")
            q = E.page()
            q.goto(fresh.plat + "/")
            wait_view(q, "landing")  # the platform home does not wait for setup
            q.goto(fresh.plat + "/#/setup")
            wait_panel(q, "setup")
            eq(q.url, fresh.proj + "/#/setup", "the wizard is a project page")
        finally:
            fresh.stop()


@case
def no_horizontal_overflow_anywhere(E):
    token = E.s.token()
    for width in (320, 375, 414, 768, 1024, 1440):
        for scheme in ("light", "dark"):
            for lang in ("en", "zh-CN", "de"):
                p = E.page(width=width, scheme=scheme, lang=lang)
                seed_session(p, E.s.proj, token)
                urls = [E.s.plat + "/", E.s.plat + "/#/login", E.s.plat + "/#/register", E.s.proj + "/#/login", E.s.proj + "/#/register", E.s.proj + "/#/forgot"]
                urls += [f"{E.s.proj}/#/app/{n}" for n in PAGES]
                for u in urls:
                    p.goto(u)
                    p.wait_for_timeout(120)
                    wid = p.evaluate("document.documentElement.scrollWidth")
                    check(wid <= width, f"{u} @ {width}px {scheme} {lang}: scrollWidth {wid} > viewport")
                E.release(p)


@case
def keyboard_and_accessible_names(E):
    p = E.page()
    p.goto(E.s.proj + "/#/login")
    wait_panel(p, "login")
    names = p.evaluate("""() => [...document.querySelectorAll('#view-auth a[href], #view-auth button, #view-auth input, #view-auth select')]
      .filter(e => e.offsetParent !== null && !e.closest('[hidden]'))
      .map(e => { const l = e.labels && e.labels[0]; const n = (e.getAttribute('aria-label') || (l && l.textContent) || e.textContent || e.getAttribute('title') || e.getAttribute('placeholder') || '').trim(); return [e.tagName + (e.name ? '[' + e.name + ']' : ''), n]; })""")
    missing = [n for n, v in names if not v]
    check(not missing, f"controls without an accessible name: {missing}")
    # the skip link and landmarks
    check(p.locator("a.skip").count() == 1 and p.locator("main#main-auth, #view-auth main").count() >= 1, "skip link and main landmark")
    # focus is visible on keyboard navigation
    p.keyboard.press("Tab")
    for _ in range(8):
        p.keyboard.press("Tab")
        ok = p.evaluate("""() => { const e = document.activeElement; if (!e || e === document.body) return true; const s = getComputedStyle(e);
          return (s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0) || s.boxShadow !== 'none' || !!e.closest('.input, .pw'); }""")
        check(ok, "focused element has no visible focus indicator")
    # the platform home too
    q = E.page()
    q.goto(E.s.plat + "/")
    wait_view(q, "landing")
    names = q.evaluate("""() => [...document.querySelectorAll('#view-landing a[href], #view-landing button')]
      .filter(e => e.offsetParent !== null).map(e => (e.getAttribute('aria-label') || e.getAttribute('aria-labelledby') && document.getElementById(e.getAttribute('aria-labelledby')).textContent || e.textContent || e.title || '').trim())""")
    check(all(names), f"platform controls without a name: {names}")
    eq(q.locator("#view-landing h1").count(), 1, "one h1 on the platform home")


# ───────────────────────── runner ─────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", default="", help="run cases whose name contains this text")
    ap.add_argument("--headed", action="store_true")
    args = ap.parse_args()
    chosen = [c for c in CASES if args.k in c.__name__]
    shots = os.environ.get("E2E_SHOTS")
    failed = []
    with tempfile.TemporaryDirectory() as tmp:
        server = Server(tmp).start()
        print(f"server on :{server.port}  platform={server.plat}  project={server.proj}")
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=not args.headed)
            for fn in chosen:
                env = Env(browser, server)
                started = time.time()
                try:
                    fn(env)
                    print(f"  ok   {fn.__name__}  ({time.time() - started:.1f}s)")
                except Exception as exc:  # noqa: BLE001 - a failing case must not stop the run
                    failed.append(fn.__name__)
                    print(f"  FAIL {fn.__name__}: {exc}")
                    if os.environ.get("E2E_TRACE"):
                        traceback.print_exc()
                    if shots:
                        Path(shots).mkdir(parents=True, exist_ok=True)
                        for i, c in enumerate(env.contexts):
                            for j, pg in enumerate(c.pages):
                                try:
                                    pg.screenshot(path=f"{shots}/{fn.__name__}-{i}-{j}.png")
                                except Exception:
                                    pass
                finally:
                    env.close()
            browser.close()
        server.stop()
        if failed:
            print("\nserver log tail:")
            print("\n".join((Path(tmp) / "server.log").read_text(errors="replace").splitlines()[-15:]))
    print(f"\n{len(chosen) - len(failed)}/{len(chosen)} cases passed" + (f"; failed: {', '.join(failed)}" if failed else ""))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
