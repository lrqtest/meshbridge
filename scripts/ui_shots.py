#!/usr/bin/env python3
"""Fixture-driven screenshots of the MeshBridge console, for visual review.

The console is only worth looking at with data in it, and the interesting
states (a transfer halfway, an offline device, a tunnel over quota) cannot be
produced on demand by a real server. This tool signs in to a LOCAL development
instance, answers the list endpoints with fixed, realistic fixtures through
Playwright request interception, and writes one PNG per page/width/theme.

    bash scripts/dev-instance.sh &              # platform localhost, project 127.0.0.1
    python3 scripts/ui_shots.py --out /tmp/shots
    python3 scripts/ui_shots.py --pages overview,devices --widths 390 --schemes dark

Nothing here touches the server's data: only responses seen by the browser are
replaced. It refuses to run against anything but a loopback host.
"""
import argparse, json, os, pathlib, re, sys, time, urllib.parse, urllib.request

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
NOW = int(time.time())
H, D, M = 3600, 86400, 60


def ago(seconds):
    return NOW - seconds


GB, MB, KB = 1 << 30, 1 << 20, 1 << 10


def fixtures():
    devices = [
        ("dev_7f3a9c21", "ren-macbook-pro", "100.64.0.2", True, 8),
        ("dev_c41b0e77", "home-nas", "100.64.0.3", True, 14),
        ("dev_5d92aa10", "studio-win-pc", "100.64.0.5", True, 5),
        ("dev_91e0c3b8", "hk-edge-vps", "100.64.0.8", True, 22),
        ("dev_2ab7f640", "ci-runner-ubuntu-22-04-us-west-2b-build-eu-42", "100.64.0.13", True, 31),
        ("dev_e08d15c9", "pi-garage", "100.64.0.9", False, 2 * D + 3 * H),
        ("dev_33c8b2fe", "old-thinkpad", "100.64.0.7", False, 19 * D),
        ("dev_0b6e4d82", "new-laptop", "", False, 0),
    ]
    dev_items = [{"id": i, "hostname": h, "tailscale_ip": ip, "online": on, "last_seen": ago(seen) if seen else 0} for i, h, ip, on, seen in devices]
    mbp, nas, win, hk, ci, pi, think, new = [d[0] for d in devices]
    projects = [
        {"id": "prj_studio", "name": "Studio", "slug": "studio", "created_at": ago(40 * D)},
        {"id": "prj_backups", "name": "Backups", "slug": "backups", "created_at": ago(22 * D)},
    ]

    def job(n, src, dst, state, route, total, pct, error="", project="prj_studio"):
        return {"id": f"job_{n:04x}c9e1a7", "project_id": project, "src": src, "dst": dst, "state": state, "route": route,
                "bytes_total": total, "bytes_done": int(total * pct / 100), "error": error}
    transfers = [
        job(1, mbp, nas, "TRANSFERRING", "DIRECT", int(48.2 * GB), 63),
        job(2, win, hk, "TRANSFERRING", "PEER_RELAY", int(12.6 * GB), 31),
        job(3, ci, nas, "VERIFYING", "DIRECT", int(3.1 * GB), 100, project="prj_backups"),
        job(4, nas, mbp, "PAUSED", "DIRECT", 820 * MB, 45),
        job(5, hk, win, "WAITING_FOR_ROUTE", "WAITING_FOR_ROUTE", int(6.4 * GB), 0),
        job(6, mbp, hk, "PROBING", "", 0, 0),
        job(7, win, nas, "QUEUED", "", 0, 0),
        job(8, mbp, nas, "COMPLETED", "DIRECT", 212 * MB, 100),
        job(9, ci, hk, "COMPLETED", "OBJECT_STORAGE", int(1.8 * GB), 100, project="prj_backups"),
        job(10, nas, win, "COMPLETED", "PEER_RELAY", int(5.5 * GB), 100),
        job(11, mbp, hk, "COMPLETED", "DERP_SMALL", 4 * KB, 100),
        job(12, nas, hk, "FAILED", "REFUSED_DERP_LARGE", int(9.8 * GB), 12, "route refused: file too large for DERP and no healthy peer relay in range", "prj_backups"),
        job(13, win, mbp, "FAILED", "DIRECT", 740 * MB, 88, "destination agent disconnected after 3 retries"),
        job(14, nas, mbp, "CANCELLED", "DIRECT", int(2.2 * GB), 7),
    ]
    tun = lambda n, name, dev, host, target, status, online, key, used, quota: {
        "id": f"tun_{n:02x}", "device_id": dev, "device_hostname": host, "name": name, "slug": f"{n:02x}" * 16,
        "url_path": f"/t/{n:02x}" * 1 + "…/", "url_subdomain": f"https://t-{n:02x}{n:02x}c0ffee.mineai.top", "target": target,
        "key_required": key, "status": status, "online": online, "strip_prefix": True, "sandbox": True,
        "monthly_quota_bytes": quota, "bytes_in_month": used, "max_request_bytes": 100 * MB, "created_at": ago(n * D)}
    tunnels = [
        tun(3, "Grafana · home lab", nas, "home-nas", "http://127.0.0.1:3000", "active", True, True, int(1.2 * GB), 5 * GB),
        tun(9, "Design preview", mbp, "ren-macbook-pro", "http://127.0.0.1:5173", "active", True, False, 310 * MB, 5 * GB),
        tun(12, "Photo album", nas, "home-nas", "https://127.0.0.1:8443", "quota_exceeded", True, True, int(5.0 * GB), 5 * GB),
        tun(20, "", pi, "pi-garage", "http://127.0.0.1:8123", "disabled", False, True, 0, 5 * GB),
    ]
    relays = [
        {"id": "rly_jp1", "name": "tokyo-relay-01", "region": "jp", "udp_port": 40000, "quota": 1024 * GB, "bytes_out_month": 412 * GB, "healthy": True, "last_seen": ago(11)},
        {"id": "rly_hk1", "name": "hongkong-relay-01", "region": "hk", "udp_port": 40000, "quota": 512 * GB, "bytes_out_month": 498 * GB, "healthy": True, "last_seen": ago(19)},
        {"id": "rly_us1", "name": "oregon-relay-01", "region": "usw", "udp_port": 40010, "quota": 0, "bytes_out_month": 37 * GB, "healthy": False, "last_seen": ago(3 * H)},
    ]
    events = [
        ("login", "admin", "login ok"), ("device enrolled", "admin", "ci-runner-ubuntu-22-04-us-west-2b-build-eu-42"),
        ("transfer created", "ren@example.com", "ren-macbook-pro → home-nas  /Volumes/Archive/2026"),
        ("tunnel created", "admin", "Grafana · home lab"), ("tunnel agent online", "", "home-nas"),
        ("tunnel quota warning", "", "Photo album: 80% of the monthly quota"), ("tunnel quota exceeded", "", "Photo album"),
        ("password reset", "mia@example.com", ""), ("registration toggled", "admin", "1"),
        ("user registered", "kai@example.com", ""), ("smtp configured", "admin", "smtp.example.com:587"),
        ("project created", "admin", "Backups"), ("device registered", "admin", "new-laptop"),
        ("tunnel key rotated", "admin", "Photo album"), ("tunnel updated", "admin", "Design preview"),
        ("tunnel agent offline", "", "pi-garage"), ("tunnel deleted", "admin", "Old staging"),
    ]
    audit = []
    for n in range(60):
        e, actor, detail = events[n % len(events)]
        audit.append({"ts": ago(n * 37 * M + 90), "actor": actor, "event": e, "project_id": "", "device_id": "", "job_id": "", "detail": detail})
    return {
        "devices": {"items": dev_items}, "transfers": {"items": transfers}, "tunnels": {"items": tunnels},
        "relays": {"items": relays}, "projects": {"items": projects, "limit": 200, "offset": 0}, "audit": audit,
        "health": {"agents_online": 5, "headscale": "ok", "jobs_active": 7, "meter_degraded": False, "ok": True, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
    }


def install(page, fx, empty=False):
    def fulfil(route, body, status=200):
        route.fulfill(status=status, content_type="application/json", body=json.dumps(body), headers={"Cache-Control": "no-store"})

    def simple(key):
        def handler(route):
            if route.request.method != "GET":
                return route.continue_()
            return fulfil(route, {"items": []} if empty else fx[key])
        return handler

    def audit(route):
        url = urllib.parse.urlparse(route.request.url)
        q = urllib.parse.parse_qs(url.query)
        limit, page_no = int(q.get("limit", ["50"])[0]), int(q.get("page", ["1"])[0])
        rows = [] if empty else fx["audit"][(page_no - 1) * limit: page_no * limit]
        fulfil(route, {"items": rows})

    for key, pattern in (("devices", r"/api/v1/devices(\?.*)?$"), ("transfers", r"/api/v1/transfers(\?.*)?$"), ("tunnels", r"/api/v1/tunnels(\?.*)?$"),
                         ("relays", r"/api/v1/relays(\?.*)?$"), ("projects", r"/api/v1/projects(\?.*)?$")):
        page.route(re.compile(".*" + pattern), simple(key))
    page.route(re.compile(r".*/api/v1/audit(\?.*)?$"), audit)
    page.route(re.compile(r".*/api/v1/health$"), lambda r: fulfil(r, {**fx["health"], "agents_online": 0, "jobs_active": 0} if empty else fx["health"]))


AUDIT_JS = """() => {
  // body clips horizontal overflow, so scrollWidth alone cannot see it: measure the boxes.
  const inner = document.documentElement.clientWidth, culprits = [];
  const clipped = (el) => { for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) { const o = getComputedStyle(p).overflowX; if (o !== "visible") return true; } return false; };
  for (const el of document.querySelectorAll("body *")) {
    if (el.closest("[hidden]") || el.closest("svg") || clipped(el)) continue;
    const r = el.getBoundingClientRect();
    if (r.width && r.right > inner + 1) culprits.push(Math.round(r.right) + " " + el.tagName.toLowerCase() + "." + String(el.className).split(" ").join(".") + (el.id ? "#" + el.id : ""));
  }
  culprits.sort((a, b) => parseInt(b) - parseInt(a));
  return { inner, scroll: culprits.length ? Math.max(...culprits.map((c) => parseInt(c))) : inner, culprits: culprits.slice(0, 8) };
}"""


def login_token(base):
    pw = (ROOT / ".meshbridge/dev/admin-password.txt").read_text().strip()
    req = urllib.request.Request(base + "/api/v1/auth/login", method="POST", data=json.dumps({"username": "admin", "password": pw}).encode(),
                                 headers={"Content-Type": "application/json", "Origin": base})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())["token"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:28081", help="project origin of a LOCAL dev instance")
    ap.add_argument("--out", required=True)
    ap.add_argument("--pages", default="overview,devices,transfers,tunnels,relays,audit,settings")
    ap.add_argument("--widths", default="1440,390")
    ap.add_argument("--schemes", default="light,dark")
    ap.add_argument("--lang", default="zh-CN")
    ap.add_argument("--empty", action="store_true", help="answer every list with no rows (first-run states)")
    ap.add_argument("--full", action="store_true", help="capture the whole scrollable page")
    ap.add_argument("--audit", action="store_true", help="also report elements that overflow the viewport horizontally")
    a = ap.parse_args()
    host = urllib.parse.urlparse(a.base).hostname
    if host not in ("127.0.0.1", "localhost", "::1"):
        sys.exit("ui_shots only runs against a loopback development instance")
    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    token, fx = login_token(a.base), fixtures()
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for scheme in a.schemes.split(","):
            for width in map(int, a.widths.split(",")):
                height = 900 if width >= 900 else 844
                ctx = browser.new_context(viewport={"width": width, "height": height}, color_scheme=scheme, locale=a.lang,
                                          device_scale_factor=1 if width >= 900 else 2)
                ctx.add_init_script(f"try{{localStorage.setItem('mb_token',{json.dumps(token)});localStorage.setItem('mb_lang',{json.dumps(a.lang)});"
                                    f"localStorage.setItem('mb_theme',{json.dumps(scheme)});}}catch(e){{}}")
                page = ctx.new_page(); install(page, fx, a.empty)
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                for name in a.pages.split(","):
                    page.goto(f"{a.base}/#/app/{name}"); page.wait_for_selector("#view-app:not([hidden])", timeout=15000)
                    page.wait_for_timeout(900)
                    if a.audit:
                        wide = page.evaluate(AUDIT_JS)
                        if wide["scroll"] > wide["inner"]:
                            print(f"OVERFLOW {name} {width}px {scheme}: page {wide['scroll']}px > {wide['inner']}px", file=sys.stderr)
                            for row in wide["culprits"]:
                                print("   ", row, file=sys.stderr)
                    path = out / f"{name}-{width}-{scheme}{'-empty' if a.empty else ''}.png"
                    page.screenshot(path=str(path), full_page=a.full)
                    print(path)
                if errors:
                    print("JS errors:", errors[:3], file=sys.stderr)
                ctx.close()
        browser.close()


if __name__ == "__main__":
    main()
