#!/usr/bin/env python3
"""check-i18n.py — keep the web UI's dictionaries honest.

* every key referenced by web/index.html and web/assets/app.js exists in en.json
* every locale has exactly en.json's keys, the same {placeholders}, and the
  plural categories its language needs (Intl.PluralRules)

    python3 scripts/check-i18n.py        # exit 1 on problems
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
I18N = WEB / "assets" / "i18n"
LOCALES = ["en", "zh-CN", "zh-TW", "ja", "ko", "es", "fr", "de", "pt-BR", "ru"]
# CLDR cardinal categories actually selected for integers.
PLURALS = {"en": {"one", "other"}, "es": {"one", "many", "other"}, "fr": {"one", "many", "other"},
           "de": {"one", "other"}, "pt-BR": {"one", "many", "other"}, "ru": {"one", "few", "many", "other"},
           "zh-CN": {"other"}, "zh-TW": {"other"}, "ja": {"other"}, "ko": {"other"}}
# Keys built at runtime from server values (state.X, route.X, …).
DYNAMIC = [r"^state\.", r"^route\.", r"^status\.", r"^event\.", r"^app\.\w+\.(title|sub)$",
           r"^app\.overview\.title(Morning|Afternoon|Evening)$", r"^auth\.strength\.", r"^meta\."]


def flatten(d, prefix=""):
    out = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict) and "other" not in v:
            out.update(flatten(v, key))
        else:
            out[key] = v
    return out


def placeholders(v):
    texts = v.values() if isinstance(v, dict) else [v]
    return set().union(*(set(re.findall(r"\{(\w+)\}", s)) for s in texts))


def used_keys():
    html = (WEB / "index.html").read_text("utf-8")
    js = (WEB / "assets" / "app.js").read_text("utf-8")
    keys = set(re.findall(r'data-i18n="([\w.]+)"', html))
    for attr in re.findall(r'data-i18n-attr="([^"]+)"', html):
        keys.update(p.split(":", 1)[1].strip() for p in attr.split(";") if ":" in p)
    keys.update(re.findall(r'\bt\(\s*"([\w.]+)"', js))
    keys.update(re.findall(r'(?:i18n|key|hint):\s*"([a-z][\w]*\.[\w.]+)"', js))
    keys.update(re.findall(r'"((?:auth|smtp|setup|common|app|enroll|tf|err)\.[\w.]+)"', js))
    return {k for k in keys if not re.search(r"\.(com|cn|net|org)$", k)}  # SMTP hostnames


def main():
    problems = []
    en = flatten(json.loads((I18N / "en.json").read_text("utf-8")))
    for k in sorted(used_keys()):
        if k not in en and not k.endswith("."):
            problems.append(f"en.json: missing key used by UI: {k}")
    used = used_keys()
    for k in sorted(en):
        if k not in used and not any(re.search(p, k) for p in DYNAMIC):
            print(f"note: en.json key looks unused: {k}")
    for loc in LOCALES[1:]:
        path = I18N / f"{loc}.json"
        if not path.exists():
            problems.append(f"{loc}.json: file missing")
            continue
        d = flatten(json.loads(path.read_text("utf-8")))
        for k in sorted(set(en) - set(d)):
            problems.append(f"{loc}.json: missing {k}")
        for k in sorted(set(d) - set(en)):
            problems.append(f"{loc}.json: unknown key {k}")
        for k in sorted(set(en) & set(d)):
            if placeholders(en[k]) != placeholders(d[k]):
                problems.append(f"{loc}.json: placeholders differ for {k}: {sorted(placeholders(d[k]))} vs {sorted(placeholders(en[k]))}")
            if isinstance(en[k], dict):
                if not isinstance(d[k], dict):
                    problems.append(f"{loc}.json: {k} must be a plural object")
                elif set(d[k]) != PLURALS[loc]:
                    problems.append(f"{loc}.json: {k} plural forms {sorted(d[k])}, expected {sorted(PLURALS[loc])}")
            elif isinstance(d[k], str) and "**" in en[k] and d[k].count("**") != en[k].count("**"):
                problems.append(f"{loc}.json: emphasis markers differ for {k}")
    for p in problems:
        print(p)
    print(f"{len(en)} keys, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
