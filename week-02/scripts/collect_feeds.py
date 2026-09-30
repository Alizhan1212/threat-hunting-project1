#!/usr/bin/env python3
"""
Week 2 — OSINT collection of phishing indicators targeting Kazakhstani brands.

Sources (all free):
  * OpenPhish community feed   — live phishing URLs            (no key)
  * crt.sh                     — Certificate Transparency logs  (no key)
  * URLhaus (abuse.ch)         — malicious URLs                 (free Auth-Key, optional)

Only indicators that contain a KZ brand keyword (config/brands.json) and are NOT
on an official domain are kept. Output: data/raw/collected_iocs.csv

Usage:
  python week2/scripts/collect_feeds.py [--days 30] [--skip-crtsh]
"""
import argparse
import csv
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
BRANDS = json.loads((ROOT / "config" / "brands.json").read_text(encoding="utf-8"))["brands"]
OUT = ROOT / "data" / "raw" / "collected_iocs.csv"
HEADERS = {"User-Agent": "AITU-CTI-student-project/1.0"}
FIELDS = ["indicator", "type", "source", "first_seen", "brand", "context"]
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


def host_of(value: str) -> str:
    value = value.strip()
    if "://" not in value:
        value = "http://" + value
    return (urlparse(value).hostname or "").lower().rstrip(".")


def is_official(host: str) -> bool:
    for b in BRANDS.values():
        for off in b["official"]:
            if host == off or host.endswith("." + off):
                return True
    return False


def match_brand(text: str) -> str | None:
    t = text.lower()
    for name, b in BRANDS.items():
        if any(k in t for k in b["keywords"]):
            return name
    return None


def openphish() -> list[dict]:
    print("[*] OpenPhish community feed ...")
    r = requests.get("https://openphish.com/feed.txt", headers=HEADERS, timeout=60)
    r.raise_for_status()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = []
    for url in r.text.splitlines():
        brand = match_brand(url)
        if brand and not is_official(host_of(url)):
            rows.append({"indicator": url, "type": "url", "source": "openphish",
                         "first_seen": now, "brand": brand, "context": "community feed"})
    print(f"    {len(rows)} KZ-brand URLs")
    return rows


def urlhaus(key: str) -> list[dict]:
    print("[*] URLhaus recent URLs ...")
    r = requests.post("https://urlhaus-api.abuse.ch/v1/urls/recent/",
                      headers={**HEADERS, "Auth-Key": key}, timeout=60)
    r.raise_for_status()
    rows = []
    for item in r.json().get("urls", []):
        url = item.get("url", "")
        brand = match_brand(url)
        if brand and not is_official(host_of(url)):
            rows.append({"indicator": url, "type": "url", "source": "urlhaus",
                         "first_seen": item.get("date_added", ""), "brand": brand,
                         "context": f"threat={item.get('threat')}; tags={item.get('tags')}"})
    print(f"    {len(rows)} KZ-brand URLs")
    return rows


def crtsh(days: int) -> list[dict]:
    """Search CT logs for certificates whose names contain brand keywords."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows, seen = [], set()
    for brand, b in BRANDS.items():
        kw = b["keywords"][0]
        print(f"[*] crt.sh %{kw}% ...")
        try:
            r = requests.get("https://crt.sh/", params={"q": f"%{kw}%", "output": "json", "exclude": "expired"},
                             headers=HEADERS, timeout=120)
            r.raise_for_status()
            data = r.json()
        except (requests.RequestException, ValueError) as e:
            print(f"    ! crt.sh failed for {kw}: {e} (it is often slow — retry later)")
            continue
        n = 0
        for cert in data:
            ts = cert.get("entry_timestamp") or cert.get("not_before") or ""
            try:
                when = datetime.fromisoformat(ts[:19]).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if when < since:
                continue
            for name in cert.get("name_value", "").split("\n"):
                d = name.strip().lower().lstrip("*.")
                # skip organisation names like "kaspi bank, jsc" — keep only real domain names
                if not DOMAIN_RE.match(d):
                    continue
                if d in seen or is_official(d) or kw not in d:
                    continue
                seen.add(d)
                n += 1
                rows.append({"indicator": d, "type": "domain", "source": "crt.sh",
                             "first_seen": ts[:19], "brand": brand,
                             "context": f"issuer={cert.get('issuer_name', '')[:80]}"})
        print(f"    {n} new domains in last {days} days")
        time.sleep(3)  # be polite to crt.sh
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=90, help="crt.sh look-back window")
    ap.add_argument("--skip-crtsh", action="store_true")
    args = ap.parse_args()
    load_dotenv(ROOT / ".env")

    rows: list[dict] = []
    for name, fn in [("openphish", openphish)]:
        try:
            rows += fn()
        except requests.RequestException as e:
            print(f"    ! {name} failed: {e}")
    key = os.getenv("URLHAUS_AUTH_KEY")
    if key:
        try:
            rows += urlhaus(key)
        except requests.RequestException as e:
            print(f"    ! urlhaus failed: {e}")
    else:
        print("[-] URLHAUS_AUTH_KEY not set — skipping URLhaus")
    if not args.skip_crtsh:
        rows += crtsh(args.days)

    if not rows:
        print("No indicators collected."); sys.exit(1)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"[+] {len(rows)} indicators -> {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
