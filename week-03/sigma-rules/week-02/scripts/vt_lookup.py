#!/usr/bin/env python3
"""
Week 2 — enrich collected indicators with VirusTotal (API v3, free tier: 4 req/min).

Usage:
  python week2/scripts/vt_lookup.py [--input data/raw/collected_iocs.csv] [--limit 20]
Output: data/raw/vt_enrichment.csv
"""
import argparse
import base64
import csv
import os
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
API = "https://www.virustotal.com/api/v3"


def vt_get(path: str, key: str) -> dict | None:
    r = requests.get(f"{API}/{path}", headers={"x-apikey": key}, timeout=30)
    if r.status_code == 404:
        return None
    if r.status_code == 429:
        print("    rate limited, sleeping 60s"); time.sleep(60)
        return vt_get(path, key)
    r.raise_for_status()
    return r.json()["data"]["attributes"]


def lookup(indicator: str, ioc_type: str, key: str) -> dict:
    if ioc_type == "url":
        uid = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        attrs = vt_get(f"urls/{uid}", key)
    elif ioc_type == "ip":
        attrs = vt_get(f"ip_addresses/{indicator}", key)
    else:
        attrs = vt_get(f"domains/{indicator}", key)
    if not attrs:
        return {"vt_malicious": "", "vt_suspicious": "", "vt_harmless": "", "vt_note": "not in VT"}
    s = attrs.get("last_analysis_stats", {})
    return {
        "vt_malicious": s.get("malicious", 0),
        "vt_suspicious": s.get("suspicious", 0),
        "vt_harmless": s.get("harmless", 0),
        "vt_note": ";".join(filter(None, [
            f"registrar={attrs.get('registrar', '')}" if attrs.get("registrar") else "",
            f"country={attrs.get('country', '')}" if attrs.get("country") else "",
            f"asn={attrs.get('as_owner', '')}" if attrs.get("as_owner") else "",
            f"title={attrs.get('title', '')}" if attrs.get("title") else "",
        ])),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(ROOT / "data/raw/collected_iocs.csv"))
    ap.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()
    load_dotenv(ROOT / ".env")
    key = os.getenv("VT_API_KEY")
    if not key:
        sys.exit("Set VT_API_KEY in .env (free key: virustotal.com -> profile -> API key)")

    with open(args.input, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))[: args.limit]
    out = ROOT / "data/raw/vt_enrichment.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        fields = ["indicator", "type", "brand", "vt_malicious", "vt_suspicious", "vt_harmless", "vt_note"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for i, row in enumerate(rows, 1):
            print(f"[{i}/{len(rows)}] {row['indicator'][:70]}")
            try:
                res = lookup(row["indicator"], row["type"], key)
            except requests.RequestException as e:
                res = {"vt_note": f"error: {e}"}
            w.writerow({"indicator": row["indicator"], "type": row["type"], "brand": row["brand"], **res})
            time.sleep(15)  # free tier = 4 requests/minute
    print(f"[+] -> {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
