#!/usr/bin/env python3
"""
Week 2 — find hosts serving look-alike Kaspi / eGov / Halyk pages with Shodan.

NOTE: search filters (http.title, ssl.cert...) need a Shodan membership/academic
upgrade or query credits. With a free account run the same queries in the web UI
(https://www.shodan.io) and take screenshots for the report instead.

Usage:
  python week2/scripts/shodan_search.py
Output: data/raw/shodan_hosts.csv
"""
import csv
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]

QUERIES = {
    "kaspi_title":   'http.title:"Kaspi" -hostname:kaspi.kz',
    "kaspi_cert":    'ssl.cert.subject.cn:kaspi -ssl.cert.subject.cn:kaspi.kz',
    "egov_title":    'http.title:"eGov" -hostname:egov.kz',
    "homebank_title": 'http.title:"Homebank" -hostname:homebank.kz',
}


def main() -> None:
    load_dotenv(ROOT / ".env")
    key = os.getenv("SHODAN_API_KEY")
    if not key:
        sys.exit("Set SHODAN_API_KEY in .env")
    import shodan

    api = shodan.Shodan(key)
    out = ROOT / "data/raw/shodan_hosts.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["query", "ip", "port", "hostnames", "org", "asn", "country", "title"])
        for name, q in QUERIES.items():
            print(f"[*] {name}: {q}")
            try:
                res = api.search(q, limit=50)
            except shodan.APIError as e:
                print(f"    ! {e}  -> run this query in the web UI and screenshot it")
                continue
            print(f"    total={res['total']}")
            for m in res["matches"]:
                w.writerow([name, m.get("ip_str"), m.get("port"), "|".join(m.get("hostnames", [])),
                            m.get("org"), m.get("asn"), m.get("location", {}).get("country_code"),
                            (m.get("http") or {}).get("title", "")])
    print(f"[+] -> {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
