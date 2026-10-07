#!/usr/bin/env python3
"""
Week 05 - Part B: the H1 hunt on REAL data.

Source: Phishing.Database (github.com/Phishing-Database/Phishing.Database),
        file phishing-domains-ACTIVE.txt - an open feed of currently active phishing domains.
        Snapshot used in the report: commit 12a20bf, 2026-10-02, 392 178 domains.

Order of work (as agreed with the instructor):
  Step 1 - Kazakhstani brands first (keywords/official domains from week-02/config/brands.json)
           1a naive rule:   domain CONTAINS a keyword        (what rule-001/rule-002 do)
           1b refined rule: a domain LABEL STARTS WITH a keyword (split on "." and "-")
  Step 2 - too few KZ hits for statistics -> the same refined rule on global analogs
           of our brands: PayPal (~Kaspi), DHL/USPS (~Kazpost/CDEK), Gosuslugi (~eGov), OLX abroad.

Usage (from week-05/):
    python3 scripts/real_feed_hunt.py                 # downloads the feed if missing
    python3 scripts/real_feed_hunt.py --feed FILE     # use an already downloaded copy
Outputs: data/real/kz_hits.csv, data/real/global_hits.csv, data/real/real_hunt_output.txt,
         data/real/feed_for_splunk.csv (full feed with a header, for Splunk upload; git-ignored)
"""
import argparse
import collections
import csv
import json
import re
import sys
import urllib.request
from pathlib import Path

W5 = Path(__file__).resolve().parent.parent
REAL = W5 / "data" / "real"
# pinned to the snapshot used in the report; replace the commit with "master" for today's feed
FEED_URL = ("https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/"
            "12a20bf8dd2b7e78d9d38fc12b3e5c970f79d1a7/phishing-domains-ACTIVE.txt")
BRANDS = json.load(open(W5.parent / "week-02" / "config" / "brands.json"))["brands"]

# Analyst verdicts for every hit of the REFINED rule on KZ brands (manual triage, 2026-10-06)
KZ_VERDICT = {
    "kaspibank.auth-telegramm.ru": ("PHISHING (Kaspi)", "Kaspi name + fake Telegram 'auth' page on a .ru host"),
    "kaspiy-delfin.tarho05.ru": ("PHISHING (Kaspi)", "Kaspi-like label on a throw-away .ru subdomain"),
    "kaspl.ga": ("PHISHING (Kaspi)", "Typosquat kaspi -> kaspl (i -> l), free .ga TLD"),
    "olxkz.pay-sacure4ds.ru": ("PHISHING (OLX.kz)", "Fake '3-D Secure' payment page for OLX Kazakhstan sellers"),
    "cdekbefotlfzxyqk-dot-millinium.ey.r.appspot.com": ("UNCLEAR", "Random App Engine label that happens to start with 'cdek'"),
    "homebank-argenta.be": ("NOT OUR BRAND", "Phishing of Argenta Bank (Belgium) 'homebank', not Halyk Homebank"),
    "ing.be.homebank.quarantainezone-omgeving.online": ("NOT OUR BRAND", "Phishing of ING Belgium 'homebank', not Halyk"),
    "krishakg2006.github.io": ("FALSE POSITIVE", "Personal GitHub page, first name 'Krisha'"),
    "krishamakwana11.github.io": ("FALSE POSITIVE", "Personal GitHub page, first name 'Krisha'"),
    "krishankantsen.github.io": ("FALSE POSITIVE", "Personal GitHub page, first name 'Krishan'"),
    "krishansharma02.github.io": ("FALSE POSITIVE", "Personal GitHub page, first name 'Krishan'"),
    "krishayinfotech.com": ("FALSE POSITIVE", "Indian IT company 'Krishay'"),
    "workers-playground-cold-violet-5b28.jusang425.workers.dev": ("FALSE POSITIVE", "Cloudflare account name 'jusang'"),
    "workers-playground-wandering-dew-9153.jusang425.workers.dev": ("FALSE POSITIVE", "Cloudflare account name 'jusang'"),
}

GLOBAL = {   # brand: (KZ analog, keywords, official domains)
    "PayPal":    ("Kaspi (payments/bank)", ["paypal"], ["paypal.com", "paypal.me"]),
    "DHL":       ("Kazpost / CDEK (delivery)", ["dhl"], ["dhl.com", "dhl.de"]),
    "USPS":      ("Kazpost (national post)", ["usps"], ["usps.com"]),
    "Gosuslugi": ("eGov (government portal)", ["gosuslugi"], ["gosuslugi.ru"]),
    "OLX (other countries)": ("OLX.kz (marketplace)", ["olx"],
                              ["olx.kz", "olx.pl", "olx.ua", "olx.ro", "olx.bg", "olx.pt", "olx.com", "olx.ba", "olx.uz"]),
}
FREE_HOSTING = ["pages.dev", "workers.dev", "vercel.app", "web.app", "firebaseapp.com", "appspot.com",
                "weebly.com", "000webhostapp.com", "github.io", "netlify.app", "repl.co", "square.site"]

out_lines = []


def say(s=""):
    print(s)
    out_lines.append(s)


def official(d, offs):
    return any(d == o or d.endswith("." + o) for o in offs)


def labels(d):
    return re.split(r"[.\-]", d)


def naive_match(d, kws):
    return any(k in d for k in kws)


def refined_match(d, kws):
    # keyword must START a label; skip pure digits ("1414") and dotted keywords ("post.kz")
    kws = [k for k in kws if not k.isdigit() and "." not in k]
    return any(t.startswith(k) and not t.startswith("homebanking") for t in labels(d) for k in kws)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--feed", default=str(REAL / "phishing-domains-ACTIVE.txt"))
    feed = Path(ap.parse_args().feed)
    REAL.mkdir(parents=True, exist_ok=True)
    if not feed.exists():
        print(f"Downloading {FEED_URL} ...", file=sys.stderr)
        urllib.request.urlretrieve(FEED_URL, feed)
    doms = sorted({l.strip().lower() for l in open(feed, encoding="utf-8") if l.strip() and not l.startswith("#")})

    with open(REAL / "feed_for_splunk.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain", "tld"])
        w.writerows([d, d.rsplit(".", 1)[-1]] for d in doms)

    say(f"Real feed: {feed.name}, {len(doms):,} unique active phishing domains")

    # ---------------- Step 1: KZ brands
    say("\n=== STEP 1. Kazakhstani brands (week-02/config/brands.json) ===")
    say(f'{"brand":8s} {"naive":>6s} {"refined":>8s}')
    kz_rows, naive_total, refined_total = [], 0, 0
    for b, v in BRANDS.items():
        n = [d for d in doms if naive_match(d, v["keywords"]) and not official(d, v["official"])]
        r = [d for d in n if refined_match(d, v["keywords"])]
        if b == "olx":   # OLX abroad belongs to Step 2; keep only Kazakhstan here
            r = [d for d in r if "olxkz" in d or "olx-kz" in d or ".kz" in d]
        naive_total += len(n)
        refined_total += len(r)
        say(f"{b:8s} {len(n):6d} {len(r):8d}")
        for d in r:
            verdict, why = KZ_VERDICT.get(d, ("UNREVIEWED", ""))
            kz_rows.append([b, d, verdict, why])
    say(f"{'TOTAL':8s} {naive_total:6d} {refined_total:8d}")

    say("\nRefined hits, analyst verdict:")
    for b, d, verdict, why in kz_rows:
        say(f"  {verdict:18s} {d:58s} {why}")
    cnt = collections.Counter(r[2] for r in kz_rows)
    say(f"-> confirmed KZ-brand phishing: {sum(v for k, v in cnt.items() if k.startswith('PHISHING'))}"
        f"  | not our brand: {cnt['NOT OUR BRAND']}  | false positive: {cnt['FALSE POSITIVE']}  | unclear: {cnt['UNCLEAR']}")

    with open(REAL / "kz_hits.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["brand", "domain", "verdict", "reason"])
        w.writerows(kz_rows)

    # examples of naive-rule noise
    say("\nWhy the naive 'contains' rule fails on real data (examples):")
    for kw, brand in [("egov", "egov"), ("1414", "egov"), ("olx", "olx"), ("homebank", "halyk")]:
        ex = [d for d in doms if kw in d and not refined_match(d, [kw])][:3]
        say(f"  '{kw}' inside: {', '.join(ex)}")

    # ---------------- Step 2: global analogs
    say("\n=== STEP 2. Global analogs of our brands (refined rule) ===")
    g_rows = []
    say(f'{"brand":24s} {"KZ analog":28s} {"naive":>6s} {"refined":>8s}  top TLDs')
    for b, (analog, kws, offs) in GLOBAL.items():
        n = [d for d in doms if naive_match(d, kws) and not official(d, offs)]
        r = [d for d in n if refined_match(d, kws) and "olxkz" not in d]   # olxkz counted in Step 1
        tlds = collections.Counter(d.rsplit(".", 1)[-1] for d in r).most_common(3)
        say(f"{b:24s} {analog:28s} {len(n):6d} {len(r):8d}  {', '.join(f'.{t} {c}' for t, c in tlds)}")
        for d in r:
            g_rows.append([b, analog, d, d.rsplit(".", 1)[-1],
                           next((h for h in FREE_HOSTING if d.endswith("." + h)), "")])
    with open(REAL / "global_hits.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["brand", "kz_analog", "domain", "tld", "free_hosting"])
        w.writerows(g_rows)

    say("\nExamples (lures similar to our KZ scenarios):")
    for b, pat in [("PayPal", "login|secure|verify"), ("DHL", "track|parcel|delivery"),
                   ("USPS", "track|parcel|redeliver|package"), ("Gosuslugi", "."),
                   ("OLX (other countries)", "pay|3ds|dostav|delivery")]:
        ex = [r[2] for r in g_rows if r[0] == b and re.search(pat, r[2])][:3]
        say(f"  {b:22s} {', '.join(ex)}")

    tld_all = collections.Counter(r[3] for r in g_rows).most_common(8)
    fh = sum(1 for r in g_rows if r[4])
    say(f"\nTriage signals across {len(g_rows)} global hits:")
    say("  top TLDs: " + ", ".join(f".{t} {c}" for t, c in tld_all))
    say(f"  on free hosting / dev platforms (pages.dev, vercel.app, web.app, ...): {fh} ({fh / len(g_rows):.0%})")

    (REAL / "real_hunt_output.txt").write_text("\n".join(out_lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
