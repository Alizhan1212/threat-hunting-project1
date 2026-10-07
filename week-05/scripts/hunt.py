#!/usr/bin/env python3
"""
Week 05 - reference hunt in plain Python.

Runs the SAME logic as the Splunk queries in ../queries/hunt_queries.spl, so the
numbers in the Splunk screenshots can be cross-checked without Splunk.

Usage (from week-05/):  python3 scripts/hunt.py
"""
import csv
from collections import defaultdict
from pathlib import Path

from config import BRAND_KEYWORDS, OFFICIAL, KNOWN_BAD_DOMAINS, KNOWN_BAD_IPS

DATA = Path(__file__).resolve().parent.parent / "data"
load = lambda n: list(csv.DictReader(open(DATA / n, encoding="utf-8")))
dns, proxy, sysmon = load("dns.csv"), load("proxy.csv"), load("sysmon.csv")


def is_official(d):
    return any(d == o or d.endswith("." + o) for o in OFFICIAL)


def is_lookalike(d):
    return any(k in d for k in BRAND_KEYWORDS) and not is_official(d)


def title(t):
    print("\n" + "=" * 78 + f"\n{t}\n" + "=" * 78)


# ------------------------------------------------------------------ H0 intel-driven
title("H0  INTEL-DRIVEN: DNS hits on week-3 MISP indicators")
hits = [r for r in dns if r["query"] in KNOWN_BAD_DOMAINS or r["answer"] in KNOWN_BAD_IPS]
for r in hits:
    print(f'{r["time"]}  {r["hostname"]:7s} {r["user"]:14s} {r["query"]} -> {r["answer"]}')
print(f"-> {len(hits)} hit(s)")

# ------------------------------------------------------------------ H1 look-alike domains
title("H1  HYPOTHESIS: DNS queries to brand look-alike domains (not official)")
agg = defaultdict(lambda: {"n": 0, "hosts": set(), "first": None})
for r in dns:
    if is_lookalike(r["query"]):
        a = agg[r["query"]]
        a["n"] += 1
        a["hosts"].add(r["hostname"])
        a["first"] = min(a["first"] or r["time"], r["time"])
print(f'{"domain":28s} {"cnt":>4s} {"hosts":>5s}  first_seen                 hosts')
for d, a in sorted(agg.items(), key=lambda x: x[1]["first"]):
    print(f'{d:28s} {a["n"]:4d} {len(a["hosts"]):5d}  {a["first"]}  {",".join(sorted(a["hosts"]))}')
print(f"-> {len(agg)} look-alike domain(s)")

# ------------------------------------------------------------------ H2 data submitted
title("H2  HYPOTHESIS: POST (form submission) to a look-alike domain")
posts = [r for r in proxy if r["method"] == "POST" and is_lookalike(r["domain"])]
for r in posts:
    print(f'{r["time"]}  {r["hostname"]:7s} {r["user"]:14s} POST {r["url"]}  bytes_out={r["bytes_out"]}')
print(f"-> {len(posts)} POST(s) from {len({r['hostname'] for r in posts})} host(s)")

# ------------------------------------------------------------------ H3 PowerShell
title("H3  HYPOTHESIS: PowerShell started by an Office application")
OFFICE = ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")
ps = [r for r in sysmon if r["event_id"] == "1" and r["image"].lower().endswith("powershell.exe")]
office_ps = [r for r in ps if r["parent_image"].lower().endswith(OFFICE)]
for r in office_ps:
    print(f'{r["time"]}  {r["hostname"]} {r["user"]}\n   parent: {r["parent_image"]}\n   cmd:    {r["command_line"][:90]}...')
    for n in sysmon:
        if n["hostname"] == r["hostname"] and n["event_id"] == "3" and n["time"] >= r["time"]:
            print(f'   net:    {n["time"]} -> {n["dest_ip"]}:{n["dest_port"]}')
            break
print(f"-> {len(office_ps)} hit(s)")

enc = [r for r in ps if " -enc" in r["command_line"].lower()]
parents = defaultdict(int)
for r in enc:
    parents[r["parent_image"]] += 1
print("\nFor comparison - every encoded PowerShell by parent (naive rule would flag all):")
for p, n in sorted(parents.items(), key=lambda x: -x[1]):
    print(f"   {n:3d}  {p}")
print(f"-> {len(enc)} encoded PowerShell events, {len(enc) - len(office_ps)} of them are a legitimate IT agent")
