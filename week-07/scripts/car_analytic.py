#!/usr/bin/env python3
"""
Week 07 - MITRE CAR-2014-04-003 "PowerShell Execution" implemented in plain Python.

Used to cross-check the SIEM results (Kibana ES|QL / Splunk give the same numbers)
and to score three versions of the analytic against the planted attacks.

  V0  CAR as published:  exe == powershell.exe AND parent_exe != explorer.exe
  V1  V0 + allow-list of known-good (parent, command line) pairs found in V0 triage
  V2  our detection: V1, matched on OriginalFileName (catches renamed copies)
      + extra branch for explorer.exe parent with hidden/encoded flags (.lnk phishing)
  V3  campaign attribution: each V2 alert is joined with the DNS queries (Sysmon EID 22)
      made by the same image on the same host within 60 s, and the domain is checked
      against our brand list: week-3 MISP IoC / new brand look-alike / official / other

Usage (from week-07/):  python3 scripts/car_analytic.py   (run generate_w7_logs.py first)
Writes data/car_results.txt and images/w7_*.png
"""
import csv
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA, IMG = ROOT / "data", ROOT / "images"


def base(path):
    return path.split("\\")[-1].lower()


# ---- the three versions ------------------------------------------------------------
def v0_car(e):
    """CAR-2014-04-003 pseudocode, literally."""
    return base(e["image"]) == "powershell.exe" and base(e["parent_image"]) != "explorer.exe"


# Allow-list built from V0 triage. Keyed on parent AND exact command line, never on the
# parent alone - otherwise an attacker who runs PowerShell from svchost would be ignored.
ALLOW = [
    (r"c:\windows\system32\svchost.exe", re.compile(r"^powershell\.exe -noprofile -file c:\\it\\inventory\.ps1$")),
    (r"c:\program files\manageengine\uems_agent\bin\dcagentservice.exe",
     re.compile(r"^powershell\.exe -noninteractive -encodedcommand " +
                re.escape("RwBlAHQALQBTAGUAcgB2AGkAYwBlAA==".lower()) + "$")),   # = "Get-Service"
    (r"c:\users\o.li\appdata\local\programs\microsoft vs code\code.exe",
     re.compile(r"^powershell\.exe -nologo( -noexit)?$")),
]


def allowed(e):
    p, c = e["parent_image"].lower(), e["command_line"].lower()
    return any(p == ap and rx.match(c) for ap, rx in ALLOW)


def v1_tuned(e):
    return v0_car(e) and not allowed(e)


SUSPICIOUS_FLAGS = re.compile(r"\s-(e|en|enc|encodedcommand)\s|\s-w(indowstyle)?\s+hidden", re.I)


def is_powershell(e):
    return (e["original_file_name"].lower() in ("powershell.exe", "pwsh.dll")
            or base(e["image"]) in ("powershell.exe", "pwsh.exe"))


def v2_ours(e):
    if not is_powershell(e) or allowed(e):
        return False
    if base(e["parent_image"]) != "explorer.exe":
        return True                                            # CAR logic (on OriginalFileName)
    return bool(SUSPICIOUS_FLAGS.search(" " + e["command_line"] + " "))   # .lnk branch


# ---- brand context from earlier weeks (week-02 brands.json, week-05 config.py, week-03 MISP)
BRANDS = {"kaspi": "Kaspi", "egov": "eGov", "eg0v": "eGov", "kazpost": "Kazpost", "post.kz": "Kazpost",
          "cdek": "CDEK", "halyk": "Halyk", "homebank": "Halyk"}
OFFICIAL = ["kaspi.kz", "kaspibank.kz", "cdn-kaspi.kz", "egov.kz", "gov.kz", "post.kz", "kazpost.kz",
            "cdek.kz", "cdek.ru", "halykbank.kz", "homebank.kz"]
MISP_IOC = ["kaspi-bonus-2026.com", "eg0v-portal.kz", "kazpost-delivery-track.net"]   # week-3 event


def classify(domain):
    d = domain.lower()
    if d in MISP_IOC:
        return "known IoC (week-3 MISP)"
    if any(d == o or d.endswith("." + o) for o in OFFICIAL):
        return "official brand site"
    if any(k in d for k in BRANDS):
        return "brand look-alike (new)"
    return "other"


def brand_of(domain):
    return next((b for k, b in BRANDS.items() if k in domain.lower()), "-")


VERSIONS = [("V0 CAR as published", v0_car), ("V1 CAR + allow-list", v1_tuned),
            ("V2 our detection", v2_ours)]


def main():
    try:
        events = [e for e in csv.DictReader(open(DATA / "sysmon_w7.csv")) if e["event_id"] == "1"]
        truth = list(csv.DictReader(open(DATA / "ground_truth.csv")))
    except FileNotFoundError:
        sys.exit("Run scripts/generate_w7_logs.py first")
    bad = {(t["time"], t["hostname"]): t["scenario"] for t in truth}
    out, summary = [], []

    def p(s=""):
        out.append(s)
        print(s)

    p(f"Process-creation events (Sysmon EID 1): {len(events)}   planted attacks: {len(truth)}")
    for name, fn in VERSIONS:
        hits = [e for e in events if fn(e)]
        tp = sorted({bad[(e['time'], e['hostname'])] for e in hits if (e["time"], e["hostname"]) in bad})
        fp = [e for e in hits if (e["time"], e["hostname"]) not in bad]
        missed = sorted(set(bad.values()) - set(tp))
        prec = len(tp) / len(hits) if hits else 0
        summary.append((name, len(hits), len(tp), len(fp), missed))
        p()
        p(f"=== {name} ===")
        p(f"alerts={len(hits)}  true positives={len(tp)} {tp}  false positives={len(fp)}  "
          f"missed={missed}  precision={prec:.1%}  recall={len(tp)}/{len(truth)}")
        p("alerts by parent process:")
        for par, n in Counter(base(e["parent_image"]) for e in hits).most_common():
            p(f"   {n:4d}  {par}")
        if len(hits) <= 10:
            p("alerts:")
            for e in hits:
                tag = bad.get((e["time"], e["hostname"]), "FP")
                p(f"   [{tag}] {e['time']} {e['hostname']} {e['user']:<14} "
                  f"{base(e['parent_image'])} -> {base(e['image'])}")
    # ---- V3 campaign attribution ------------------------------------------------------
    from datetime import datetime
    allev = list(csv.DictReader(open(DATA / "sysmon_w7.csv")))
    dnsq = [e for e in allev if e["event_id"] == "22"]
    ts = lambda e: datetime.fromisoformat(e["time"])
    p()
    p("=== V3 campaign attribution: V2 alert + DNS query of the same image within 60 s ===")
    attributed = 0
    for e in [x for x in events if v2_ours(x)]:
        q = [d for d in dnsq if d["hostname"] == e["hostname"] and d["image"] == e["image"]
             and 0 <= (ts(d) - ts(e)).total_seconds() <= 60]
        for d in q or [{"query_name": "(no DNS)"}]:
            cls = classify(d["query_name"]) if q else "-"
            attributed += cls not in ("-", "other", "official brand site")
            p(f"   [{bad.get((e['time'], e['hostname']), 'FP')}] {e['hostname']}  {base(e['image']):<15} -> "
              f"{d['query_name']:<28} brand={brand_of(d['query_name']):<8} {cls}")
    p(f"alerts attributed to a brand campaign: {attributed}")
    p()
    p("=== For comparison: brand-related DNS without any process alert (domain-only view) ===")
    for d in dnsq:
        cls = classify(d["query_name"])
        if cls in ("known IoC (week-3 MISP)", "brand look-alike (new)"):
            p(f"   {d['time']} {d['hostname']} {base(d['image']):<15} {d['query_name']:<28} {cls}")
    browsers = ("chrome.exe", "msedge.exe", "firefox.exe", "outlook.exe")
    rule = [d for d in dnsq if classify(d["query_name"]) in ("known IoC (week-3 MISP)", "brand look-alike (new)")
            and base(d["image"]) not in browsers]
    p(f"DNS rule (brand look-alike resolved by a non-browser process): {len(rule)} alerts on "
      f"{sorted({d['hostname'] for d in rule})}")
    c = Counter(classify(d["query_name"]) for d in dnsq)
    p("DNS queries by class: " + ", ".join(f"{k}={v}" for k, v in c.most_common()))

    (DATA / "car_results.txt").write_text("\n".join(out) + "\n")
    charts(events, summary)


def charts(events, summary):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("(matplotlib not installed - charts skipped)")
        return
    IMG.mkdir(exist_ok=True)
    ink, muted, grid = "#1f2328", "#59636e", "#d8dee4"
    tp_c, fp_c = "#2a6fdb", "#c9ced6"
    plt.rcParams.update({"font.size": 11, "axes.edgecolor": grid, "axes.labelcolor": ink,
                         "xtick.color": muted, "ytick.color": muted})

    # 1. TP vs FP per version
    fig, ax = plt.subplots(figsize=(8, 4.2))
    names = [s[0] for s in summary]
    tps, fps = [s[2] for s in summary], [s[3] for s in summary]
    y = range(len(names))[::-1]
    ax.barh(list(y), tps, color=tp_c, label="true positive (planted attack)")
    ax.barh(list(y), fps, left=tps, color=fp_c, label="false positive")
    for yi, s in zip(y, summary):
        miss = ", ".join(s[4]) if s[4] else "none"
        ax.text(s[1] + 2, yi, f"{s[1]} alerts · {s[2]}/5 attacks · missed: {miss}",
                va="center", color=ink, fontsize=10)
    ax.set_yticks(list(y), names)
    ax.set_xlim(0, max(s[1] for s in summary) * 1.75)
    ax.set_xlabel("alerts in one week (24 workstations)")
    ax.set_title("CAR-2014-04-003 on lab data: as published vs tuned", loc="left", color=ink)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, loc="lower right", fontsize=9)
    fig.tight_layout()
    fig.savefig(IMG / "w7_versions_tp_fp.png", dpi=150)
    plt.close(fig)

    # 2. What V0 fires on - parents
    hits = [e for e in events if v0_car(e)]
    c = Counter(base(e["parent_image"]) for e in hits).most_common()
    fig, ax = plt.subplots(figsize=(8, 3.6))
    labels, vals = [k for k, _ in c][::-1], [v for _, v in c][::-1]
    colors = [tp_c if k in ("winword.exe", "cmd.exe", "mshta.exe") else fp_c for k in labels]
    ax.barh(labels, vals, color=colors)
    for i, v in enumerate(vals):
        ax.text(v + 1.5, i, str(v), va="center", color=ink, fontsize=10)
    ax.set_title("V0 alerts by parent process (blue = planted attack)", loc="left", color=ink)
    ax.set_xlabel("alerts")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(IMG / "w7_v0_by_parent.png", dpi=150)
    plt.close(fig)
    print("charts written to images/")


if __name__ == "__main__":
    main()
