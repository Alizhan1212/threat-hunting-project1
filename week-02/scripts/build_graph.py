#!/usr/bin/env python3
"""
Week 2 — link-analysis graph (Maltego-style) built from collected OSINT relations.

Input : data/relations.csv  (source,source_type,target,target_type,relation,evidence)
Output: screenshots/w2_link_graph.png

Every edge in the CSV comes from a real lookup (VirusTotal, Shodan, nslookup) —
see the "evidence" column. Only matplotlib is required.

Usage:
  python3 week2/scripts/build_graph.py
"""
import csv
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "data" / "relations.csv"
OUT = ROOT / "screenshots" / "w2_link_graph.png"

STYLE = {  # node type -> (colour, label shown in legend)
    "domain":    ("#2563eb", "Domain"),
    "ip":        ("#16a34a", "IP address"),
    "asn":       ("#9333ea", "ASN / network"),
    "org":       ("#ea580c", "Hosting organisation"),
    "geo":       ("#0891b2", "Location"),
    "registrar": ("#ca8a04", "Registrar"),
    "status":    ("#dc2626", "Status"),
    "netblock":  ("#7c3aed", "Netblock"),
    "dns":       ("#64748b", "Name servers"),
    "mail":      ("#0d9488", "Mail server"),
    "date":      ("#a16207", "Registration date"),
}


def load():
    with SRC.open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    types = {}
    for r in rows:
        types.setdefault(r["source"], r["source_type"])
        types.setdefault(r["target"], r["target_type"])
    return rows, types


def layout(rows, types):
    """Simple layered layout: roots (domains that are only sources) on the left,
    their children in the middle, grandchildren on the right."""
    children = defaultdict(list)
    has_parent = set()
    for r in rows:
        children[r["source"]].append(r["target"])
        has_parent.add(r["target"])
    roots = [n for n in types if n not in has_parent]
    pos, y_cursor = {}, 0.0
    for root in roots:
        kids = children[root]
        block = max(1, sum(max(1, len(children[k])) for k in kids))
        top = y_cursor
        pos[root] = (0.0, -(top + block / 2 - 0.5))
        y = top
        for k in kids:
            gk = children[k]
            span = max(1, len(gk))
            pos.setdefault(k, (1.0, -(y + span / 2 - 0.5)))
            for i, g in enumerate(gk):
                pos.setdefault(g, (2.0, -(y + i)))
            y += span
        y_cursor = top + block + 0.8
    return pos


def main():
    rows, types = load()
    pos = layout(rows, types)
    h = max(5, 0.75 * (max(-p[1] for p in pos.values()) + 2))
    fig, ax = plt.subplots(figsize=(15, h))
    ax.set_axis_off()

    for r in rows:
        (x1, y1), (x2, y2) = pos[r["source"]], pos[r["target"]]
        ax.annotate("", xy=(x2 - 0.13, y2), xytext=(x1 + 0.13, y1),
                    arrowprops=dict(arrowstyle="-|>", color="#94a3b8", lw=1.3))
        t = 0.6
        ax.text(x1 + (x2 - x1) * t, y1 + (y2 - y1) * t, r["relation"], fontsize=7.5,
                color="#334155", ha="center", va="center", zorder=4,
                bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="#e2e8f0", lw=0.6))

    for node, (x, y) in pos.items():
        colour = STYLE.get(types[node], ("#64748b", ""))[0]
        ax.scatter([x], [y], s=900, color=colour, zorder=3, edgecolors="white", linewidths=2)
        ax.text(x, y - 0.33, node, ha="center", va="top", fontsize=9.5, fontweight="bold", color="#0f172a")

    used = {types[n] for n in pos}
    handles = [plt.Line2D([], [], marker="o", ls="", markersize=11, color=STYLE[t][0], label=STYLE[t][1])
               for t in STYLE if t in used]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.02), ncol=min(len(handles), 6),
              frameon=False, fontsize=9)
    fig.suptitle("Link analysis — candidate domains from KZ-brand OSINT collection (week 2)",
                 fontsize=13, x=0.02, ha="left", color="#0f172a")
    fig.text(0.02, 0.94, "Sources: VirusTotal passive DNS, Shodan, nslookup, dig, whois (2026-09-29/30). Built by build_graph.py",
             fontsize=8.5, color="#64748b", ha="left")
    ax.set_xlim(-0.4, 2.55)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=160, bbox_inches="tight", facecolor="white")
    print(f"[+] graph -> {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
