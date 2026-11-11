#!/usr/bin/env python3
"""
Week 10 - render ATT&CK Navigator layers to SVG (Navigator-style matrix).

Draws only the techniques present in each layer, grouped by ATT&CK tactic
(same column order as ATT&CK Navigator), coloured exactly as in the layer,
with the layer legend. Output: ../svg/<layer>.svg

Usage:
    python3 scripts/render_svg.py                       # downloads STIX if needed
    python3 scripts/render_svg.py --stix enterprise-attack.json
"""
import argparse
import glob
import json
import os
import urllib.request
from xml.sax.saxutils import escape

STIX_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            "master/enterprise-attack/enterprise-attack.json")
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.dirname(HERE)

COL_W, CELL_H, GAP = 190, 46, 6
PAD, HEAD_H, TITLE_H = 24, 52, 70
FONT = "Helvetica, Arial, sans-serif"


def ext_id(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def text_color(hex_color):
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return "#000000" if (0.299 * r + 0.587 * g + 0.114 * b) > 160 else "#ffffff"


def wrap(s, width=26, lines=2):
    words, out, cur = s.split(), [], ""
    for w in words:
        if len(cur) + len(w) + (1 if cur else 0) <= width:
            cur = f"{cur} {w}".strip()
        else:
            out.append(cur)
            cur = w
    out.append(cur)
    if len(out) > lines:
        out = out[:lines]
        out[-1] = out[-1][:width - 1] + "…"
    return out


def render(layer, tech, tactics, tactic_name, version):
    cols = {}
    for t in layer["techniques"]:
        tid = t["techniqueID"]
        phases = [p["phase_name"] for p in tech[tid]["kill_chain_phases"]]
        tac = t.get("tactic") or min(phases, key=tactics.index)
        cols.setdefault(tac, []).append(t)
    used = [t for t in tactics if t in cols]
    for tac in used:
        cols[tac].sort(key=lambda t: t["techniqueID"])
    rows = max(len(v) for v in cols.values())

    legend = layer.get("legendItems", [])
    width = PAD * 2 + len(used) * (COL_W + GAP) - GAP
    grid_h = rows * (CELL_H + GAP)
    legend_h = 40 + 26 * len(legend)
    height = TITLE_H + HEAD_H + grid_h + legend_h + PAD

    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
         f'viewBox="0 0 {width} {height}" font-family="{FONT}">',
         f'<rect width="100%" height="100%" fill="#ffffff"/>',
         f'<text x="{PAD}" y="34" font-size="22" font-weight="bold" fill="#111">'
         f'{escape(layer["name"])}</text>',
         f'<text x="{PAD}" y="58" font-size="12" fill="#555">MITRE ATT&amp;CK Enterprise v{version} · '
         f'{len(layer["techniques"])} techniques · shown: techniques in this layer only</text>']

    y0 = TITLE_H
    for i, tac in enumerate(used):
        x = PAD + i * (COL_W + GAP)
        s.append(f'<rect x="{x}" y="{y0}" width="{COL_W}" height="{HEAD_H - 8}" fill="#dddddd"/>')
        s.append(f'<text x="{x + COL_W / 2}" y="{y0 + 20}" font-size="13" font-weight="bold" '
                 f'text-anchor="middle" fill="#111">{escape(tactic_name[tac])}</text>')
        s.append(f'<text x="{x + COL_W / 2}" y="{y0 + 36}" font-size="11" text-anchor="middle" '
                 f'fill="#444">{len(cols[tac])} technique{"s" if len(cols[tac]) != 1 else ""}</text>')
        for j, t in enumerate(cols[tac]):
            tid = t["techniqueID"]
            cy = y0 + HEAD_H + j * (CELL_H + GAP)
            color = t.get("color", "#ffffff")
            fg = text_color(color)
            name = tech[tid]["name"]
            if "." in tid:  # sub-technique: show parent name for context
                parent = tech.get(tid.split(".")[0])
                if parent:
                    name = f'{parent["name"]}: {name}'
            title = escape(f'{tid} {name}' + (f' — {t["comment"]}' if t.get("comment") else ""))
            s.append(f'<g><title>{title}</title>')
            s.append(f'<rect x="{x}" y="{cy}" width="{COL_W}" height="{CELL_H}" rx="3" '
                     f'fill="{color}" stroke="#999" stroke-width="0.6"/>')
            s.append(f'<text x="{x + 8}" y="{cy + 15}" font-size="11" font-weight="bold" '
                     f'fill="{fg}">{tid}</text>')
            for k, line in enumerate(wrap(name)):
                s.append(f'<text x="{x + 8}" y="{cy + 29 + k * 12}" font-size="10.5" '
                         f'fill="{fg}">{escape(line)}</text>')
            s.append('</g>')

    ly = TITLE_H + HEAD_H + grid_h + 24
    s.append(f'<text x="{PAD}" y="{ly}" font-size="13" font-weight="bold" fill="#111">Legend</text>')
    for i, item in enumerate(legend):
        yy = ly + 14 + i * 26
        s.append(f'<rect x="{PAD}" y="{yy}" width="18" height="18" fill="{item["color"]}" stroke="#999"/>')
        s.append(f'<text x="{PAD + 28}" y="{yy + 14}" font-size="12" fill="#222">'
                 f'{escape(item["label"])}</text>')
    s.append('</svg>')
    return "\n".join(s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stix")
    args = ap.parse_args()
    path = args.stix or os.path.join(HERE, "enterprise-attack.json")
    if not os.path.exists(path):
        print("Downloading ATT&CK STIX ...")
        urllib.request.urlretrieve(STIX_URL, path)
    objs = json.load(open(path, encoding="utf-8"))["objects"]
    by_id = {o["id"]: o for o in objs}
    version = next(o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection")
    tech = {ext_id(o): o for o in objs if o["type"] == "attack-pattern" and not o.get("revoked")}
    matrix = next(o for o in objs if o["type"] == "x-mitre-matrix")
    tactics = [by_id[t]["x_mitre_shortname"] for t in matrix["tactic_refs"]]
    tactic_name = {by_id[t]["x_mitre_shortname"]: by_id[t]["name"] for t in matrix["tactic_refs"]}

    os.makedirs(os.path.join(OUT, "svg"), exist_ok=True)
    for f in sorted(glob.glob(os.path.join(OUT, "navigator", "*.json"))):
        layer = json.load(open(f, encoding="utf-8"))
        out = os.path.join(OUT, "svg", os.path.basename(f).replace(".json", ".svg"))
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(render(layer, tech, tactics, tactic_name, version))
        print("wrote", os.path.relpath(out, OUT))


if __name__ == "__main__":
    main()
