#!/usr/bin/env python3
"""
Week 10 - build ATT&CK Navigator layers for APT29 and compare them with our
group topic (phishing that impersonates Kazakhstani brands).

What it does
1. Downloads MITRE ATT&CK Enterprise STIX data (or uses a local copy).
2. Pulls every technique MITRE links to APT29 (G0016) -> layer 1.
3. Adds the techniques we mapped by hand from three 2024-2025 APT29 phishing
   campaigns (see ../README.md, section 3) -> marks them in layer 1.
4. Builds layer 2 from our KZ-brand phishing model (week 8 emulation plan).
5. Builds layer 3 = overlap of APT29 phishing campaigns vs our model.
6. Prints the overlap table and draws ../images/w10_overlap_matrix.png

Usage:
    pip install matplotlib
    python3 scripts/build_layers.py                 # downloads STIX (~55 MB)
    python3 scripts/build_layers.py --stix enterprise-attack.json
"""
import argparse
import json
import os
import urllib.request

STIX_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            "master/enterprise-attack/enterprise-attack.json")
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.dirname(HERE)

# --- Techniques mapped by us from public reports (section 3 of README) -------
CAMPAIGNS = {
    "A": "WINELOADER vs German political parties (Mandiant, Mar 2024)",
    "B": "Signed .RDP files, 100+ orgs (Microsoft, Oct 2024)",
    "C": "GRAPELOADER wine-tasting lure vs diplomats (Check Point, Apr 2025)",
}
APT29_CAMPAIGN_TTPS = {
    "T1584.004": ("A", "Compromised WordPress server hosts the ZIP / HTA"),
    "T1583.001": ("C", "Sender domains bakenhof[.]com, silry[.]com"),
    "T1588.004": ("B", "RDP file signed with a Let's Encrypt certificate"),
    "T1566.001": ("AB", "Attached lure document with link (A); .RDP file attached (B)"),
    "T1566.002": ("AC", "Link to invite.php (A) / to wine.zip (C)"),
    "T1684.001": ("ABC", "Poses as CDU, Microsoft/AWS staff, a European MFA"),
    "T1204.001": ("AC", "Victim clicks the link in the invitation"),
    "T1204.002": ("ABC", "Victim opens invite.hta / .rdp / wine.exe"),
    "T1218.005": ("A", "ROOTSAW runs as an HTA (mshta.exe)"),
    "T1140": ("A", "certutil -decode rebuilds invite.zip"),
    "T1105": ("AC", "Second stage downloaded after the click"),
    "T1574.001": ("AC", "DLL side-loading: SqlDumper.exe / wine.exe (PowerPoint)"),
    "T1027": ("AC", "RC4-encrypted core module, junk-code DLL"),
    "T1055.003": ("A", "WINELOADER thread execution hijacking (Mandiant table)"),
    "T1547.001": ("ABC", "Run key POWERPNT (C); Run key per Zscaler (A); AutoStart possible after RDP (B)"),
    "T1082": ("AC", "Host fingerprint: computer name, process"),
    "T1033": ("AC", "Username sent in first beacon"),
    "T1057": ("A", "Process discovery (Mandiant table)"),
    "T1005": ("B", "Victim drives exposed over the RDP session"),
    "T1039": ("B", "Network drives exposed over the RDP session"),
    "T1115": ("B", "Clipboard redirected to attacker RDP server"),
    "T1071.001": ("AC", "HTTPS GET/POST beacons to C2"),
}

# --- Our group model (week 8 plan + weeks 5/7 hunting) ----------------------
KZ_TTPS = {
    "T1598": "Collect brand assets / wording for lures",
    "T1583.001": "Look-alike domains (kaspl[.]ga, egov-kz-pay[.]online)",
    "T1608.005": "Credential-capture page staged behind the link",
    "T1566.002": "SMS / messenger / e-mail link: 'parcel held', 'eGov payout'",
    "T1566.001": "Kazpost-themed .docm attachment (week 5, H3)",
    "T1684.001": "Poses as Kaspi, eGov, Kazpost, CDEK",
    "T1204.001": "Victim opens the link",
    "T1204.002": "Victim opens the attachment",
    "T1059.001": "Word -> PowerShell (weeks 5 and 7)",
    "T1056.003": "Fake login / card form captures data",
    "T1111": "Fake form asks for the Kaspi SMS code",
    "T1547.001": "Implant autostart (lab emulation, week 8)",
    "T1053.005": "Scheduled task persistence (lab emulation)",
    "T1082": "Host discovery (CALDERA, week 8)",
    "T1083": "File discovery (CALDERA, week 8)",
    "T1005": "Stage local data",
    "T1071.001": "C2 over HTTPS",
    "T1041": "Exfiltration over C2",
    "T1567": "Exfiltration to web service / Telegram bot",
}

RED, BLUE, PURPLE, GREY = "#e74c3c", "#3498db", "#8e44ad", "#d5d8dc"


def load_stix(path):
    if not path:
        path = os.path.join(HERE, "enterprise-attack.json")
        if not os.path.exists(path):
            print("Downloading ATT&CK STIX ...")
            urllib.request.urlretrieve(STIX_URL, path)
    return json.load(open(path, encoding="utf-8"))["objects"]


def ext_id(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stix")
    args = ap.parse_args()
    objs = load_stix(args.stix)
    by_id = {o["id"]: o for o in objs}

    version = next(o.get("x_mitre_version") for o in objs
                   if o["type"] == "x-mitre-collection")
    attack_major = version.split(".")[0]

    tech = {ext_id(o): o for o in objs if o["type"] == "attack-pattern"
            and not o.get("revoked") and not o.get("x_mitre_deprecated")}
    for tid in list(APT29_CAMPAIGN_TTPS) + list(KZ_TTPS):
        assert tid in tech, f"{tid} not in ATT&CK v{version} (revoked/renamed?)"

    matrix = next(o for o in objs if o["type"] == "x-mitre-matrix")
    tactics = [by_id[t]["x_mitre_shortname"] for t in matrix["tactic_refs"]]
    tactic_name = {by_id[t]["x_mitre_shortname"]: by_id[t]["name"]
                   for t in matrix["tactic_refs"]}

    g = next(o for o in objs if o["type"] == "intrusion-set" and ext_id(o) == "G0016")
    mitre_apt29 = set()
    for r in objs:
        if (r["type"] == "relationship" and r["relationship_type"] == "uses"
                and r["source_ref"] == g["id"]
                and r["target_ref"].startswith("attack-pattern")
                and not r.get("revoked")):
            t = by_id[r["target_ref"]]
            if not t.get("revoked") and not t.get("x_mitre_deprecated"):
                mitre_apt29.add(ext_id(t))

    def entry(tid, color, comment, score=None):
        e = {"techniqueID": tid, "color": color, "comment": comment,
             "enabled": True, "showSubtechniques": True}
        if score is not None:
            e["score"] = score
        return e

    def layer(name, desc, techniques, legend):
        return {
            "name": name,
            "versions": {"attack": attack_major, "navigator": "5.1.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": desc,
            "filters": {"platforms": ["PRE", "Windows", "Linux", "macOS", "Network",
                                      "SaaS", "Office Suite", "Identity Provider"]},
            "sorting": 0,
            "layout": {"layout": "side", "showID": True, "showName": True,
                       "expandedSubtechniques": "annotated"},
            "hideDisabled": False,
            "techniques": techniques,
            "legendItems": legend,
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
        }

    # Layer 1 - APT29
    l1 = []
    for tid in sorted(mitre_apt29 | set(APT29_CAMPAIGN_TTPS)):
        in_mitre = tid in mitre_apt29
        camp = APT29_CAMPAIGN_TTPS.get(tid)
        if camp and in_mitre:
            color, note = "#c0392b", f"MITRE G0016 + campaigns {camp[0]}: {camp[1]}"
        elif camp:
            color, note = "#e67e22", f"Campaigns {camp[0]} only (not yet in G0016): {camp[1]}"
        else:
            color, note = "#f5b7b1", "Documented by MITRE for APT29 (G0016)"
        l1.append(entry(tid, color, note))
    layer1 = layer(
        "Week10 - APT29 TTPs",
        f"APT29 / Midnight Blizzard (G0016). ATT&CK v{version}. MITRE group page "
        f"({len(mitre_apt29)} techniques) + our mapping of 3 phishing campaigns "
        "2024-2025 (WINELOADER, RDP files, GRAPELOADER).",
        l1,
        [{"label": "MITRE G0016 and seen in 2024-25 campaigns", "color": "#c0392b"},
         {"label": "Seen in 2024-25 campaigns, not yet on G0016 page", "color": "#e67e22"},
         {"label": "MITRE G0016 only (older activity)", "color": "#f5b7b1"}])

    # Layer 2 - our KZ phishing model
    layer2 = layer(
        "Week10 - KZ brand phishing TTPs",
        "Our group topic: phishing impersonating Kaspi, eGov, Kazpost, CDEK. "
        "From the week 8 emulation plan and weeks 5/7 hunting.",
        [entry(t, BLUE, c) for t, c in sorted(KZ_TTPS.items())],
        [{"label": "KZ brand phishing (our model)", "color": BLUE}])

    # Layer 3 - overlap
    apt = set(APT29_CAMPAIGN_TTPS)
    kz = set(KZ_TTPS)
    l3 = []
    for tid in sorted(apt | kz):
        if tid in apt and tid in kz:
            l3.append(entry(tid, PURPLE, f"BOTH. APT29: {APT29_CAMPAIGN_TTPS[tid][1]} | KZ: {KZ_TTPS[tid]}", 3))
        elif tid in apt:
            l3.append(entry(tid, RED, f"APT29 only: {APT29_CAMPAIGN_TTPS[tid][1]}", 1))
        else:
            l3.append(entry(tid, BLUE, f"KZ phishing only: {KZ_TTPS[tid]}", 2))
    layer3 = layer(
        "Week10 - APT29 vs KZ brand phishing",
        "Overlap of APT29 phishing campaigns (2024-2025) with our KZ-brand phishing model.",
        l3,
        [{"label": "Both", "color": PURPLE},
         {"label": "APT29 only", "color": RED},
         {"label": "KZ brand phishing only", "color": BLUE}])

    for name, obj in [("apt29_layer.json", layer1),
                      ("kz_phishing_layer.json", layer2),
                      ("comparison_layer.json", layer3)]:
        with open(os.path.join(OUT, "navigator", name), "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
        print(f"wrote navigator/{name}: {len(obj['techniques'])} techniques")

    both = sorted(apt & kz)
    print(f"\nATT&CK v{version}; APT29 on MITRE page: {len(mitre_apt29)}; "
          f"campaign TTPs: {len(apt)}; KZ TTPs: {len(kz)}; overlap: {len(both)}")
    print("Jaccard overlap:", round(len(both) / len(apt | kz), 2))
    print("Both:", ", ".join(both))
    print("Campaign TTPs also on MITRE G0016:", len(apt & mitre_apt29), "/", len(apt))

    draw(tactics, tactic_name, tech, apt, kz)


def draw(tactics, tactic_name, tech, apt, kz):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.patches import Patch
    except ImportError:
        print("matplotlib not installed - skipping image")
        return
    cols = {}
    for tid in sorted(apt | kz):
        phases = [p["phase_name"] for p in tech[tid]["kill_chain_phases"]]
        first = min(phases, key=tactics.index)  # one column per technique
        cols.setdefault(first, []).append(tid)
    used = [t for t in tactics if t in cols]
    rows = max(len(v) for v in cols.values())
    fig, ax = plt.subplots(figsize=(2.15 * len(used), 0.62 * rows + 1.6))
    for x, tac in enumerate(used):
        ax.text(x + 0.5, -0.45, tactic_name[tac], ha="center", va="center",
                fontsize=9, fontweight="bold", wrap=True)
        for y, tid in enumerate(cols[tac]):
            c = PURPLE if (tid in apt and tid in kz) else RED if tid in apt else BLUE
            ax.add_patch(plt.Rectangle((x + 0.04, y + 0.06), 0.92, 0.88,
                                       color=c, ec="white"))
            name = tech[tid]["name"]
            name = name if len(name) <= 26 else name[:24] + "…"
            ax.text(x + 0.5, y + 0.5, f"{tid}\n{name}", ha="center", va="center",
                    fontsize=7.2, color="white")
    ax.set_xlim(0, len(used))
    ax.set_ylim(rows, -0.9)
    ax.axis("off")
    ax.set_title("APT29 phishing campaigns (2024-25) vs KZ brand phishing - ATT&CK overlap",
                 fontsize=12, pad=14)
    ax.legend(handles=[Patch(color=PURPLE, label="Both"),
                       Patch(color=RED, label="APT29 only"),
                       Patch(color=BLUE, label="KZ brand phishing only")],
              loc="lower center", bbox_to_anchor=(0.5, -0.08), ncol=3, frameon=False)
    path = os.path.join(OUT, "images", "w10_overlap_matrix.png")
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor="white")
    print("wrote images/w10_overlap_matrix.png")


if __name__ == "__main__":
    main()
