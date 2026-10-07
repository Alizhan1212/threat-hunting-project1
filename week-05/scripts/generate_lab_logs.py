#!/usr/bin/env python3
"""
Week 05 - generate one week of LAB logs for the threat hunt.

Writes three CSV files to ../data/ (upload them to Splunk or Kibana):
  dns.csv     time, src_ip, hostname, user, query, answer, rcode
  proxy.csv   time, src_ip, hostname, user, method, url, domain, status, bytes_out, user_agent
  sysmon.csv  time, hostname, user, event_id, image, parent_image, command_line, dest_ip, dest_port

Background traffic is random but seeded, so every run gives identical files.
The planted scenarios are listed in PLANTED below and in ../README.md section 4.
Nothing in these logs is a working attack: the "malicious" PowerShell command line
is base64 of a plain-text placeholder string.

Usage (from week-05/):  python3 scripts/generate_lab_logs.py
"""
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import KNOWN_BAD_DOMAINS, BENIGN_LOOKALIKES

random.seed(2026)
TZ = timezone(timedelta(hours=5))
START = datetime(2026, 9, 28, tzinfo=TZ)        # Monday
OUT = Path(__file__).resolve().parent.parent / "data"

USERS = ["it.admin", "a.akhmetov", "b.zhunusova", "d.omarov", "e.kim", "g.abenova",
         "k.bekov", "l.sadykova", "m.tulegenov", "n.kassymova", "o.li", "r.mukanov",
         "s.aitkulova", "t.zhaksylykov", "u.baimukhanova", "v.sokolova", "y.dauletov",
         "z.temirova", "a.yesenov", "b.karimova", "d.alieva", "e.sultanov", "f.mamyrova",
         "m.ospanova"]
HOSTS = [{"host": f"WS-{i:03d}", "ip": f"10.10.1.{10 + i}", "user": u} for i, u in enumerate(USERS)]
H = {h["host"]: h for h in HOSTS}

# normal sites: (domain, answer IP, weight)
NORMAL = [
    ("www.google.com", "142.250.74.4", 30), ("outlook.office365.com", "52.97.146.162", 25),
    ("teams.microsoft.com", "52.113.194.132", 20), ("web.telegram.org", "149.154.167.99", 10),
    ("kaspi.kz", "88.204.164.10", 8), ("pay.kaspi.kz", "88.204.164.12", 4),
    ("egov.kz", "195.12.113.27", 6), ("idp.egov.kz", "195.12.113.30", 3),
    ("post.kz", "91.185.15.50", 3), ("track.post.kz", "91.185.15.52", 2),
    ("cdek.kz", "178.248.237.70", 3), ("homebank.kz", "185.98.4.20", 3),
    ("www.youtube.com", "142.250.74.14", 12), ("github.com", "140.82.121.4", 5),
    ("krisha.kz", "92.46.56.10", 4), ("olx.kz", "54.76.12.30", 4),
    ("windowsupdate.microsoft.com", "13.107.4.50", 6), ("hh.kz", "94.124.200.40", 3),
]
# real week-2 false positives - appear a few times, all harmless browsing
BENIGN_IP = {"cdekteam.ru": "185.215.4.20", "egov.proteantech.in": "103.21.58.10",
             "kolesa-darom.ru": "92.53.96.120"}

dns, proxy, sysmon = [], [], []
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0"


def ts(day, hh, mm, ss=0):
    return (START + timedelta(days=day, hours=hh, minutes=mm, seconds=ss)).isoformat()


def visit(t, h, domain, ip, method="GET", path="/", status=200, bytes_out=None):
    dns.append([t, h["ip"], h["host"], h["user"], domain, ip, "NOERROR"])
    proxy.append([t, h["ip"], h["host"], h["user"], method, f"https://{domain}{path}", domain,
                  status, bytes_out if bytes_out is not None else random.randint(300, 900), UA])


# ---------------------------------------------------------------- background
weights = [w for _, _, w in NORMAL]
for day in range(7):
    workday = day < 5
    for h in HOSTS:
        for _ in range(random.randint(25, 45) if workday else random.randint(0, 6)):
            d, ip, _ = random.choices(NORMAL, weights)[0]
            t = ts(day, random.randint(9, 18), random.randint(0, 59), random.randint(0, 59))
            m = "POST" if random.random() < 0.08 else "GET"
            visit(t, h, d, ip, m, "/" if m == "GET" else "/api", 200,
                  random.randint(800, 4000) if m == "POST" else None)

for i, d in enumerate(BENIGN_LOOKALIKES):
    for j in range(3):
        h = random.choice(HOSTS)
        visit(ts(random.randint(0, 4), random.randint(10, 17), random.randint(0, 59)), h, d, BENIGN_IP[d])

# normal PowerShell: nightly inventory task + a software agent using -EncodedCommand (known FP)
for day in range(7):
    for h in HOSTS:
        sysmon.append([ts(day, 2, 0, random.randint(0, 59)), h["host"], "SYSTEM", 1,
                       r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                       r"C:\Windows\System32\svchost.exe",
                       r"powershell.exe -NoProfile -File C:\IT\inventory.ps1", "", ""])
for day in range(5):
    for h in random.sample(HOSTS, 6):
        sysmon.append([ts(day, random.randint(9, 17), random.randint(0, 59)), h["host"], "SYSTEM", 1,
                       r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                       r"C:\Program Files\ManageEngine\UEMS_Agent\bin\dcagentservice.exe",
                       "powershell.exe -NonInteractive -EncodedCommand RwBlAHQALQBTAGUAcgB2AGkAYwBlAA==",
                       "", ""])
for h in HOSTS:   # users opening Office normally
    for day in range(5):
        sysmon.append([ts(day, 9, random.randint(0, 30)), h["host"], h["user"], 1,
                       r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
                       r"C:\Windows\explorer.exe", '"OUTLOOK.EXE"', "", ""])

# ---------------------------------------------------------------- planted scenarios
PLANTED = []

# S1 - known IoC from MISP (intel-driven hunt should catch it)
h = H["WS-007"]
visit(ts(1, 11, 42, 5), h, KNOWN_BAD_DOMAINS[0], "185.120.10.45")
PLANTED.append("S1 WS-007 kaspi-bonus-2026.com (MISP IoC), GET only")

# S2 - NEW look-alike domains not in any feed (only hypothesis-driven hunt catches them)
new_domains = [
    ("WS-012", 2, "kaspi-gold-bonus.top",    "198.51.100.23", "/login",          "/login/verify"),
    ("WS-012", 2, "kaspi-gold-bonus.top",    "198.51.100.23", "/sms",            "/sms/confirm"),
    ("WS-015", 3, "egov-vyplata.online",     "198.51.100.77", "/posobie",        "/posobie/card"),
    ("WS-019", 3, "kazpost-posylka.site",    "203.0.113.41",  "/track",          "/pay"),
    ("WS-004", 4, "cdek-dostavka-kz.info",   "203.0.113.58",  "/order",          None),   # opened, did not submit
]
for host, day, dom, ip, get_path, post_path in new_domains:
    h = H[host]
    hh, mm = random.randint(10, 16), random.randint(0, 50)
    visit(ts(day, hh, mm, 3), h, dom, ip, "GET", get_path)
    if post_path:
        visit(ts(day, hh, mm + 1, 40), h, dom, ip, "POST", post_path, 200, random.randint(1500, 3000))
    if get_path == "/sms":
        continue
    PLANTED.append(f"S2 {host} {dom} {'GET+POST (data submitted)' if post_path else 'GET only'}")

# S3 - "Kazpost parcel" email attachment -> Word -> encoded PowerShell -> outbound connection
h = H["WS-021"]
LAB_B64 = ("TABBAEIALQBTAEEATQBQAEwARQA6ACAAcwBpAG0AdQBsAGEAdABlAGQAIABkAG8AdwBuAGwAbwBhAGQAZQByACAAcABsAGEAYwBl"
           "AGgAbwBsAGQAZQByACAAZgBvAHIAIABkAGUAdABlAGMAdABpAG8AbgAgAHAAcgBhAGMAdABpAGMAZQA=")
sysmon += [
    [ts(2, 14, 5, 10), h["host"], h["user"], 1,
     r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
     r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
     f'"WINWORD.EXE" /n "C:\\Users\\{h['user']}\\AppData\\Local\\Temp\\Kazpost_Uvedomlenie_4471.docm"', "", ""],
    [ts(2, 14, 5, 22), h["host"], h["user"], 1,
     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
     f"powershell.exe -nop -w hidden -enc {LAB_B64}", "", ""],
    [ts(2, 14, 5, 24), h["host"], h["user"], 3,
     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "", "", "203.0.113.99", 443],
]
dns.append([ts(2, 14, 5, 23), h["ip"], h["host"], h["user"], "kazpost-notice.site", "203.0.113.99", "NOERROR"])
PLANTED.append("S3 WS-021 OUTLOOK->WINWORD(.docm)->powershell -enc -> 203.0.113.99 (kazpost-notice.site)")

# ---------------------------------------------------------------- write
OUT.mkdir(exist_ok=True)
for name, hdr, rows in [
    ("dns.csv", ["time", "src_ip", "hostname", "user", "query", "answer", "rcode"], dns),
    ("proxy.csv", ["time", "src_ip", "hostname", "user", "method", "url", "domain", "status", "bytes_out", "user_agent"], proxy),
    ("sysmon.csv", ["time", "hostname", "user", "event_id", "image", "parent_image", "command_line", "dest_ip", "dest_port"], sysmon),
]:
    rows.sort(key=lambda r: r[0])
    with open(OUT / name, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(hdr)
        w.writerows(rows)
    print(f"{name:11s} {len(rows):6d} events")
print("\nPlanted scenarios (answer key):")
for p in PLANTED:
    print("  -", p)
