#!/usr/bin/env python3
"""
Week 07 - generate one week of LAB Sysmon process-creation logs for testing the
MITRE CAR analytic CAR-2014-04-003 "PowerShell Execution" in a SIEM.

Same fictitious company as week 5 ("QazLogistics LLP", 24 workstations WS-000..WS-023),
next working week: 2026-10-12 (Mon) .. 2026-10-18 (Sun), Asia/Almaty (+05:00).

Writes to ../data/:
  sysmon_w7.csv     the log to upload to the SIEM (no labels inside, like real data)
                    columns: time, hostname, user, event_id, image, original_file_name,
                             parent_image, command_line, dest_ip, dest_port, query_name
                    event_id: 1 process creation, 3 network connection, 22 DNS query
  ground_truth.csv  which events are the planted attacks (used only to SCORE the analytic)

Background (benign) activity:
  B1  nightly IT inventory: svchost.exe -> powershell -File C:\\IT\\inventory.ps1 (24 hosts x 7 days)
  B2  ManageEngine UEMS agent: dcagentservice.exe -> powershell -EncodedCommand (30 runs)
  B3  users start Outlook from explorer.exe every working morning
  B4  it.admin opens PowerShell by hand (explorer.exe -> powershell.exe), plain commands
  B5  developer o.li uses the VS Code terminal (Code.exe -> powershell.exe)
  B6  DNS from Chrome/Outlook, incl. official brand sites (kaspi.kz, egov.kz ...), the benign
      look-alike cdekteam.ru from week-2 OSINT, and one user who only clicked a Kazpost link

Planted phishing scenarios (all lab-safe: every -enc payload is base64 of a plain-text
placeholder string, nothing here is a working attack, 203.0.113.0/24 is TEST-NET-3):
  M1  Kazpost  .docm  OUTLOOK -> WINWORD -> powershell -enc            (WS-021)
  M2  Kaspi    .xlsm  OUTLOOK -> EXCEL -> cmd.exe -> powershell -enc   (WS-008)
  M3  eGov     .hta   OUTLOOK -> mshta.exe -> powershell -enc          (WS-014)
  M4  CDEK     .lnk   explorer.exe -> powershell -w hidden -enc        (WS-003)
  M5  Kaspi    .js    wscript.exe -> renamed powershell (winupdate.exe) (WS-017)
Each payload then resolves a brand look-alike domain (EID 22) and connects to it (EID 3):
  M1 kazpost-delivery-track.net, M2 kaspi-bonus-2026.com, M3 eg0v-portal.kz  (week-3 MISP IoCs)
  M4 cdek-nakladnaya.top, M5 kaspi-cashback.online                         (new, in no feed)

Usage (from week-07/):  python3 scripts/generate_w7_logs.py [--shift-to-now]
"""
import base64
import csv
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(2027)
TZ = timezone(timedelta(hours=5))
START = datetime(2026, 10, 12, tzinfo=TZ)  # Monday
OUT = Path(__file__).resolve().parent.parent / "data"

USERS = ["it.admin", "a.akhmetov", "b.zhunusova", "d.omarov", "e.kim", "g.abenova",
         "k.bekov", "l.sadykova", "m.tulegenov", "n.kassymova", "o.li", "r.mukanov",
         "s.aitkulova", "t.zhaksylykov", "u.baimukhanova", "v.sokolova", "y.dauletov",
         "z.temirova", "a.yesenov", "b.karimova", "d.alieva", "e.sultanov", "f.mamyrova",
         "m.ospanova"]
HOSTS = {f"WS-{i:03d}": u for i, u in enumerate(USERS)}

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
EXPLORER = r"C:\Windows\explorer.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
DCAGENT = r"C:\Program Files\ManageEngine\UEMS_Agent\bin\dcagentservice.exe"
OFFICE = r"C:\Program Files\Microsoft Office\root\Office16"
OUTLOOK, WINWORD, EXCEL = OFFICE + r"\OUTLOOK.EXE", OFFICE + r"\WINWORD.EXE", OFFICE + r"\EXCEL.EXE"
CMD = r"C:\Windows\System32\cmd.exe"
MSHTA = r"C:\Windows\System32\mshta.exe"
WSCRIPT = r"C:\Windows\System32\wscript.exe"
CODE = r"C:\Users\o.li\AppData\Local\Programs\Microsoft VS Code\Code.exe"


def enc(text):
    """PowerShell -EncodedCommand format: base64 of UTF-16LE. Placeholder text only."""
    return base64.b64encode(text.encode("utf-16-le")).decode()


ADMIN_CMDS = ["powershell.exe", '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"',
              "powershell.exe -NoExit -Command Get-Service Spooler",
              "powershell.exe -Command Get-ADUser -Filter *"]
DEV_CMDS = ["powershell.exe -NoLogo", "powershell.exe -NoLogo -NoExit"]

events, truth = [], []


def ev(t, host, user, image, parent, cmd, eid=1, ofn=None, dst="", port="", query=""):
    if ofn is None:
        ofn = {PS: "PowerShell.EXE", CMD: "Cmd.Exe", MSHTA: "MSHTA.EXE", WSCRIPT: "wscript.exe",
               WINWORD: "WinWord.exe", EXCEL: "Excel.exe", OUTLOOK: "Outlook.exe"}.get(image, "")
    if eid in (3, 22):           # Sysmon EID 3 / 22 carry Image but no OriginalFileName
        ofn = ""
    events.append({"time": t.isoformat(), "hostname": host, "user": user, "event_id": eid,
                   "image": image, "original_file_name": ofn, "parent_image": parent,
                   "command_line": cmd, "dest_ip": dst, "dest_port": port, "query_name": query})
    return events[-1]


def dns(t, host, user, image, query):
    """Sysmon Event ID 22 (DnsQuery): which process resolved which domain."""
    return ev(t, host, user, image, "", "", eid=22, query=query)


def plant(sid, brand, e):
    truth.append({"scenario": sid, "brand": brand, "time": e["time"], "hostname": e["hostname"],
                  "image": e["image"], "parent_image": e["parent_image"]})


for day in range(7):
    d = START + timedelta(days=day)
    workday = day < 5
    # B1 nightly inventory on every host
    for i, host in enumerate(HOSTS):
        ev(d + timedelta(hours=2, seconds=i * 2 + random.randint(0, 1)), host, "SYSTEM", PS, SVCHOST,
           r"powershell.exe -NoProfile -File C:\IT\inventory.ps1")
    if not workday:
        continue
    # B3 Outlook every morning
    for host, user in HOSTS.items():
        ev(d + timedelta(hours=9, minutes=random.randint(0, 25)), host, user, OUTLOOK, EXPLORER, '"OUTLOOK.EXE"')
    # B2 ManageEngine agent, 6 runs per working day
    for _ in range(6):
        host = random.choice(list(HOSTS))
        ev(d + timedelta(hours=random.randint(10, 17), minutes=random.randint(0, 59)), host, "SYSTEM", PS,
           DCAGENT, "powershell.exe -NonInteractive -EncodedCommand " + enc("Get-Service"))
    # B4 admin interactive PowerShell (3 per day on WS-000)
    for _ in range(3):
        ev(d + timedelta(hours=random.randint(9, 17), minutes=random.randint(0, 59)), "WS-000", "it.admin",
           PS, EXPLORER, random.choice(ADMIN_CMDS))
    # B5 developer terminal in VS Code (2 per day on WS-010)
    for _ in range(2):
        ev(d + timedelta(hours=random.randint(10, 18), minutes=random.randint(0, 59)), "WS-010", "o.li",
           PS, CODE, random.choice(DEV_CMDS))

# B6 DNS (Sysmon EID 22) from browsers and Outlook - own RNG, so B1-B5 stay unchanged
rnd = random.Random(722)
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
NORMAL_DNS = ["www.google.com", "kaspi.kz", "egov.kz", "post.kz", "cdek.kz", "web.telegram.org",
              "teams.microsoft.com", "kolesa.kz", "krisha.kz", "halykbank.kz"]
for day in range(5):
    d = START + timedelta(days=day)
    for host, user in HOSTS.items():
        dns(d + timedelta(hours=9, minutes=30), host, user, OUTLOOK, "outlook.office365.com")
        for _ in range(3):
            dns(d + timedelta(hours=rnd.randint(10, 17), minutes=rnd.randint(0, 59), seconds=rnd.randint(0, 59)),
                host, user, CHROME, rnd.choice(NORMAL_DNS))
# benign look-alike from week-2 OSINT: a user really visits cdekteam.ru (Russian site, 0/91 on VT)
dns(START + timedelta(days=2, hours=16, minutes=5), "WS-012", "s.aitkulova", CHROME, "cdekteam.ru")
# a user clicks the Kazpost link in the browser but does not open the attachment (week-3 IoC)
dns(START + timedelta(days=1, hours=10, minutes=52), "WS-005", "g.abenova", CHROME, "kazpost-delivery-track.net")

# ---- planted scenarios -------------------------------------------------------------
PH = "LAB-SAMPLE: simulated downloader placeholder for detection practice"

# M1 Kazpost parcel notice (.docm) - Tue 13 Oct
t = START + timedelta(days=1, hours=10, minutes=41)
ev(t, "WS-021", "e.sultanov", WINWORD, OUTLOOK, f'"WINWORD.EXE" /n "C:\\Users\\e.sultanov\\Downloads\\Kazpost_uvedomlenie.docm" /o ""')
plant("M1", "Kazpost", ev(t + timedelta(seconds=6), "WS-021", "e.sultanov", PS, WINWORD,
      "powershell.exe -nop -w hidden -enc " + enc(PH)))
dns(t + timedelta(seconds=7), "WS-021", "e.sultanov", PS, "kazpost-delivery-track.net")   # week-3 MISP IoC
ev(t + timedelta(seconds=8), "WS-021", "e.sultanov", PS, "", "", eid=3, dst="203.0.113.99", port=443)

# M2 Kaspi "statement" (.xlsm) -> cmd -> powershell - Wed 14 Oct
t = START + timedelta(days=2, hours=11, minutes=17)
ev(t, "WS-008", "m.tulegenov", EXCEL, OUTLOOK, f'"EXCEL.EXE" "C:\\Users\\m.tulegenov\\Downloads\\Kaspi_vypiska_oktyabr.xlsm"')
ev(t + timedelta(seconds=5), "WS-008", "m.tulegenov", CMD, EXCEL,
   "cmd.exe /c powershell -ep bypass -enc " + enc(PH))
plant("M2", "Kaspi", ev(t + timedelta(seconds=6), "WS-008", "m.tulegenov", PS, CMD,
      "powershell -ep bypass -enc " + enc(PH)))
dns(t + timedelta(seconds=7), "WS-008", "m.tulegenov", PS, "kaspi-bonus-2026.com")   # week-3 MISP IoC
ev(t + timedelta(seconds=8), "WS-008", "m.tulegenov", PS, "", "", eid=3, dst="203.0.113.47", port=443)

# M3 eGov notification (.hta) -> mshta -> powershell - Thu 15 Oct
t = START + timedelta(days=3, hours=14, minutes=2)
ev(t, "WS-014", "t.zhaksylykov", MSHTA, OUTLOOK,
   '"C:\\Windows\\System32\\mshta.exe" "C:\\Users\\t.zhaksylykov\\Downloads\\egov_uvedomlenie.hta"')
plant("M3", "eGov", ev(t + timedelta(seconds=4), "WS-014", "t.zhaksylykov", PS, MSHTA,
      "powershell.exe -w hidden -enc " + enc(PH)))
dns(t + timedelta(seconds=5), "WS-014", "t.zhaksylykov", PS, "eg0v-portal.kz")   # week-3 MISP IoC
ev(t + timedelta(seconds=6), "WS-014", "t.zhaksylykov", PS, "", "", eid=3, dst="203.0.113.12", port=443)

# M4 CDEK waybill shortcut (.lnk inside a .zip) - Fri 16 Oct. Parent is explorer.exe!
t = START + timedelta(days=4, hours=9, minutes=48)
plant("M4", "CDEK", ev(t, "WS-003", "d.omarov", PS, EXPLORER,
      "powershell.exe -WindowStyle Hidden -EncodedCommand " + enc(PH)))
dns(t + timedelta(seconds=2), "WS-003", "d.omarov", PS, "cdek-nakladnaya.top")   # NEW domain, not in any feed
ev(t + timedelta(seconds=3), "WS-003", "d.omarov", PS, "", "", eid=3, dst="203.0.113.150", port=443)

# M5 Kaspi bonus (.js) -> wscript -> COPY of powershell renamed to winupdate.exe - Fri 16 Oct
t = START + timedelta(days=4, hours=15, minutes=33)
ev(t, "WS-017", "z.temirova", WSCRIPT, EXPLORER,
   '"C:\\Windows\\System32\\WScript.exe" "C:\\Users\\z.temirova\\Downloads\\Kaspi_bonus_50000.js"')
fake = r"C:\Users\Public\Libraries\winupdate.exe"
plant("M5", "Kaspi", ev(t + timedelta(seconds=9), "WS-017", "z.temirova", fake, WSCRIPT,
      "winupdate.exe -nop -enc " + enc(PH), ofn="PowerShell.EXE"))
dns(t + timedelta(seconds=10), "WS-017", "z.temirova", fake, "kaspi-cashback.online")   # NEW domain
ev(t + timedelta(seconds=11), "WS-017", "z.temirova", fake, "", "", eid=3, dst="203.0.113.201", port=443)

events.sort(key=lambda e: e["time"])

# --shift-to-now: move the whole week so that the last event is 1 hour ago.
# Needed only if the Kibana detection rule must fire on "live" time (rule look-back).
if "--shift-to-now" in sys.argv:
    last = datetime.fromisoformat(events[-1]["time"])
    delta = datetime.now(TZ) - timedelta(hours=1) - last
    delta = timedelta(seconds=int(delta.total_seconds()))
    for e in events + truth:
        e["time"] = (datetime.fromisoformat(e["time"]) + delta).isoformat()
    print(f"timestamps shifted by {delta}")

OUT.mkdir(exist_ok=True)
with open(OUT / "sysmon_w7.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(events[0]))
    w.writeheader()
    w.writerows(events)
with open(OUT / "ground_truth.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(truth[0]))
    w.writeheader()
    w.writerows(truth)
print(f"sysmon_w7.csv: {len(events)} events  |  ground_truth.csv: {len(truth)} planted attacks")
