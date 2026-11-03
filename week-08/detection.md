# Detection — how a defender catches each phase

This is the blue-team core of the week 8 deliverable. For every phase of the emulation plan we state **where to look**, **what signal**, and a **hunt idea** a threat hunter could run.

> All detections below are standard defensive telemetry. None of them require running the attack against real users.

## Pre-compromise (monitoring / takedown)

| Phase | Where to look | Signal | Hunt idea |
|---|---|---|---|
| Resource Development (T1583.001) | Certificate Transparency logs, domain registration feeds (WHOIS, certstream) | Newly registered / newly seen domains containing brand strings (kaspi, egov, kazpost, cdek) or common typo-variants | Daily diff of new certs/domains matching a brand keyword list; route hits to brand-abuse takedown |
| Initial Access (T1566) | Abuse mailbox, user reports, URL reputation | Delivery- or bonus-themed lures linking to the domains above | Correlate reported lure URLs against the new-domain feed |

## Post-compromise (endpoint + network — what we emulate)

| Phase | Where to look | Signal (example) | Hunt idea |
|---|---|---|---|
| Execution (T1204) | Sysmon EID 1 (process create) | Office/script interpreter spawning an unexpected child | Parent-child anomaly hunt (e.g. document app → shell) |
| Persistence — Run Keys (T1547.001) | Sysmon EID 13 (registry set) / auditd | New value under `...\CurrentVersion\Run` | Baseline autostart entries; alert on additions |
| Persistence — Scheduled Task (T1053.005) | Windows Security EID 4698; Sysmon EID 1 (`schtasks`) | Task created outside change windows | Hunt task creations by non-admin / unusual user |
| Discovery (T1082, T1083) | Sysmon EID 1 | Bursts of `systeminfo`, `whoami`, mass directory listing | Frequency/volume hunt on discovery commands per host |
| Collection (T1005) | File access auditing / EDR | Staging many files into one archive/temp dir | Hunt sudden archive creation preceding egress |
| C2 (T1071.001) | Proxy / DNS / firewall logs | Beacon-like periodic HTTPS to a low-reputation host | Beacon hunt: regular interval + small, steady payloads |
| Exfiltration (T1041 / T1567) | Proxy / NetFlow | Outbound to a web-service/API endpoint atypical for that host, or volume spike | Hunt first-time outbound to messaging/web-service APIs from endpoints that never use them |
| Exfiltration to Telegram (T1567) | Proxy / DNS / Sysmon EID 22 | `api.telegram.org` resolved or contacted by a non-browser, non-Telegram process | Telegram is plausible here: `kaspibank.auth-telegramm.ru` (week 5) imitates Telegram auth. Alert on rare process → `api.telegram.org` |

## IOCs to maintain

- List of observed lookalike domains / URLs (from OSINT)
- Hashes of any sample files analysed (in a sandbox)
- Destination endpoints seen in the exfil phase

## Mapping back to ATT&CK

Each row above corresponds to a technique highlighted in `navigator-layer-w8.json`, so the detection coverage and the emulation plan use the same technique IDs end to end.
