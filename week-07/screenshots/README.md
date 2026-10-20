# Screenshots to take in Kibana (full desktop)

| File | What | Expected |
|---|---|---|
| `w7_elk_q0.png` | ES\|QL block Q0 | event_id 1 = 353, 3 = 5, 22 = 487 |
| `w7_elk_v0.png` | block V0 | 211 rows |
| `w7_elk_v0b.png` | block V0b | svchost 168, dcagentservice 30, Code 10, WINWORD/cmd/mshta 1 each |
| `w7_elk_v1.png` | block V1 | 3 rows: WS-021, WS-008, WS-014 |
| `w7_elk_v1_blind.png` | block V1-blind | WS-000 15, WS-003 1, WS-017 1 |
| `w7_elk_v2.png` | block V2 | 5 rows: M1–M5 |
| `w7_elk_v2_chain.png` | block V2-chain | 5 connections to 203.0.113.x:443 |
| `w7_elk_v3.png` | block V3 (campaign attribution) | 7 rows: 5 alerts with brand + WS-005, WS-012 domain-only |
| `w7_elk_v3_dns.png` | block V3-dns (topic rule) | 5 rows: M1–M5 |
| `w7_elk_rule.png` | Security → Rules → rule details (ATT&CK mapping visible) | |
| `w7_elk_alerts.png` | Security → Alerts | tuned rule 5, as-published rule 211, brand DNS rule 5 |
| `w7_navigator.png` | Navigator with `navigator-layer-w7.json` | |

All screenshots taken 2026-10-20 in Kibana 9.5.5 (Elastic in Docker on MacBook M2) and embedded in `../README.md`.
Extra: `w7_elk_v3_p2.png` (V3 result table), `w7_elk_rules_list.png` (3 W7 rules), `w7_elk_alert_details.png` (one alert opened).
