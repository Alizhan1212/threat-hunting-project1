# Week 5 — Loading the lab data into Splunk or ELK

Generate the data first: `python3 scripts/generate_lab_logs.py` (creates `data/*.csv`).

## Option A: Splunk (recommended, queries in `queries/hunt_queries.spl`)

Splunk Enterprise has a free 60-day trial (then Splunk Free). It runs only on **x86-64 Windows or x86-64 Linux** (Splunk system requirements; ARM Linux and Apple-silicon macOS are not supported for a full Splunk instance). So:
- **Windows PC:** install Splunk directly, or inside a Kali/Ubuntu x86-64 VM (VirtualBox/VMware) with the `.deb` package.
- **MacBook M1/M2:** a VM there is ARM, so Splunk will not run in it. Use a Windows PC, or use Option B (ELK in Docker, works on Apple silicon).

Kali/Ubuntu VM install (x86-64):
```bash
# download the .deb from splunk.com -> Splunk Enterprise -> Linux -> .deb (free account)
sudo dpkg -i splunk-*-linux-amd64.deb
sudo /opt/splunk/bin/splunk start --accept-license    # set admin user + password
# open http://localhost:8000 in the VM browser
```

1. Download Splunk Enterprise from splunk.com (free account), install, open `http://localhost:8000`.
2. **Settings → Indexes → New Index** → name `th_lab`.
3. **Settings → Add Data → Upload** → choose `data/dns.csv`.
   - Source type: **csv** → **Save As** → name `lab_dns`
   - Timestamp: **Advanced → Timestamp extraction: "Timestamp field" = `time`**
   - Index: `th_lab` → Submit
4. Repeat for `proxy.csv` → sourcetype `lab_proxy`, and `sysmon.csv` → `lab_sysmon`.
5. **Search & Reporting**, time picker **All time**, check: `index=th_lab | stats count by sourcetype`
   → expected `lab_dns 4319`, `lab_proxy 4318`, `lab_sysmon 321`.
6. Run each block of `queries/hunt_queries.spl` and save the screenshots:

| Screenshot file | Query | Expected result |
|---|---|---|
| `screenshots/w5_splunk_count.png` | step 5 | 3 sourcetypes with the counts above |
| `screenshots/w5_splunk_h0.png` | H0 | 1 row: WS-007, kaspi-bonus-2026.com |
| `screenshots/w5_splunk_h1.png` | H1 | 8 domains |
| `screenshots/w5_splunk_h2.png` | H2 | 4 POSTs, WS-012 / WS-015 / WS-019 |
| `screenshots/w5_splunk_h3.png` | H3 | 1 row: WS-021, WINWORD.EXE → powershell |
| `screenshots/w5_splunk_h3b.png` | H3b | 30 IT agent vs 1 WINWORD |

Then uncomment the `<!-- screenshot -->` lines in `README.md` as image links.

## Option B: Elastic Stack (Docker, works on MacBook M1/M2)

Elastic publishes ARM64 images, so this runs natively on Apple silicon.

> **This is how the assignment was actually completed:** Elastic (ELK) in Docker on a Mac (Apple silicon, M2), 4 GB RAM. The CSVs were loaded into `th-dns`, `th-proxy`, `th-sysmon`, `th-real` and every block of `queries/hunt_queries_elk.esql` (H0–H3b) and `queries/real_feed_queries_elk.esql` (R0–R4) was run in Kibana → Discover → ES|QL. All numbers matched the expected values below, and the screenshots are the `w5_elk_*.png` files in `screenshots/`.

1. Install **Docker Desktop for Mac (Apple chip)** from docker.com and start it.
   Settings → Resources → give Docker at least **4 GB memory**.
2. In Terminal:
   ```bash
   curl -fsSL https://elastic.co/start-local | sh
   ```
   The script starts Elasticsearch + Kibana and prints the `elastic` password (also saved in `elastic-start-local/.env`).
3. Open `http://localhost:5601` and log in as `elastic`.
4. Kibana → search bar → **"Upload a file"** (Machine Learning → Data Visualizer → File). Upload each file and press **Import**:

| File | Index name | Time field |
|---|---|---|
| `data/dns.csv` | `th-dns` | `time` |
| `data/proxy.csv` | `th-proxy` | `time` |
| `data/sysmon.csv` | `th-sysmon` | `time` |
| `data/real/feed_for_splunk.csv` (create it first with `python3 scripts/real_feed_hunt.py`) | `th-real` | none |

5. **Discover → switch to ES|QL** (top right). Paste one block at a time:
   - Part A: `queries/hunt_queries_elk.esql` (H0, H1, H2, H3, H3b)
   - Part B: `queries/real_feed_queries_elk.esql` (R0, R1, R2, R3, R4)
   - For Part A set the time picker to cover **2026-09-28 … 2026-10-05** (or "Last 2 years").
6. Take the same screenshots as listed for Splunk (name them `w5_elk_h1.png`, `w5_elk_real_r3.png`, …). Expected numbers are identical.

To stop: `cd elastic-start-local && ./stop.sh` · start again: `./start.sh`.
The local setup runs with a 30-day trial licence, which is enough for this assignment.

## Part B: real phishing feed in Splunk

1. `python3 scripts/real_feed_hunt.py` downloads `phishing-domains-ACTIVE.txt` (~11 MB) from Phishing.Database and creates `data/real/feed_for_splunk.csv` (columns `domain`, `tld`).
2. Create index `th_real`. **Add Data → Upload** → `feed_for_splunk.csv` → sourcetype **csv**, save as `real_feed` → Timestamp: **Current time** → index `th_real`.
3. For query R2b: **Settings → Lookups → Lookup table files → New** → upload `data/real/kz_hits.csv` (name `kz_hits.csv`), then **Permissions → All apps**.
4. Run the blocks of `queries/real_feed_queries.spl` (time picker "All time"):

| Screenshot file | Query | Expected (2026-10-02 snapshot) |
|---|---|---|
| `screenshots/w5_splunk_real_r0.png` | R0 | 392 164 |
| `screenshots/w5_splunk_real_r1.png` | R1 naive | 214 hits, mostly `olx`, `egov`, `1414` |
| `screenshots/w5_splunk_real_r2.png` | R2b refined + verdicts | 14 rows: 4 PHISHING, 2 NOT OUR BRAND, 7 FP, 1 UNCLEAR |
| `screenshots/w5_splunk_real_r3.png` | R3 global | USPS 1313, PayPal 1078, DHL 404, OLX 55, Gosuslugi 16 |
| `screenshots/w5_splunk_real_r4.png` | R4 | top TLDs, `.top` first |

The script downloads the exact snapshot used in the report (commit `12a20bf`). The feed is updated daily: to hunt on today's data, change the commit in `FEED_URL` to `master`. The numbers will then differ slightly.

## Without any SIEM

`python3 scripts/hunt.py` (Part A) and `python3 scripts/real_feed_hunt.py` (Part B) print the same results (saved in `data/hunt_output.txt` and `data/real/real_hunt_output.txt`).
