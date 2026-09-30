## Week 3: Threat Intelligence Platforms (MISP) & Detection Engineering

### 1. MISP Deployment
- Successfully deployed **MISP (Malware Information Sharing Platform)** locally using Docker containers.
- Configured the environment to store, share, and manage Cyber Threat Intelligence (CTI) data.

### 2. Event Creation & IoC Management
- Created a dedicated threat event: **Phishing Campaign targeting Kaspi, eGov, and Kazpost**.
- Added multiple Indicators of Compromise (IoCs) with the **IDS (Intrusion Detection System)** flag enabled for SIEM export:
  - **Domains (Typosquatting):** `kaspi-bonus-2026.com`, `eg0v-portal.kz`, `kazpost-delivery-track.net`
  - **IP Addresses:** `185.120.10.45`, `193.100.20.15`
  - **URL & Email:** Malicious login endpoint and fake sender address (`security@kaspi-bonus-2026.com`).
- Exported the complete event as a JSON file for external platform integration.

### 3. Detection Engineering (Sigma Rule)
- Developed a **Sigma rule** (`rule-001-kz-phishing-dns.yml`) to detect DNS queries associated with the identified phishing infrastructure.
- **Log Source:** DNS
- **MITRE ATT&CK Mapping:** Initial Access (T1566.002 - Phishing: Spearphishing Link).

### Artifacts in this Repository
- `week-03/misp-event-export.json`: Raw MISP event export.
- `week-03/sigma-rules/rule-001-kz-phishing-dns.yml`: Sigma detection rule.
- Screenshots of the local MISP deployment and event attributes.
