# Threat Hunting Project (Weeks 1–3 Increment)

**Group Members:** [Ikson,Kazhymukan,Alizhan]  
**Topic:** Introduction to Threat Hunting Practice  

---

## Week 1: Cyber Threat Intelligence Fundamentals

### 1. CTI Terms Glossary
| Term | Definition |
| :--- | :--- |
| **CTI (Cyber Threat Intelligence)** | Evidence-based knowledge about cyber threats that helps organizations make informed decisions. |
| **IOC (Indicator of Compromise)** | Artifacts (IPs, hashes, domain names) that indicate a potential system compromise. |
| **TTP (Tactics, Techniques, Procedures)** | Patterns of activities or methods used by threat actors. |
| **Threat Hunting** | Proactive search for cyber threats that have evaded existing security controls. |

### 2. Threat Classification & Sources
- **Phishing:** Social engineering attacks via email.
- **Ransomware:** Malware encrypting business data for ransom.
- **APT (Advanced Persistent Threats):** State-sponsored or sophisticated threat groups.

---

## Week 2: Data Collection Process

### 1. OSINT Data Collection
Collected intelligence on suspicious domain/IP/hash using **Shodan** and **VirusTotal**.
*(Add screenshots below)*

### 2. Data Source Mapping
| Target Data | Source Log | Event ID / Log Type |
| :--- | :--- | :--- |
| Process Execution | Sysmon / Windows Event Log | Event ID 1 (Process Create) |
| Network Connections | Firewall Logs / Sysmon | Event ID 3 (Network Connect) |

---

## Week 3: Data Processing and Exploitation

### 1. MISP Threat Sharing Platform
Deployed MISP instance and imported IOCs (hashes/IPs) related to the scenario.

### 2. Data Normalization & Filtering
Applied log normalization rules (using Python/Sigma) to remove benign noise and filter critical events.
