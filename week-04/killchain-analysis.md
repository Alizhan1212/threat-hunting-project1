# Week 04: The Cyber Kill Chain

**Case study:** SolarWinds Orion supply-chain attack (SUNBURST), attributed to APT29 / UNC2452 / "Nobelium"
**Models used:** Lockheed Martin Cyber Kill Chain, mapped to MITRE ATT&CK
**Author:** Alizhan1212

---

## 1. Introduction

### 1.1 Lockheed Martin Cyber Kill Chain
The Kill Chain (Hutchins, Cloppert, Amin, 2011) is an intelligence-driven defense model that describes an intrusion as seven sequential stages. Its core idea: the attacker must succeed at *every* stage, while the defender only needs to break *one*.

| # | Stage | Attacker goal |
|---|-------|---------------|
| 1 | Reconnaissance | Research and select targets |
| 2 | Weaponization | Build the malicious payload / delivery package |
| 3 | Delivery | Transmit the weapon to the target |
| 4 | Exploitation | Trigger the weapon, exploit a vulnerability or trust |
| 5 | Installation | Establish persistence on the victim |
| 6 | Command & Control (C2) | Open a remote control channel |
| 7 | Actions on Objectives | Achieve the goal (data theft, destruction, etc.) |

### 1.2 Why map to ATT&CK?
The Kill Chain is high-level and linear. MITRE ATT&CK adds granular, technique-level detail (TTPs) that can be used for detection engineering and threat hunting. The Kill Chain tells us *where* in the intrusion we are; ATT&CK tells us *how* the adversary did it.

### 1.3 Why SolarWinds?
- Extremely well documented (Mandiant/FireEye, Microsoft, CISA, MITRE).
- Touches every Kill Chain stage, including a rare supply-chain delivery.
- Approx. 18,000 organizations received the trojanized update; a much smaller set (roughly a hundred) were actively exploited, including US government agencies and major tech companies.

---

## 2. Attack Timeline (summary)

| Date | Event |
|------|-------|
| ~Sep 2019 | Attackers gain access to the SolarWinds development/build environment |
| Oct 2019 | Test code injected into Orion builds (a "dry run") |
| Feb 2020 | SUNBURST backdoor injected into Orion builds (versions 2019.4 HF5 to 2020.2.1) via the SUNSPOT build implant |
| Mar to Jun 2020 | Trojanized updates distributed to customers through the legitimate update channel |
| 2020 | Selected victims receive second-stage tooling (TEARDROP / Cobalt Strike); lateral movement into cloud identity systems |
| 13 Dec 2020 | Publicly disclosed by FireEye (Mandiant) after it discovered its own compromise |

---

## 3. Kill Chain Analysis with ATT&CK Mapping

### Stage 1: Reconnaissance
**What happened:** The attackers studied SolarWinds' software build and release process and chose Orion because of its privileged network position and its massive customer base (government and Fortune 500). Choosing *who* to exploit among the downstream victims was done later, based on the beacon data they received.

| ATT&CK Tactic | Technique | ID | Relevance |
|---|---|---|---|
| Reconnaissance | Gather Victim Org Information | T1591 | Learning about SolarWinds' organization and build pipeline (inferred) |
| Reconnaissance | Gather Victim Network Information | T1590 | Understanding the dev environment (inferred) |

> Note: Public reporting on pre-compromise recon is limited; these mappings are inferred from attacker behavior.

### Stage 2: Weaponization
**What happened:** APT29 developed **SUNSPOT**, malware that watched for the Orion build process and swapped a source file with a backdoored version, and **SUNBURST**, a trojanized DLL (`SolarWinds.Orion.Core.BusinessLayer.dll`). They also prepared C2 infrastructure using domains and servers located in the victims' own country to blend in.

| ATT&CK Tactic | Technique | ID | Relevance |
|---|---|---|---|
| Resource Development | Develop Capabilities: Malware | T1587.001 | SUNSPOT, SUNBURST, TEARDROP |
| Resource Development | Acquire Infrastructure: Domains | T1583.001 | C2 domain `avsvmcloud[.]com` |
| Resource Development | Compromise Infrastructure: Server | T1584.004 | Compromised/rented servers for C2 |

### Stage 3: Delivery
**What happened:** Instead of phishing, the malware was delivered through SolarWinds' own trusted, legitimate update mechanism. Customers downloaded and installed the update themselves.

| ATT&CK Tactic | Technique | ID | Relevance |
|---|---|---|---|
| Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Trojanized Orion update |
| Initial Access | Trusted Relationship | T1199 | Customers trusted the vendor's update channel |

### Stage 4: Exploitation
**What happened:** No software vulnerability was needed in the customer environment. The exploit was *trust*: the DLL was signed with SolarWinds' valid digital certificate (injected before the signing step), so it passed integrity checks and ran inside the legitimate `SolarWinds.BusinessLayerHost.exe` process.

| ATT&CK Tactic | Technique | ID | Relevance |
|---|---|---|---|
| Defense Evasion | Subvert Trust Controls: Code Signing | T1553.002 | Validly signed malicious DLL |
| Execution | Command and Scripting / native execution via trusted process | T1059 | Commands run by the backdoor after activation |

### Stage 5: Installation
**What happened:** The backdoor was installed as part of the normal Orion update, so persistence came "for free" with the legitimate service. SUNBURST then lay dormant for roughly 12 to 14 days, checked for security tools and analysis environments, and only then activated. Later-stage tools (TEARDROP, Cobalt Strike Beacon) were deployed to high-value victims, with filenames mimicking legitimate ones and with tooling removed after use.

| ATT&CK Tactic | Technique | ID | Relevance |
|---|---|---|---|
| Persistence | Compromise Client Software Binary | T1554 | Backdoor embedded in a legitimate binary that runs as a service |
| Defense Evasion | Virtualization/Sandbox Evasion: Time Based Evasion | T1497.003 | Dormancy period before activation |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Checked for and avoided security/forensic tools |
| Defense Evasion | Obfuscated Files or Information | T1027 | Obfuscated strings and payloads |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | Tools named after legitimate files |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | Removed tools after use |

### Stage 6: Command & Control
**What happened:** SUNBURST beaconed over HTTPS to `avsvmcloud[.]com`. Victim information was encoded into generated subdomains (DGA-like). DNS responses (CNAME records) steered compromised hosts to a second-stage C2 server only for selected targets. Traffic mimicked the legitimate Orion Improvement Program protocol to blend in.

| ATT&CK Tactic | Technique | ID | Relevance |
|---|---|---|---|
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP(S) C2 that mimicked Orion traffic |
| Command and Control | Dynamic Resolution: Domain Generation Algorithm | T1568.002 | Encoded per-victim subdomains |
| Command and Control | Data Encoding: Standard Encoding | T1132.001 | Encoded C2 data |
| Command and Control | Ingress Tool Transfer | T1105 | Delivery of second-stage payloads |

### Stage 7: Actions on Objectives
**What happened:** Objective was long-term espionage. After landing on a selected victim, the operators moved laterally, stole credentials, and pivoted into the victim's cloud identity infrastructure. They forged SAML tokens ("Golden SAML") and abused application credentials to read email and other data in Microsoft 365.

| ATT&CK Tactic | Technique | ID | Relevance |
|---|---|---|---|
| Credential Access | OS Credential Dumping | T1003 | Harvesting credentials on compromised hosts |
| Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 | Moving between hosts with valid credentials |
| Initial Access / Persistence | Valid Accounts | T1078 | Using stolen legitimate accounts |
| Credential Access | Forge Web Credentials: SAML Tokens | T1606.002 | Golden SAML forgery |
| Lateral Movement | Use Alternate Authentication Material: Application Access Token | T1550.001 | Abusing tokens to access cloud resources |
| Persistence | Account Manipulation: Additional Cloud Credentials | T1098.001 | Adding credentials to apps/service principals |
| Collection | Email Collection: Remote Email Collection | T1114.002 | Reading mailboxes of targeted staff |

---

## 4. Summary Matrix: Kill Chain to ATT&CK

| Kill Chain Stage | ATT&CK Tactic(s) | Key Techniques |
|---|---|---|
| 1. Reconnaissance | Reconnaissance | T1591, T1590 |
| 2. Weaponization | Resource Development | T1587.001, T1583.001, T1584.004 |
| 3. Delivery | Initial Access | T1195.002, T1199 |
| 4. Exploitation | Defense Evasion, Execution | T1553.002, T1059 |
| 5. Installation | Persistence, Defense Evasion | T1554, T1497.003, T1562.001, T1027, T1036.005, T1070.004 |
| 6. C2 | Command and Control | T1071.001, T1568.002, T1132.001, T1105 |
| 7. Actions on Objectives | Credential Access, Lateral Movement, Collection | T1003, T1021.001, T1078, T1606.002, T1550.001, T1098.001, T1114.002 |

---

## 5. Defensive Analysis: Where Could the Chain Have Been Broken?

| Stage | Possible defensive action |
|---|---|
| Reconnaissance | Limit public info on build/release infrastructure; threat-intel monitoring |
| Weaponization | Little direct control; rely on intelligence sharing and threat-actor tracking |
| Delivery | Build-pipeline integrity: reproducible builds, separate and hardened build servers, SBOMs, vendor risk management |
| Exploitation | Verify update behavior, not only signatures; application allowlisting and behavior monitoring |
| Installation | EDR on servers, alerting on unexpected child processes or DLL behavior of monitoring tools |
| C2 | Restrict egress from management servers (Orion servers did not need open internet), DNS monitoring, detection of anomalous subdomain patterns |
| Actions on Objectives | Protect identity systems (AD FS / token-signing certs), MFA, conditional access, audit of new app credentials, UEBA |

**Key lessons**
1. **Trust is an attack surface.** Valid signatures and trusted vendors are not guarantees of safety.
2. **Network segmentation and egress filtering** of privileged management tools would have blocked C2 for many victims (Stage 6).
3. **Identity is the new perimeter.** The most damaging stage (Stage 7) happened in cloud identity, not on the malware host.
4. **Kill Chain limitation:** the model is linear and perimeter-focused. Here the attacker looped back (post-compromise, stage 5 to 7 repeated in the cloud), which ATT&CK's tactic matrix captures better.

---

## 6. Kill Chain vs. ATT&CK: Reflection

| | Kill Chain | ATT&CK |
|---|---|---|
| Granularity | 7 high-level phases | 14 tactics, hundreds of techniques |
| Structure | Linear | Non-linear matrix |
| Best for | Communicating and planning defense at a strategic level | Detection engineering, threat hunting, red/purple teaming |
| Weakness | Weak on post-compromise and insider/cloud behavior | Can be overwhelming without prioritization |

They work best together: use the Kill Chain to structure the story of an intrusion and ATT&CK to build concrete detections for each stage.

---

## 7. References
- Hutchins, Cloppert, Amin. *Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains.* Lockheed Martin, 2011.
- Lockheed Martin, *Cyber Kill Chain* page: https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
- MITRE ATT&CK, SolarWinds Compromise campaign (C0024): https://attack.mitre.org/campaigns/C0024/
- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
- CISA Alert AA20-352A, *Advanced Persistent Threat Compromise of Government Agencies, Critical Infrastructure, and Private Sector Organizations.*
- Mandiant (FireEye), *Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor*, Dec 2020.

> **Verification note:** Technique IDs should be double-checked against the current ATT&CK version at attack.mitre.org, since IDs and sub-techniques are occasionally renumbered.
