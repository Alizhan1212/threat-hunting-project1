# Attack chain — phishing impersonating Kazakhstani brands

Conceptual kill chain for the emulation plan. Pre-compromise phases are *documented*; post-compromise phases are *emulated in an isolated lab*.

```mermaid
flowchart TD
    A["Recon<br/>T1598 Phishing for Information"] --> B["Resource Development<br/>T1583.001 Domains · T1608.005 Link Target"]
    B --> C["Initial Access<br/>T1566.002 Spearphishing Link<br/>(mobile: T1660)"]
    C --> D["Execution<br/>T1204 User Execution"]
    D --> E["Credential Access<br/>T1056.003 Web Portal Capture · T1111 MFA Interception"]
    D --> F["Persistence<br/>T1547.001 Run Keys · T1053.005 Scheduled Task"]
    F --> G["Discovery<br/>T1082 · T1083"]
    G --> H["Collection<br/>T1005 Data from Local System"]
    H --> I["C2<br/>T1071.001 Web Protocols"]
    I --> J["Exfiltration<br/>T1041 over C2 · T1567 over Web Service"]

    classDef documented fill:#fde2e2,stroke:#c0392b,color:#000;
    classDef emulated fill:#e2f0d9,stroke:#27ae60,color:#000;
    class A,B,C,E documented;
    class D,F,G,H,I,J emulated;
```

**Legend:** red = documented only (would require deceiving real people); green = safe to emulate in the lab against our own VM with harmless stand-in data.
