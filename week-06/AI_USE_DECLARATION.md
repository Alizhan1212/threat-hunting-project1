# AI Use Declaration: Week 06 (MITRE ATT&CK Framework)

**Project:** threat-hunting-project1
**Student:** [your name]
**Date:** [date]
**Assignment:** Week 06, ATT&CK Framework: study one technique (T1059.004 Unix Shell), simulate it, and map the results to ATT&CK

---

## 1. AI tool used

- **Tool:** Claude, an AI assistant made by Anthropic (Claude Sonnet 5.5)
- **Access:** claude.ai chat interface

## 2. What the AI produced

| File | AI contribution |
|---|---|
| `report.md` | Wrote the report text: ATT&CK background (tactics, techniques, procedures), T1059.004 study, lab description, evidence tables, ATT&CK mapping, mitigations, limitations, Week 7 plan, and a draft of the observations section (5.4) |
| `simulate_t1059_004.sh` | Wrote the harmless bash simulation script |
| `navigator-layer.json` | Wrote the ATT&CK Navigator layer file |
| Sigma rule (inside `report.md`) | Wrote the detection rule |
| Support | Step-by-step lab and Git instructions, troubleshooting help (auditd command, Navigator version issue), and defense preparation notes |

## 3. What I did myself

- Set up the lab: Kali Linux 2026.2 in a VirtualBox virtual machine, with a clean snapshot.
- Installed auditd and added the audit rule for process execution.
- Ran the simulation script in my own lab VM and collected the logs.
- Took all five screenshots from my own lab: auditd rule, script output, shell commands in the audit log, Base64 evidence in the audit log, and the ATT&CK Navigator layer.
- Loaded the layer in ATT&CK Navigator and handled the version and display problems that appeared.
- Reviewed the AI-written text, filled in my personal details, and adjusted it where needed.
- Organized the files and committed them to this GitHub repository.

## 4. Verification and limits

- The AI could not open attack.mitre.org while writing. Technique and mitigation IDs came from the AI's own knowledge and may differ from the current ATT&CK version.
- Verification of technique and mitigation IDs against attack.mitre.org: [state what you checked, or write "not checked"].
- The simulation, logs, and screenshots are from my own lab run and are not AI-generated.

## 5. Statement

I understand the material in this submission and can explain it. I am responsible for the content of the Week 06 submission, including the parts drafted by the AI.

**Signature / name:** [your name]
