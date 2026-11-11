# AI Use Declaration: Week 09 (Atomic Red Team)

**Project:** threat-hunting-project1
**Student:** Muptiadil Ikhsan
**Date:** 2026-11-10
**Assignment:** Week 09, Atomic Red Team: run selected atomic tests (T1059, T1003) and record and analyze the results in a SIEM

---

## 1. AI tool used

- **Tool:** Claude, an AI assistant made by Anthropic (Claude Sonnet 5.5)
- **Access:** claude.ai chat interface

## 2. What the AI produced

| File | AI contribution |
|---|---|
| `README.md` | Wrote the report template: Atomic Red Team background, comparison with CALDERA, link to the phishing topic, lab setup steps, results tables, analysis questions, Sigma rule, mitigations, and limitations |
| `run_atomic.sh` | Wrote the wrapper script that previews, runs, and cleans up one atomic test and logs START/END times |
| `fix_audit_rules.sh` | Wrote the script that writes the two audit rules permanently to `/etc/audit/rules.d/` after the rules were lost on a reboot |
| Support | Step-by-step instructions, troubleshooting (auditd rule syntax, Docker/WSL setup, Kibana CSV import), and defense preparation notes |

## 3. What I did myself

- Installed PowerShell and cloned Red Canary's open-source Atomic Red Team repositories in my lab VM.
- Listed the available tests, read their details, and selected which ones to run.
- Ran the tests in my own isolated Kali VM (including working through a lost-rules issue and a VM restart) and completed the cleanup.
- Stood up a local Elastic/Kibana stack with Docker when the group's shared instance was not reachable.
- Collected the logs, exported them to CSV, uploaded and searched them in Kibana, and recorded the results.
- Took all screenshots, verified the real command-line evidence behind the results table, and committed the files.

## 4. Verification and limits

- The atomic tests themselves are from Red Canary's open-source library and were **not** written by the AI or by me.
- The AI could not run the tests or access my SIEM. All results, screenshots, and SIEM observations come from my own lab run.
- Technique and mitigation IDs came from the AI's knowledge. Verification against attack.mitre.org: not checked yet — to be done before final submission.

## 5. Statement

I understand the material in this submission and can explain it. I am responsible for the content of the Week 09 submission, including the parts drafted by the AI.

**Signature / name:** Muptiadil Ikhsan
