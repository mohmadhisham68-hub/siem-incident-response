[README (1).md](https://github.com/user-attachments/files/27705080/README.1.md)
# 🔎 Incident Response & SIEM Lab

> Hands-on SOC simulation — alert triage, threat correlation, and incident reporting across Splunk and Microsoft Sentinel.

---

## Overview

This project simulates a real-world SOC environment where I performed end-to-end incident response across two SIEM platforms. The work covers alert triage, IOC analysis, threat hunting, log automation, and formal incident reporting — following structured runbook procedures throughout.

---

## 🛠️ Tools & Technologies

| Category | Tools |
|---|---|
| SIEM | Splunk, Microsoft Sentinel |
| Scripting | Python, PowerShell |
| Threat Intel | VirusTotal, IOC Lookup |
| Framework | MITRE ATT&CK |
| Log Sources | Windows Event IDs (4624, 4625, 4688) |

---

## 📋 What Was Done

### Alert Triage & Correlation
- Correlated alerts across Splunk and Sentinel to identify brute-force patterns, lateral movement, and anomalous user behaviour
- Triaged suspicious samples and phishing indicators via VirusTotal
- Extracted IOCs and cross-referenced against MITRE ATT&CK techniques

### Endpoint & EDR Analysis
- Applied endpoint detection concepts to analyse suspicious process behaviour
- Flagged anomalous activity patterns for escalation based on process creation logs (Event ID 4688)

### Python Automation
- Built Python ingestion scripts that cut manual log pre-processing time by **40%** across repeated alert types
- Automated repetitive triage steps to allow faster analyst throughput

### PowerShell Log Parsing
- Surfaced suspicious activity from Windows Event IDs:
  - `4624` — Successful logon
  - `4625` — Failed logon (brute-force indicator)
  - `4688` — Process creation (execution chain analysis)

### Incident Reporting & Leadership
- Led a 4-analyst team independently managing reporting while collaborating across findings
- Produced a unified incident timeline across Splunk and Sentinel
- Presented findings to a mock CISO panel
- Authored a credential-attack runbook that was adopted by the full team

---

## 🗂️ MITRE ATT&CK Techniques Covered

| Technique ID | Name |
|---|---|
| T1110 | Brute Force |
| T1078 | Valid Accounts (Credential Stuffing) |
| T1021 | Remote Services (Lateral Movement) |
| T1059 | Command and Scripting Interpreter |

---

## 📁 Repository Structure

```
siem-incident-response/
├── scripts/
│   ├── log_ingestor.py          # Python log pre-processing automation
│   └── event_id_parser.ps1      # PowerShell Windows Event ID parser
├── runbooks/
│   └── credential_attack_runbook.md   # Runbook authored during the lab
├── reports/
│   └── incident_timeline.md     # Unified Splunk + Sentinel incident timeline
└── README.md
```

---

## 🔑 Key Takeaways

- Gained practical experience triaging real alert types in two enterprise SIEMs
- Understood how brute-force and lateral movement appear across log sources
- Learned how to write analyst-grade runbooks and present findings to leadership
- Reduced manual work significantly through scripted automation

---

## 📬 Contact

**Mohamed Hishamudeen**
[LinkedIn](https://linkedin.com/in/mohamed-hishamudeen) · [mohmadhisham68@gmail.com](mailto:mohmadhisham68@gmail.com)
