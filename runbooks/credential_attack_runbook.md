[credential_attack_runbook.md](https://github.com/user-attachments/files/27707243/credential_attack_runbook.md)
# Runbook: Credential-Based Attack Response
**Classification:** Internal SOC Use  
**Author:** Mohamed Hishamudeen  
**Version:** 1.0  
**MITRE ATT&CK:** T1110 (Brute Force), T1078 (Valid Accounts), T1021 (Remote Services)

---

## Purpose

This runbook provides step-by-step guidance for SOC analysts responding to suspected credential-based attacks, including brute-force attempts and valid account abuse. It covers detection, triage, containment, and escalation.

---

## Trigger Conditions

Initiate this runbook when any of the following alerts fire:

| Alert | Threshold | SIEM |
|---|---|---|
| Multiple failed logons from single IP | 5+ in 60 seconds | Splunk / Sentinel |
| Successful logon after repeated failures | 3+ failures then success | Splunk / Sentinel |
| Logon outside business hours | Any logon 10PM–6AM | Sentinel |
| Logon from unusual geolocation | Any non-SG/approved country | Sentinel |
| Lateral movement indicators | 4624 across multiple hosts | Splunk |

---

## Step 1 — Initial Triage (< 5 minutes)

**1.1** Confirm the alert is genuine (not a known test or scheduled task):
- Check if the source IP is a known scanner, pentest tool, or internal monitoring system
- Check if the username is a service account with known automated login patterns

**1.2** Gather basic context:
```
Username:     ___________________________
Source IP:    ___________________________
Target host:  ___________________________
Time (UTC):   ___________________________
Logon Type:   ___ (2=Interactive, 3=Network, 10=RemoteInteractive)
Failed count: ___________________________
```

**1.3** Query Splunk for failed logon history:
```spl
index=wineventlog EventCode=4625 Account_Name="<username>"
| timechart span=1m count
| where count > 3
```

**1.4** Query Sentinel for same user across multiple hosts:
```kql
SecurityEvent
| where EventID == 4625
| where TargetUserName == "<username>"
| summarize FailCount=count() by Computer, IpAddress, bin(TimeGenerated, 5m)
| where FailCount > 3
```

---

## Step 2 — IOC Enrichment (< 10 minutes)

**2.1** Look up the source IP on VirusTotal:
- Navigate to [virustotal.com](https://www.virustotal.com)
- Check detection ratio, associated malware, and community comments
- Flag if any vendor detects it as malicious or associated with known threat actor

**2.2** Cross-reference IP against threat intel feeds:
- AbuseIPDB: [abuseipdb.com](https://www.abuseipdb.com)
- Shodan: [shodan.io](https://www.shodan.io) — check exposed services on that IP

**2.3** Document findings:
```
VT Detection Ratio:   ___/90
AbuseIPDB Score:      ___/100
Shodan Open Ports:    ___________________________
Associated Malware:   ___________________________
Threat Actor (if any):___________________________
```

---

## Step 3 — Severity Classification

| Condition | Severity |
|---|---|
| Failed logins only, no success, low VT score | LOW |
| 3–4 failed logins, unknown IP | MEDIUM |
| 5+ failed logins from flagged IP | HIGH |
| Successful logon after brute-force, or flagged IP | CRITICAL |
| Lateral movement confirmed post-logon | CRITICAL |

---

## Step 4 — Containment

### If severity is HIGH or CRITICAL:

**4.1** Disable the affected account immediately:
- Active Directory: `Disable-ADAccount -Identity <username>`
- Or raise a change ticket for AD team if no direct access

**4.2** Block the source IP at the firewall or via Sentinel automation rule

**4.3** Force password reset on the affected account

**4.4** Check for active sessions and terminate if found:
```spl
index=wineventlog EventCode=4624 Account_Name="<username>"
| where _time > relative_time(now(), "-1h")
```

---

## Step 5 — Investigation

**5.1** Check for lateral movement following the successful logon:
```kql
SecurityEvent
| where EventID == 4624
| where TargetUserName == "<username>"
| where TimeGenerated > ago(2h)
| project TimeGenerated, Computer, IpAddress, LogonType
```

**5.2** Check process creation by the account post-logon (Event ID 4688):
```spl
index=wineventlog EventCode=4688 Account_Name="<username>"
| table _time, ComputerName, Process_Name, Process_Command_Line
```

**5.3** Look for persistence mechanisms:
- Scheduled tasks created (Event ID 4698)
- New local accounts created (Event ID 4720)
- Registry run key modifications

---

## Step 6 — Escalation Criteria

Escalate to Tier 2 / IR Lead if:
- Successful logon confirmed from malicious IP
- Lateral movement detected across 2+ hosts
- Privileged account (admin/service) was targeted successfully
- Data exfiltration indicators present (large outbound transfers, unusual access)

---

## Step 7 — Documentation & Closure

Complete the incident ticket with:
- [ ] Timeline of events (first failed logon → last activity)
- [ ] IOC list (IP, username, affected hosts)
- [ ] Actions taken (account disabled, IP blocked, password reset)
- [ ] MITRE ATT&CK techniques identified
- [ ] Escalation decision and outcome
- [ ] Recommended long-term mitigations (MFA, geo-blocking, account lockout policy)

---

## References

- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
- [Microsoft Security Event IDs](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events)
