[incident_timeline.md](https://github.com/user-attachments/files/27707280/incident_timeline.md)
# Incident Report: Credential Brute-Force & Lateral Movement
**Incident ID:** INC-2025-001  
**Date:** 2025-06-01  
**Analyst:** Mohamed Hishamudeen  
**Severity:** CRITICAL  
**Status:** Resolved  
**MITRE ATT&CK:** T1110, T1078, T1021, T1059

---

## Executive Summary

On 2025-06-01, SOC analysts detected a sustained brute-force attack against domain user `jsmith` originating from external IP `192.168.1.50`. After five failed attempts within 20 seconds, the attacker achieved a successful logon at 08:00:21 UTC. Post-compromise activity included execution of a base64-encoded PowerShell command and lateral movement to a secondary host. The account was disabled and the IP blocked within 15 minutes of detection.

---

## Incident Timeline

| Time (UTC) | Event ID | Event | Details | Severity |
|---|---|---|---|---|
| 08:00:01 | 4625 | Failed Logon | `jsmith` from `192.168.1.50` — attempt 1 | MEDIUM |
| 08:00:05 | 4625 | Failed Logon | `jsmith` from `192.168.1.50` — attempt 2 | MEDIUM |
| 08:00:09 | 4625 | Failed Logon | `jsmith` from `192.168.1.50` — attempt 3 | HIGH |
| 08:00:13 | 4625 | Failed Logon | `jsmith` from `192.168.1.50` — attempt 4 | HIGH |
| 08:00:17 | 4625 | Failed Logon | `jsmith` from `192.168.1.50` — attempt 5 | CRITICAL |
| 08:00:21 | 4624 | **Successful Logon** | `jsmith` from `192.168.1.50` after 5 failures | CRITICAL |
| 08:01:00 | 4688 | Process Creation | `powershell.exe -enc <base64>` executed by `jsmith` | HIGH |
| 08:02:30 | 4624 | Lateral Movement | `jsmith` logon detected on `WKSTN-04` | CRITICAL |
| 08:14:00 | — | **Containment** | Account disabled, IP blocked, session terminated | — |

---

## IOC List

| Type | Value | Context |
|---|---|---|
| IP Address | `192.168.1.50` | Brute-force source |
| Username | `jsmith` | Compromised account |
| Process | `powershell.exe -enc` | Encoded command execution post-compromise |
| Host | `WKSTN-04` | Lateral movement target |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Observed Activity |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | 5 failed logons in 20 seconds |
| T1078 | Valid Accounts | Successful logon with compromised credentials |
| T1059.001 | PowerShell | Encoded PowerShell execution post-compromise |
| T1021 | Remote Services | Lateral movement to WKSTN-04 |

---

## Actions Taken

| Action | Time (UTC) | Performed By |
|---|---|---|
| Alert triaged and confirmed | 08:05:00 | Hishamudeen |
| IP `192.168.1.50` blocked at firewall | 08:10:00 | Hishamudeen |
| Account `jsmith` disabled in AD | 08:12:00 | Hishamudeen |
| Active session on WKSTN-04 terminated | 08:14:00 | Hishamudeen |
| Password reset initiated | 08:20:00 | IT Admin |
| Incident ticket closed | 09:00:00 | Hishamudeen |

---

## Root Cause

The account `jsmith` did not have Multi-Factor Authentication (MFA) enabled, allowing the attacker to gain access solely through password guessing. No account lockout policy was in place, which permitted unlimited login attempts.

---

## Recommendations

1. **Enable MFA** for all domain accounts, prioritising internet-facing and privileged accounts
2. **Implement account lockout policy** — lock after 5 failed attempts for 30 minutes
3. **Enable geo-blocking** for logons outside approved regions
4. **Audit PowerShell execution policy** — enforce Constrained Language Mode
5. **Review lateral movement detection rules** — alert on same-user logon across 2+ hosts within 10 minutes

---

## Appendix — Splunk Queries Used

```spl
# Detect brute-force
index=wineventlog EventCode=4625 Account_Name="jsmith"
| timechart span=10s count
| where count >= 3

# Confirm successful logon after failures
index=wineventlog EventCode=4624 Account_Name="jsmith" src_ip="192.168.1.50"

# Post-compromise process activity
index=wineventlog EventCode=4688 Account_Name="jsmith"
| table _time, ComputerName, Process_Name, Process_Command_Line
```
