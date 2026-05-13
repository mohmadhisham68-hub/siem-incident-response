"""
log_ingestor.py
---------------
Automates pre-processing of Windows Security Event logs before SIEM ingestion.
Reduces manual analyst effort by filtering, normalising, and tagging events
relevant to brute-force and credential-based attacks.

Author: Mohamed Hishamudeen
MITRE ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts)
"""

import json
import re
import csv
import sys
from datetime import datetime
from collections import defaultdict

# --- Configuration ---
BRUTE_FORCE_THRESHOLD = 5       # Failed logins within window to flag
TIME_WINDOW_SECONDS = 60        # Window in seconds for brute-force detection
SEVERITY_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}

# Windows Event IDs of interest
MONITORED_EVENT_IDS = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4688": "Process Creation"
}


def parse_log_line(line: str) -> dict | None:
    """
    Parse a single log line into a structured dict.
    Expected format (CSV): timestamp,event_id,username,source_ip,details
    """
    try:
        parts = line.strip().split(",", 4)
        if len(parts) < 5:
            return None
        return {
            "timestamp": parts[0],
            "event_id": parts[1].strip(),
            "username": parts[2].strip(),
            "source_ip": parts[3].strip(),
            "details": parts[4].strip()
        }
    except Exception:
        return None


def classify_severity(event: dict, failed_counts: dict) -> str:
    """
    Classify severity based on event type and failed login counts.
    """
    eid = event["event_id"]
    user = event["username"]
    ip = event["source_ip"]

    if eid == "4625":
        count = failed_counts.get((user, ip), 0)
        if count >= BRUTE_FORCE_THRESHOLD:
            return "CRITICAL"
        elif count >= 3:
            return "HIGH"
        else:
            return "MEDIUM"

    elif eid == "4624":
        # Flag if there were prior failures from same source (potential success after brute)
        if failed_counts.get((user, ip), 0) >= 3:
            return "HIGH"
        return "LOW"

    elif eid == "4688":
        suspicious_processes = ["cmd.exe", "powershell.exe", "wscript.exe",
                                 "mshta.exe", "regsvr32.exe", "rundll32.exe"]
        if any(proc in event["details"].lower() for proc in suspicious_processes):
            return "HIGH"
        return "LOW"

    return "LOW"


def map_mitre(event: dict) -> str:
    """
    Map event to MITRE ATT&CK technique.
    """
    eid = event["event_id"]
    mapping = {
        "4625": "T1110 - Brute Force",
        "4624": "T1078 - Valid Accounts",
        "4688": "T1059 - Command and Scripting Interpreter"
    }
    return mapping.get(eid, "Unknown")


def process_logs(input_path: str, output_path: str):
    """
    Main processing pipeline:
    1. Parse raw log lines
    2. Track failed login counts per (user, ip)
    3. Classify severity
    4. Map to MITRE ATT&CK
    5. Output enriched JSON for SIEM ingestion
    """
    failed_counts = defaultdict(int)
    parsed_events = []

    print(f"[*] Reading logs from: {input_path}")

    with open(input_path, "r") as f:
        lines = f.readlines()

    # First pass — count failed logins per (user, ip)
    for line in lines:
        event = parse_log_line(line)
        if not event:
            continue
        if event["event_id"] == "4625":
            key = (event["username"], event["source_ip"])
            failed_counts[key] += 1

    # Second pass — enrich and classify
    for line in lines:
        event = parse_log_line(line)
        if not event:
            continue
        if event["event_id"] not in MONITORED_EVENT_IDS:
            continue

        severity = classify_severity(event, failed_counts)
        mitre = map_mitre(event)
        event_name = MONITORED_EVENT_IDS[event["event_id"]]

        enriched = {
            "timestamp": event["timestamp"],
            "event_id": event["event_id"],
            "event_name": event_name,
            "username": event["username"],
            "source_ip": event["source_ip"],
            "details": event["details"],
            "severity": severity,
            "mitre_technique": mitre,
            "failed_login_count": failed_counts.get(
                (event["username"], event["source_ip"]), 0
            ) if event["event_id"] in ("4624", "4625") else None,
            "ingested_at": datetime.utcnow().isoformat() + "Z"
        }
        parsed_events.append(enriched)

    # Sort by severity descending
    parsed_events.sort(
        key=lambda x: SEVERITY_LEVELS.get(x["severity"], 0), reverse=True
    )

    # Write output
    with open(output_path, "w") as out:
        json.dump(parsed_events, out, indent=2)

    print(f"[+] Processed {len(parsed_events)} events.")
    print(f"[+] Output written to: {output_path}")

    # Summary
    severity_summary = defaultdict(int)
    for e in parsed_events:
        severity_summary[e["severity"]] += 1

    print("\n[*] Severity Summary:")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"    {level}: {severity_summary.get(level, 0)}")


def generate_sample_logs(output_path: str):
    """
    Generates a sample CSV log file for testing.
    """
    sample_lines = [
        "2025-06-01T08:00:01,4625,jsmith,192.168.1.50,Failed logon attempt",
        "2025-06-01T08:00:05,4625,jsmith,192.168.1.50,Failed logon attempt",
        "2025-06-01T08:00:09,4625,jsmith,192.168.1.50,Failed logon attempt",
        "2025-06-01T08:00:13,4625,jsmith,192.168.1.50,Failed logon attempt",
        "2025-06-01T08:00:17,4625,jsmith,192.168.1.50,Failed logon attempt",
        "2025-06-01T08:00:21,4624,jsmith,192.168.1.50,Successful logon",
        "2025-06-01T08:01:00,4688,jsmith,192.168.1.50,Process created: powershell.exe -enc base64string",
        "2025-06-01T08:02:00,4625,admin,10.0.0.5,Failed logon attempt",
        "2025-06-01T08:02:10,4624,svc_backup,10.0.0.8,Successful logon",
        "2025-06-01T08:03:00,4688,svc_backup,10.0.0.8,Process created: cmd.exe /c whoami",
    ]
    with open(output_path, "w") as f:
        for line in sample_lines:
            f.write(line + "\n")
    print(f"[+] Sample log file written to: {output_path}")


if __name__ == "__main__":
    import os
    os.makedirs("sample_data", exist_ok=True)
    os.makedirs("output", exist_ok=True)

    sample_input = "sample_data/sample_events.csv"
    enriched_output = "output/enriched_events.json"

    generate_sample_logs(sample_input)
    process_logs(sample_input, enriched_output)
