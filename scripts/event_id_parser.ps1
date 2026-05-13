# event_id_parser.ps1
# -------------------
# Parses Windows Security Event Log for suspicious activity
# Targets Event IDs: 4624 (Logon), 4625 (Failed Logon), 4688 (Process Creation)
#
# Author: Mohamed Hishamudeen
# MITRE ATT&CK: T1110, T1078, T1059

param(
    [int]$MaxEvents = 500,
    [string]$OutputPath = ".\output\event_report.csv",
    [int]$BruteForceThreshold = 5
)

$SuspiciousProcesses = @("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe")
$Results = @()
$FailedLogons = @{}

Write-Host "[*] Collecting Security Events..." -ForegroundColor Cyan

# --- Collect Events ---
$Events4625 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
$Events4624 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
$Events4688 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

# --- Process 4625: Failed Logons ---
Write-Host "[*] Processing Event ID 4625 - Failed Logons..." -ForegroundColor Yellow

foreach ($event in $Events4625) {
    $xml = [xml]$event.ToXml()
    $data = $xml.Event.EventData.Data

    $username = ($data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
    $sourceIP  = ($data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
    $logonType = ($data | Where-Object { $_.Name -eq "LogonType" }).'#text'

    if (-not $username -or $username -eq "-") { continue }

    $key = "$username|$sourceIP"
    if ($FailedLogons.ContainsKey($key)) {
        $FailedLogons[$key]++
    } else {
        $FailedLogons[$key] = 1
    }

    $severity = if ($FailedLogons[$key] -ge $BruteForceThreshold) { "CRITICAL" }
                elseif ($FailedLogons[$key] -ge 3) { "HIGH" }
                else { "MEDIUM" }

    $Results += [PSCustomObject]@{
        Timestamp     = $event.TimeCreated
        EventID       = "4625"
        EventName     = "Failed Logon"
        Username      = $username
        SourceIP      = $sourceIP
        LogonType     = $logonType
        Details       = "Failed logon attempt #$($FailedLogons[$key])"
        Severity      = $severity
        MITRE         = "T1110 - Brute Force"
    }
}

# --- Process 4624: Successful Logons ---
Write-Host "[*] Processing Event ID 4624 - Successful Logons..." -ForegroundColor Yellow

foreach ($event in $Events4624) {
    $xml = [xml]$event.ToXml()
    $data = $xml.Event.EventData.Data

    $username  = ($data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
    $sourceIP  = ($data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
    $logonType = ($data | Where-Object { $_.Name -eq "LogonType" }).'#text'

    if (-not $username -or $username -eq "-") { continue }
    # Skip machine accounts
    if ($username -match "\$$") { continue }

    $key = "$username|$sourceIP"
    $priorFails = if ($FailedLogons.ContainsKey($key)) { $FailedLogons[$key] } else { 0 }

    $severity = if ($priorFails -ge 3) { "HIGH" } else { "LOW" }
    $detail = if ($priorFails -ge 3) {
        "Successful logon after $priorFails failed attempts — possible brute-force success"
    } else {
        "Normal successful logon"
    }

    $Results += [PSCustomObject]@{
        Timestamp  = $event.TimeCreated
        EventID    = "4624"
        EventName  = "Successful Logon"
        Username   = $username
        SourceIP   = $sourceIP
        LogonType  = $logonType
        Details    = $detail
        Severity   = $severity
        MITRE      = "T1078 - Valid Accounts"
    }
}

# --- Process 4688: Process Creation ---
Write-Host "[*] Processing Event ID 4688 - Process Creation..." -ForegroundColor Yellow

foreach ($event in $Events4688) {
    $xml = [xml]$event.ToXml()
    $data = $xml.Event.EventData.Data

    $username    = ($data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
    $processName = ($data | Where-Object { $_.Name -eq "NewProcessName" }).'#text'
    $cmdLine     = ($data | Where-Object { $_.Name -eq "CommandLine" }).'#text'

    if (-not $processName) { continue }

    $procFile = Split-Path $processName -Leaf
    $isSuspicious = $SuspiciousProcesses -contains $procFile.ToLower()

    if (-not $isSuspicious) { continue }

    $Results += [PSCustomObject]@{
        Timestamp  = $event.TimeCreated
        EventID    = "4688"
        EventName  = "Process Creation"
        Username   = $username
        SourceIP   = "N/A"
        LogonType  = "N/A"
        Details    = "Suspicious process: $processName | CMD: $cmdLine"
        Severity   = "HIGH"
        MITRE      = "T1059 - Command and Scripting Interpreter"
    }
}

# --- Output ---
if ($Results.Count -eq 0) {
    Write-Host "[!] No suspicious events found." -ForegroundColor Green
    exit
}

New-Item -ItemType Directory -Force -Path (Split-Path $OutputPath) | Out-Null
$Results | Sort-Object Severity -Descending | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host "`n[+] Report saved to: $OutputPath" -ForegroundColor Green

# Summary
Write-Host "`n[*] Summary:" -ForegroundColor Cyan
$Results | Group-Object Severity | ForEach-Object {
    Write-Host "    $($_.Name): $($_.Count) events"
}
