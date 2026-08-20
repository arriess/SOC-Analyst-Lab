# Microsoft Sentinel / KQL — Repeated Failed Logons

## Status
**Validated — Controlled Lab Detection**

## Objective
Reproduce the repeated failed-logon detection in Microsoft Sentinel using Windows Security Event telemetry and Kusto Query Language (KQL).

## Lab Architecture

```text
Windows 11 lab host
       ↓
Azure Arc
       ↓
Azure Monitor Agent (AMA)
       ↓
Data Collection Rule — Minimal Security Events
       ↓
Log Analytics Workspace
       ↓
Microsoft Sentinel — SecurityEvent table
       ↓
KQL detection
```

## Telemetry
- Data source: Windows Security Event Logs
- Sentinel table: `SecurityEvent`
- Event ID: `4625` — An account failed to log on
- Collection: Windows Security Events via AMA
- DCR event set: Minimal

## Detection Logic
Detect **5 or more failed logons for the same target account and computer within a 2-minute window**.

```kusto
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(15m)
| extend WindowStart = bin(TimeGenerated, 2m)
| summarize
    FailedLogons = count(),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by TargetAccount, Computer, WindowStart
| where FailedLogons >= 5
| project
    TimeGenerated = LastFailure,
    Computer,
    TargetAccount,
    FailedLogons,
    FirstFailure,
    LastFailure
| order by TimeGenerated desc
```

## Validation
A controlled test account was used to generate five failed interactive logon attempts in the authorized Windows lab. Windows recorded Event ID 4625 locally, AMA forwarded the events to the Sentinel workspace, and the KQL detection returned a matching result with `FailedLogons = 5`.

This validates the detection logic and the telemetry path end-to-end through Microsoft Sentinel.

## Analyst Assessment
The test activity was **Benign / Authorized Security Lab Activity**. In a production SOC, repeated failed logons can be associated with password guessing, user error, misconfigured services, or brute-force activity and require contextual triage.

## MITRE ATT&CK
- **T1110 — Brute Force**

## Skills Demonstrated
- Microsoft Sentinel
- Kusto Query Language (KQL)
- Azure Arc
- Azure Monitor Agent (AMA)
- Data Collection Rules
- Windows Security Event analysis
- Event ID 4625 analysis
- Authentication-event correlation
- Detection validation
- Security evidence sanitization

## Evidence
A sanitized portfolio screenshot was produced from the successful Sentinel KQL result. Exact timestamps and local identifiers are redacted in public evidence.

## Scope and Ethics
All events were generated on an owned/authorized lab machine using a dedicated test account. No third-party accounts, systems, or networks were targeted.
