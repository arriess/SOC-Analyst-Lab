# SOC Analyst Lab

Hands-on Security Operations Center (SOC) portfolio focused on **Windows security monitoring, Splunk SIEM, Microsoft Sentinel, KQL, Wireshark, threat detection, alert triage, and incident investigation**.

> **Current status:** Portfolio-ready core lab complete — 5 Splunk detections validated end-to-end, 2 analyst investigations documented, and Detection 001 reproduced and validated in Microsoft Sentinel with KQL.

## Objective

Build practical SOC analyst capability by generating controlled security telemetry, analyzing Windows and network activity, developing detections, correlating events, validating findings across multiple security tools, documenting analyst reasoning, and publishing sanitized evidence.

## Current Lab Capabilities

- Windows Security Event Log analysis
- Splunk Enterprise and SPL
- Microsoft Sentinel and KQL
- Azure Arc and Azure Monitor Agent (AMA)
- Data Collection Rules and `SecurityEvent` telemetry
- Authentication-event correlation
- Windows process-creation analysis
- Account and privilege-change monitoring
- Scheduled Splunk alerts
- Alert triage and false-positive analysis
- Wireshark packet capture and DNS analysis
- MITRE ATT&CK mapping
- Security documentation and evidence sanitization

## Validated Splunk Detections

| Detection | Telemetry | Logic | Severity | Status |
|---|---|---|---|---|
| **001 — Repeated Failed Logons** | 4625 | 5+ failed logons within 2 minutes | Medium | ✅ Validated |
| **002 — Command Prompt Spawning PowerShell** | 4688 | `cmd.exe → powershell.exe` | Low | ✅ Validated |
| **003 — Failed Logons Followed by Success** | 4625 + 4624 | 5+ failures followed by success within 5 minutes | Medium | ✅ Validated |
| **004 — New Local User Account Created** | 4720 | New account creation | Medium | ✅ Validated |
| **005 — User Added to Local Administrators Group** | 4732 | Addition to built-in Administrators | High | ✅ Validated |

All five detections were tested with controlled lab activity, reproduced in Splunk, configured as scheduled alerts, and validated through Triggered Alerts.

## Microsoft Sentinel / KQL Validation

### Detection 001 — Repeated Failed Logons

**Status:** ✅ Validated in Microsoft Sentinel

The Windows lab host was onboarded through **Azure Arc**, monitored with **Azure Monitor Agent (AMA)**, and connected to Microsoft Sentinel through a **Data Collection Rule** using the Minimal Windows Security Events set.

The full telemetry path was validated:

```text
Controlled failed logons
        ↓
Windows Security Event ID 4625
        ↓
Azure Arc + AMA
        ↓
Data Collection Rule
        ↓
Log Analytics Workspace
        ↓
Microsoft Sentinel SecurityEvent table
        ↓
KQL correlation
        ↓
5 failed logons detected
```

KQL validation reproduced the same detection logic used in Splunk: **5 or more failed logons for the same target account and computer within a 2-minute window**.

Documentation: [`sentinel/001-repeated-failed-logons-kql.md`](sentinel/001-repeated-failed-logons-kql.md)

## Analyst Investigations

| Investigation | Data Source | Focus | Classification | Status |
|---|---|---|---|---|
| **001 — Windows Failed Login Analysis** | Windows Security Logs | Repeated Event ID 4625 activity | Benign / Authorized Test | ✅ Completed |
| **002 — DNS Traffic Analysis with Wireshark** | DNS packets | A/AAAA request-response analysis | Benign / Authorized Test | ✅ Completed |

## Repository Structure

```text
SOC-Analyst-Lab/
├── README.md
├── docs/
│   └── lab-setup.md
├── detections/
│   ├── 001-repeated-failed-logons.md
│   ├── 002-cmd-to-powershell.md
│   ├── 003-failed-logons-followed-by-success.md
│   ├── 004-new-local-user-account.md
│   └── 005-local-admin-group-addition.md
├── sentinel/
│   └── 001-repeated-failed-logons-kql.md
├── investigations/
│   ├── 001-windows-failed-logins.md
│   └── 002-dns-traffic-analysis.md
├── sample-logs/
│   └── README.md
└── screenshots/
    ├── 001-event-4625-overview.jpg
    ├── 002-splunk-triggered-alert.jpg
    ├── 003-cmd-powershell-triggered-alert.jpg
    ├── 004-failed-logons-followed-by-success-alert.jpg
    ├── 005-new-local-user-account-alert.jpg
    ├── 006-local-admin-group-addition-alert.jpg
    └── 007-wireshark-dns-example-analysis-sanitized.jpg
```

## Lab Roadmap

- [x] Build Windows security logging lab
- [x] Ingest Windows Security logs into Splunk
- [x] Validate five Splunk detections end-to-end
- [x] Configure scheduled Splunk alerts
- [x] Complete Windows failed-login investigation
- [x] Complete Wireshark DNS traffic investigation
- [x] Onboard Windows lab host to Azure Arc
- [x] Deploy Azure Monitor Agent
- [x] Configure Windows Security Events via AMA
- [x] Ingest Windows events into Microsoft Sentinel `SecurityEvent`
- [x] Reproduce and validate Detection 001 using KQL
- [x] Produce sanitized Sentinel/KQL portfolio evidence

## Tools Used

- Windows Event Viewer / Windows Security Logs
- PowerShell / Command Prompt
- Splunk Enterprise / SPL
- Microsoft Sentinel / KQL
- Azure Arc
- Azure Monitor Agent (AMA)
- Log Analytics / Data Collection Rules
- Wireshark / DNS analysis
- MITRE ATT&CK
- GitHub

## Privacy

Public portfolio evidence is sanitized. Real usernames, hostnames, account domains, credentials, subscription/tenant identifiers, local addresses, MAC addresses, exact timestamps where unnecessary, and other identifying information are excluded or redacted.

## Ethics

All activity documented in this repository was performed on owned or explicitly authorized lab systems. Test accounts and controlled telemetry were used; no third-party systems, accounts, or network traffic were intentionally targeted.

## Author

**Hicham Essafi**  
Cybersecurity | Junior SOC Analyst / Security Operations

- LinkedIn: https://www.linkedin.com/in/hicham-essafi/
- TryHackMe: https://tryhackme.com/p/HichamEssafi
- GitHub: https://github.com/arriess
