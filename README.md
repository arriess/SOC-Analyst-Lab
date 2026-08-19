# SOC Analyst Lab

Hands-on Security Operations Center (SOC) portfolio project focused on **Windows security monitoring, log analysis, alert triage, detection engineering, Splunk SIEM investigations, and network traffic analysis**.

> **Current status:** Core portfolio lab complete — 5 Splunk detections validated end-to-end and 2 analyst investigations documented in a controlled environment.

## Objective

The purpose of this repository is to document practical SOC analyst work using controlled lab environments. The project focuses on generating security telemetry, analyzing Windows events and network traffic, building SPL detection logic, creating scheduled SIEM alerts, validating alert triggers, documenting analyst reasoning, and publishing sanitized evidence.

## Current Lab Capabilities

- Windows Security Event Log analysis
- Authentication-event investigation
- Windows process-creation analysis
- Windows account-management monitoring
- Local privilege-change monitoring
- Splunk log ingestion
- Splunk Search Processing Language (SPL)
- Per-account event correlation
- Parent-child process correlation
- Scheduled SIEM alert creation
- Alert threshold tuning and throttling
- Alert triage and false-positive analysis
- Wireshark packet capture and DNS traffic analysis
- DNS query/response filtering
- MITRE ATT&CK mapping where behavior is relevant
- Security documentation and evidence sanitization

## Validated Detections

| Detection | Telemetry | Logic | Severity | Status |
|---|---|---|---|---|
| **001 — Repeated Failed Logons** | Event ID 4625 | 5+ failed logons within 2 minutes | Medium | ✅ Validated |
| **002 — Command Prompt Spawning PowerShell** | Event ID 4688 | `cmd.exe → powershell.exe` process chain | Low | ✅ Validated |
| **003 — Failed Logons Followed by Success** | Event IDs 4625 + 4624 | 5+ failures followed by a success for the same account within 5 minutes | Medium | ✅ Validated |
| **004 — New Local User Account Created** | Event ID 4720 | New user account creation detected | Medium | ✅ Validated |
| **005 — User Added to Local Administrators Group** | Event ID 4732 | Account added to built-in Local Administrators | High | ✅ Validated |

Each detection was tested with controlled lab activity, reproduced in Splunk, saved as a scheduled alert, and confirmed in **Triggered Alerts**.

## Analyst Investigations

| Investigation | Data Source | Focus | Classification | Status |
|---|---|---|---|---|
| **001 — Windows Failed Login Analysis** | Windows Security Logs | Repeated Event ID 4625 activity | Benign / Authorized Test | ✅ Completed |
| **002 — DNS Traffic Analysis with Wireshark** | Network packets / DNS | A and AAAA query-response analysis for `example.com` | Benign / Authorized Test | ✅ Completed |

## End-to-End Workflow Practiced

```text
Controlled activity
       ↓
Windows / network telemetry
       ↓
Splunk or Wireshark analysis
       ↓
Detection / filtering / correlation
       ↓
Alert or analyst finding
       ↓
Triage + documentation
       ↓
Sanitized portfolio evidence
```

## Lab Roadmap

- [x] Build Windows security logging lab
- [x] Generate controlled failed-login events
- [x] Investigate Windows Event ID 4625
- [x] Ingest Windows Security logs into Splunk
- [x] Build and validate repeated failed-logon detection
- [x] Create and trigger a Splunk scheduled alert
- [x] Analyze Event ID 4688 process-creation telemetry
- [x] Detect `cmd.exe → powershell.exe` process chains
- [x] Correlate failed and successful authentication events by account
- [x] Detect Windows user-account creation with Event ID 4720
- [x] Detect additions to the local Administrators group with Event ID 4732
- [x] Validate five Splunk detections end-to-end
- [x] Add sanitized Splunk visual evidence
- [x] Capture and analyze DNS traffic with Wireshark
- [x] Document a network-traffic investigation with sanitized evidence
- [x] Complete the core Windows + Splunk + Wireshark portfolio lab
- [ ] Future expansion: reproduce selected detections in Microsoft Sentinel / KQL when available

## Repository Structure

```text
SOC-Analyst-Lab/
├── README.md
├── docs/
│   └── lab-setup.md
├── investigations/
│   ├── 001-windows-failed-logins.md
│   └── 002-dns-traffic-analysis.md
├── detections/
│   ├── README.md
│   ├── 001-repeated-failed-logons.md
│   ├── 002-cmd-to-powershell.md
│   ├── 003-failed-logons-followed-by-success.md
│   ├── 004-new-local-user-account.md
│   └── 005-local-admin-group-addition.md
├── sample-logs/
│   └── README.md
└── screenshots/
    ├── README.md
    ├── 001-event-4625-overview.jpg
    ├── 002-splunk-triggered-alert.jpg
    ├── 003-cmd-powershell-triggered-alert.jpg
    ├── 004-failed-logons-followed-by-success-alert.jpg
    ├── 005-new-local-user-account-alert.jpg
    ├── 006-local-admin-group-addition-alert.jpg
    └── 007-wireshark-dns-example-analysis-sanitized.jpg
```

## Investigation 001 — Windows Failed Login Analysis

**Status:** Completed — Controlled Lab Simulation

Five repeated Windows failed-logon events (Event ID **4625**) were generated in an authorized local lab and investigated as a SOC analyst scenario. The activity was classified as **Benign / Authorized Security Test**, with evidence, findings, MITRE ATT&CK mapping, and response recommendations documented in:

[`investigations/001-windows-failed-logins.md`](investigations/001-windows-failed-logins.md)

## Investigation 002 — DNS Traffic Analysis with Wireshark

**Status:** Completed — Controlled / Authorized Network Analysis

A controlled DNS lookup for `example.com` was captured and isolated in Wireshark. The investigation analyzed **A and AAAA DNS queries and responses**, used a targeted display filter, classified the traffic as benign, and published sanitized evidence without exposing local identifiers.

[`investigations/002-dns-traffic-analysis.md`](investigations/002-dns-traffic-analysis.md)

## Detection 001 — Repeated Failed Logons

**Status:** Validated — PowerShell + Splunk SIEM

Detects **5 or more Event ID 4625 failed logons within a 2-minute window**. The rule was validated locally and then reproduced as a scheduled Splunk alert.

[`detections/001-repeated-failed-logons.md`](detections/001-repeated-failed-logons.md)

## Detection 002 — Command Prompt Spawning PowerShell

**Status:** Validated — Splunk Scheduled Alert

Detects the Windows process chain:

```text
cmd.exe → powershell.exe
```

using Event ID **4688** parent-child process telemetry. This behavior is treated as contextual rather than inherently malicious and is configured with **Low** severity.

[`detections/002-cmd-to-powershell.md`](detections/002-cmd-to-powershell.md)

## Detection 003 — Repeated Failed Logons Followed by Success

**Status:** Validated — Splunk Scheduled Alert

Correlates Event IDs **4625** and **4624** to identify **5 or more failed logons followed by a successful logon for the same account within 5 minutes**. The alert is configured with **Medium** severity and requires analyst triage because legitimate password mistakes can produce the same pattern.

[`detections/003-failed-logons-followed-by-success.md`](detections/003-failed-logons-followed-by-success.md)

## Detection 004 — New Local User Account Created

**Status:** Validated — Splunk Scheduled Alert

Detects Windows Event ID **4720** when a new user account is created. The alert is configured with **Medium** severity because account creation is legitimate in many administrative workflows but can be security-relevant when unexpected or followed by privilege changes.

[`detections/004-new-local-user-account.md`](detections/004-new-local-user-account.md)

## Detection 005 — User Added to Local Administrators Group

**Status:** Validated — Splunk Scheduled Alert

Detects Windows Event ID **4732** when an account is added to the built-in local **Administrators** group (`S-1-5-32-544`). The alert is configured with **High** severity because the change grants local administrative privileges and should be reviewed when unexpected.

[`detections/005-local-admin-group-addition.md`](detections/005-local-admin-group-addition.md)

## Tools Used

- Windows Event Viewer
- Windows Security Logs
- PowerShell
- Windows Command Prompt
- Splunk Enterprise
- Splunk Search Processing Language (SPL)
- Wireshark
- DNS traffic analysis
- MITRE ATT&CK
- GitHub for portfolio documentation

### Future Expansion

- Microsoft Sentinel / KQL, when available
- Additional network and endpoint telemetry sources

## Privacy

Public portfolio evidence is sanitized before publication. Real local usernames, hostnames, account domains, credentials, private/public IP addresses when unnecessary, MAC addresses, unnecessary exact timestamps, and other identifying information are excluded or redacted.

## Ethics

All activity documented in this repository is performed on systems and lab environments that I own or am explicitly authorized to test. Network analysis is limited to controlled traffic generated for the lab; third-party traffic is not intentionally targeted or intercepted.

## Author

**Hicham Essafi**  
Cybersecurity | Junior SOC Analyst / Security Operations

- LinkedIn: https://www.linkedin.com/in/hicham-essafi/
- TryHackMe: https://tryhackme.com/p/HichamEssafi
- GitHub: https://github.com/arriess
