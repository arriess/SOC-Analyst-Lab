# Lab Setup

## Status

**Active — validated Windows + Splunk SOC lab**

This document records the environment actually used for the investigations and detections in this repository.

## Environment

- Windows host used as the controlled endpoint
- Windows Security Event Logging
- Windows Event Viewer
- PowerShell
- Windows Command Prompt
- Splunk Enterprise installed locally
- Splunk Search & Reporting
- Dedicated Splunk index: `soc_lab`

## Windows Telemetry Used

The current lab has validated collection and analysis of:

- Event ID **4624** — Successful logon
- Event ID **4625** — Failed logon
- Event ID **4688** — Process creation
- Event ID **4720** — User account creation

## Audit Configuration Used

The lab enabled the Windows audit categories required for the completed exercises, including successful and failed logon auditing and process-creation auditing.

Command-line process arguments are not required for the published detections in this repository. This reduces the risk of unnecessarily collecting or exposing sensitive command-line data.

## Splunk Data Flow

```text
Windows Security Log
        ↓
Splunk Windows Event Log input
        ↓
Index: soc_lab
        ↓
SPL searches and correlation
        ↓
Scheduled alerts
        ↓
Triggered Alerts
```

## Validation Approach

Security events are generated only through controlled activity on the local lab system. A detection is documented as validated only after:

1. The expected Windows event is generated.
2. Splunk ingests the event into `soc_lab`.
3. The SPL search returns the expected result.
4. The rule is configured as a scheduled alert where applicable.
5. A fresh controlled test successfully appears in Splunk Triggered Alerts.

## Privacy and Safety

Public evidence is sanitized before upload. Real local usernames, hostnames, account domains, credentials, public IP addresses, unnecessary exact timestamps, and unrelated system details are excluded or redacted.

All testing is performed only on systems and accounts owned by or explicitly authorized for the lab user.
