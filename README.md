# SOC Analyst Lab

Hands-on Security Operations Center (SOC) portfolio project focused on **security monitoring, log analysis, alert triage, and incident investigation**.

> **Status:** In progress — investigations are documented only after they are performed in the lab.

## Objective

The purpose of this repository is to document practical SOC analyst work using controlled lab environments. Each investigation will include the evidence reviewed, analyst reasoning, detection logic, MITRE ATT&CK mapping where applicable, and recommended response actions.

## Skills Practiced

- Security monitoring
- Windows event log analysis
- Alert triage
- Incident investigation
- Threat detection
- Network traffic analysis
- IOC analysis
- MITRE ATT&CK mapping
- Security documentation

## Lab Roadmap

- [x] Build Windows security logging lab
- [x] Generate controlled failed-login events
- [x] Investigate Windows Event ID 4625
- [x] Identify repeated authentication failures
- [x] Document triage and analyst findings
- [x] Add screenshots and evidence
- [x] Create and validate detection logic for repeated failed logins
- [ ] Expand into SIEM monitoring with Splunk or Microsoft Sentinel

## Repository Structure

```text
SOC-Analyst-Lab/
├── README.md
├── docs/
│   └── lab-setup.md
├── investigations/
│   └── 001-windows-failed-logins.md
├── detections/
│   ├── README.md
│   └── 001-repeated-failed-logons.md
├── sample-logs/
│   └── README.md
└── screenshots/
    ├── README.md
    └── 001-event-4625-overview.jpg
```

## Investigation 001 — Windows Failed Login Analysis

**Status:** Completed — Controlled Lab Simulation

The first investigation analyzed five repeated Windows failed-logon events (Event ID **4625**) generated in an authorized local lab. The activity was triaged as **Benign / Authorized Security Test**, with evidence, analyst findings, MITRE ATT&CK mapping, and recommended response actions documented in:

[`investigations/001-windows-failed-logins.md`](investigations/001-windows-failed-logins.md)

## Detection 001 — Repeated Failed Logons

**Status:** Validated — Local Lab

A PowerShell-based threshold detection was validated against the controlled Event ID 4625 dataset. The rule triggered when **5 failed logons occurred within a 2-minute window**.

[`detections/001-repeated-failed-logons.md`](detections/001-repeated-failed-logons.md)

## Tools

Current / planned tools for this lab:

- Windows Event Viewer
- Windows Security Logs
- VirtualBox
- Wireshark
- PowerShell / Windows command line
- Splunk *(planned)*
- Microsoft Sentinel *(planned)*

## Ethics

All activity documented in this repository is performed in systems and lab environments that I own or am explicitly authorized to test.

## Author

**Hicham Essafi**  
Cybersecurity | Junior SOC Analyst / Security Operations

- LinkedIn: https://www.linkedin.com/in/hicham-essafi/
- TryHackMe: https://tryhackme.com/p/HichamEssafi
- GitHub: https://github.com/arriess
