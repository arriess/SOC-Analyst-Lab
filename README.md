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

- [ ] Build Windows security logging lab
- [ ] Generate controlled failed-login events
- [ ] Investigate Windows Event ID 4625
- [ ] Identify repeated authentication failures
- [ ] Document triage and analyst findings
- [ ] Add screenshots and evidence
- [ ] Create detection logic for repeated failed logins
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
│   └── README.md
├── sample-logs/
│   └── README.md
└── screenshots/
    └── README.md
```

## Investigation 001 — Windows Failed Login Analysis

**Status:** Planned / In Progress

The first investigation will analyze repeated failed authentication events in a controlled Windows lab. The investigation will focus on Windows Security Event ID **4625** and determine whether the activity represents normal user error or suspicious repeated authentication attempts.

No investigation result is claimed until the lab has been performed and evidence has been collected.

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
