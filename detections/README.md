# Detection Engineering

This directory contains detection logic that has been **tested against controlled lab data and validated in Splunk**.

## Validated Detections

| ID | Detection | Windows Telemetry | Severity | Status |
|---|---|---|---|---|
| 001 | [Repeated Failed Logons](001-repeated-failed-logons.md) | Event ID 4625 | Medium | ✅ Validated |
| 002 | [Command Prompt Spawning PowerShell](002-cmd-to-powershell.md) | Event ID 4688 | Low | ✅ Validated |
| 003 | [Failed Logons Followed by Success](003-failed-logons-followed-by-success.md) | Event IDs 4625 + 4624 | Medium | ✅ Validated |
| 004 | [New Local User Account Created](004-new-local-user-account.md) | Event ID 4720 | Medium | ✅ Validated |

## Validation Standard

A detection is marked as validated only after the relevant activity is reproduced in the controlled lab, the expected Windows telemetry is ingested into Splunk, the SPL logic returns the intended result, and the scheduled alert is successfully observed in **Triggered Alerts**.

Detection matches are treated as security signals that require context and triage; they are not automatically described as malicious activity.
