# Detection 002 — Command Prompt Spawning PowerShell

## Status

**Validated — Splunk Lab**

This detection identifies Windows process-creation events where `cmd.exe` is the parent process and `powershell.exe` is the newly created child process.

This process chain is **not malicious by itself**. It is useful as contextual telemetry because PowerShell is frequently used for both legitimate administration and attacker execution. The alert should therefore be triaged together with user context, frequency, source system, surrounding process activity, and any related network or authentication events.

## Data Source

- Windows Security Event Log
- Event ID: **4688** — A new process has been created
- Splunk index: `soc_lab`

## Detection Objective

Identify the process chain:

```text
cmd.exe
   ↓
powershell.exe
```

## SPL Validation Query

```spl
index=soc_lab EventCode=4688 "powershell.exe" earliest=-5m
| rex field=_raw "New Process Name:\s+(?<new_process>[^\r\n]+)"
| rex field=_raw "(?:Creator|Parent) Process Name:\s+(?<parent_process>[^\r\n]+)"
| eval is_powershell=if(match(lower(new_process),"powershell\.exe$"),1,0)
| eval is_cmd_parent=if(match(lower(parent_process),"cmd\.exe$"),1,0)
| where is_powershell=1
| stats sum(is_cmd_parent) AS powershell_from_cmd
```

## Validation Result

A controlled lab test launched PowerShell from Command Prompt. Splunk identified matching Event ID 4688 process-creation records and returned:

```text
powershell_from_cmd
2
```

**Result:** The parent-child process relationship was detected successfully.

The count was greater than one because multiple matching process-creation events were present in the selected five-minute search window. The detection validates the process relationship, not a claim that two malicious executions occurred.

## Triage Guidance

When this process chain appears unexpectedly, review:

1. Whether the execution was initiated by an expected administrator or user workflow.
2. Whether the behavior is isolated or repeated.
3. Whether additional suspicious child processes follow PowerShell.
4. Whether nearby authentication, persistence, network, or endpoint events increase confidence.
5. Whether the endpoint is a workstation, administrative host, or server where PowerShell use is expected.

## Potential False Positives

- Administrative scripts.
- Troubleshooting commands.
- Software installers or management tools.
- Legitimate automation launched through a command shell.
- Security lab activity.

## Severity

**Default: Low / Informational**

Raise severity only when additional suspicious context is present, such as unexpected users, repeated execution, suspicious descendants, unusual network activity, or other correlated alerts.

## MITRE ATT&CK

- **T1059.001 — Command and Scripting Interpreter: PowerShell**
- Parent context may also involve **T1059.003 — Windows Command Shell**

The ATT&CK mapping describes the execution techniques represented by the telemetry. It does not prove malicious activity.

## Privacy

Public documentation should not expose real usernames, hostnames, account domains, credentials, command-line secrets, or unnecessary exact timestamps.

## Next Step

Create a Splunk scheduled alert for the process-chain detection and validate that a fresh controlled `cmd.exe → powershell.exe` execution appears in Triggered Alerts.
