# Detection 001 — Repeated Windows Failed Logons

## Status

**Testing — Not Yet Validated**

This detection is based on the completed Windows Event ID 4625 investigation. It will only be marked as validated after the detection logic is executed successfully against lab data.

## Detection Objective

Identify a burst of repeated Windows authentication failures that may indicate password guessing, brute-force activity, a misconfigured service, or repeated user error.

## Data Source

- Windows Security Event Log
- Event ID: **4625** — failed logon

## Detection Logic

Trigger an alert when:

> **5 or more Event ID 4625 failed-logon events occur within a 2-minute window.**

### Conceptual Rule

```text
IF EventID = 4625
AND failed_logon_count >= 5
WITHIN 2 minutes
THEN generate alert
```

## Local PowerShell Validation

The following PowerShell logic checks recent Windows Security logs for any two-minute window containing at least five Event ID 4625 events.

```powershell
$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4625
    StartTime=(Get-Date).AddHours(-2)
} | Sort-Object TimeCreated

$alertFound = $false

for ($i = 0; $i -lt $events.Count; $i++) {
    $windowEnd = $events[$i].TimeCreated.AddMinutes(2)
    $window = $events | Where-Object {
        $_.TimeCreated -ge $events[$i].TimeCreated -and
        $_.TimeCreated -le $windowEnd
    }

    if ($window.Count -ge 5) {
        Write-Output "ALERT: $($window.Count) failed logons detected within 2 minutes"
        $alertFound = $true
        break
    }
}

if (-not $alertFound) {
    Write-Output "No threshold breach detected"
}
```

The output intentionally avoids printing usernames, hostnames, or exact timestamps so the validation result can be documented without exposing unnecessary identifiers.

## Expected Test Result

The controlled lab generated five failed-logon events in approximately two minutes, so the expected result is:

```text
ALERT: 5 failed logons detected within 2 minutes
```

## Triage Guidance

If this alert occurs unexpectedly in a production environment, an analyst should review:

1. Whether the same account is being targeted repeatedly.
2. Whether the failures originate from the same source system or IP address.
3. Whether a successful logon (Event ID 4624) follows the failures.
4. Whether privileged or service accounts are involved.
5. Whether the source is expected business activity, user error, or suspicious authentication behavior.

## Potential False Positives

- A user repeatedly typing the wrong password.
- Saved credentials that are no longer valid.
- A scheduled task or service using an outdated password.
- Legitimate administrative testing.

## Severity

**Default:** Medium

Severity should be increased when privileged accounts, unknown external sources, many target accounts, or a successful authentication following repeated failures are observed.

## MITRE ATT&CK

**T1110.001 — Brute Force: Password Guessing**

This mapping represents behavior the rule is designed to detect. A detection match alone does not prove malicious activity.

## Next Step

After local validation, this detection will be translated into SIEM-specific correlation logic such as:

- Splunk SPL
- Microsoft Sentinel KQL
