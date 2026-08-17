# Detection 001 — Repeated Windows Failed Logons

## Status

**Validated — Local Lab**

This detection was successfully executed against controlled Windows Security log data and triggered when the configured threshold was reached.

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

## Validated PowerShell Logic

Run PowerShell with permission to read the Windows Security log.

```powershell
$events = @(Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4625
    StartTime=(Get-Date).AddHours(-2)
} | Sort-Object TimeCreated)

$alertFound = $false

for ($i = 0; $i -lt $events.Count; $i++) {
    $windowStart = $events[$i].TimeCreated
    $windowEnd   = $windowStart.AddMinutes(2)

    $count = @(
        $events | Where-Object {
            $_.TimeCreated -ge $windowStart -and
            $_.TimeCreated -le $windowEnd
        }
    ).Count

    if ($count -ge 5) {
        Write-Output "ALERT: $count failed logons detected within 2 minutes"
        $alertFound = $true
        break
    }
}

if (-not $alertFound) {
    Write-Output "No threshold breach detected"
}
```

The output intentionally avoids printing usernames, hostnames, or exact timestamps so validation can be documented without exposing unnecessary identifiers.

## Validation Result

The controlled lab contained five Event ID 4625 failed-logon events within the configured two-minute threshold.

Observed output:

```text
ALERT: 5 failed logons detected within 2 minutes
```

**Result:** Detection triggered as expected.

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

Translate the validated detection into SIEM-specific correlation logic:

- Splunk SPL
- Microsoft Sentinel KQL
