# Detection 003 — Repeated Failed Logons Followed by Success

## Status

**Validated — Splunk Scheduled Alert**

This detection identifies a successful Windows logon that occurs after **5 or more failed logons for the same account within a 5-minute window**.

This pattern can indicate successful password guessing or brute-force activity, but it can also result from legitimate user error followed by a correct password. The detection therefore requires analyst triage and should not be treated as proof of compromise by itself.

## Data Sources

- Windows Security Event Log
- Event ID **4625** — failed logon
- Event ID **4624** — successful logon
- Splunk index: `soc_lab`

## Detection Objective

Identify the sequence:

```text
5+ failed logons for one account
            ↓
 successful logon
            ↓
   within 5 minutes
```

## SPL Detection Query

```spl
index=soc_lab (EventCode=4624 OR EventCode=4625)
| rex field=_raw "(?ms)Account For Which Logon Failed:.*?Account Name:\s+(?<failed_user>[^\r\n]+)"
| rex field=_raw "(?ms)New Logon:.*?Account Name:\s+(?<success_user>[^\r\n]+)"
| eval target_user=case(
    EventCode=4625, trim(failed_user),
    EventCode=4624, trim(success_user)
  )
| where isnotnull(target_user) AND target_user!="-"
| sort 0 + _time
| streamstats time_window=5m count(eval(EventCode=4625)) AS failed_logons BY target_user
| where EventCode=4624 AND failed_logons>=5
| eval account="REDACTED_ACCOUNT", successful_logons=1
| table account failed_logons successful_logons
```

The public-facing result intentionally replaces the real account name with `REDACTED_ACCOUNT`.

## Validation Result

A dedicated local lab account was used to generate a controlled authentication sequence. Splunk returned:

```text
account             failed_logons    successful_logons
REDACTED_ACCOUNT    5                1
```

**Result:** The correlation successfully identified a successful logon following five failed logons for the same account within the five-minute detection window.

## Splunk Scheduled Alert

The validated query was saved as a Splunk scheduled alert with the following configuration:

| Setting | Value |
|---|---|
| Alert name | Repeated Failed Logons Followed by Success |
| Alert type | Scheduled |
| Search window | Last 10 minutes |
| Detection correlation window | 5 minutes |
| Schedule | Every 5 minutes |
| Trigger condition | Number of Results > 0 |
| Trigger mode | Once |
| Throttle | 10 minutes |
| Severity | Medium |
| Action | Add to Triggered Alerts |

A fresh controlled sequence was generated after the alert was enabled. Splunk ingested the corresponding authentication events, evaluated the correlation logic, and the alert appeared successfully in **Triggered Alerts** with **Medium** severity.

## End-to-End Validation

```text
Windows Event ID 4625 ×5
          ↓
Windows Event ID 4624
          ↓
Splunk ingestion
          ↓
Per-account correlation
          ↓
5-minute sequence validation
          ↓
Scheduled detection
          ↓
Triggered Alert (Medium)
```

## Triage Guidance

If this alert occurs unexpectedly in a production environment, review:

1. Whether the same account was targeted in all failed attempts.
2. The source host or source network address associated with the failures and success.
3. Whether the successful logon originated from the same source as the failures.
4. The logon type and whether it matches normal behavior for the account.
5. Whether the account is privileged, administrative, or otherwise sensitive.
6. Activity immediately after the successful authentication, including process creation, network access, or privilege use.
7. Whether the sequence can be explained by legitimate user password mistakes.

## Potential False Positives

- A legitimate user repeatedly entering an incorrect password before succeeding.
- Cached or stale credentials followed by a correct interactive login.
- Administrative testing.
- Security lab activity.

## Severity

**Default: Medium**

Severity should be increased when the account is privileged, the source is unusual, the login occurs from an unexpected host or network, or suspicious post-authentication behavior follows the successful logon.

## MITRE ATT&CK

**T1110 — Brute Force**

Depending on context, the behavior may be consistent with password guessing or other brute-force techniques. The ATT&CK mapping represents the behavior the correlation is designed to surface; it does not prove malicious activity.

## Privacy

Public documentation intentionally excludes or redacts real account names, local hostnames, account domains, credentials, public IP addresses, exact trigger timestamps, and other unnecessary identifying information.

## Next Step

Add sanitized visual evidence for the Triggered Alert and continue expanding the lab with detections focused on different telemetry sources or behaviors.
