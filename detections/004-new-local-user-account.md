# Detection 004 — New Local User Account Created

## Status

**Validated — Splunk Scheduled Alert**

This detection identifies Windows Security Event ID **4720**, which indicates that a new user account was created.

Account creation is not malicious by itself. In a production environment, however, unexpected account creation can be important security telemetry and should be reviewed in context, particularly when the account is created outside normal administrative workflows or is followed by privilege changes.

## Data Source

- Windows Security Event Log
- Event ID **4720** — A user account was created
- Splunk index: `soc_lab`

## Detection Objective

Identify new local user-account creation events and surface them for analyst review.

## SPL Detection Query

```spl
index=soc_lab EventCode=4720
| eval created_account="REDACTED_ACCOUNT"
| stats count AS account_creation_events BY created_account
```

The public-facing result intentionally replaces the real account name with `REDACTED_ACCOUNT`.

## Validation Result

A controlled local lab account was created and Splunk returned:

```text
created_account      account_creation_events
REDACTED_ACCOUNT     1
```

**Result:** Event ID 4720 was successfully ingested and detected in Splunk.

## Splunk Scheduled Alert

The validated query was saved as a scheduled Splunk alert with the following configuration:

| Setting | Value |
|---|---|
| Alert name | New Local User Account Created |
| Alert type | Scheduled |
| Search window | Last 5 minutes |
| Schedule | Every 5 minutes |
| Trigger condition | Number of Results > 0 |
| Trigger mode | Once |
| Throttle | 10 minutes |
| Severity | Medium |
| Action | Add to Triggered Alerts |

A fresh controlled account-creation event was generated after the alert was enabled. Splunk ingested Event ID 4720, evaluated the detection, and the alert appeared successfully in **Triggered Alerts** with **Medium** severity.

## End-to-End Validation

```text
New local account created
          ↓
Windows Event ID 4720
          ↓
Splunk ingestion
          ↓
SPL detection
          ↓
Scheduled alert
          ↓
Triggered Alert (Medium)
```

## Triage Guidance

If this alert occurs unexpectedly in a production environment, review:

1. Who initiated the account creation.
2. Whether the account name and creation time match an approved administrative change.
3. Whether the new account is local, service-related, or part of a normal provisioning workflow.
4. Whether the account is subsequently added to privileged groups.
5. Whether the account performs unusual authentication, process execution, or network activity after creation.
6. Whether additional account-management events occur shortly before or after the creation.

## Potential False Positives

- Legitimate administrator account provisioning.
- IT onboarding workflows.
- Temporary test accounts.
- Application or service installation creating a local account.
- Security lab activity.

## Severity

**Default: Medium**

Raise severity when the account is created unexpectedly, outside an approved change window, by an unusual administrator, or is followed by privileged-group membership changes or suspicious activity.

## MITRE ATT&CK

**T1136 — Create Account**

The ATT&CK mapping represents behavior this detection is designed to surface. A match alone does not prove malicious activity.

## Privacy

Public documentation intentionally excludes or redacts real account names, hostnames, account domains, credentials, public IP addresses, exact trigger timestamps, and other unnecessary identifying information.

## Next Step

Add sanitized visual evidence for the triggered alert and continue expanding the lab with privilege-change or other Windows security detections.
