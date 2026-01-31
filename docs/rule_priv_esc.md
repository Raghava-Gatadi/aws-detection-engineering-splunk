# Detection: Failed Privilege Escalation (T1078/T1068)

## Rule Metadata
| Attribute | Details |
| :--- | :--- |
| **Severity** | MEDIUM to CRITICAL (Dynamic) |
| **MITRE Technique** | [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| **SPL File** | [Link to Query](../detections/3_failed_privilege_escalation.spl) |

## Technical Context
**Why this is malicious:**
Compromised credentials often have limited scope. Attackers attempt to "break out" by guessing permissions or trying to attach administrative policies to their user. A spike in `AccessDenied` indicates this "fumbling in the dark."

## Analyst Playbook
**Step 1: Severity Assessment**
*   <5 Failures: Watch list.
*   \>10 Failures (CRITICAL): User is actively running a brute-force script.

**Step 2: Target Analysis**
*   What was denied?
    *   `PutUserPolicy` / `AttachRolePolicy` (Trying to become Admin).
    *   `CreateLoginProfile` (Trying to create a console password).

## False Positive Analysis
*   **Misconfigured Applications:** A broken Lambda function trying to access an S3 bucket it doesn't have permission for.
    *   *differentiation:* These usually occur at regular intervals (cron job pattern).

## Validation (Invictus Dataset)
*   **True Positive Observed:**
    *   **User:** `bert-jan`
    *   **Failures:** 15 `AccessDenied` errors trying to read `DescribeInstanceAttribute` (UserData credential theft).

### Sample Detection Output
| EventTime | sourceIPAddress | userIdentity.arn | failed_attempts | attempted_events | severity |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 2023-07-10T12:00:00Z | 192.168.10.20 | ...assumed-role/stratus-red-team-get-usr-data-role/... | **15** | `DescribeInstanceAttribute` | **CRITICAL** |
| 2023-07-10T11:50:00Z | 192.168.10.20 | ...assumed-role/stratus-red-team-ec2-get-password-data-role/... | 5 | `GetPasswordData` | MEDIUM |