# Detection: CloudTrail Tampering (T1562.008)

## Rule Metadata
| Attribute | Details |
| :--- | :--- |
| **Severity** | CRITICAL |
| **MITRE Technique** | [T1562.008: Impair Defenses (Disable Cloud Logs)](https://attack.mitre.org/techniques/T1562/008/) |
| **SPL File** | [Link to Query](../detections/4_cloudtrail_tampering.spl) |

## Technical Context
**Why this is malicious:**
AWS CloudTrail is the "flight recorder" for the cloud environment. Attackers often attempt to stop or delete trails immediately after gaining administrative access to blind security teams before performing destructive actions. 

**Specific Behaviors Monitored:**
*   `StopLogging`: Pauses recording of events.
*   `DeleteTrail`: Permanently removes the trail configuration.
*   `UpdateTrail`: Can be used to disable global logging or log file validation.

## Analyst Playbook (Triage Guide)
**Step 1: Immediate Containment**
*   This alert acts as a "Panic Button." Assume compromise until proven otherwise.
*   Check if the user is a known administrator or an automation account (Terraform/CloudFormation).

**Step 2: Contextual Analysis**
*   Run a search for the `userIdentity.arn` in the 1 hour *preceding* the alert.
*   *Pivot Question:* Did this user just perform `AssumeRole` or `ConsoleLogin` from an anomalous IP?

**Step 3: Impact Assessment**
*   Check for `Delete*` events immediately following the CloudTrail tampering.
*   *Invictus Scenario:* The attacker (`bert-jan`) stopped logging 7 minutes before attempting to wipe infrastructure.

## False Positive Analysis
*   **Infrastructure as Code (IaC):** Terraform destroying a temporary sandbox environment.
    *   *Filter:* `userAgent` contains "Terraform" AND account is `dev/sandbox`.
*   **Cost Savings:** Admins disabling trails in unused regions (rare).

## Validation (Invictus Dataset)
*   **True Positive Observed:**
    *   **Time:** 12:30 PM
    *   **User:** `arn:aws:iam::123456789012:user/bert-jan`
    *   **Action:** `StopLogging`
    *   **Outcome:** Detected successfully.

### Sample Detection Output
| eventTime | eventName | user | sourceIP |
| :--- | :--- | :--- | :--- |
| 2023-07-10 12:01:23 | **StopLogging** | ...:user/bert-jan | 192.168.10.20 |
| 2023-07-10 11:59:02 | **DeleteTrail** | ...:user/bert-jan | 192.168.10.20 |
| 2023-07-10 12:00:08 | PutEventSelectors | ...:user/bert-jan | 192.168.10.20 |