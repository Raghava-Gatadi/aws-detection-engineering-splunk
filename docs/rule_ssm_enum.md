# Detection: SSM Parameter Enumeration (T1555.006)

## Rule Metadata
| Attribute | Details |
| :--- | :--- |
| **Severity** | HIGH |
| **MITRE Technique** | [T1555.006: Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/006/) |
| **SPL File** | [Link to Query](../detections/2_ssm_parameter_enumeration.spl) |

## Technical Context
**Why this is malicious:**
AWS Systems Manager (SSM) Parameter Store often holds application secrets, database strings, and API keys. Attackers iterate through parameters to steal these credentials for lateral movement.

**Logic:**
Detects high-frequency calls to `GetParameter` or `GetParametersByPath`.

## Analyst Playbook
**Step 1: Verify Permissions**
*   Does this user/role *normally* access these specific parameters?
*   Check `errorCode`. If `AccessDenied` is high, it indicates blind enumeration (guessing names).

**Step 2: Check for Exfiltration**
*   Did `GetParameter` succeed?
*   Did the IP address download a large volume of data immediately after?

## False Positive Analysis
*   **Application Bootstrapping:** EC2 instances often fetch configs on startup.
    *   *Filter:* `userAgent` contains "aws-sdk-java" AND Source IP is internal EC2.

## 📊 Validation (Invictus Dataset)
*   **True Positive Observed:**
    *   **User:** `bert-jan`
    *   **Activity:** 75 SSM operations in 37 minutes.
    *   **Target:** `GetParameters` followed by `DeleteParameter` (Evidence destruction).

### Sample Detection Output
| event_time | user | user_agent_snippet | distinct_api_calls | unique_params |
| :--- | :--- | :--- | :--- | :--- |
| 2023-07-10 11:50:00 | ...:user/bert-jan | `stratus-red-team_11a6ef34...` | 3 | **16** |