# Detection: Lateral Movement via AssumeRole (T1550.001)

## Rule Metadata
| Attribute | Details |
| :--- | :--- |
| **Severity** | HIGH |
| **MITRE Technique** | [T1550.001: Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/001/) |
| **SPL File** | [Link to Query](../detections/5_lateral_movement_assumerole.spl) |

## Technical Context
**Why this is malicious:**
"Role Chaining" involves assuming one role, then using that role to assume another, effectively hopping between accounts or privilege levels to obscure the original entry point.

## Analyst Playbook
**Step 1: Trace the Chain**
*   Splunk Search: `index=invictus eventName=AssumeRole`
*   Look at `userIdentity.sessionContext.sessionIssuer.userName`. Is it hopping from `Role-A` -> `Role-B`?

**Step 2: Cross-Account Check**
*   Is the source IP external, or is the request coming from another AWS account?

## False Positive Analysis
*   **CI/CD Pipelines:** Jenkins/GitLab runners often assume roles to deploy code.
*   **Monitoring Tools:** Datadog/Splunk forwarders assuming roles to collect logs.

## Validation (Invictus Dataset)
*   **True Positive Observed:**
    *   **Activity:** 17 `AssumeRole` events in 10 minutes.
    *   **Pattern:** Attacker pivoting through `Stratus Red Team` roles.

### Sample Detection Output
| event_time | user | action | attempts | error_message |
| :--- | :--- | :--- | :--- | :--- |
| 2023-07-10 12:00:00 | ...:user/bert-jan | AssumeRole | **3** | User is not authorized to perform: `sts:AssumeRole` on resource: `...role/stratus-red-team-leave-org-role` |