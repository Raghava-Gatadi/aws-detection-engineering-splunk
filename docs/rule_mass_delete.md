# Detection: Mass Deletion / Destruction (T1485)

## Rule Metadata
| Attribute | Details |
| :--- | :--- |
| **Severity** | MEDIUM to CRITICAL |
| **MITRE Technique** | [T1485: Data Destruction](https://attack.mitre.org/techniques/T1485/) |
| **SPL File** | [Link to Query](../detections/6_mass_destruction.spl) |

## Technical Context
**Why this is malicious:**
The ultimate goal of many attackers is ransomware or sabotage. This rule detects bulk deletion of resources or the targeted deletion of security keys (KMS).

## 🕵️Analyst Playbook
**Step 1: Asset Value**
*   What is being deleted?
    *   `DeleteBucket` (High Risk: Data Loss).
    *   `DeleteKMSKey` (Critical Risk: Irrecoverable Data Loss).
    *   `TerminateInstances` (Service Disruption).

**Step 2: User Intent**
*   Is this a lifecycle policy (AmazonS3)?
*   Did the user perform `API Recon` immediately prior?

## Validation (Invictus Dataset)
*   **True Positive Observed:**
    *   **User:** `bert-jan`
    *   **Actions:** `DeleteParameter` (41 events), `DeleteBucket`, `TerminateInstances`.
    *   **Timing:** Occurred at the very end of the attack (Cleanup phase).

### Sample Detection Output
| event_time | user | sourceIP | deletion_count | actions_taken |
| :--- | :--- | :--- | :--- | :--- |
| 2023-07-10 12:35:00 | ...:user/bert-jan | 192.168.10.20 | 1 | **DeleteTrail** |