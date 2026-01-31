# Detection: API Reconnaissance Spike (T1595.002)

## Rule Metadata
| Attribute | Details |
| :--- | :--- |
| **Severity** | MEDIUM |
| **MITRE Technique** | [T1595.002: Active Scanning (Vulnerability Scanning)](https://attack.mitre.org/techniques/T1595/002/) |
| **SPL File** | [Link to Query](../detections/1_api_recon_spike.spl) |

## Technical Context
**Why this is malicious:**
Before launching an attack, adversaries must map the environment to identify high-value targets (S3 buckets, RDS databases, IAM roles). Automated tools (like ScoutSuite or Pacu) generate a massive volume of `List*`, `Get*`, and `Describe*` calls in a short window.

**Logic:**
We look for >10 **unique** API calls within a 10-minute window. Counting *unique* calls is superior to raw volume because it filters out scripts that simply retry the same failed action repeatedly.

## 🕵️Analyst Playbook
**Step 1: Identify Source**
*   Is the IP address external or internal (VPN/Office)?
*   Is the `userAgent` a known tool (e.g., `Boto3`, `Kali`, `Go-http-client`)?

**Step 2: Intent Analysis**
*   Review the specific APIs called.
    *   *Benign:* `DescribeInstances` (Dashboard loading).
    *   *Suspicious:* `GetAccountAuthorizationDetails`, `ListUsers`, `GetBucketPolicy`.

## False Positive Analysis
*   **CMDB Scanners:** Tools like Wiz, Prisma Cloud, or internal inventory scripts run periodically.
    *   *Tuning:* Whitelist the specific IAM Role ARNs used by these security tools.
*   **DevOps Deployments:** Terraform `plan` runs often generate many "Read" events.

## Validation (Invictus Dataset)
*   **True Positive Observed:**
    *   **User:** `bert-jan`
    *   **Volume:** 187 unique API calls in <10 minutes.
    *   **Key Signals:** `DescribeVpcs`, `ListUsers`, `GetBucketAcl`.

### Sample Detection Output
| _time | user | sourceIP | unique_api_calls | top_apis |
| :--- | :--- | :--- | :--- | :--- |
| 2023-07-10 12:20:00 | ...:user/bert-jan | 10.8.8.10 | **47** | `DescribeAccountAttributes`, `DescribeDBClusters`, `ListBuckets`... |
| 2023-07-10 12:20:00 | ...:user/bert-jan | 192.168.10.20 | **45** | `DescribeRouteTables`, `DescribeSecurityGroups`, `ListRolePolicies`... |
| 2023-07-10 11:50:00 | ...:user/bert-jan | 192.168.10.20 | 22 | `DescribeParameters`, `GetParameters`, `ListTags` |