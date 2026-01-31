# AWS Security Monitoring: Detection Engineering Portfolio

### Project Overview
This project demonstrates a complete Detection Engineering lifecycle for AWS environments using **Splunk**. It focuses on identifying high-fidelity threats across the Cloud Kill Chain, from initial reconnaissance to impact (data destruction).

The detection logic was developed and validated against the **Invictus Incident Response** dataset, a red-team simulation of a compromised AWS environment.

*   **Dataset Source:** [Invictus IR AWS Dataset (GitHub)](https://github.com/invictus-ir/aws_dataset)
*   **Technologies:** Splunk Enterprise, AWS CloudTrail, MITRE ATT&CK.

---

## Detection Coverage Map
This project implements a multi-stage detection strategy designed to catch attackers at various pivot points.

| Rule Name | MITRE Tactic | Technique | Severity | Logic Summary |
| :--- | :--- | :--- | :--- | :--- |
| **[API Reconnaissance Spike](docs/rule_recon_spike.md)** | Discovery | T1595.002 | `MEDIUM` | Detects >10 unique API calls within 10m from a single identity. |
| **[SSM Parameter Enumeration](docs/rule_ssm_enum.md)** | Credential Access | T1555.006 | `HIGH` | Identifies bulk retrieval of secrets from AWS Systems Manager. |
| **[Failed Privilege Escalation](docs/rule_priv_esc.md)** | Initial Access | T1078 | `MED-CRIT` | Alerts on rapid succession (3+) of `AccessDenied` errors. |
| **[CloudTrail Tampering](docs/rule_cloudtrail_tamper.md)** | Defense Evasion | T1562.008 | `CRITICAL` | Immediate alert on `StopLogging` or `DeleteTrail` events. |
| **[Lateral Movement (AssumeRole)](docs/rule_lateral_movement.md)** | Lateral Movement | T1550.001 | `HIGH` | Detects role chaining and automated role assumption spikes. |
| **[Mass Deletion/Destruction](docs/rule_mass_delete.md)** | Impact | T1485 | `MED-CRIT` | Monitors for bulk deletion of S3 buckets, EC2 instances, or KMS keys. |

---

## Engineering Philosophy & Thresholding
Detection engineering is a balance between **Recall** (catching the bad guy) and **Precision** (avoiding burnout). My thresholds were tuned based on the statistical baselines observed in the dataset:

*   **Time-Binning:** Most rules utilize `bin _time span=5m` or `10m`. In the analyzed attack data, the threat actor's intensity tripled in the second hour (6.75 → 21.7 events/min). A 10-minute window captures this burst behavior while filtering out slow, legitimate administrative work.
*   **Cardinality Analysis:** Rather than just counting raw events, rules like *API Reconnaissance* use `dc(eventName)` (Distinct Count). This prevents false positives caused by a script retrying the *same* benign action 50 times.
*   **Severity Dynamism:** The *Failed Privilege Escalation* rule utilizes dynamic severity. 3 failures is a warning; 10 failures upgrades the alert to `CRITICAL` to prioritize brute-force attempts.

---

## Case Study: The "Invictus" Simulation
The logic in this repository was validated against the provided Red Team simulation log set.

**Scenario:**
An external attacker compromised the IAM User `bert-jan`. Over the course of **55 minutes**, the actor moved from discovery to data destruction.

**Attack Timeline Analysis:**
*   **11:50 AM (Reconnaissance):** Attacker triggers the *API Recon Spike* rule with 187 unique actions, mapping VPCs and IAM users.
*   **12:10 PM (Escalation):** Attacker attempts to brute-force permissions, triggering the *Failed PrivEsc* rule (15 failed `DescribeInstanceAttribute` calls).
*   **12:20 PM (Persistence):** Attacker pivots through roles, triggering the *Lateral Movement* rule (17 `AssumeRole` events).
*   **12:30 PM (Impact):** The attack concludes with `DeleteParameter` and `StopLogging` calls, triggering the *Mass Deletion* and *CloudTrail Tampering* rules.

---

## Repository Structure
*   `/detections` - Raw SPL (Search Processing Language) files for import into Splunk.
*   `/docs` - Detailed documentation for each rule, including "The Why," False Positive validation, and SOC Playbooks.
*   `/logs` - Sample JSON logs from the CloudTrail dataset for testing.

## 🚀 Getting Started

### 1. Download the Dataset
*   Navigate to the [Invictus IR AWS Dataset GitHub repository](https://github.com/invictus-ir/aws_dataset).
*   Download the entire repository as a ZIP file.
*   Extract the contents to a local directory on your machine. You will find a `logs` folder within the extracted files.

### 2. Ingest Logs into Splunk
*   **Login:** Access your Splunk Enterprise dashboard.
*   **Settings:** In the top-right corner, click on "Settings."
*   **Data Inputs:** From the dropdown menu, select "Data inputs."
*   **Files & Directories:** Under the "Sources" section, click on "Files & Directories."
*   **New:** In the top-right corner, click the "New file or Directory" button.
*   **Select Log Source:**
    *   Click "Choose File" (or "Browse") and navigate to the extracted dataset folder. Select the `logs` directory.
    *   Click "Next."
*   **Configure Input:**
    *   **Source Type:** Select `_json`. This tells Splunk to parse the data as JSON.
    *   **Index:** Create a new index by typing `invictus` into the index field. If the index already exists, you can select it.
    *   **Review:** Ensure your settings are correct.
    *   Click "Submit" (or "Done").
*   **Start Searching:** Splunk will begin ingesting the logs. It may take a few minutes depending on the dataset size. Once complete, you can start searching in the "Search & Reporting" app using `index=invictus`.

### 3. Deploy Detection Alerts
*   Once your data is indexed and searchable, navigate to the "Search & Reporting" app in Splunk.
*   Go to "Settings" > "Searches, Reports, and Alerts."
*   Click "New Alert."
*   Copy the SPL content from each file in the `/detections` directory (e.g., `1_api_recon_spike.spl`) into the search query field.
*   Configure the alert's schedule, trigger conditions, and actions as needed.

---
## Acknowledgements
Special thanks to **Invictus Incident Response** for making their attack dataset public.
*   Repository: [https://github.com/invictus-ir/aws_dataset](https://github.com/invictus-ir/aws_dataset)

*Created by Raghava Gatadi*