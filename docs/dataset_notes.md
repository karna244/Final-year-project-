# Dataset Documentation & Data Dictionary
## AI-Based Cyber Incident Prioritization and Risk-Aware Alert Triage

### 1. Overview
The benchmark cybersecurity dataset is modeled after enterprise SOC alert streams and intrusion detection systems (IDS/SIEM). It contains **1,280 chronologically ordered security alerts** spanning both multi-stage attack campaigns and benign background operations.

### 2. Data Dictionary

| Column Name | Data Type | Nullable | Description | Example Values |
| :--- | :--- | :---: | :--- | :--- |
| `event_id` | String | No | Unique alert identifier | `ALT-10001`, `ALT-10450` |
| `timestamp` | Datetime | No | ISO-8601 event occurrence time | `2026-10-20 08:00:15` |
| `source_ip` | String | No | Originating IPv4 entity | `198.51.100.45`, `10.0.2.14` |
| `destination_ip` | String | No | Target host IPv4 entity | `10.0.1.20`, `185.220.101.5` |
| `source_port` | Integer | No | Ephemeral source port | `49215`, `54120` |
| `destination_port` | Integer | No | Targeted destination service port | `22`, `80`, `443`, `445` |
| `protocol` | String | No | Network transport layer protocol | `TCP`, `UDP`, `ICMP` |
| `event_type` | String | No | Classified security alert category | `SSH_Brute_Force`, `C2_Beacon` |
| `severity` | String | No | Upstream reported severity | `Low`, `Medium`, `High`, `Critical` |
| `asset_criticality` | String | No | Business value tier of destination asset | `Tier-1_Crown_Jewel`, `Tier-3_Workstation` |
| `process_name` | String | No | Operating system process associated | `sshd`, `nginx`, `powershell.exe` |
| `user` | String | No | Account context executing the event | `root`, `admin-temp`, `jsmith` |
| `label` | Integer | No | Ground-truth label (1 = Malicious, 0 = Benign) | `1`, `0` |

### 3. Attack Categories & Campaign Anatomy
1. **SSH Brute Force:** External threat actor brute-forcing SSH credentials against internal jump hosts. High-frequency bursts.
2. **SQL Injection:** Exploitation attempts against customer-facing web services (`nginx`) targeting backend databases.
3. **Port Scan / Reconnaissance:** Subnet scanning across multiple target servers over common enterprise ports.
4. **Command & Control (C2) Beaconing:** Internal compromised workstation communicating with external adversarial C2 IPs over encrypted channels.
5. **Privilege Escalation:** Execution of obfuscated PowerShell scripts by non-administrative accounts attempting `SYSTEM` escalation.
6. **Lateral Movement (SMB):** Compromised internal host attempting unauthorized access to Tier-1 file servers over Port 445.

### 4. Benign Background Telemetry & False Positives
* **Vulnerability Scanning (Nessus Agent):** Automated security vulnerability assessment tool producing repetitive benign alerts (key candidate for deduplication).
* **Routine Administration:** Scheduled backups (`rsync`), NTP time synchronizations, and authorized system administration.
* **Standard Web Traffic:** Internal employee outbound HTTPS browsing.
