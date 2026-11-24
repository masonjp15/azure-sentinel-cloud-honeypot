# 🛡️ Serverless Azure Cloud Honeypot & Microsoft Sentinel SIEM Detection Lab

![Azure](https://img.shields.io/badge/Microsoft%20Azure-Storage%20%26%20Sentinel-0078D4?logo=microsoftazure)
![SIEM](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel%20%2F%20Defender%20XDR-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1595%20Active%20Scanning-red)

## 📌 Project Overview
A zero-VM, serverless cloud security detection lab built in **Microsoft Azure** and **Microsoft Defender XDR / Microsoft Sentinel**. This project simulates an internet-facing corporate portal (`corpportalassets01`) hosted on an **Azure Storage Static Website**, ingests live HTTP telemetry (`StorageBlobLogs`) into a **Log Analytics Workspace**, detects automated directory enumeration using custom **Kusto Query Language (KQL)** analytics rules, and validates remediation via network firewall isolation.

---

## 🏗️ Architecture & Telemetry Pipeline
1. **Deception Surface (Honeypot):** Azure Storage Account (`corpportalassets01`) configured with Static Website hosting (`https://corpportalassets01.z28.web.core.windows.net/`) exposing realistic decoy portal paths.
2. **Telemetry Ingestion:** Azure Monitor Diagnostic Settings streaming `StorageRead` (`StorageBlobLogs`) events in near real time to Log Analytics (`law-sentinel-honeypot`).
3. **Detection Engineering:** Custom scheduled KQL analytics rule mapped to **MITRE ATT&CK Reconnaissance (T1595)** that aggregates `CallerIpAddress` activity and triggers Medium-severity incidents in Microsoft Defender XDR when distinct probed URIs exceed baseline thresholds.
4. **Remediation & Hardening:** Storage Account firewall restricted from public internet access to explicit client IPv4 allowlisting, verified via `HTTP 403 AuthorizationFailure` responses on external cellular traffic.

---

## 🔍 Detection Rule (`detections/cloud-storage-web-scan.kql`)
```kql
// Title: Cloud Storage Web Scan Detected
// MITRE ATT&CK: T1595 (Reconnaissance - Active Scanning)
// Severity: Medium
StorageBlobLogs
| where isnotempty(CallerIpAddress)
| summarize TotalRequests = count(), DistinctPaths = dcount(Uri), SamplePaths = make_set(Uri, 10) by CallerIpAddress, bin(TimeGenerated, 24h)
| where DistinctPaths >= 2
