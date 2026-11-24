# Serverless Azure Cloud Honeypot & Microsoft Sentinel Lab

[![Azure](https://img.shields.io/badge/Microsoft%20Azure-Storage%20%26%20Sentinel-0078D4?logo=microsoftazure)](https://azure.microsoft.com/)
[![SIEM](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel%20%2F%20Defender%20XDR-blue)](https://learn.microsoft.com/en-us/azure/sentinel/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1595%20Active%20Scanning-red)](https://attack.mitre.org/techniques/T1595/)

## Overview
I built this serverless cloud security lab in **Microsoft Azure** and **Microsoft Sentinel / Defender XDR** to capture and detect automated web reconnaissance without running or paying for virtual machines. It uses an **Azure Storage Static Website** (`corpportalassets01`) as a low-interaction web honeypot, streams `StorageBlobLogs` into a **Log Analytics Workspace**, alerts on multi-path directory scanning with a custom **KQL** rule, and locks down the endpoint using Storage firewall rules.

## Architecture
1. **Static Website Endpoint:** Azure Storage Account (`corpportalassets01`) hosting a static web endpoint (`https://corpportalassets01.z28.web.core.windows.net/`) with decoy corporate portal paths.
2. **Log Ingestion:** Azure Diagnostic Settings forwarding `StorageRead` events (`StorageBlobLogs`) to Log Analytics (`law-sentinel-honeypot`).
3. **Detection Rule:** Scheduled KQL analytics rule mapped to **MITRE ATT&CK T1595 (Active Scanning)** that groups requests by `CallerIpAddress` and triggers a Medium-severity incident in Microsoft Defender XDR when a single IP probes 2 or more distinct URIs.
4. **Network Containment:** Storage Account networking changed from public access to **Selected networks** with explicit IPv4 allowlisting.

## Detection Rule (`detections/cloud-storage-web-scan.kql`)
```kql
// Title: Cloud Storage Web Scan Detected
// MITRE ATT&CK: T1595 (Reconnaissance - Active Scanning)
// Severity: Medium
StorageBlobLogs
| where isnotempty(CallerIpAddress)
| summarize TotalRequests = count(), DistinctPaths = dcount(Uri), SamplePaths = make_set(Uri, 10) by CallerIpAddress, bin(TimeGenerated, 24h)
| where DistinctPaths >= 2
```
---

## Detection & Remediation Evidence

### 1. Defender XDR Incident Queue (Multi-IP Reconnaissance Log)
<img width="1512" height="982" alt="Screenshot 2026-11-23 at 7 02 44 PM" src="https://github.com/user-attachments/assets/4cd7db34-da14-41e1-b2de-41569e6744ce" />

### 2. Incident #1 Triage & Alert Details
<img width="1512" height="982" alt="Screenshot 2026-11-23 at 8 04 34 PM" src="https://github.com/user-attachments/assets/58d9da28-0b3b-43c7-b550-0a8cab2d9df2" />

### 3. Sentinel Telemetry & Attack Map Workbook
<img width="1512" height="982" alt="Screenshot 2026-11-23 at 5 29 43 PM" src="https://github.com/user-attachments/assets/8e921f5e-d086-4aa5-81fe-50abc5bb4e99" />

### 4. Firewall Hardening & `HTTP 404` Verification
<img width="603" height="1311" alt="IMG_2352" src="https://github.com/user-attachments/assets/9d5bdbe9-a127-4ed5-abab-77c3f950ab72" />

---

## Key Takeaways & Hardening Controls
* **Detecting Enumeration Early:** Aggregating `dcount(Uri)` per `CallerIpAddress` reliably separates single-page visitors from automated vulnerability scanners probing `.env`, `/admin`, and backup paths.
* **Defense-in-Depth for Cloud Storage:** Public blob/static endpoints should never rely on security through obscurity; enforcing **Selected Networks + IPv4 Allowlisting** or **Private Endpoints** eliminates unauthorized internet exposure at the network edge.
