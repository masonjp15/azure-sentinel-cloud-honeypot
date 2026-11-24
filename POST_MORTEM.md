# Incident Post-Mortem: Cloud Storage Web Enumeration (`Incident #1`)

| Field | Details |
| :--- | :--- |
| **Incident Title** | Cloud Storage Web Scan Detected (`ID 1`) |
| **Severity** | Medium |
| **MITRE ATT&CK Mapping** | Reconnaissance — Active Scanning (`T1595`) |
| **Target Asset** | `corpportalassets01` (`https://corpportalassets01.z28.web.core.windows.net/`) |
| **SIEM / XDR Platform** | Microsoft Sentinel & Microsoft Defender XDR |
| **Status** | Remediated & Verified (`HTTP 404 WebContentNotFound`) |

---

## 1. Executive Summary
During active exposure of the decoy Azure Storage Static Website (`corpportalassets01`), automated HTTP directory enumeration attempts were detected probing multiple sensitive URI paths (`/.env`, `/admin`, and related configuration endpoints). The custom scheduled KQL detection rule (`Cloud Storage Web Scan Detected`) aggregated request telemetry from `StorageBlobLogs`, identified multi-path scanning behavior by source IP, and generated actionable Medium-severity incidents in Microsoft Defender XDR. Remediation was completed by restricting Storage Account network access from public internet exposure to explicit IPv4 allowlisting and verifying that unauthorized external requests return HTTP 404 (WebContentNotFound).

---

## 2. Detection & Telemetry Analysis
* **Telemetry Source:** Azure Storage Diagnostic Settings streaming `StorageRead` events into Log Analytics (`law-sentinel-honeypot`).
* **Behavioral Trigger:** Source IPs requesting **2 or more distinct URI paths** (`DistinctPaths >= 2`) within a 24-hour window triggered the scheduled analytics rule.
* **Observed Attacker Behavior:** Probing targeted common web application configuration and administrative paths rather than normal static landing page assets, confirming automated reconnaissance activity rather than accidental user navigation.
* **Entity Enrichment:** Mapping `CallerIpAddress` to Sentinel's IP entity surfaced source IP reputation and geographic distribution inside the Sentinel Attack Map Workbook.

---

## 3. Containment & Remediation Actions
1. **Network Access Restriction:** Updated `corpportalassets01` **Networking → Firewalls and virtual networks** from *Enabled from all networks* to *Enabled from selected virtual networks and IP addresses*.
2. **Client Allowlisting:** Added only the authorized administrative workstation IPv4 address to the Storage Account firewall allowlist.
3. **External Verification:** Tested endpoint reachability from an unauthenticated external cellular connection (Wi-Fi disabled), confirming all requests to `https://corpportalassets01.z28.web.core.windows.net/.env` returned HTTP 404 WebContentNotFound at the Azure Storage edge.

---

## 4. Lessons Learned & Engineering Recommendations
* **What Worked Well:**
  * Serverless architecture (`Azure Storage Static Website` + `Log Analytics` + `Sentinel`) captured full HTTP request paths without maintaining or patching virtual machines.
  * Aggregating `dcount(Uri)` per `CallerIpAddress` cleanly isolated multi-path enumeration from single-request background noise.
* **Production Hardening & Detection Tuning:**
  * **Exclude Static Web Sub-Resources:** Filter out legitimate `.css`, `.js`, and image extensions (`Uri !endswith ".css"`) so multi-asset browser page loads do not inflate `DistinctPaths`.
  * **Filter on HTTP Error Codes:** Restrict enumeration rules to `StatusCode in (403, 404)` to isolate failed brute-force probes from authorized `200 OK` traffic.
  * **Enforce Private Endpoints in Production:** For internal corporate portals, pair Storage Account firewall rules with **Azure Private Endpoints** and **Microsoft Entra ID** authorization rather than public anonymous blob/web endpoints.
