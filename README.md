


# 💣 Incident Response Playbook: Ransomware Attack

## 📌 Overview

This playbook guides response to ransomware events involving file encryption, ransom notes, lateral spread, and potential data exfiltration. Detection should be fast and response decisive to reduce impact.

---

## 📁 Incident Type

- Ransomware Detected
- Mass File Encryption
- Lateral Movement via SMB/RDP
- Ransom Note Observed

---

## 🧠 MITRE ATT&CK Mapping

| Tactic            | Technique                                 |
|-------------------|--------------------------------------------|
| Initial Access    | T1133 - External Remote Services           |
| Execution         | T1059 - Command and Scripting Interpreter  |
| Impact            | T1486 - Data Encrypted for Impact          |
| Discovery         | T1083 - File and Directory Discovery       |
| Lateral Movement  | T1021.002 - SMB/Remote Desktop Protocol    |
| Defense Evasion   | T1562 - Impair Defenses                    |

---

## 🧰 Tools Used

- Sysmon + Olaf config
- Splunk or Wazuh
- VirusTotal
- TheHive + Shuffle
- Velociraptor / DFIR toolkits
- Endpoint Detection & Response (EDR)
- Windows Event Logs
- Backup monitoring tools (e.g., Veeam logs, PowerShell)

---

## 🔍 Detection

### 🔎 Indicators:
- Files renamed with extensions like `.locky`, `.deadbolt`, `.crypt`
- `vssadmin delete shadows` or `wbadmin delete catalog`
- Unexpected use of `C:\Users\Public\` for malware staging
- Scheduled tasks or encoded PowerShell

---

### 🧠 Splunk Detection Query

```spl
index=sysmon 
(
    CommandLine="*vssadmin delete shadows*" OR 
    CommandLine="*wbadmin delete catalog*"
) OR 
(
    FileName="*.locky" OR FileName="*.deadbolt"
) OR 
(
    Image="*\\powershell.exe" CommandLine="*Base64*"
)
````

---

## 🧪 Enrichment

### Python Script: Check Backup Logs + VT Hash Lookup

```python
import requests
from datetime import datetime

# Check hash on VirusTotal
def vt_lookup(file_hash):
    headers = {"x-apikey": "<VT_API_KEY>"}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url, headers=headers)
    data = response.json()
    return data["data"]["attributes"]["last_analysis_stats"]

# Simulate backup check (example logic)
def check_backups(logs):
    for entry in logs:
        if "backup successful" in entry.lower():
            print(f"✅ Backup Found: {entry}")
        elif "failure" in entry.lower():
            print(f"❌ Backup Failed: {entry}")

# Example call
sample_logs = [
    f"{datetime.now()}: Daily backup successful",
    f"{datetime.now()}: Monthly archive failed due to space"
]
check_backups(sample_logs)
```

---

## 🛡️ Containment

* Disconnect infected machines from network
* Disable SMB, shared folders, and RDP temporarily
* Block ransomware domain or C2 IPs on firewall
* Isolate infected VLANs
* Lock AD accounts showing lateral movement
* Notify legal & leadership if exfiltration suspected

---

## 🧼 Eradication

* Identify and wipe compromised endpoints
* Remove all persistence (Startup folders, Run keys, Task Scheduler)
* Clear ransom notes and encrypted files
* Re-image systems using golden image
* Change all affected passwords (admin, service, etc.)

---

## 🧯 Recovery

* Restore from verified offline backups
* Patch initial entry vector (VPN, RDP, email gateway, etc.)
* Re-enable affected services (SMB/RDP) **after** hardening
* Perform full AV/EDR scans before rejoining to domain
* Enable application whitelisting and controlled folder access

---

## 📊 Post-Incident Activities

* Full incident report in TheHive
* RCA (Root Cause Analysis) + MITRE mapping summary
* Threat Intel submission (YARA, IOCs)
* Internal debrief with SOC and IT
* Executive Summary for leadership
* Run tabletop simulation of scenario with lessons learned

---

## 🖼️ Screenshots To Include in Portfolio

* Sysmon logs showing encryption behavior
* Splunk dashboard with detection alert
* VirusTotal hash verdict
* TheHive case evidence timeline
* Screenshot of blocked IP on firewall or DNS sinkhole

---

## 🔗 External References

* [MITRE T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
* [VirusTotal Hash Scan](https://www.virustotal.com/)
* [Ransomware Response Checklist (CISA)](https://www.cisa.gov/sites/default/files/publications/cisa_ransomware-response-checklist.pdf)


