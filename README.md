# 📊 Splunk SIEM Lab

A home SIEM lab using **Splunk Enterprise** to collect, parse, and alert on Windows security events, built to practice the log analysis and detection work of a SOC analyst.

---

## 🧰 Lab Environment

| Component | Details |
|---|---|
| SIEM | Splunk Enterprise on **Ubuntu Server 26.04** VM (headless) |
| Endpoint | **Windows 10** VM with Splunk Universal Forwarder |
| Telemetry | Windows Event Logs + **Sysmon** (SwiftOnSecurity config) |
| Parsing | Splunk Add-on for Windows |
| Host | Both VMs on the same host machine |

```
┌──────────────────────────────┐              ┌──────────────────────────────┐
│  Windows 10 VM               │              │  Ubuntu Server VM            │
│  • Windows Event Logs        │   forward    │  Splunk Enterprise           │
│  • Sysmon (SwiftOnSecurity)  │ ───────────► │  • index: windows            │
│  • Universal Forwarder       │              │  • Add-on for Windows        │
└──────────────────────────────┘              │  • Alerts                    │
                                              └──────────────────────────────┘
```

---

## ✅ What I Built

### 1. Log Forwarding
- Installed Splunk Enterprise on a headless Ubuntu Server VM.
- Configured the Universal Forwarder on Windows to send Event Logs into a dedicated **`windows`** index.

### 2. Field Parsing with the Splunk Add-on for Windows
- Installed the add-on (.spl) through Splunk Web.
- Events now have structured fields (e.g. `SourceName`, `LogName`) instead of raw text.

### 3. Sysmon Telemetry
- Installed Sysmon with the SwiftOnSecurity config and added a Sysmon input to the forwarder's `inputs.conf`.
- Fields like `Image` and `CommandLine` are parsed by the Windows add-on, so no separate Sysmon add-on was needed.

### 4. Boot-start
- Enabled Splunk boot-start (systemd), so Splunk comes up automatically whenever the VM starts.

### 5. First Detection: Multiple Failed Logons (Event ID 4625)
- Scheduled alert that fires on **5+ failed logons for the same account within 5 minutes** (MITRE ATT&CK T1110, Brute Force).
- The first version had a missing `EventCode` filter and only ran once a week; reviewed and fixed it, then tested it end to end. ✅

```spl
index=windows source="wineventlog:security" EventCode=4625
| eval target_user=mvindex(Account_Name, -1)
| bin _time span=5m
| stats count as failures values(Logon_Type) as logon_types values(Workstation_Name) as source_hosts by _time, target_user
| where failures >= 5
```

Full write-up (settings, iteration history, testing): [`detections/multiple-failed-logons-4625.md`](detections/multiple-failed-logons-4625.md)

---

## 🐛 Troubleshooting Log

| Problem | Cause | Fix |
|---|---|---|
| Sysmon events not reaching Splunk; forwarder reported **access denied (error code 5)** | The forwarder service account could not read the Sysmon event channel | Added `NT SERVICE\SplunkForwarder` to the **Event Log Readers** group |
| Alert fired, but on normal activity | Search had no `EventCode=4625` filter, so it counted every Security event | Added the filter and rewrote the detection ([details](detections/multiple-failed-logons-4625.md)) |
| Alert would miss attacks most of the week | `cron_schedule = 0 6 * * 1` (Mondays 06:00 only) with a 5-minute window | Schedule every 5 minutes |
| Failed logons visible on Windows but **not in Splunk**, no obvious error | Free space on `/` fell below Splunk's 5000 MB minimum, so the **indexer paused** data writes | Extended the root partition, restarted Splunk; the forwarder re-sent the queued events |

> **Lesson:** a SIEM can go blind quietly. Splunk only showed a warning in the bell menu; searches simply returned nothing new.

---

## 📁 Repository Contents

| Path | What it is |
|---|---|
| `forwarder/inputs.conf` | Event Log + Sysmon inputs on the Universal Forwarder |
| `forwarder/outputs.conf` | Forwarding to the Splunk server (IP replaced with a placeholder) |
| `detections/` | Detection write-ups: SPL, alert settings, testing |

---

## 📸 Screenshots

### Triggered alert (4625 brute-force detection)
![Triggered alert](screenshots/triggered-alert-4625.png)

### Windows events in the `windows` index
Events from the forwarder with fields extracted by the Splunk Add-on for Windows (left panel).

![index=windows search](screenshots/search-windows-index.png)

### Sysmon process creation (Event ID 1)
Sysmon adds process-level detail that the default Windows logs lack: the executable (`Image`), its full `CommandLine`, and the parent process.

| `Image` | `CommandLine` + parent process |
|---|---|
| ![Sysmon Image field](screenshots/sysmon-image.png) | ![Sysmon CommandLine field](screenshots/sysmon-commandline.png) |

---

## 🗺️ Roadmap

- [x] Brute-force detection on 4625
- [ ] Detection practice on 4624 and other key Event IDs (e.g. 4625 → 4624, password spraying)
- [ ] More Sysmon-based detections (process creation, network connections)
- [ ] Add **Elastic** to the lab
- [ ] Integrate with my [Wazuh Endpoint Security Lab](../wazuh-endpoint-security-lab)

---

*Part of my roadmap toward becoming a **SOC Analyst** (Phase 2: SIEM & Log Analysis).*
