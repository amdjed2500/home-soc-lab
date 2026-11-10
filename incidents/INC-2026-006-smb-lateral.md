# Incident Report — INC-2026-006

> Scenario: SMB Lateral Movement — simulated lab exercise. Live SOC evidence collection pending lab deployment.

## Incident Summary
- **Incident ID:** INC-2026-006
- **Date Detected:** 2026-11-07 10:00:00
- **Date Resolved:** 2026-11-07 10:35:00
- **Severity:** Critical
- **Status:** Resolved
- **Scenario:** SMB Lateral Movement

## 1. Preparation
- Detection source: Suricata alert (rule 1000005 — SMB Lateral Movement Attempt) + Zeek smb.log
- Initial triage: Analyst reviewed alert in Kibana, confirmed SMB lateral movement from Kali (192.168.20.10) to Windows target (192.168.10.10) on port 445
- Pre-attack verification: Suricata and Zeek running; custom rules loaded; SPAN port capturing on Security Onion eth1

## 2. Identification
- **Affected systems:** Windows 10 target (192.168.10.10) — SMB service (port 445), Security Onion monitoring
- **Indicators of Compromise (IOCs):**
  - IPs: 192.168.20.10 (attacker/Kali), 192.168.10.10 (target/Windows)
  - Domains: N/A
  - Hashes: N/A
  - File paths: N/A
  - Tool: impacket psexec.py (admin:password@192.168.10.10)
  - SMB session: attacker established SMB session to target port 445 with file access
- **MITRE ATT&CK mapping:** T1021.002 (Remote Services: SMB/Windows Admin Shares), T1570 (Lateral Tool Transfer), T1005 (Data from Local System)

### Raw Alert (Suricata EVE JSON)
```json
{
  "timestamp": "2026-11-07T10:00:08.987654+0000",
  "event_type": "alert",
  "src_ip": "192.168.20.10",
  "src_port": 52341,
  "dest_ip": "192.168.10.10",
  "dest_port": 445,
  "proto": "TCP",
  "smb": {
    "command": "SMB2_CREATE",
    "filename": "PSEXESVC.exe"
  },
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000005,
    "rev": 1,
    "signature": "SMB Lateral Movement Attempt",
    "category": "Attempted Administrator Privilege Gain",
    "severity": 1
  }
}
```

### Zeek SMB Log
```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p command filename
1730973608.987654 CxSmb01 192.168.20.10 52341 192.168.10.10 445 SMB2_CREATE PSEXESVC.exe
1730973609.098765 CxSmb02 192.168.20.10 52342 192.168.10.10 445 SMB2_WRITE PSEXESVC.exe
1730973610.109876 CxSmb03 192.168.20.10 52343 192.168.10.10 445 SMB2_READ svcctl
```

### Kibana Query
```
dest_port: 445 AND src_ip: 192.168.20.10
```

## 3. Containment
- Short-term: Blocked attacker IP 192.168.20.10; isolated Windows target (192.168.10.10) from network
- Long-term: Disabled SMB on non-essential hosts; enabled SMB signing and encryption; restricted SMB to management VLAN

## 4. Eradication
- Terminated SMB session and removed PSEXESVC.exe
- Verified no files transferred or modified on target
- Checked for persistence mechanisms (services, scheduled tasks, registry) — none found
- Reset compromised "admin" credentials

## 5. Recovery
- Restored Windows target from clean snapshot
- Re-enabled SMB with signing and encryption required
- Monitored for follow-up lateral movement (none detected)

## 6. Lessons Learned
- **Root cause:** SMB (port 445) exposed across VLANs with weak admin credentials; impacket psexec allowed remote service creation
- **What went well:** Suricata SMB rule fired on first SMB2_CREATE; Zeek smb.log captured file access; Kibana showed SMB session from attacker
- **What to improve:** Disable SMBv1; enforce SMB signing; implement LAPS for local admin passwords; segment SMB traffic to management VLAN only
- **Action items:**
  1. Disable SMBv1 on all Windows hosts ✅
  2. Enable SMB signing and encryption ✅
  3. Implement LAPS for local administrator accounts ✅
  4. Add Kibana alert: SMB session from non-management VLAN ✅

## Timeline
| Time | Event |
|------|-------|
| 09:59:55 | SMB lateral movement initiated (psexec.py) from Kali |
| 10:00:08 | Suricata alert triggered (rule 1000005) |
| 10:00:10 | Zeek smb.log shows file access (PSEXESVC.exe) |
| 10:00:15 | Kibana alert fired to analyst |
| 10:03:00 | Analyst confirmed lateral movement in Kibana |
| 10:05:00 | Windows target isolated; attacker IP blocked |
| 10:10:00 | SMB session terminated; PSEXESVC.exe removed |
| 10:20:00 | Persistence check clean; credentials reset |
| 10:35:00 | Incident closed — target restored from snapshot |

## Evidence
- Screenshot: `evidence/screenshots/scenario-5-smb-lateral/suricata-alert.png`
- Screenshot: `evidence/screenshots/scenario-5-smb-lateral/zeek-smb-log.png`
- Screenshot: `evidence/screenshots/scenario-5-smb-lateral/kibana-smb-session.png`
- Suricata log: `evidence/logs/suricata-fast.log`
- Zeek log: `evidence/logs/zeek-smb.log`
- PCAP: `evidence/pcap/scenario-5-smb-lateral.pcap`
- Kibana dashboard: "SOC Overview" → SMB panel

## Live Detection Validation — 2026-11-10 (host-based harness)

> The timeline above is the **simulated** narrative. The artefacts below are **real** (see `evidence/host-validation/README.md`).

- Traffic: 3 established TCP sessions to `10.10.10.10:445` carrying a real SMB1 `\xffSMB` negotiate header.
- Real alerts: 3× `11/10/2026-21:17:46 [**] [1:1000005:1] SMB Lateral Movement Attempt [**] {TCP} 10.10.20.10:36810 -> 10.10.10.10:445`
- Artefacts: `evidence/host-validation/pcap/s5-smb-lateral.pcap`, `logs/s5-smb-lateral.fast.log`, `logs/s5-smb-lateral.eve.json`
- Limitation: the target is a stub listener on :445, not a Windows SMB service — no `psexec`/`PSEXESVC.exe` or Event ID 4688 evidence. The rule's SMB-header content match is confirmed.

---
*Report by: Amdjed Salhi*
*Date: 2026-11-07*
