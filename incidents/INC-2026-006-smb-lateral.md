# Incident Report — INC-2026-006

## Incident Summary
- **Incident ID:** INC-2026-006
- **Date Detected:** YYYY-MM-DD HH:MM
- **Date Resolved:** YYYY-MM-DD HH:MM
- **Severity:** Critical
- **Status:** Open
- **Scenario:** SMB Lateral Movement

## 1. Preparation
- Detection source: Suricata alert (rule 1000005 — SMB Lateral Movement Attempt)
- Initial triage: Analyst reviewed alert in Kibana, confirmed SMB lateral movement from Kali to Windows

## 2. Identification
- **Affected systems:** Windows 10 (192.168.10.10) — SMB service (port 445)
- **Indicators of Compromise (IOCs):**
  - IPs: 192.168.20.10 (attacker/Kali), 192.168.10.10 (target/Windows)
  - Domains: N/A
  - Hashes: N/A
  - File paths: N/A
- **MITRE ATT&CK mapping:** T1021.002 (Remote Services: SMB/Windows Admin Shares), T1570 (Lateral Tool Transfer)

## 3. Containment
- Short-term: Blocked attacker IP, isolated Windows target
- Long-term: Disabled SMB on non-essential hosts, enabled SMB signing

## 4. Eradication
- Terminated SMB session
- Verified no files transferred or modified
- Checked for persistence mechanisms

## 5. Recovery
- Restored Windows target from clean snapshot
- Re-enabled SMB with signing and encryption
- Monitored for follow-up lateral movement

## 6. Lessons Learned
- **Root cause:** 
- **What went well:** 
- **What to improve:** 
- **Action items:** 

## Timeline
| Time | Event |
|------|-------|
| HH:MM | SMB lateral movement initiated (psexec) |
| HH:MM | Suricata alert triggered (rule 1000005) |
| HH:MM | Zeek smb.log shows file access |
| HH:MM | Kibana alert fired to analyst |
| HH:MM | Analyst confirmed lateral movement |
| HH:MM | Windows target isolated |
| HH:MM | Attacker IP blocked |
| HH:MM | Incident closed |

## Evidence
- Screenshot: `evidence/screenshots/scenario-5-smb-lateral/suricata-alert.png`
- Screenshot: `evidence/screenshots/scenario-5-smb-lateral/zeek-smb-log.png`
- Screenshot: `evidence/screenshots/scenario-5-smb-lateral/kibana-smb-session.png`
- Suricata log: `evidence/logs/suricata-fast.log`
- Zeek log: `evidence/logs/zeek-smb.log`

---
*Report by: Amdjed Salhi*