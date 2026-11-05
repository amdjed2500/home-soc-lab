# Incident Report — INC-2026-003

## Incident Summary
- **Incident ID:** INC-2026-003
- **Date Detected:** YYYY-MM-DD HH:MM
- **Date Resolved:** YYYY-MM-DD HH:MM
- **Severity:** High
- **Status:** Open
- **Scenario:** SSH Brute Force

## 1. Preparation
- Detection source: Suricata alert (rule 1000002 — SSH Brute Force Attempt)
- Initial triage: Analyst reviewed alert in Kibana, confirmed brute force from Kali

## 2. Identification
- **Affected systems:** Windows 10 (192.168.10.10) — SSH service
- **Indicators of Compromise (IOCs):**
  - IPs: 192.168.20.10 (attacker/Kali), 192.168.10.10 (target/Windows)
  - Domains: N/A
  - Hashes: N/A
  - File paths: N/A
- **MITRE ATT&CK mapping:** T1110 (Brute Force), T1021.004 (Remote Services: SSH)

## 3. Containment
- Short-term: Blocked attacker IP on pfSense
- Long-term: Disabled SSH on Windows, added fail2ban-equivalent

## 4. Eradication
- No successful authentication from attacker
- Verified no backdoors or persistence

## 5. Recovery
- Restored SSH service with key-based auth only
- Monitored for follow-up activity

## 6. Lessons Learned
- **Root cause:** 
- **What went well:** 
- **What to improve:** 
- **Action items:** 

## Timeline
| Time | Event |
|------|-------|
| HH:MM | Hydra brute force initiated |
| HH:MM | Suricata alert triggered (rule 1000002) |
| HH:MM | Kibana alert fired to analyst |
| HH:MM | Analyst confirmed brute force |
| HH:MM | Attacker IP blocked |
| HH:MM | Incident closed |

## Evidence
- Screenshot: `evidence/screenshots/scenario-2-ssh-brute-force/suricata-alert.png`
- Screenshot: `evidence/screenshots/scenario-2-ssh-brute-force/zeek-ssh-log.png`
- Screenshot: `evidence/screenshots/scenario-2-ssh-brute-force/kibana-events.png`
- Suricata log: `evidence/logs/suricata-fast.log`
- Zeek log: `evidence/logs/zeek-ssh.log`

---
*Report by: Amdjed Salhi*