# Incident Report — INC-2026-002

## Incident Summary
- **Incident ID:** INC-2026-002
- **Date Detected:** YYYY-MM-DD HH:MM
- **Date Resolved:** YYYY-MM-DD HH:MM
- **Severity:** Medium
- **Status:** Open
- **Scenario:** Port Scan (Reconnaissance)

## 1. Preparation
- Detection source: Suricata alert (rule 1000001 — Port Scan Detected)
- Initial triage: Analyst reviewed alert in Kibana, confirmed port scan from Kali attacker

## 2. Identification
- **Affected systems:** Windows 10 (192.168.10.10), Security Onion monitoring
- **Indicators of Compromise (IOCs):**
  - IPs: 192.168.20.10 (attacker/Kali), 192.168.10.10 (target/Windows)
  - Domains: N/A
  - Hashes: N/A
  - File paths: N/A
- **MITRE ATT&CK mapping:** T1046 (Network Service Discovery), T1595 (Active Scanning)

## 3. Containment
- Short-term: Blocked attacker IP on pfSense
- Long-term: Added IP to blocklist alias

## 4. Eradication
- No malware or persistence (reconnaissance only)
- Verified no successful connections from attacker

## 5. Recovery
- Restored normal firewall state
- Monitored for follow-up activity

## 6. Lessons Learned
- **Root cause:** 
- **What went well:** 
- **What to improve:** 
- **Action items:** 

## Timeline
| Time | Event |
|------|-------|
| HH:MM | Initial nmap scan executed |
| HH:MM | Suricata alert triggered (rule 1000001) |
| HH:MM | Kibana alert fired to analyst |
| HH:MM | Analyst confirmed port scan |
| HH:MM | Incident closed |

## Evidence
- Screenshot: `evidence/screenshots/scenario-1-port-scan/suricata-alert.png`
- Screenshot: `evidence/screenshots/scenario-1-port-scan/zeek-conn-log.png`
- Screenshot: `evidence/screenshots/scenario-1-port-scan/kibana-alert.png`
- Suricata log: `evidence/logs/suricata-fast.log`
- PCAP: `evidence/pcap/scenario-1-port-scan.pcap`

---
*Report by: Amdjed Salhi*