# Incident Report — INC-2026-004

## Incident Summary
- **Incident ID:** INC-2026-004
- **Date Detected:** YYYY-MM-DD HH:MM
- **Date Resolved:** YYYY-MM-DD HH:MM
- **Severity:** High
- **Status:** Open
- **Scenario:** DNS Tunneling

## 1. Preparation
- Detection source: Suricata alert (rule 1000003 — Possible DNS Tunneling)
- Initial triage: Analyst reviewed alert in Kibana, confirmed DNS tunneling from Kali

## 2. Identification
- **Affected systems:** DNS server (192.168.1.1), Security Onion monitoring
- **Indicators of Compromise (IOCs):**
  - IPs: 192.168.20.10 (attacker/Kali)
  - Domains: attacker.com (tunnel domain)
  - Hashes: N/A
  - File paths: N/A
- **MITRE ATT&CK mapping:** T1071.004 (Application Layer Protocol: DNS), T1048 (Exfiltration Over Alternative Protocol)

## 3. Containment
- Short-term: Blocked attacker IP, blocked attacker.com on DNS
- Long-term: Added DNS query length monitoring rule

## 4. Eradication
- Terminated DNS tunnel session
- Verified no data exfiltration completed

## 5. Recovery
- Restored normal DNS resolution
- Monitored for follow-up tunneling attempts

## 6. Lessons Learned
- **Root cause:** 
- **What went well:** 
- **What to improve:** 
- **Action items:** 

## Timeline
| Time | Event |
|------|-------|
| HH:MM | DNS tunneling initiated (dnscat2) |
| HH:MM | Suricata alert triggered (rule 1000003) |
| HH:MM | Zeek dns.log shows long queries |
| HH:MM | Kibana alert fired to analyst |
| HH:MM | Analyst confirmed tunneling |
| HH:MM | Attacker IP and domain blocked |
| HH:MM | Incident closed |

## Evidence
- Screenshot: `evidence/screenshots/scenario-3-dns-tunneling/suricata-alert.png`
- Screenshot: `evidence/screenshots/scenario-3-dns-tunneling/zeek-dns-log.png`
- Screenshot: `evidence/screenshots/scenario-3-dns-tunneling/kibana-dns-queries.png`
- Suricata log: `evidence/logs/suricata-fast.log`
- Zeek log: `evidence/logs/zeek-dns.log`

---
*Report by: Amdjed Salhi*