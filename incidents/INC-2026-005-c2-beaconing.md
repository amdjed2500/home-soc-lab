# Incident Report — INC-2026-005

## Incident Summary
- **Incident ID:** INC-2026-005
- **Date Detected:** YYYY-MM-DD HH:MM
- **Date Resolved:** YYYY-MM-DD HH:MM
- **Severity:** High
- **Status:** Open
- **Scenario:** C2 Beaconing

## 1. Preparation
- Detection source: Suricata alert (rule 1000004 — Possible C2 Beaconing) + Zeek notice (C2_Beacon_Detected)
- Initial triage: Analyst reviewed alert in Kibana, confirmed periodic beaconing from Windows target

## 2. Identification
- **Affected systems:** Windows 10 (192.168.10.10), C2 server (external)
- **Indicators of Compromise (IOCs):**
  - IPs: 192.168.10.10 (victim), c2-server.com (C2 server)
  - Domains: c2-server.com
  - Hashes: N/A
  - File paths: N/A
- **MITRE ATT&CK mapping:** T1071.001 (Application Layer Protocol: Web Protocols), T1008 (Fallback Channels)

## 3. Containment
- Short-term: Blocked C2 domain on pfSense, isolated Windows target
- Long-term: Added C2 domain to threat intel blocklist

## 4. Eradication
- Terminated beaconing process on Windows target
- Verified no additional C2 channels

## 5. Recovery
- Restored Windows target from clean snapshot
- Monitored for follow-up beaconing

## 6. Lessons Learned
- **Root cause:** 
- **What went well:** 
- **What to improve:** 
- **Action items:** 

## Timeline
| Time | Event |
|------|-------|
| HH:MM | Beaconing loop initiated |
| HH:MM | Zeek notice triggered after 5 beacons |
| HH:MM | Suricata alert triggered (rule 1000004) |
| HH:MM | Kibana alert fired to analyst |
| HH:MM | Analyst confirmed C2 beaconing |
| HH:MM | Windows target isolated |
| HH:MM | C2 domain blocked |
| HH:MM | Incident closed |

## Evidence
- Screenshot: `evidence/screenshots/scenario-4-c2-beaconing/suricata-alert.png`
- Screenshot: `evidence/screenshots/scenario-4-c2-beaconing/zeek-notice.png`
- Screenshot: `evidence/screenshots/scenario-4-c2-beaconing/kibana-beacon-pattern.png`
- Suricata log: `evidence/logs/suricata-fast.log`
- Zeek log: `evidence/logs/zeek-notice.log`

---
*Report by: Amdjed Salhi*