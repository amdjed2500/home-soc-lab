# Incident Report Template

## Incident Summary
- **Incident ID:** INC-YYYY-NNN
- **Date Detected:** YYYY-MM-DD HH:MM
- **Date Resolved:** YYYY-MM-DD HH:MM
- **Severity:** Critical / High / Medium / Low
- **Status:** Open / In Progress / Resolved / Closed

## 1. Preparation
- Detection source: SIEM alert / manual / user report
- Initial triage: [describe]

## 2. Identification
- **Affected systems:** [hostnames, IPs]
- **Indicators of Compromise (IOCs):**
  - IPs: 
  - Domains: 
  - Hashes: 
  - File paths: 
- **MITRE ATT&CK mapping:** TXXXX

## 3. Containment
- Short-term: [isolate host, block IP]
- Long-term: [patch, reimage]

## 4. Eradication
- [Remove malware, close backdoors, reset credentials]

## 5. Recovery
- [Restore from backup, verify integrity, monitor]

## 6. Lessons Learned
- **Root cause:** 
- **What went well:** 
- **What to improve:** 
- **Action items:** 

## Timeline
| Time | Event |
|------|-------|
| HH:MM | Initial alert triggered |
| HH:MM | Host isolated |
| HH:MM | Malware identified |
| HH:MM | Remediation complete |

## Evidence
- PCAP files: [path]
- Memory dumps: [path]
- Log exports: [path]

---
*Report by: Amdjed Salhi*