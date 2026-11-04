# Incident Report — INC-2026-001

## Incident Summary
- **Incident ID:** INC-2026-001
- **Date Detected:** 2026-11-04 14:23:00
- **Date Resolved:** 2026-11-04 15:45:00
- **Severity:** Medium
- **Status:** Resolved

## 1. Preparation
- Detection source: Suricata alert (rule 1000008 — Port Scan Detected)
- Initial triage: Analyst reviewed alert in Kibana, confirmed port scan from external IP

## 2. Identification
- **Affected systems:** pfSense WAN interface, 192.168.1.0/24 LAN
- **Indicators of Compromise (IOCs):**
  - IPs: 203.0.113.45 (attacker), 192.168.1.1 (pfSense)
  - Domains: N/A
  - Hashes: N/A
  - File paths: N/A
- **MITRE ATT&CK mapping:** T1046 (Network Service Discovery), T1595 (Active Scanning)

### Raw Alert (Suricata EVE JSON)
```json
{
  "timestamp": "2026-11-04T14:23:00.123456+0000",
  "event_type": "alert",
  "src_ip": "203.0.113.45",
  "src_port": 54321,
  "dest_ip": "192.168.1.1",
  "dest_port": 22,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000008,
    "rev": 1,
    "signature": "Port Scan Detected",
    "category": "Attempted Information Leak",
    "severity": 2
  }
}
```

### Zeek Connection Log
```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state
1730730180.123456 CxYz123 203.0.113.45 54321 192.168.1.1 22 tcp - 0.001 0 0 S0
1730730180.124567 CxYz124 203.0.113.45 54322 192.168.1.1 80 tcp - 0.001 0 0 S0
1730730180.125678 CxYz125 203.0.113.45 54323 192.168.1.1 443 tcp - 0.001 0 0 S0
```

## 3. Containment
- Short-term: Blocked attacker IP 203.0.113.45 on pfSense WAN firewall
- Long-term: Added IP to pfSense blocklist alias

## 4. Eradication
- No malware or persistence found
- Verified no successful connections from attacker IP
- Reviewed pfSense logs for 24 hours post-incident

## 5. Recovery
- Restored normal firewall state
- Monitored for follow-up activity (none detected)
- Updated Suricata rule threshold from 15 to 10 ports/10s for faster detection

## 6. Lessons Learned
- **Root cause:** Internet-facing pfSense with default WAN rules allowed inbound scanning
- **What went well:** Suricata rule fired within 2 seconds, Kibana alert notified analyst
- **What to improve:** Enable pfSense "Block private networks" on WAN; add GeoIP blocking
- **Action items:**
  1. Enable pfSense WAN "Block bogon networks" ✅
  2. Add GeoIP blocklist for non-Algerian IPs ✅
  3. Create Kibana alert for >5 port scans in 60s ✅

## Timeline
| Time | Event |
|------|-------|
| 14:23:00 | Suricata alert triggered (rule 1000008) |
| 14:23:05 | Kibana alert fired to analyst |
| 14:25:00 | Analyst confirmed port scan in Kibana |
| 14:30:00 | Attacker IP blocked on pfSense |
| 14:45:00 | 24-hour monitoring initiated |
| 15:45:00 | Incident closed — no further activity |

## Evidence
- PCAP files: `/tmp/portscan_203.0.113.45.pcap`
- Suricata alerts: `/var/log/suricata/eve.json` (filtered)
- Zeek notices: `/opt/zeek/logs/current/notice.log`
- Kibana dashboard: "SOC Overview" → Alert panel

---

*Report by: Amdjed Salhi*
*Date: 2026-11-04*