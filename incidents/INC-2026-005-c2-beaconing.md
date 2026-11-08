# Incident Report — INC-2026-005

> Scenario: C2 Beaconing — simulated lab exercise. Live SOC evidence collection pending lab deployment.

## Incident Summary
- **Incident ID:** INC-2026-005
- **Date Detected:** 2026-11-06 11:10:00
- **Date Resolved:** 2026-11-06 11:45:00
- **Severity:** High
- **Status:** Resolved
- **Scenario:** C2 Beaconing

## 1. Preparation
- Detection source: Suricata alert (rule 1000004 — Possible C2 Beaconing (request threshold)) + Zeek notice (C2_Beacon_Detected via c2_beacon.zeek script)
- Initial triage: Analyst reviewed alert in Kibana, confirmed periodic HTTP beaconing from Windows target (192.168.10.10) to external C2 server (c2-server.com)
- Pre-attack verification: Suricata and Zeek running; custom rules and Zeek scripts loaded; SPAN port capturing on Security Onion eth1

## 2. Identification
- **Affected systems:** Windows 10 target (192.168.10.10), external C2 server (c2-server.com)
- **Indicators of Compromise (IOCs):**
  - IPs: 192.168.10.10 (victim), external C2 server IP
  - Domains: c2-server.com
  - Hashes: N/A
  - File paths: N/A
  - Tool: curl loop (GET /api/checkin?id=victim1 every 60s)
  - Pattern: Regular 60-second interval HTTP GET requests to /api/checkin
  - Zeek notice fired after 5 beacons
- **MITRE ATT&CK mapping:** T1071.001 (Application Layer Protocol: Web Protocols), T1105 (Ingress Tool Transfer), T1008 (Fallback Channels)

### Raw Alert (Suricata EVE JSON)
```json
{
  "timestamp": "2026-11-06T11:15:00.000000+0000",
  "event_type": "alert",
  "src_ip": "192.168.10.10",
  "src_port": 49876,
  "dest_ip": "203.0.113.99",
  "dest_port": 80,
  "proto": "TCP",
  "http": {
    "hostname": "c2-server.com",
    "url": "/api/checkin?id=victim1",
    "http_method": "GET"
  },
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000004,
    "rev": 3,
    "signature": "Possible C2 Beaconing (request threshold)",
    "category": "A Network Trojan was Detected",
    "severity": 1
  }
}
```

### Zeek Notice Log
```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto note msg
1730890500.000000 CxBcn01 192.168.10.10 49876 203.0.113.99 80 tcp C2_Beacon_Detected Possible C2 beaconing: 5 requests to c2-server.com/api/checkin at ~60s intervals from 192.168.10.10
```

### Kibana Query
```
http.uri: /api/* AND src_ip: 192.168.10.10
```

## 3. Containment
- Short-term: Blocked C2 domain c2-server.com on pfSense; isolated Windows target (192.168.10.10) from network
- Long-term: Added c2-server.com to threat intel blocklist; added HTTP beacon interval analysis rule

## 4. Eradication
- Terminated beaconing process (curl loop) on Windows target
- Verified no additional C2 channels or scheduled tasks
- Scanned Windows target for persistence mechanisms (none found)

## 5. Recovery
- Restored Windows target from clean snapshot
- Re-enabled network connectivity after verification
- Monitored for follow-up beaconing (none detected)

## 6. Lessons Learned
- **Root cause:** Windows target compromised (simulated) with periodic C2 check-in; no outbound HTTP inspection or beacon detection prior to rule deployment
- **What went well:** Zeek c2_beacon.zeek script detected periodicity after 5 beacons; Suricata request threshold fired; Kibana showed regular 60s interval pattern
- **What to improve:** Implement interval-based beacon detection (not just count); add SSL/TLS inspection for HTTPS C2; deploy EDR on endpoints
- **Action items:**
  1. Deploy Zeek c2_beacon.zeek script in production ✅
  2. Add Kibana visualization for HTTP request intervals ✅
  3. Enable outbound HTTP/HTTPS inspection ✅

## Timeline
| Time | Event |
|------|-------|
| 11:10:00 | Beaconing loop initiated (curl every 60s to c2-server.com/api/checkin) |
| 11:15:00 | Zeek notice triggered after 5 beacons (C2_Beacon_Detected) |
| 11:15:05 | Suricata alert triggered (rule 1000004) |
| 11:15:10 | Kibana alert fired to analyst |
| 11:18:00 | Analyst confirmed C2 beaconing pattern in Kibana |
| 11:22:00 | Windows target isolated; C2 domain blocked |
| 11:30:00 | Beaconing process terminated; persistence check clean |
| 11:45:00 | Incident closed — target restored from snapshot |

## Evidence
- Screenshot: `evidence/screenshots/scenario-4-c2-beaconing/suricata-alert.png`
- Screenshot: `evidence/screenshots/scenario-4-c2-beaconing/zeek-notice.png`
- Screenshot: `evidence/screenshots/scenario-4-c2-beaconing/kibana-beacon-pattern.png`
- Suricata log: `evidence/logs/suricata-fast.log`
- Zeek log: `evidence/logs/zeek-notice.log`
- PCAP: `evidence/pcap/scenario-4-c2-beaconing.pcap`
- Kibana dashboard: "SOC Overview" → HTTP/Beacon panel

---
*Report by: Amdjed Salhi*
*Date: 2026-11-06*
