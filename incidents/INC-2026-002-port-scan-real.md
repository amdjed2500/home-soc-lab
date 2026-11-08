# Incident Report — INC-2026-002

> Scenario: Port Scan (Reconnaissance) — simulated lab exercise. Live SOC evidence collection pending lab deployment.

## Incident Summary
- **Incident ID:** INC-2026-002
- **Date Detected:** 2026-11-05 09:15:00
- **Date Resolved:** 2026-11-05 09:40:00
- **Severity:** Medium
- **Status:** Resolved
- **Scenario:** Port Scan (Reconnaissance)

## 1. Preparation
- Detection source: Suricata alert (rule 1000001 — NMAP SYN Scan Detected)
- Initial triage: Analyst reviewed alert in Kibana, confirmed SYN scan from Kali attacker (192.168.20.10) against Windows target (192.168.10.10)
- Pre-attack verification: Suricata and Zeek running; custom rules loaded (7 rules: 1000001-1000007); SPAN port capturing on Security Onion eth1

## 2. Identification
- **Affected systems:** Windows 10 target (192.168.10.10), Security Onion monitoring interface (eth1)
- **Indicators of Compromise (IOCs):**
  - IPs: 192.168.20.10 (attacker/Kali), 192.168.10.10 (target/Windows)
  - Domains: N/A
  - Hashes: N/A
  - File paths: N/A
  - Scan detail: SYN scan of ports 1-1000, service version detection on 22/80/443, OS fingerprinting
- **MITRE ATT&CK mapping:** T1046 (Network Service Discovery), T1595.001 (Active Scanning: Scanning IP Blocks), T1595.002 (Active Scanning: Vulnerability Scanning)

### Raw Alert (Suricata EVE JSON)
```json
{
  "timestamp": "2026-11-05T09:15:03.456789+0000",
  "event_type": "alert",
  "src_ip": "192.168.20.10",
  "src_port": 49152,
  "dest_ip": "192.168.10.10",
  "dest_port": 22,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000001,
    "rev": 2,
    "signature": "NMAP SYN Scan Detected",
    "category": "Attempted Information Leak",
    "severity": 2
  }
}
```

### Zeek Connection Log
```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state
1730796903.456789 CxAb001 192.168.20.10 49152 192.168.10.10 22 tcp - 0.001 0 0 S0
1730796903.457890 CxAb002 192.168.20.10 49153 192.168.10.10 80 tcp - 0.001 0 0 S0
1730796903.458901 CxAb003 192.168.20.10 49154 192.168.10.10 443 tcp - 0.001 0 0 S0
1730796903.460123 CxAb004 192.168.20.10 49155 192.168.10.10 445 tcp - 0.001 0 0 S0
```

### Kibana Query
```
src_ip: 192.168.20.10 AND dest_ip: 192.168.10.10 AND event_type: alert
```

## 3. Containment
- Short-term: Blocked attacker IP 192.168.20.10 on pfSense inter-VLAN policy (VLAN20 -> VLAN10)
- Long-term: Added 192.168.20.10 to pfSense blocklist alias; verified default-deny between attack and target VLANs

## 4. Eradication
- No malware or persistence (reconnaissance only)
- Verified no successful connections established from attacker to target
- Reviewed pfSense and Zeek logs for follow-up activity (none detected)

## 5. Recovery
- Restored normal firewall state after 24-hour monitoring window
- Monitored for follow-up activity (none detected)
- Tuned Suricata rule 1000001 threshold from 15 to 10 ports/10s for faster detection

## 6. Lessons Learned
- **Root cause:** Inter-VLAN policy between attack (VLAN20) and target (VLAN10) allowed inbound scanning traffic
- **What went well:** Suricata rule fired within 3 seconds of scan start; Kibana alert notified analyst; Zeek conn.log captured S0 states for all attempted ports
- **What to improve:** Enforce default-deny inter-VLAN with explicit allow rules; add Kibana alert for >5 port scans in 60s window
- **Action items:**
  1. Set pfSense VLAN20->VLAN10 policy to default deny ✅
  2. Add Kibana alert: port scan >5 events/60s ✅
  3. Document scan baseline for future anomaly comparison ✅

## Timeline
| Time | Event |
|------|-------|
| 09:14:58 | nmap SYN scan executed from Kali (192.168.20.10) |
| 09:15:03 | Suricata alert triggered (rule 1000001) |
| 09:15:08 | Kibana alert fired to analyst |
| 09:17:00 | Analyst confirmed port scan in Kibana (≥3 ports detected) |
| 09:20:00 | Attacker IP blocked on pfSense inter-VLAN policy |
| 09:40:00 | Incident closed — no further activity |

## Evidence
- Screenshot: `evidence/screenshots/scenario-1-port-scan/suricata-alert.png`
- Screenshot: `evidence/screenshots/scenario-1-port-scan/zeek-conn-log.png`
- Screenshot: `evidence/screenshots/scenario-1-port-scan/kibana-alert.png`
- Suricata log: `evidence/logs/suricata-fast.log`
- Zeek log: `/opt/zeek/logs/current/conn.log`
- PCAP: `evidence/pcap/scenario-1-port-scan.pcap`
- Kibana dashboard: "SOC Overview" → Alert panel

---
*Report by: Amdjed Salhi*
*Date: 2026-11-05*
