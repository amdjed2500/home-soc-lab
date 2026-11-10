# Incident Report — INC-2026-004

> Scenario: DNS Tunneling — simulated lab exercise. Live SOC evidence collection pending lab deployment.

## Incident Summary
- **Incident ID:** INC-2026-004
- **Date Detected:** 2026-11-06 10:05:00
- **Date Resolved:** 2026-11-06 10:40:00
- **Severity:** High
- **Status:** Resolved
- **Scenario:** DNS Tunneling

## 1. Preparation
- Detection source: Suricata alert (rule 1000003 — Possible DNS Tunneling (long label heuristic)) + Zeek dns.log + custom dns_tunneling.zeek script
- Initial triage: Analyst reviewed alert in Kibana, confirmed long DNS queries from Kali (192.168.20.10) to DNS server (192.168.1.1) for tunnel domain attacker.com
- Pre-attack verification: Suricata and Zeek running; custom rules loaded; SPAN port capturing on Security Onion eth1

## 2. Identification
- **Affected systems:** DNS server (192.168.1.1), Security Onion monitoring
- **Indicators of Compromise (IOCs):**
  - IPs: 192.168.20.10 (attacker/Kali)
  - Domains: attacker.com (tunnel domain), long subdomain labels (>20 chars)
  - Hashes: N/A
  - File paths: N/A
  - Tool: dnscat2 (DNS tunneling, domain=attacker.com)
  - Query detail: DNS queries with subdomain labels >50 chars, unusual query frequency
- **MITRE ATT&CK mapping:** T1071.004 (Application Layer Protocol: DNS), T1048 (Exfiltration Over Alternative Protocol), T1048.003 (Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol)

### Raw Alert (Suricata EVE JSON)
```json
{
  "timestamp": "2026-11-06T10:05:12.654321+0000",
  "event_type": "alert",
  "src_ip": "192.168.20.10",
  "src_port": 40123,
  "dest_ip": "192.168.1.1",
  "dest_port": 53,
  "proto": "UDP",
  "dns": {
    "query": "aGVsbG93b3JsZHRoaXNpc2xvbmdxdWVyeQ.attacker.com",
    "type": "TXT"
  },
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000003,
    "rev": 3,
    "signature": "Possible DNS Tunneling (long label heuristic)",
    "category": "Potential Corporate Privacy Violation",
    "severity": 2
  }
}
```

### Zeek DNS Log
```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto query qclass qtype rcode answers TTLs
1730887512.654321 CxDns01 192.168.20.10 40123 192.168.1.1 53 udp aGVsbG93b3JsZHRoaXNpc2xvbmdxdWVyeQ.attacker.com 1 16 0 - -
1730887513.765432 CxDns02 192.168.20.10 40124 192.168.1.1 53 udp bG9uZ3F1ZXJ5ZGF0YXR1bm5lbGluZw.attacker.com 1 16 0 - -
1730887514.876543 CxDns03 192.168.20.10 40125 192.168.1.1 53 udp dW51c3VhbHF1ZXJ5cGF0dGVybg.attacker.com 1 16 0 - -
```

### Kibana Query
```
dns.query: * AND dns.query_length > 50
```

## 3. Containment
- Short-term: Blocked attacker IP 192.168.20.10 on pfSense; blocked attacker.com on DNS resolver
- Long-term: Added DNS query length monitoring rule; enabled DNS entropy/length alerting

## 4. Eradication
- Terminated DNS tunnel session (dnscat2 process on Kali)
- Verified no data exfiltration completed (no TXT responses with payload)
- Reviewed DNS logs for other tunnel domains (none found)

## 5. Recovery
- Restored normal DNS resolution
- Monitored for follow-up tunneling attempts (none detected)
- Updated Suricata rule 1000003 with entropy-based refinement

## 6. Lessons Learned
- **Root cause:** DNS resolver allowed unrestricted outbound queries to arbitrary domains; no DNS query length/entropy monitoring in place
- **What went well:** Suricata long-label heuristic fired on first tunnel query; Zeek dns.log captured all queries; Kibana showed queries >50 chars
- **What to improve:** Implement DNS query length and entropy alerting; restrict outbound DNS to approved resolvers; add threat intel for tunnel domains
- **Action items:**
  1. Block outbound DNS to non-approved resolvers ✅
  2. Add Kibana alert: DNS query length >50 chars ✅
  3. Integrate DNS threat intel feed ✅

## Timeline
| Time | Event |
|------|-------|
| 10:05:00 | DNS tunneling initiated (dnscat2, domain=attacker.com) |
| 10:05:12 | Suricata alert triggered (rule 1000003) |
| 10:05:15 | Zeek dns.log shows long queries (>50 chars) |
| 10:05:20 | Kibana alert fired to analyst |
| 10:08:00 | Analyst confirmed DNS tunneling in Kibana |
| 10:12:00 | Attacker IP and attacker.com blocked |
| 10:40:00 | Incident closed — no further activity |

## Evidence
- Screenshot: `evidence/screenshots/scenario-3-dns-tunneling/suricata-alert.png`
- Screenshot: `evidence/screenshots/scenario-3-dns-tunneling/zeek-dns-log.png`
- Screenshot: `evidence/screenshots/scenario-3-dns-tunneling/kibana-dns-queries.png`
- Suricata log: `evidence/logs/suricata-fast.log`
- Zeek log: `evidence/logs/zeek-dns.log`
- PCAP: `evidence/pcap/scenario-3-dns-tunneling.pcap`
- Kibana dashboard: "SOC Overview" → DNS panel

## Live Detection Validation — 2026-11-10 (host-based harness)

> The timeline above is the **simulated** narrative. The artefacts below are **real** (see `evidence/host-validation/README.md`).

- Traffic: 14 DNS A-queries with random **32-hex-character** labels (`<32hex>.data.tunnel.attacker.com`) sent to 8.8.8.8 from the target host.
- Real alert: `11/10/2026-21:11:37.695489 [**] [1:1000003:3] Possible DNS Tunneling (long label heuristic) [**] {UDP} 10.10.10.10:55870 -> 8.8.8.8:53`
- Suricata parsed **14 DNS events** from the capture; the alert fired on the 10th matching query.
- Artefacts: `evidence/host-validation/pcap/s3-dns-tunneling.pcap`, `logs/s3-dns-tunneling.fast.log`, `logs/s3-dns-tunneling.eve.json`
- Not covered here: Zeek `dns.log` / `dns_tunneling.zeek` notice, Kibana >50-char query panel, threat-intel feed.

---
*Report by: Amdjed Salhi*
*Date: 2026-11-06*
