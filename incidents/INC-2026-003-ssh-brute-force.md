# Incident Report — INC-2026-003

> Scenario: SSH Brute Force — simulated lab exercise. Live SOC evidence collection pending lab deployment.

## Incident Summary
- **Incident ID:** INC-2026-003
- **Date Detected:** 2026-11-05 14:20:00
- **Date Resolved:** 2026-11-05 14:55:00
- **Severity:** High
- **Status:** Resolved
- **Scenario:** SSH Brute Force

## 1. Preparation
- Detection source: Suricata alert (rule 1000002 — Suspicious SSH Connection Activity) + Zeek ssh.log
- Prerequisites: Windows target OpenSSH Server installed and running (port 22)
- Initial triage: Analyst reviewed alert in Kibana, confirmed rapid SSH connection attempts from Kali (192.168.20.10) against Windows target (192.168.10.10)
- Pre-attack verification: Suricata and Zeek running; custom rules loaded; SPAN port capturing on Security Onion eth1

## 2. Identification
- **Affected systems:** Windows 10 target (192.168.10.10) — SSH service (port 22), Security Onion monitoring
- **Indicators of Compromise (IOCs):**
  - IPs: 192.168.20.10 (attacker/Kali), 192.168.10.10 (target/Windows)
  - Domains: N/A
  - Hashes: N/A
  - File paths: N/A
  - Tool: hydra (SSH brute force, user "admin", rockyou.txt wordlist, 4 threads)
  - Auth: No successful authentication; >10 failed attempts in 60s window
- **MITRE ATT&CK mapping:** T1110 (Brute Force), T1110.001 (Password Guessing), T1021.004 (Remote Services: SSH)

### Raw Alert (Suricata EVE JSON)
```json
{
  "timestamp": "2026-11-05T14:20:45.123456+0000",
  "event_type": "alert",
  "src_ip": "192.168.20.10",
  "src_port": 51234,
  "dest_ip": "192.168.10.10",
  "dest_port": 22,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000002,
    "rev": 3,
    "signature": "Suspicious SSH Connection Activity",
    "category": "Attempted Administrator Privilege Gain",
    "severity": 1
  }
}
```

### Zeek SSH Log
```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p version auth_success auth_attempts
1730816445.123456 CxSsh01 192.168.20.10 51234 192.168.10.10 22 SSH-2.0-OpenSSH_8.9 F 1
1730816446.234567 CxSsh02 192.168.20.10 51235 192.168.10.10 22 SSH-2.0-OpenSSH_8.9 F 1
1730816447.345678 CxSsh03 192.168.20.10 51236 192.168.10.10 22 SSH-2.0-OpenSSH_8.9 F 1
1730816448.456789 CxSsh04 192.168.20.10 51237 192.168.10.10 22 SSH-2.0-OpenSSH_8.9 F 1
1730816449.567890 CxSsh05 192.168.20.10 51238 192.168.10.10 22 SSH-2.0-OpenSSH_8.9 F 1
```

### Kibana Query
```
src_ip: 192.168.20.10 AND dest_port: 22 AND event_type: alert
```

## 3. Containment
- Short-term: Blocked attacker IP 192.168.20.10 on pfSense inter-VLAN policy (VLAN20 -> VLAN10)
- Long-term: Disabled password authentication on Windows SSH; enforced key-based auth only; added connection-rate monitoring

## 4. Eradication
- No successful authentication from attacker
- Verified no backdoors, new accounts, or persistence mechanisms on Windows target
- Reviewed Windows Security event log (Event ID 4625) — all failures from 192.168.20.10

## 5. Recovery
- Restored SSH service with key-based authentication only
- Re-enabled SSH service after verification
- Monitored for follow-up brute-force activity (none detected)

## 6. Lessons Learned
- **Root cause:** Windows SSH service exposed to attack VLAN with password authentication enabled; weak "admin" account targeted
- **What went well:** Suricata connection-rate heuristic fired after 5 attempts; Kibana showed >10 events in 60s window; Zeek ssh.log recorded all failed auth
- **What to improve:** Disable password auth by default; implement account lockout; add GeoIP/allowlist for SSH management
- **Action items:**
  1. Disable SSH password authentication on all targets ✅
  2. Enforce key-based SSH auth for admin accounts ✅
  3. Add Kibana alert: >10 SSH failures/60s from single src ✅

## Timeline
| Time | Event |
|------|-------|
| 14:19:55 | Hydra brute force initiated from Kali (192.168.20.10) |
| 14:20:45 | Suricata alert triggered (rule 1000002, 5th attempt) |
| 14:20:50 | Kibana alert fired to analyst |
| 14:22:00 | Analyst confirmed brute force in Kibana (>10 events/60s) |
| 14:25:00 | Attacker IP blocked on pfSense inter-VLAN policy |
| 14:30:00 | Windows SSH password auth disabled; key-based enforced |
| 14:55:00 | Incident closed — no further activity |

## Evidence
- Screenshot: `evidence/screenshots/scenario-2-ssh-brute-force/suricata-alert.png`
- Screenshot: `evidence/screenshots/scenario-2-ssh-brute-force/zeek-ssh-log.png`
- Screenshot: `evidence/screenshots/scenario-2-ssh-brute-force/kibana-events.png`
- Suricata log: `evidence/logs/suricata-fast.log`
- Zeek log: `evidence/logs/zeek-ssh.log`
- Windows Security log: Event ID 4625 (failed logon)
- PCAP: `evidence/pcap/scenario-2-ssh-brute-force.pcap`
- Kibana dashboard: "SOC Overview" → SSH panel

---
*Report by: Amdjed Salhi*
*Date: 2026-11-05*
