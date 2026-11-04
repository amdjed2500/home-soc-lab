# Shared Investigation Scenario: Network Detection → Memory Forensics

## Overview
This document demonstrates an **end-to-end investigation workflow** connecting two repositories:

- **Home SOC Lab** (https://github.com/amdjed2500/home-soc-lab) — network detection & monitoring
- **Memory Forensics Triage** (https://github.com/amdjed2500/memory-forensics-triage) — memory dump analysis

## Scenario: Suspicious Network Activity → Memory Investigation

### Phase 1: Attack Simulation (Home SOC Lab)

**Attacker:** Kali Linux (192.168.20.10)  
**Target:** Windows 10 VM (192.168.10.10)  
**Attack:** Nmap SYN scan + SSH brute force

```bash
# From Kali
nmap -sS -p 22,80,443,445,3389 192.168.10.10
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.10.10
```

### Phase 2: Detection (Suricata + Zeek)

**Suricata Alert (rule 1000008 — Port Scan):**
```json
{
  "timestamp": "2026-11-04T14:23:00.123456+0000",
  "event_type": "alert",
  "src_ip": "192.168.20.10",
  "src_port": 54321,
  "dest_ip": "192.168.10.10",
  "dest_port": 22,
  "proto": "TCP",
  "alert": {
    "signature_id": 1000008,
    "signature": "Port Scan Detected",
    "severity": 2
  }
}
```

**Suricata Alert (rule 1000002 — SSH Brute Force):**
```json
{
  "timestamp": "2026-11-04T14:24:15.789012+0000",
  "event_type": "alert",
  "src_ip": "192.168.20.10",
  "src_port": 54322,
  "dest_ip": "192.168.10.10",
  "dest_port": 22,
  "proto": "TCP",
  "alert": {
    "signature_id": 1000002,
    "signature": "SSH Brute Force Attempt",
    "severity": 1
  }
}
```

**Zeek Connection Log:**
```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state
1730730180.123456 CxYz123 192.168.20.10 54321 192.168.10.10 22 tcp ssh 0.001 0 0 S0
1730730180.124567 CxYz124 192.168.20.10 54322 192.168.10.10 80 tcp http 0.001 0 0 S0
1730730180.125678 CxYz125 192.168.20.10 54323 192.168.10.10 443 tcp ssl 0.001 0 0 S0
```

### Phase 3: Investigation (Security Onion Kibana)

**Query:** `src_ip: 192.168.20.10 AND dest_ip: 192.168.10.10`

**Findings:**
- Source IP: 192.168.20.10 (Kali)
- Destination IP: 192.168.10.10 (Windows target)
- Ports scanned: 22, 80, 443, 445, 3389
- SSH brute force: 47 failed login attempts in 60 seconds
- Time range: 14:23:00 — 14:25:30

**Affected service:** SSH (port 22) on Windows target

### Phase 4: Containment (pfSense)

```bash
# Block attacker IP on pfSense WAN
pfctl -t blocked_ips -T add 192.168.20.10
# Add to pfSense blocklist alias
```

### Phase 5: Memory Acquisition (Windows Target)

Since SSH brute force was detected, we acquire memory from the affected Windows machine for forensic analysis.

```bash
# On Windows target (192.168.10.10)
# Using WinPmem or FTK Imager
winpmem_mini_x64.exe memory_dump.raw
# Hash the dump
sha256sum memory_dump.raw > memory_dump.sha256
```

### Phase 6: Memory Forensics Analysis (Memory Forensics Triage)

**Run the triage tool:**
```bash
cd memory-forensics-triage
python -m src.cli.main analyze --dump memory_dump.raw --output report/
```

**Expected findings:**
- Process list: suspicious `ssh.exe` (PID 1234) spawned by `cmd.exe`
- Network connections: established SSH session from 192.168.20.10
- Hidden process: `svchost.exe` (PID 5678) with no parent (possible injection)
- IOC match: known malicious IP in network connections
- YARA rule: `hidden_process.yml` triggered on process hollowing

**Sample report output:**
```
Memory Forensics Triage Report
==============================
Dump: memory_dump.raw
Hash: sha256:abc123...
Profile: Win10x64

Processes (12 total):
  PID  1234  ssh.exe        parent: cmd.exe (PID 987)  [SUSPICIOUS]
  PID  5678  svchost.exe    parent: NONE              [HIDDEN/INJECTED]

Network Connections (3):
  192.168.10.10:22 ← 192.168.20.10:54321  [ESTABLISHED]  ← attacker
  192.168.10.10:445 ← 0.0.0.0:0             [LISTENING]

IOCs Found:
  - IP: 192.168.20.10 (known attacker from SOC alert)
  - Process: svchost.exe with no parent (process hollowing indicator)

YARA Matches:
  - hidden_process.yml: MATCH on PID 5678

Recommendation: Isolate host, reimage, reset credentials.
```

### Phase 7: Incident Report (Combined)

**Incident ID:** INC-2026-002  
**Severity:** High  
**Status:** Resolved

#### Timeline
| Time | Event | Source |
|------|-------|--------|
| 14:23:00 | Port scan detected | Suricata (rule 1000008) |
| 14:24:15 | SSH brute force detected | Suricata (rule 1000002) |
| 14:25:00 | Analyst investigates in Kibana | Security Onion |
| 14:30:00 | Attacker IP blocked on pfSense | pfSense |
| 14:35:00 | Memory acquired from Windows target | WinPmem |
| 14:40:00 | Memory triage completed | memory-forensics-triage |
| 14:45:00 | Hidden process identified | Forensic analysis |
| 15:00:00 | Host isolated, credentials reset | IR team |

#### Detection Logic
- **Network layer:** Suricata rules 1000008 (port scan) + 1000002 (SSH brute force)
- **Memory layer:** YARA rule `hidden_process.yml` + process tree anomaly (no parent)
- **Correlation:** Source IP 192.168.20.10 appears in both Suricata alerts and memory network connections

#### Remediation
1. ✅ Blocked attacker IP on pfSense
2. ✅ Isolated affected Windows host
3. ✅ Reset all credentials on affected host
4. ✅ Reimaged Windows target
5. ✅ Updated Suricata rule thresholds
6. ✅ Added memory forensics to IR playbook

#### Tools Used
- **Home SOC Lab:** Suricata, Zeek, pfSense, Security Onion, Kibana
- **Memory Forensics Triage:** Volatility, YARA, custom detection engine, IOC extractor

---

*This scenario demonstrates how network detection (Home SOC Lab) and memory forensics (Memory Forensics Triage) work together in an end-to-end investigation workflow.*

*Built by Amdjed Salhi*