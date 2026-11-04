# Validation Procedure — Proving the SOC Works

## Purpose
This document provides **repeatable tests** to verify that the SOC lab correctly captures, parses, and alerts on security events. Each test must pass before the lab is considered operational.

## Prerequisites
- All VMs running (pfSense, Security Onion, Kali, Windows Target)
- Suricata and Zeek running on Security Onion
- Kibana accessible at https://security-onion-ip:5601
- pfSense syslog forwarding enabled

## Test 1: Suricata Rule Validation

### Objective: Verify custom Suricata rules fire correctly.

### Steps
```bash
# On Security Onion
sudo suricata -T -c /etc/suricata/suricata.yaml
# Expected: "Configuration provided was successfully loaded"

# Check rules loaded
sudo grep -c "100000" /etc/suricata/rules/custom.rules
# Expected: 7 (rules 1000001-1000007)

# Trigger a port scan from Kali
nmap -sS -p 22,80,443 192.168.10.10

# Check alert
sudo tail -5 /var/log/suricata/fast.log
# Expected: "Port Scan Detected" alert
```

### Pass Criteria
- [ ] `suricata -T` returns success
- [ ] 8 custom rules loaded
- [ ] Alert appears in fast.log within 5 seconds
- [ ] Alert contains correct src_ip (192.168.20.10) and dest_ip (192.168.10.10)

---

## Test 2: Zeek Script Validation

### Objective: Verify custom Zeek script generates notices.

### Steps
```bash
# On Security Onion
sudo zeekctl status
# Expected: "running"

# Check script loaded
sudo grep "c2_beacon" /opt/zeek/share/zeek/site/local.zeek
# Expected: "@load ./c2_beacon"

# Simulate beaconing (15s intervals to match detection threshold)
for i in $(seq 1 6); do
  curl -s http://192.168.10.10/api/checkin
  sleep 15
done

# Check notice
sudo tail -5 /opt/zeek/logs/current/notice.log
# Expected: "C2_Beacon_Detected"
```

### Pass Criteria
- [ ] Zeek is running
- [ ] Custom script is loaded
- [ ] Notice appears in notice.log
- [ ] Notice contains correct src IP

---

## Test 3: pfSense Syslog Validation

### Objective: Verify pfSense logs arrive at Security Onion.

### Steps
```bash
# On Security Onion
# Generate test traffic through pfSense
curl -s http://example.com

# Check syslog
sudo tail -5 /var/log/pfsense.log
# Expected: pfSense firewall entries

# Verify in Kibana
# Open Kibana → Discover → Filter: source: pfsense*
# Expected: documents with src_ip, dst_ip, action fields
```

### Pass Criteria
- [ ] pfSense logs arrive at Security Onion
- [ ] Logs are parsed (fields extracted)
- [ ] Kibana shows pfSense documents
- [ ] src_ip and dst_ip fields populated

---

## Test 4: SPAN Port Validation

### Objective: Verify Security Onion sees all network traffic.

### Steps
```bash
# On Security Onion monitoring interface
sudo tcpdump -i eth1 -nn -c 20

# From Kali, generate traffic
ping 192.168.10.10

# Verify tcpdump shows the ping traffic
# Expected: ICMP packets between 192.168.20.10 and 192.168.10.10
```

### Pass Criteria
- [ ] tcpdump captures traffic on eth1
- [ ] ICMP packets visible
- [ ] Traffic from multiple VLANs visible

---

## Test 5: Kibana Dashboard Validation

### Objective: Verify dashboards display data.

### Steps
1. Open Kibana: https://security-onion-ip:5601
2. Navigate to Dashboard → "SOC Overview"
3. Verify panels:
   - Top 10 source IPs (bar chart) — should show 192.168.20.10
   - Alert severity over time (line chart) — should show recent alerts
   - Top Suricata signatures (pie chart) — should show custom rules
   - Recent alerts (data table) — should list alerts

### Pass Criteria
- [ ] Dashboard loads without errors
- [ ] All 4 panels display data
- [ ] Data matches expected attack traffic
- [ ] Time range filter works

---

## Test 6: End-to-End Alert Validation

### Objective: Verify full pipeline: attack → detection → alert → Kibana.

### Steps
```bash
# 1. Execute attack from Kali
nmap -sS -p 22,80,443 192.168.10.10

# 2. Wait 10 seconds

# 3. Check Suricata
sudo grep "Port Scan Detected" /var/log/suricata/fast.log

# 4. Check Kibana
# Open Kibana → Discover → Filter: alert.signature: "Port Scan Detected"
# Expected: document with src_ip=192.168.20.10, dest_ip=192.168.10.10

# 5. Check Zeek
sudo grep "192.168.20.10" /opt/zeek/logs/current/conn.log
```

### Pass Criteria
- [ ] Suricata alert fires
- [ ] Alert appears in Kibana within 30 seconds
- [ ] Alert has correct src_ip, dest_ip, signature
- [ ] Zeek conn.log shows connection attempts
- [ ] All three data sources correlate

---

## Test 7: Inter-VLAN Policy Validation

### Objective: Verify firewall rules enforce segmentation.

### Steps
```bash
# From Kali (VLAN20) — should SUCCEED (allowed)
nmap -sS -p 22 192.168.10.10

# From Kali (VLAN20) — should FAIL (blocked)
ping 192.168.30.1
ping 192.168.1.1
curl -s http://example.com --max-time 5

# From Windows Target (VLAN10) — should FAIL (blocked)
ping 192.168.20.10
ping 192.168.30.1
```

### Pass Criteria
- [ ] Attack to targets: ALLOWED
- [ ] Attack to monitoring: BLOCKED
- [ ] Attack to management: BLOCKED
- [ ] Attack to internet: BLOCKED
- [ ] Target to attack: BLOCKED
- [ ] Target to monitoring: BLOCKED

---

## Validation Summary

| Test | Description | Status |
|------|-------------|--------|
| 1 | Suricata rules fire | ☐ |
| 2 | Zeek scripts generate notices | ☐ |
| 3 | pfSense syslog arrives | ☐ |
| 4 | SPAN port captures traffic | ☐ |
| 5 | Kibana dashboards work | ☐ |
| 6 | End-to-end alert pipeline | ☐ |
| 7 | Inter-VLAN policies enforced | ☐ |

**All 7 tests must pass** before the SOC is considered operational.

---

*Built by Amdjed Salhi*