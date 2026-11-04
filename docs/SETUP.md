# Home SOC Lab — Setup Guide (v2 — Complete Implementation)

## Prerequisites
- Host machine with 16GB+ RAM, 100GB+ disk
- VirtualBox or VMware Workstation
- pfSense ISO, Security Onion ISO, Kali ISO

## 1. Network Segmentation & VLANs

### Topology
```
[Internet] → [pfSense WAN (em0)]
              ├── [pfSense LAN (em1) → 192.168.1.0/24 (Management)]
              ├── [pfSense VLAN10 (em1.10) → 192.168.10.0/24 (Targets)]
              ├── [pfSense VLAN20 (em1.20) → 192.168.20.0/24 (Attack)]
              └── [pfSense VLAN30 (em1.30) → 192.168.30.0/24 (Monitoring/SPAN)]
```

### pfSense VLAN Configuration
1. Interfaces → Assignments → VLANs → Add
   - Parent: em1 (LAN)
   - VLAN Tag: 10, 20, 30
2. Interfaces → Assignments → Add each VLAN as interface (OPT1, OPT2, OPT3)
3. Enable each interface, set static IP:
   - OPT1 (VLAN10): 192.168.10.1/24
   - OPT2 (VLAN20): 192.168.20.1/24
   - OPT3 (VLAN30): 192.168.30.1/24
4. Firewall rules per interface (see pfsense/config/firewall_rules.md)

### VirtualBox/VMware Setup
- Create virtual switches: WAN (NAT), LAN, VLAN10, VLAN20, VLAN30
- pfSense VM: 2 NICs (WAN + LAN trunk with VLANs)
- Security Onion VM: 1 NIC on LAN (management) + 1 NIC on VLAN30 (SPAN/monitoring)
- Kali VM: 1 NIC on VLAN20
- Target VMs: 1 NIC on VLAN10

## 2. SPAN/Mirror Port for Traffic Visibility

### Why: Security Onion must see ALL traffic, not just management traffic.

### Option A: Virtual Switch Port Mirroring (VMware/ESXi)
1. Create a dedicated port group "Monitoring" on the vSwitch
2. Enable promiscuous mode on the Monitoring port group
3. Configure a mirror session on the vSwitch:
   - Source: LAN port group (or specific VLAN)
   - Destination: Monitoring port group
4. Security Onion monitoring NIC (eth1) → connected to Monitoring port group
5. Verify: `tcpdump -i eth1 -c 10` on Security Onion should show LAN traffic

### Option B: Physical Managed Switch (SPAN/RSPAN)
1. On the managed switch, configure a mirror session:
   - Source ports: all ports carrying VLAN traffic
   - Destination port: port connected to Security Onion eth1
2. Security Onion monitoring NIC (eth1) → connected to mirror destination port
3. Verify: `tcpdump -i eth1 -c 10` on Security Onion should show traffic

### Option C: Hypervisor-Specific (VirtualBox)
1. VirtualBox does not support SPAN natively
2. Alternative: Use a Linux bridge with macvtap and tcpdump
3. Or: Use a dedicated monitoring VM that captures via promiscuous mode on the host interface
4. For portfolio purposes, document the design even if full SPAN isn't achievable in VirtualBox

### Important Distinction
- **Promiscuous mode alone** is NOT equivalent to a proper mirror session
- Promiscuous mode allows a NIC to see all traffic on its segment
- A mirror/SPAN session explicitly copies traffic from source ports to a destination port
- Without proper mirroring, Security Onion eth1 will only see broadcast/multicast traffic, not unicast flows between other hosts

### Verification
```bash
# On Security Onion — should see UNICAST traffic between other hosts
sudo tcpdump -i eth1 -nn -c 20
# Look for: IP 192.168.20.10 > 192.168.10.10 (unicast, not broadcast)
```

## 3. pfSense Syslog Integration

### pfSense Configuration
1. Status → System Logs → Settings
2. Enable "Send log messages to remote syslog server"
3. Remote syslog server: 192.168.1.50 (Security Onion IP)
4. Remote syslog port: 514 (UDP) or 6514 (TCP/TLS)
5. Select log categories: Firewall, DHCP, DNS, VPN, System

### Security Onion Configuration (syslog-ng)
1. SSH into Security Onion
2. Edit `/etc/syslog-ng/syslog-ng.conf`:
```
source s_pfSense { udp(ip(0.0.0.0) port(514)); };
destination d_pfSense { file("/var/log/pfsense.log"); };
log { source(s_pfSense); destination(d_pfSense); };
```
3. Restart syslog-ng: `sudo systemctl restart syslog-ng`

### Verification
```bash
# On Security Onion, generate test traffic
curl http://example.com
# Check logs
tail -f /var/log/pfsense.log
# Should see pfSense firewall entries
```

### Parsing Verification (Kibana)
1. Open Kibana → Discover
2. Filter: `source: pfsense*` or `tags: pfsense`
3. Verify fields: src_ip, dst_ip, action, interface, protocol
4. If not parsing, check Logstash pipeline: `/opt/logstash/pipeline/`

## 4. Suricata Configuration

### Install Suricata on Security Onion (already included)
```bash
# Verify Suricata is running
sudo systemctl status suricata
# Check rules
sudo suricata -T -c /etc/suricata/suricata.yaml
```

### Custom Rules Deployment
1. Copy custom rules to `/etc/suricata/rules/custom.rules`
2. Add to suricata.yaml:
```yaml
rule-files:
  - suricata.rules
  - custom.rules
```
3. Restart: `sudo systemctl restart suricata`
4. Verify: `sudo tail -f /var/log/suricata/fast.log`

### EVE JSON Output (for SIEM)
EVE JSON is enabled by default. Verify:
```bash
sudo tail -f /var/log/suricata/eve.json | jq .
```

## 5. Zeek Configuration

### Enable Zeek on Security Onion
```bash
sudo so-zeek
# Or manually:
sudo zeek -i eth1 /opt/zeek/share/zeek/site/local.zeek
```

### Custom Script Deployment
1. Copy `zeek/scripts/c2_beacon.zeek` to `/opt/zeek/share/zeek/site/`
2. Add to `local.zeek`: `@load ./c2_beacon`
3. Restart Zeek: `sudo zeekctl deploy`
4. Verify: `sudo tail -f /opt/zeek/logs/current/notice.log`

## 6. Attack Simulation & Evidence Collection

### Attack Scenarios
| # | Attack | Tool | Expected Detection |
|---|--------|------|-------------------|
| 1 | Port scan | nmap -sS | Suricata rule 1000008 |
| 2 | SSH brute force | hydra | Suricata rule 1000002 |
| 3 | DNS tunneling | dnscat2 | Suricata rule 1000003 |
| 4 | SMB lateral movement | impacket | Suricata rule 1000005 |
| 5 | C2 beaconing | custom script | Zeek notice |

### Evidence Collection
```bash
# Capture traffic during attack
sudo tcpdump -i eth1 -w /tmp/attack_scenario1.pcap
# Export Suricata alerts
sudo jq 'select(.event_type=="alert")' /var/log/suricata/eve.json > alerts.json
# Export Zeek notices
cat /opt/zeek/logs/current/notice.log
```

### Incident Report
Use `templates/incident_report.md` for each detected attack.

## 7. Dashboards & Alerting

### Kibana Dashboards (Security Onion)
1. Open Kibana: https://security-onion-ip:5601
2. Create dashboard: "SOC Overview"
   - Panel 1: Top 10 source IPs (bar chart)
   - Panel 2: Alert severity over time (line chart)
   - Panel 3: Top Suricata signatures (pie chart)
   - Panel 4: Recent alerts (data table)
3. Set up alerts: Kibana → Stack Management → Rules → Create rule

### Alert Configuration
- Alert on: Suricata alert count > 10 in 5 min
- Alert on: New SSH brute force detected
- Alert on: C2 beaconing notice from Zeek

## 8. Verification Checklist

- [ ] pfSense firewall rules active and logging
- [ ] VLANs configured and traffic flowing
- [ ] SPAN port mirroring traffic to Security Onion
- [ ] pfSense syslog arriving at Security Onion
- [ ] Syslog parsing correctly in Kibana
- [ ] Suricata running and detecting attacks
- [ ] Custom Suricata rules loaded and firing
- [ ] Zeek running and generating notices
- [ ] Kibana dashboards created
- [ ] Alerts configured and tested
- [ ] Attack simulation completed
- [ ] Incident reports written

## 9. Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| No traffic in Security Onion | SPAN port not configured | Check virtual switch promiscuous mode |
| Suricata not alerting | Rules not loaded | Check suricata.yaml rule-files |
| Zeek not generating notices | Script not loaded | Check local.zeek @load directive |
| Syslog not parsing | Logstash pipeline issue | Check /opt/logstash/pipeline/ |
| Kibana no data | Index pattern missing | Create index pattern: logstash-* |

---

*Built by Amdjed Salhi*