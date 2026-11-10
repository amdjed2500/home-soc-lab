# 🏠 Home SOC Lab

A documented home security operations center (SOC) lab for portfolio showcase. Built with pfSense, Security Onion, and Suricata IDS — demonstrating network security, SIEM, and incident response skills.

![pfSense](https://img.shields.io/badge/pfSense-Firewall-blue)
![Security Onion](https://img.shields.io/badge/Security%20Onion-SIEM-orange)
![Suricata](https://img.shields.io/badge/Suricata-IDS-red)
![License](https://img.shields.io/badge/License-MIT-green)

## Architecture
```
[Internet] → [pfSense WAN (em0)]
              ├── [pfSense LAN (em1) → 192.168.1.0/24 (Management)]
              ├── [pfSense VLAN10 (em1.10) → 192.168.10.0/24 (Targets)]
              └── [pfSense VLAN20 (em1.20) → 192.168.20.0/24 (Attack)]
                      ↓ (SPAN/Mirror via managed switch or hypervisor)
              [Security Onion]
                ├── eth0 (Management) → 192.168.1.50 (routed, has IP)
                └── eth1 (Monitoring) → passive capture, NO IP, NO routing
```

## Components
- **pfSense** — firewall, NAT, VPN, traffic shaping, VLAN routing
- **Security Onion** — SIEM, log management, IDS/IPS (Suricata + Zeek)
  - **Management interface (eth0):** administration, Kibana, SSH
  - **Monitoring interface (eth1):** receives SPAN/mirrored traffic (required, not optional)
- **Kali Linux** — attack simulation (isolated on VLAN20)
- **Windows/Linux VMs** — targets for testing (isolated on VLAN10)

## Network Visibility Design
Security Onion has TWO interfaces:
1. **Management (eth0):** 192.168.1.50 — for administration, Kibana, SSH
2. **Monitoring (eth1):** receives mirrored traffic from pfSense SPAN port

A management interface alone does NOT provide traffic visibility. The monitoring interface is **required** to inspect all network traffic.

## Documentation
- [Setup Guide](docs/SETUP.md) — complete v2 setup with VLANs, SPAN, syslog
- [Architecture](docs/ARCHITECTURE.md) — Mermaid topology diagram
- [Inter-VLAN Policies](pfsense/config/inter_vlan_policies.md) — specific firewall rules per VLAN
- [Attack Scenarios](docs/attack_scenarios.md) — 5 repeatable scenarios with expected detections
- [Validation Procedure](docs/validation_procedure.md) — 7 tests proving the SOC works
- [Detection-Rule Validation Evidence](evidence/host-validation/README.md) — real pcaps + Suricata 8 replay proving **all 7 custom rules fire** (2026-11-10)
- [Shared Investigation](docs/SHARED_INVESTIGATION_SCENARIO.md) — network → memory forensics workflow

## Skills Demonstrated
- Network segmentation & VLAN design
- Traffic visibility via SPAN/mirror port
- SIEM deployment & log correlation
- IDS/IPS rule tuning (Suricata + Zeek)
- Inter-VLAN firewall policy enforcement
- Repeatable attack simulation
- Validation & testing procedures
- Incident response workflow
- Documentation & architecture design

## Author
Amdjed Salhi

## License
MIT
