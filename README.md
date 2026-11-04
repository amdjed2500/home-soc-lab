# 🏠 Home SOC Lab

A documented home security operations center (SOC) lab for portfolio showcase. Built with pfSense, Security Onion, and Suricata IDS — demonstrating network security, SIEM, and incident response skills.

![pfSense](https://img.shields.io/badge/pfSense-Firewall-blue)
![Security Onion](https://img.shields.io/badge/Security%20Onion-SIEM-orange)
![Suricata](https://img.shields.io/badge/Suricata-IDS-red)
![License](https://img.shields.io/badge/License-MIT-green)

## Architecture
```
[Internet] → [pfSense Firewall] → [LAN Switch]
                                    ├── [Security Onion (SIEM/IDS)]
                                    ├── [Attack Box (Kali)]
                                    └── [Target VMs (Windows/Linux)]
```

## Components
- **pfSense** — firewall, NAT, VPN, traffic shaping
- **Security Onion** — SIEM, log management, IDS/IPS (Suricata + Zeek)
- **Kali Linux** — attack simulation
- **Windows/Linux VMs** — targets for testing

## Setup Guide
See [docs/SETUP.md](docs/SETUP.md).

## Skills Demonstrated
- Network segmentation & firewall rules
- SIEM deployment & log correlation
- IDS/IPS rule tuning (Suricata)
- Incident response workflow
- Documentation & architecture design

## Author
Amdjed Salhi

## License
MIT
