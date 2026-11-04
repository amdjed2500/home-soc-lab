# Home SOC Lab — Setup Guide

## Prerequisites
- Host machine with 16GB+ RAM, 100GB+ disk
- VirtualBox or VMware Workstation
- pfSense ISO, Security Onion ISO, Kali ISO

## Step 1: Network Topology
1. Create a virtual switch (LAN) in your hypervisor.
2. pfSense: 2 NICs (WAN + LAN). WAN → NAT/bridged to internet. LAN → internal switch.
3. Security Onion: 1 NIC on LAN (monitoring port optional).
4. Kali + targets: on LAN.

## Step 2: pfSense
1. Install pfSense on VM.
2. Configure WAN (DHCP) and LAN (192.168.1.1/24).
3. Enable firewall rules: block WAN→LAN, allow LAN→any.
4. Enable logging.

## Step 3: Security Onion
1. Install Security Onion (standalone).
2. Configure management interface on LAN.
3. Enable Suricata IDS + Zeek.
4. Forward pfSense logs (syslog) to Security Onion.

## Step 4: Attack Simulation
1. From Kali, run nmap scans, Nikto, etc.
2. Observe alerts in Security Onion (Kibana/Squert).
3. Document findings.

## Step 5: Documentation
- Screenshot dashboards.
- Write incident reports for each detected attack.
- Export rules and configs.

## Deliverables for Portfolio
- Architecture diagram
- Setup screenshots
- Sample incident report
- Custom Suricata rule
- Blog post / writeup

---

*Built by Amdjed Salhi*