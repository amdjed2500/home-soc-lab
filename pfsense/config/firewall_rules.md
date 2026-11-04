# pfSense Firewall Rules Template

## LAN → Any (Allow outbound)
Action: Pass
Interface: LAN
Protocol: Any
Source: LAN net
Destination: Any
Log: Yes

## WAN → LAN (Block all inbound by default)
Action: Block
Interface: WAN
Protocol: Any
Source: Any
Destination: WAN address
Log: Yes

## Allow SSH to pfSense (management)
Action: Pass
Interface: LAN
Protocol: TCP
Source: LAN net
Destination: This firewall (self)
Port: 22
Log: Yes

## Allow HTTPS to pfSense (web UI)
Action: Pass
Interface: LAN
Protocol: TCP
Source: LAN net
Destination: This firewall (self)
Port: 443
Log: Yes

## Block DNS to external (force local DNS)
Action: Block
Interface: LAN
Protocol: TCP/UDP
Source: LAN net
Destination: Any
Port: 53
Log: Yes

## NAT: Port forward SSH to internal host
Action: NAT
Interface: WAN
Protocol: TCP
Destination: WAN address
Port: 2222
Redirect: 192.168.1.10:22

## Aliases
- HOME_NET: 192.168.1.0/24
- ATTACKER_IPS: (add known bad IPs)
- MANAGEMENT: 192.168.1.1, 192.168.1.2