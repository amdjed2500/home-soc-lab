# Inter-VLAN Firewall Policies

## Policy Matrix

| Source VLAN | Destination VLAN | Action | Ports | Log | Rationale |
|-------------|------------------|--------|-------|-----|-----------|
| VLAN10 (Targets) | VLAN20 (Attack) | Block | Any | Yes | Targets must not reach attacker network |
| VLAN10 (Targets) | VLAN30 (Monitoring) | Block | Any | Yes | Targets must not reach monitoring network |
| VLAN20 (Attack) | VLAN10 (Targets) | Allow | 22,80,443,445,3389 | Yes | Attack simulation to targets only |
| VLAN20 (Attack) | VLAN30 (Monitoring) | Block | Any | Yes | Attacker must not see monitoring |
| VLAN20 (Attack) | LAN (Management) | Block | Any | Yes | Attacker must not reach management |
| VLAN30 (Monitoring) | VLAN10 (Targets) | Block | Any | Yes | Monitoring is passive capture only — no initiated connections |
| VLAN30 (Monitoring) | VLAN20 (Attack) | Block | Any | Yes | Monitoring is passive capture only — no initiated connections |
| VLAN30 (Monitoring) | LAN (Management) | Block | Any | Yes | Monitoring is passive capture only — no initiated connections |
| LAN (Management) | Any | Allow | Any | Yes | Management full access (admin only) |
| Any | Any | Block | Any | Yes | Default deny |

## Monitoring Interface Design (eth1)
The Security Onion monitoring interface (eth1) is a **passive capture interface**:
- Receives mirrored traffic from the SPAN/mirror port
- Does NOT initiate any network connections
- Does NOT have an IP address (promiscuous mode only)
- Does NOT participate in any VLAN routing

This is a critical security design principle: a monitoring interface should never
be able to initiate connections to any network segment.

## pfSense Rule Implementation

### Interface: VLAN10 (Targets)
```
Action: Block
Source: VLAN10 net
Destination: VLAN20 net
Log: Yes
Description: Block targets from reaching attack network

Action: Block
Source: VLAN10 net
Destination: VLAN30 net
Log: Yes
Description: Block targets from reaching monitoring network

Action: Block
Source: VLAN10 net
Destination: LAN net
Log: Yes
Description: Block targets from reaching management

Action: Pass
Source: VLAN10 net
Destination: Any
Log: Yes
Description: Allow targets outbound (internet)
```

### Interface: VLAN20 (Attack)
```
Action: Pass
Source: VLAN20 net
Destination: VLAN10 net
Protocol: TCP
Destination Port: 22,80,443,445,3389
Log: Yes
Description: Allow attack simulation to target services only

Action: Block
Source: VLAN20 net
Destination: VLAN30 net
Log: Yes
Description: Block attacker from monitoring network

Action: Block
Source: VLAN20 net
Destination: LAN net
Log: Yes
Description: Block attacker from management network

Action: Block
Source: VLAN20 net
Destination: Any
Log: Yes
Description: Block attacker from internet (isolated)
```

### Interface: VLAN30 (Monitoring) — REMOVED
VLAN30 is no longer a routed pfSense interface. The monitoring interface (eth1) is
a passive capture interface with no IP address and no routing.

If you still want a management VLAN for Security Onion, use the LAN (192.168.1.0/24)
or create a dedicated management VLAN. The monitoring interface (eth1) should NOT
have a pfSense interface or firewall rules — it receives mirrored traffic passively.

## Verification
```bash
# From Kali (VLAN20) — should SUCCEED
nmap -sS -p 22 192.168.10.10

# From Kali (VLAN20) — should FAIL (blocked)
ping 192.168.30.1  # monitoring network
ping 192.168.1.1    # management network
curl http://example.com  # internet

# From Windows Target (VLAN10) — should FAIL (blocked)
ping 192.168.20.10  # attack network
ping 192.168.30.1   # monitoring network
```

---

*Built by Amdjed Salhi*