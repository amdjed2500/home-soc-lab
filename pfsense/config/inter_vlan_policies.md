# Inter-VLAN Firewall Policies

## Policy Matrix

| Source VLAN | Destination VLAN | Action | Ports | Log | Rationale |
|-------------|------------------|--------|-------|-----|-----------|
| VLAN10 (Targets) | VLAN20 (Attack) | Block | Any | Yes | Targets must not reach attacker network |
| VLAN10 (Targets) | VLAN30 (Monitoring) | Block | Any | Yes | Targets must not reach monitoring network |
| VLAN20 (Attack) | VLAN10 (Targets) | Allow | 22,80,443,445,3389 | Yes | Attack simulation to targets only |
| VLAN20 (Attack) | VLAN30 (Monitoring) | Block | Any | Yes | Attacker must not see monitoring |
| VLAN20 (Attack) | LAN (Management) | Block | Any | Yes | Attacker must not reach management |
| VLAN30 (Monitoring) | VLAN10 (Targets) | Allow | Any | No | Monitoring must see target traffic (SPAN) |
| VLAN30 (Monitoring) | VLAN20 (Attack) | Allow | Any | No | Monitoring must see attack traffic (SPAN) |
| VLAN30 (Monitoring) | LAN (Management) | Allow | 443,22 | Yes | Monitoring management access only |
| LAN (Management) | Any | Allow | Any | Yes | Management full access (admin only) |
| Any | Any | Block | Any | Yes | Default deny |

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

### Interface: VLAN30 (Monitoring)
```
Action: Pass
Source: VLAN30 net
Destination: VLAN10 net
Log: No
Description: Monitoring visibility to targets (SPAN)

Action: Pass
Source: VLAN30 net
Destination: VLAN20 net
Log: No
Description: Monitoring visibility to attackers (SPAN)

Action: Pass
Source: VLAN30 net
Destination: LAN net
Protocol: TCP
Destination Port: 443,22
Log: Yes
Description: Monitoring management access

Action: Block
Source: VLAN30 net
Destination: Any
Log: Yes
Description: Block monitoring from internet
```

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