# Host-Based Detection-Rule Validation — 2026-11-10

**Status: REAL evidence captured** (not simulated). Every pcap, alert line and auth-log entry
below was produced by executing real attack tools against a real (isolated) network and
inspecting the resulting traffic with the repo's own `rules/suricata/custom.rules`.

**Harness:** WSL2 Ubuntu 26.04 — Suricata **8.0.3**, nmap **7.98**, tcpdump **4.99.6**, dig **9.20.24**
**Reproduce:** `wsl.exe -d Ubuntu -u root -- bash scripts/validate_rules_wsl.sh`

---

## Why this exists

The full lab (pfSense + Security Onion + VLANs + SPAN + Windows target) is not deployed, so
end-to-end lab evidence is still pending. This harness isolates the **detection layer** — the part
the portfolio actually claims: *do the custom Suricata rules really fire on real attack traffic?*
It builds a genuine 2-host network with Linux network namespaces and a veth link, runs the five
scenarios from `docs/attack_scenarios.md` from the attacker host, captures traffic with tcpdump,
then replays each capture offline through Suricata using the repo's rules.

| Role | Analogue | Address |
|------|----------|---------|
| Host namespace (attacker) | VLAN20 / Kali | `10.10.20.10` |
| `socv` netns (target) | VLAN10 / Windows | `10.10.10.10` |
| Capture point | SPAN / mirrored port | interface `vhost` |

---

## Result: 7 / 7 custom rules validated on real traffic

| SID | Signature | Scenario | Alerts | Real alert line (abridged) |
|-----|-----------|----------|--------|-----------------------------|
| 1000001 | NMAP SYN Scan Detected | S1 port scan | 1 | `{TCP} 10.10.20.10:42449 -> 10.10.10.10:80` |
| 1000002 | Suspicious SSH Connection Activity | S2 SSH brute force | 1 | `{TCP} 10.10.20.10:40068 -> 10.10.10.10:22` |
| 1000003 | Possible DNS Tunneling (long label heuristic) | S3 DNS tunneling | 1 | `{UDP} 10.10.10.10:55870 -> 8.8.8.8:53` |
| 1000004 | Possible C2 Beaconing (request threshold) | S4 C2 beaconing | 1 | `{TCP} 10.10.10.10:51742 -> <external>:8080` |
| 1000005 | SMB Lateral Movement Attempt | S5 SMB lateral | 3 | `{TCP} 10.10.20.10:36810 -> 10.10.10.10:445` |
| 1000006 | PowerShell Download Cradle (HTTP body heuristic) | S4 (cradle fetch) | 6 | `{TCP} <external>:8081 -> 10.10.10.10:36222` |
| 1000007 | Possible ICMP Tunneling | bonus ICMP test | 5 | `{ICMP} 10.10.10.10 -> 8.8.8.8` |

Rule-load result: `1 rule files processed. 7 rules successfully loaded, 0 rules failed, 0 rules skipped`
(the `threshold` keyword still parses on Suricata 8.0.3).

### Per-scenario detail

- **S1 — port scan.** `nmap -sS -Pn -p 1-1000 10.10.10.10` → **2,000 IPv4 packets** captured
  (1,000 SYN + 1,000 RST). Alert `1000001` fired on the 15th SYN (`threshold: type both, track by_src,
  count 15, seconds 10`). Pass criteria: ≥3 ports (1,000 seen) ✅, alert inside 5 s of scan start ✅.
- **S2 — SSH brute force.** Real `sshd` inside the target netns; 12 `ssh` attempts with a wrong
  password. **222 IPv4 packets** captured. Endpoint logs recorded 12 real failures:
  `Invalid user admin from 10.10.20.10` / `Failed password for invalid user admin from 10.10.20.10`
  (see `logs/s2-authlog-failures.txt`). Alert `1000002` fired after the 5th connection ✅.
- **S3 — DNS tunneling.** 14 queries with random **32-hex-character** labels
  (`<32hex>.data.tunnel.attacker.com`) to 8.8.8.8 — **14 DNS events** parsed by Suricata, alert
  `1000003` on the 10th matching query ✅.
- **S4 — C2 beaconing + PowerShell cradle.** 6× `GET /api/checkin?id=victim1` plus 6× a fetch of a
  PowerShell payload whose response body contains `Invoke-WebRequest` — **149 IPv4 packets**, both
  HTTP transactions fully parsed. Alerts `1000004` and `1000006` ✅.
- **S5 — SMB lateral movement.** 3 established TCP sessions to `10.10.10.10:445` carrying a real
  SMB1 `\xffSMB` negotiate header — 3× alert `1000005` ✅.
- **S6 — ICMP.** `ping -s 300` → 5× alert `1000007` (`dsize:>100`) ✅.

---

## What this proves / what it does NOT prove

**Proves**
- All 7 custom Suricata rules fire on real attack traffic, with correct src/dst and thresholds.
- Rule syntax is valid and loads cleanly on Suricata 8.0.3.
- The five scenarios in `docs/attack_scenarios.md` produce detections at layer 3/4/7.
- Detection is reproducible from a single script — a reviewer can rerun it.

**Does NOT prove** (still requires the deployed lab)
- pfSense VLAN segmentation, inter-VLAN policy enforcement, syslog forwarding.
- SPAN/mirror-port capture on Security Onion `eth1`.
- Zeek script notices (`c2_beacon.zeek`, `dns_tunneling.zeek`) — Zeek was not in the harness.
- Kibana dashboards/alerting and the Logstash→Elasticsearch pipeline.
- Windows-side artefacts (Event ID 4625/4688, `psexec` service creation) — the S5 target is a stub
  listener, not a Windows SMB service.

---

## Artefacts

```
evidence/host-validation/
├── README.md                     <- this file
├── config/
│   ├── custom.rules              <- copy of rules/suricata/custom.rules used in the replay
│   └── validation.yaml           <- offline replay config (HOME_NET=10.10.10.0/24, EXTERNAL_NET=!HOME_NET)
├── pcap/
│   ├── s1-port-scan.pcap         (145 KB, ~2,000 packets)
│   ├── s2-ssh-brute.pcap         ( 63 KB, 222 packets)
│   ├── s3-dns-tunneling.pcap     (2.3 KB, 14 DNS queries)
│   ├── s4-c2-beaconing.pcap      ( 19 KB, 149 packets, HTTP + PS body)
│   ├── s5-smb-lateral.pcap       (504 B, 3 SMB sessions)
│   └── s6-icmp-tunnel.pcap       (1.9 KB, 5 large ICMP echo requests)
└── logs/
    ├── suricata-validation.txt   <- full replay transcript (all 6 pcaps)
    ├── s1..s6.fast.log           <- per-scenario fast.log
    ├── s1..s6.eve.json           <- per-scenario EVE JSON (alert/flow/dns/http records)
    ├── s1-nmap-output.txt        <- nmap output
    ├── s2-ssh-attempts.txt       <- ssh client output
    ├── s2-authlog-failures.txt   <- real sshd failed-auth lines
    └── sshd-start.log
```

## Notes / gotchas discovered

- Captures taken on the veth have invalid L3 checksums (no NIC offload), so the replay must run with
  `-k none` (or `pcap-file: checksum-checks: no`). Without it Suricata silently parses **no** HTTP/DNS
  events and rules 1000003/1000004/1000006 never fire.
- `HTTP_PORTS`/`SSH_PORTS` belong under `port-groups`, not `address-groups` — putting them in
  `address-groups` aborts the run with `failed to parse address "80"`.
- An offline replay of a complete scenario capture is the cheapest way to re-validate a rule after
  tuning: no VMs required.

---
*Captured by Amdjed Salhi / Second Brain — 2026-11-10*
