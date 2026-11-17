#!/bin/bash
CONTAINER="metasploitable"
PORTS=$1

if [ -z "$PORTS" ]; then
  echo "Usage: $0 <port1,port2|all>"
  exit 1
fi

# Safely grab the FIRST IPv4 address cleanly
TARGET_IP=10.10.10.10

if [ -z "$TARGET_IP" ]; then
  echo "[-] Could not find IP for '$CONTAINER'"
  exit 1
fi

sudo iptables -F DOCKER-USER

if [ "$PORTS" != "all" ]; then
  # Insert rules in strict top-to-bottom order
  sudo iptables -A DOCKER-USER -d "$TARGET_IP" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  sudo iptables -A DOCKER-USER -d "$TARGET_IP" -p tcp -m multiport --dports "$PORTS" -j ACCEPT
  sudo iptables -A DOCKER-USER -d "$TARGET_IP" -j DROP
  echo "[+] Isolated $CONTAINER ($TARGET_IP) to TCP port(s): $PORTS"
else
  echo "[+] Opened all ports on $CONTAINER ($TARGET_IP)"
fi

sudo iptables -A DOCKER-USER -j RETURN
