#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Check if the run designation argument is provided
if [ -z "$1" ]; then
  echo "Error: No run designation provided."
  echo "Usage: $0 <RUN_DESIGNATION>"
  echo "Example: $0 run-name-1"
  exit 1
fi

RUN_DESIGNATION="$1"

echo "==> 1. Recreating 'metasploitable' container..."
docker compose up -d metasploitable --force-recreate

echo "==> 2. Recreating 'attacker' container..."
docker compose up -d attacker --force-recreate

echo "==> 3. Starting background tcpdump packet capture (Designation: $RUN_DESIGNATION)..."
docker exec -d metasploitable tcpdump -i eth0 -w /tmp/$RUN_DESIGNATION.pcap >/dev/null 2>&1 &

echo "==> 4. Creating flag in /etc directory..."
docker exec -d metasploitable sh -c "echo flag{that_was_easy} > /etc/flag.txt"

echo "==> Success! Containers are up and tcpdump is running in the background."
echo "    To stop the capture later, run: docker exec attacker pkill tcpdump"
