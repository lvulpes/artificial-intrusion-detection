#!/bin/bash

# Exit immediately if any command fails
set -e

# Check if the directory name argument is provided
if [ -z "$1" ]; then
    echo "Error: No directory name provided."
    echo "Usage: $0 <directory_name>"
    exit 1
fi

DIR_NAME="$1"
TARGET_DIR="./logs/$DIR_NAME"
PCAP_DIR="./pcaps/$DIR_NAME"

echo "==> 0. Killing the traffic capture..."
docker exec metasploitable pkill tcpdump

echo "==> 1. Creating tar archive inside the 'attacker' container..."
docker compose exec attacker sh -c "tar -czvf /tmp/all-logs.tar.gz /logs/*"

echo "==> 2. Creating local directory: $TARGET_DIR..."
mkdir -p "$TARGET_DIR"
mkdir -p "$PCAP_DIR"

echo "==> 3. Copying archive from container to host..."
docker compose cp attacker:/tmp/all-logs.tar.gz "$TARGET_DIR/"

echo "==> 4. Extracting archive..."
tar -xzvf "$TARGET_DIR/all-logs.tar.gz" -C "$TARGET_DIR"

echo "==> 5. Deleting the archive files..."
rm "$TARGET_DIR/all-logs.tar.gz"
docker compose exec attacker rm /tmp/all-logs.tar.gz

echo "==> 6. Copying pcap file..."
docker compose cp metasploitable:"/tmp/$DIR_NAME".pcap "$PCAP_DIR/"

echo "==> Done! Logs successfully extracted to: $TARGET_DIR"
