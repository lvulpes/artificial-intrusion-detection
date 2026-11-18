# artificial-intrusion-detection
Passive Identification of Autonomous LLM Agents via Network Fingerprinting and Machine Learning

## Exploit instructions

1. Spin up the containers
``` terminal
docker compose up -d
```

2. Start the traffic recording and install the flag and allow ports
``` terminal
./scripts/start-run.sh run-designation-1
# change ports depending on run
./scripts/allow-docker-ports.sh 21,6200
```

3. Drop into the attacker node and start autopentester, follow prompts
``` terminal
docker exec -it attacker bash
/opt/autopentester-venv/bin/autopentester
```

4. When the flag is found the framework should abort, otherwise CTRL+C and get the logs
``` terminal
exit
./scripts/get-attacker-logs.sh run-designation-1
```

5. If rebuilding use these commands for attacker or metasploitable
``` terminal
docker compose build attacker
docker compose up -d --force-recreate attacker
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
