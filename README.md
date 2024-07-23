# Detailed Report: Installation and Configuration of Suricata IDS/IPS on Ubuntu

## 1. Introduction

Suricata is an open-source network threat detection engine capable of functioning as an Intrusion Detection System (IDS), Intrusion Prevention System (IPS), and Network Security Monitoring (NSM). This report outlines the detailed steps for installing, configuring, and implementing Suricata on an Ubuntu system to operate in both IDS and IPS modes.

## 2. Installation Steps

### Step 1: Install Prerequisite Software

Ensure that the required software properties package is installed:

```bash
sudo apt-get install software-properties-common
```

### Step 2: Add Suricata PPA
Add the Suricata stable Personal Package Archive (PPA) to your system:

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
```
### Step 3: Update Package List
Update your package list to include the Suricata repository:

```bash
sudo apt-get update
```
### Step 4: Install Suricata
Install Suricata using the package manager:

```bash
sudo apt-get install suricata -y
```
## 3. Configuration Steps
### Step 5: Enable and Check Suricata Service
Enable Suricata to start on boot and check its status:

```bash
sudo systemctl enable suricata.service
sudo systemctl status suricata.service
```
### Step 6: Stop Suricata Service
Stop the Suricata service to make configuration changes:

```bash
sudo systemctl stop suricata.service
```
### Step 7: Verify Suricata Installation Directory
List the contents of the Suricata configuration directory to ensure everything is in place:

```bash
ls -al /etc/suricata
```
### Step 8: Edit Suricata Configuration File
Edit the Suricata configuration file to adjust settings as needed:

```bash
sudo nano /etc/suricata/suricata.yaml
```
### Step 9: Update Suricata Rules
Update the Suricata rules to the latest version and enable additional sources:

```bash
sudo suricata-update
sudo suricata-update enable-source malsilo/win-malware
sudo suricata-update
```
### Step 10: Create Custom IPS Rules
Stop the Suricata service and create custom rules:

```bash
sudo systemctl stop suricata.service
sudo nano /etc/suricata/rules/local.rules
```
Add example rules for the top ten ports:

```plaintext
drop tcp any any -> $HOME_NET 21 (msg:"Custom FTP rule"; sid:1000001; rev:1;)
drop tcp any any -> $HOME_NET 22 (msg:"Custom SSH rule"; sid:1000002; rev:1;)
drop tcp any any -> $HOME_NET 23 (msg:"Custom Telnet rule"; sid:1000003; rev:1;)
drop tcp any any -> $HOME_NET 25 (msg:"Custom SMTP rule"; sid:1000004; rev:1;)
drop tcp any any -> $HOME_NET 53 (msg:"Custom DNS rule"; sid:1000005; rev:1;)
drop tcp any any -> $HOME_NET 80 (msg:"Custom HTTP rule"; sid:1000006; rev:1;)
drop tcp any any -> $HOME_NET 110 (msg:"Custom POP3 rule"; sid:1000007; rev:1;)
drop tcp any any -> $HOME_NET 143 (msg:"Custom IMAP rule"; sid:1000008; rev:1;)
drop tcp any any -> $HOME_NET 443 (msg:"Custom HTTPS rule"; sid:1000009; rev:1;)
drop tcp any any -> $HOME_NET 3306 (msg:"Custom MySQL rule"; sid:1000010; rev:1;)
```
Save and exit the editor (Ctrl + O, Enter, Ctrl + X).
You can add rule according to your requirements.

### Step 11: Update Suricata Configuration to Include Local Rules
Edit the Suricata configuration file to include the path to the local rules:

```bash
sudo nano /etc/suricata/suricata.yaml
```
Add the following line under the rule-files section:

```yaml
- /etc/suricata/rules/local.rules
```
Save and exit the editor (Ctrl + O, Enter, Ctrl + X).

### Step 12: Test Suricata Configuration
Test if the configuration file is valid:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```
### Step 13: Start Suricata Service
If the configuration test is successful, start the Suricata service:

```bash
sudo systemctl start suricata.service
```
### Step 14: Check Suricata Logs
To verify that Suricata is running correctly, monitor the logs:

```bash
sudo tail -f /var/log/suricata/fast.log
```
### Step 15: Test Custom HTTP Rule
Use a second machine (VM2) to test the custom HTTP rule:

```bash
curl http://<Suricata_IP_Address>:80
```
## 4. Configuring Suricata as an IPS
### Step 16: Configure Suricata for IPS Mode
Stop the Suricata service and configure it for IPS mode:

```bash
sudo systemctl stop suricata.service
sudo nano /etc/default/suricata
```
Find and modify the following lines:

```plaintext
#LISTENMODE=af-packet
LISTENMODE=nfqueue
#IFACE
```
Save and exit the editor (Ctrl + O, Enter, Ctrl + X).

### Step 17: Start Suricata Service in IPS Mode
Start and restart the Suricata service to apply the changes:

```bash
sudo systemctl start suricata.service
sudo systemctl restart suricata.service
sudo service suricata restart
sudo systemctl status suricata.service
```
Check if the status indicates that Suricata is running in IPS mode.

### Step 18: Redirect Traffic to Suricata's NFQUEUE
Edit the UFW before.rules file to redirect traffic to Suricata’s NFQUEUE:

```bash
sudo nano /etc/ufw/before.rules
```
Add the following lines:

```plaintext
-I INPUT -j NFQUEUE
-I OUTPUT -j NFQUEUE
```
Save and exit the editor (Ctrl + O, Enter, Ctrl + X).

### Step 19: Enable UFW with the New Rules
Enable the UFW to load the new rules:

```bash
sudo ufw enable
```

### Step 20: Additional Custom IPS Rules
Add more IPS rules to block specific types of traffic:

```bash
sudo nano /etc/suricata/rules/local.rules
```
Example rules to block ICMP and other attacks:

```plaintext
drop ICMP any any -> $HOME_NET any (msg:"ICMP Request Blocked"; sid:2; rev:1;)
```
Save and exit the editor (Ctrl + O, Enter, Ctrl + X).

### Step 21: Start Suricata Service
Start the Suricata service to apply the new rules:

```bash
sudo systemctl start suricata.service
```
## 5. Conclusion
Following these steps ensures that Suricata is properly installed, configured, and running in both IDS and IPS modes. Custom rules can be added and modified to meet specific security needs, ensuring robust network monitoring and protection.

## 6. Appendix: Common Commands
-Enable Suricata on boot: sudo systemctl enable suricata.service
-Check Suricata status: sudo systemctl status suricata.service
-Stop Suricata: sudo systemctl stop suricata.service
-Start Suricata: sudo systemctl start suricata.service
-Restart Suricata: sudo systemctl restart suricata.service
-View Suricata logs: sudo tail -f /var/log/suricata/fast.log
-Test Suricata configuration: sudo suricata -T -c /etc/suricata/suricata.yaml -v
-Update Suricata rules: sudo suricata-update

## Contributions

Thank you for your interest in contributing to this project. However, we do not accept contributions at this time. 

## License
This project is licensed under the propetary License. See the [LICENSE](LICENSE) file for details.
