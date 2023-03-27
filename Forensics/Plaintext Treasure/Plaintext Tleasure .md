# Plaintext Tleasure

Category: Forensics
Difficulty: very easy
Points: 350

************Category************: Forensics

****************Points:**************** 350

************************Difficulty:************************ very easy

## Description

Threat intelligence has found that the aliens operate through a command and control server hosted on their infrastructure. Pandora managed to penetrate their defenses and have access to their internal network. Because their server uses HTTP, Pandora captured the network traffic to steal the server's administrator credentials. Open the provided file using Wireshark, and locate the username and password of the admin.

## Walkthrough

### File Analysis

The file is a pcap, and honestly, it was as simple as running strings on it… 

```python
strings files/capture.pcap | grep -i htb
#HTB{th3s3_4l13ns_st1ll_us3_HTTP}
```

**************Flag:************** HTB{th3s3_4l13ns_st1ll_us3_HTTP}