# Roten

Category: Forensics
Difficulty: very easy
Points: 375

************Category************: Forensics

****************Points:**************** 425

************************Difficulty:************************  easy

## Description

The iMoS is responsible for collecting and analyzing targeting data across various galaxies. The data is collected through their webserver, which is accessible to authorized personnel only. However, the iMoS suspects that their webserver has been compromised, and they are unable to locate the source of the breach. They suspect that some kind of shell has been uploaded, but they are unable to find it. The iMoS have provided you with some network data to analyse, its up to you to save us.

## Walkthrough

### File Analysis

This is a quite large PCAP with looooads of packets, specifically HTTP ones. Towards the end, we can see some privilege escalation, as there is evidence some sort of reverse shell was uploaded since the attacker was able to get results for commands such as '**ls**' and **whoami**. Our task, then, is to find, how and where this backdoor is.

This is a quite large PCAP with looooads of packets, specifically HTTP ones. Towards the end, we can see some privilege escalation, as there is evidence some sort of reverse shell was uploaded since the attacker was able to get results for commands such as '**ls**' and **whoami**. Our task, then, is to find, how and where this backdoor is.

The whoami packet, is in packet **18504.**  Logically, the shell would have been uploaded using a POST method, so we can filter for '**http.request.method == 'POST'**' in Wireshark. This gives us 9 packets. Two of them are PDFs, which I dissected and found nothing.  I as convinced this was a PDF javascript exploit :(. The other ones are very small, but there is one **x-php packet**, in frame 1929. It's an obfuscated PHP Script.

### Deobfuscation

I like to use a [sandbox](https://onlinephp.io/) to quickly deobfuscate codes. I replace the eval, with ‘echo’, and here’s the output:

And there’s the flag, in the comments!

**************Flag:************** HTB{W0w_ROt_A_DaY}