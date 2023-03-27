# Bashic Ransomware

Category: Forensics
Difficulty: hard
Points: 725

************Category************: Forensics

****************Points:**************** 725

************************Difficulty:************************ hard

## Description

The aliens are gathering their best malware developers to stop Pandora from using the relic to her advantage. They relieved their ancient ransomware techniques hidden for years in ancient tombs of their ancestors. The developed ransomware has now infected Linux servers known to be used by Pandora. The ransom is the relic. If Pandora returns the relic, then her files will be decrypted. Can you help Pandora decrypt her files and save the relic?

## Walkthrough

### File Analysis

There are four files that are provided:

- flag.txt.a59ap
- linux-image-5.10.0-21.zip
- forensics.mem
- traffic.pcap

linux-image-5.10.0-21.zip is the Volatility Profile, which is in Json, meaning, we need to use Volatility3. 

### 1. Traffic.pcap

Looking into it, it only contains 12 HTTP packets, with one file ‘Kxr43fMD9t.manifest’, that was downloaded. We can use the  Export Objects → HTTP option to save the file. This file is Base64 encoded. Its output is really long, so I will load it in python instead.

### 2. Ransomware Analysis

```python
cat Kxr43fMD9t.manifest | base64 -d | tr ';' '\n'

```

The last two lines are calls to eval:

```python
x=$(eval "$Hc2$w$c$rQW$d$s$w$b$Hc2$v$xZp$f$w$V9z$rQW$L$U$xZp")
eval "$N0q$x$Hc2$rQW"
```

So I’ll just leave them out of python to avoid issues. 

```python
cat Kxr43fMD9t.manifest | base64 -d | tr ';' '\n' | wc -l 
#get number of lines - 26
cat Kxr43fMD9t.manifest | base64 -d | tr ';' '\n' | head -n 24 | sed 's/"/"""/g' > vals.py
#format the quotation marks to avoid errors
```

Now, in python:

```python
from vals import *
x =  "Hc2$w$c$rQW$d$s$w$b$Hc2$v$xZp$f$w$V9z$rQW$L$U$xZp"
x = x.replace('$','+')
x = eval(x)
y = "N0q$x$Hc2$rQW".replace('$','+')
eval(y)

```

So this script echoes a base64 encoded text, reverses it, and then base64 decodes it. We can do that in python ourselves.

```python
import base64
to_dec =s[2:-6]
dec = base64.b64decode(to_dec[::-1])

```

This time, it’s a bash script, which I’m guessing is the ransomware in question. 

1. **uFMHx73AXNF6CTsbtzYM**

decodes a base64 encoded string and imports as a key in GPG, saves it as ‘RansomKey’. 

1. **MMYPE1MNIGuGPBmyCUo6**

Takes a random string of 16 bytes, and uses it as a private key, the posts the data to a reverse PHP shell. Then, for all files in the directory, it encrypts it with GPG using the random string. 

What we need to do, is recover this private key from the memory dump. And, guess what! There’s a specific plugin, for Linux memory dumps, that searches for GPG keys!

### 3. Memory Dump Analysis

This is the [plugin](https://github.com/kudelskisecurity/volatility-gpg) required. We need to copy both the plugin, and Json profile to Volatility3’s path: 

```python
7z x linux-image-5.10.0-21.zip
sudo cp linux-image-5.10.0-21.json /usr/local/lib/python3.8/dist-packages/volatility3/symbols/linux/

git clone https://github.com/kudelskisecurity/volatility-gpg
sudo cp volatility-gpg/linux/* /usr/local/lib/python3.8/dist-packages/volatility3/plugins/linux/

```

Now, we can use both plugins to see if something is recovered:

```python
vol3 -f forensics.mem linux.gpg_full.GPGItem
              
Offset	Private key	Secret size	Plaintext
Searching from 24 Mar 2023 04:47:17 UTC to 12 Sep 2023 06:06:55 UTC

0x7f96f0002038	86246ef7da91e80ac9f1587bf8d93e76	32	wJ5kENwyu8amx2RM
0x7f96f0002038	86246ef7da91e80ac9f1587bf8d93e76	32	wJ5kENwyu8amx2RM
```

```python
vol3 -f forensics.mem linux.gpg_partial.GPGPassphrase
#nothing
```

So we found our secret key! I’m super unfamiliar with GPG, so I’m going to try to do this whole thing without using the command line. 

```python
import gnupg
import base64 

key = '' #paste the key from the decrypted manifest file
key = base64.b64decode(key)
passphrase = 'wJ5kENwyu8amx2RM'
encfile = open('flag.txt.a59ap','rb').read()

gpg = gnupg.GPG()
import_result = gpg.import_keys(key)
decrypted_data = gpg.decrypt(encfile,passphrase=passphrase)
print(decrypted_data._as_text())
#HTB{n0_n33d_t0_r3turn_th3_r3l1c_1_gu3ss}
```

**************Flag:************** HTB{n0_n33d_t0_r3turn_th3_r3l1c_1_gu3ss}