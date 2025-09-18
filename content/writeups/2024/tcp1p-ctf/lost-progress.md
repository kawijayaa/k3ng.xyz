---
icon: fingerprint
---

# Lost Progress

### Challenge Description

My friend Andi just crashed his computer and all the progress he made are gone. It was 2 of his secret passwords with each of them being inside an image and a text file. Luckily he has an automatic RAM capture program incase something like this happen, but no idea on how to use it…

### Flag

`TCP1P{wIeRRRMQqykX6zs3O7KSQY6Xq6z4TKnr_ekxyAH2jIrh0Opyu432tk9y0KdiujkMu}`

***

### Analysis and Solution

We are given a memory dump from a Windows system. From the description, we are supposed to recover passwords from an image and a text file. Let's do some more reconnaissance first by see what processes are running.

```
❯ vol.py -f dumped windows.pslist
Volatility 3 Framework 2.11.0
Progress:  100.00               PDB scanning finished
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

(cut for brevity)
348     776     Code.exe        0xe38d0c591080  0       -       1       False   2024-10-03 10:12:24.000000 UTC  2024-10-03 13:42:14.000000 UTC  Disabled
1716    348     Code.exe        0xe38d0d60d080  0       -       1       False   2024-10-03 10:12:31.000000 UTC  2024-10-03 13:42:14.000000 UTC  Disabled
(cut for brevity)
5584    3556    notepad.exe     0xe38d10685240  4       -       1       False   2024-10-03 13:41:33.000000 UTC  N/A     Disabled
(cut for brevity)
5380    3556    gimp-2.10.exe   0xe38d0becf080  11      -       1       False   2024-10-03 15:34:51.000000 UTC  N/A     Disabled
(cut for brevity)
```

From the Volatility3 output, we could see some candidates of the processes that could store the passwords. Let's try to dump the GIMP process first to find the passwords.

`❯ vol.py -f dumped windows.memmap --dump --pid 5380`

After dumping the process and changing the extension to `.data`, we can open the file with GIMP to see the image that is opened on the dumped GIMP process.&#x20;

After tinkering with the offset, width and height, we find the password that is inside the image.

<figure><img src="../../.gitbook/assets/image (62).png" alt=""><figcaption><p>The password inside of the image</p></figcaption></figure>

By tinkering with the offset, width and height (again), we also find the password that is inside the text file.

<figure><img src="../../.gitbook/assets/image (63).png" alt=""><figcaption><p>The password inside the text file</p></figcaption></figure>
