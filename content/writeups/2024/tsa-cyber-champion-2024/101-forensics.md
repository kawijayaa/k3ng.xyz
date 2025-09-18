---
icon: fingerprint
---

# 101 - Forensics

### Challenge Description

Forensics 101

Author: Fedra

### Flag

`TSA{Forensic_101_0d1b25a70976d70f}`

***

### Analysis

We are given a packet capture file which contains many ICMP packets. From one of the ICMP packets, we can see that the data transmitted contains the first 16 bytes of a PNG header that is repeated.

<figure><img src="../../.gitbook/assets/Screenshot 2024-11-10 125011.png" alt=""><figcaption><p>Data of one of the ICMP packet</p></figcaption></figure>

### Solution

From the analysis, we need to create a script to get the first 16 bytes of the data from every ICMP packets and parse all the PNG files from that. The resulting PNG files will form a flag.

```python
from scapy.all import *

packets = rdpcap("./101.pcap")

out = b''

for packet in packets:
    if packet.haslayer(ICMP) and packet.haslayer(Raw) and packet.getlayer(IP).src == "192.168.56.1":
        out += packet.getlayer(Raw).load[16:32]

starts = [m.start() for m in re.finditer(b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a', out)]
ends = [m.end() for m in re.finditer(b'\x49\x45\x4e\x44\xae\x42\x60\x82', out)]

for i in range(len(starts)):
    file = out[starts[i]:ends[i]]
    with open(f"dumps/{i}.png", "wb") as f:
        f.write(file)
```

<figure><img src="../../.gitbook/assets/Screenshot 2024-11-10 125745.png" alt=""><figcaption><p>PNG files from the script</p></figcaption></figure>
