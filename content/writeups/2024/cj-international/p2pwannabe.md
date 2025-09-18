---
icon: fingerprint
---

# P2PWannabe

### Challenge Description

Author: Blacowhait

Uruzic is a protocol network maniac! he want make protocol byself by combine 2 protocol he loved! P2P and multiplex! in this time he just implement like transfer file as usual between server and client, but adapt behavior of 2 protocol he loved! can you get file inside this traffic with protocol he created?!

### Flag

`CJ{i_wanna_make_this_protocol_running_properly}`

***

### Analysis and Solution

We are given a network packet capture file, and this challenge doesn't really give us any hints on what to do. After searching for hours, we dumped the TCP stream and used good ol' `binwalk` on it and found that the data is sent using the zlib compression.

<figure><img src="../../.gitbook/assets/image (57).png" alt=""><figcaption><p>Binwalk output of TCP stream dump</p></figcaption></figure>

From the first packet sent, we can see we have 8 bytes of data (presumably a header of some sort) before the zlib header. After some trial-and-error, we found that the last two bytes of the header has a unique value for every chunk, therefore it could mean that this value is the sequence or index. Since the chunks are divided into multiple packets, we need a script to parse and assemble them.

After getting all the Zlib datas and decompressing them, we got around \~1900 PNG files containing what seems to be hexadecimal.

<figure><img src="../../.gitbook/assets/image (58).png" alt=""><figcaption><p>Extracted PNG images</p></figcaption></figure>

Since we have a f\*ck-ton of images and there is no way that we will do this manually, we need to create a script to extract the characters using OCR. After extracting the hexadecimals and converting them, we will get the flag somewhere inside the text.

### Solver Script

```python
import zlib
import re
import pytesseract
import os
from scapy.all import *
from PIL import Image

# Parse packets
packets = rdpcap("./uruzic.pcapng")
data = b""
for p in packets:
    if p.haslayer(TCP) and p.haslayer(Raw) and p.getlayer(TCP).dport == 8081 and p.getlayer(TCP).flags == 0x18:
        data += p.getlayer(Raw).load

offsets = [m.start()-8 for m in re.finditer(b"\x78\x9c", data)]
chunks = []
for i in range(len(offsets)-1):
    if offsets[i] == len(offsets)-1:
        break
    header = data[offsets[i]:offsets[i]+8]
    seq = struct.unpack(">H", header[6:8])[0]
    zlib_data = data[offsets[i]+8:offsets[i+1]]
    chunks.append((header, zlib_data, seq))

for c in chunks:
    z = c[1]
    try:
        decompressed = zlib.decompress(z)
        with open(f"./dumps/dump{c[2]}.png", "wb") as f:
            f.write(decompressed)
    except zlib.error:
        pass

# Get image text
def atoi(text):
    return int(text) if text.isdigit() else text

def natural_keys(text):
    return [ atoi(c) for c in re.split(r'(\d+)', text) ]

res = ""
for file in sorted(os.listdir("./dumps"), key=natural_keys):
    if file.endswith(".png"):
        seq = atoi(re.search(r"dump(\d+)\.png", file).group(1))
        print(seq)
        img = Image.open(f"./dumps/{file}")
        text = pytesseract.image_to_string(img, config='--psm 10').strip()
        if text == "i.)":
            text = "5"
        if text == "F;":
            text = "E"
        res += text

final = ''.join([chr(int(''.join(c), 16)) for c in zip(res[0::2],res[1::2])]) 

print(re.findall(r"CJ{.*}", final)[0])

```
