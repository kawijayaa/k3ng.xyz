---
icon: fingerprint
---

# eavesdropped

### Challenge Description

Recently, I discovered that a malicious actor has been using my proxy to obtain specific information from a particular server. Could you help me figure out what the attacker did?

Author: nagi

### Flag

`TSA{c0mmand_4nd_control_0ver_mitmprox1es_c1ee2e623a}`

***

### Analysis

We are given a file containing some sort of log of a network traffic. From the contents, we can see some sort of `git clone` operation happening and also some HTTP requests at the end of the log.

<figure><img src="../../.gitbook/assets/image (50).png" alt=""><figcaption><p>Git clone message</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (51).png" alt=""><figcaption><p>HTTP request on the file</p></figcaption></figure>

Since Git uses Zlib as their compression algorithm, we can use `binwalk` to extract all Git objects.

<figure><img src="../../.gitbook/assets/Screenshot 2024-11-10 131331.png" alt=""><figcaption><p>Binwalk output</p></figcaption></figure>

After decompressing the extracted Zlib files, there is one file that contains byte-compiled Python executable. After decompiling the file, we can see a client.py file from a tool called trevorc2.

<figure><img src="../../.gitbook/assets/Screenshot 2024-11-10 131828.png" alt=""><figcaption><p>Trevorc2 client.py</p></figcaption></figure>

The trevorc2 tool is used to mask command execution using a cloned website. From the decompiled code, the payload itself will be stored on the nonce with the format `nonce="(.+?)"` and will be decrypted using AES with the result of XORing the reversed `CIPHER` variable with the `__author__` variable as the key. The resulting payload will contain the hostname and the command itself with the format `hostname::::command`. After executing the command, the output will be encrypted again using the same algorithm and key and will be hidden on the query parameter.

<figure><img src="../../.gitbook/assets/Screenshot 2024-11-10 132420.png" alt=""><figcaption><p>AES cipher definition</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/Screenshot 2024-11-10 132047.png" alt=""><figcaption><p>Command execution code</p></figcaption></figure>

We parsed the nonces and decrypt using the previously analyzed decryption flow to get the commands used.

<figure><img src="../../.gitbook/assets/Screenshot 2024-11-10 132804.png" alt=""><figcaption><p>Output of the parsed nonces</p></figcaption></figure>

From the output, we can see a `flag.png` is being archived using a password with some kind of format. The first part of the password is the hostname, the second part is a random password from the first 64 passwords from the rockyou.txt wordlist. The last part is a number between 1 and 65537. Then, the Base64 representation of the `flag.zip` is outputted.

### Solution

Before getting the zip file, we need to create a custom wordlist from the analyzed format. The hostname is retrieved from the first part of the parsed nonces.

```python
from itertools import product

rockyou = open("/usr/share/wordlists/rockyou.txt", "rb").read().splitlines()[:64]
hostname = "phionify"
number = range(1, 65538)

a = [[hostname], [x.decode('utf-8') for x in rockyou], [str(x) for x in number]]

with open("wordlist.txt", "w") as f:
    for x in product(*a):
        f.write(x[0] + "_" + x[1] + "_" + x[2] + "\n")
```

After creating a new wordlist, we can get the `flag.zip` by parsing the last query parameter on the log file.

```python
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from collections import Counter
import pwn
import re

class AESCipher(object):
    """
    A classical AES Cipher. Can use any size of data and any size of password thanks to padding.
    Also ensure the coherence and the type of the data with a unicode to byte converter.
    """

    def __init__(self, key):
        self.bs = 16
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

ROOT_PATH_QUERY = '/'
SITE_PATH_QUERY = '/search'
QUERY_STRING = 'q='
CIPHER = 'zxtWV82qG1Zj0DhyjSCYsB7iSkJNvRf4zO9sxSAqL6'
__author__ = 'Dave Kennedy (@HackingDave)'
cipher = AESCipher(key=pwn.xor(CIPHER[::-1], __author__))

with open("flows", "rb") as f:
    flows = f.read()
    ctr = Counter(re.findall(rb'search\?q=(.+?)\,', flows)).most_common()[-1]
    data = base64.b64decode(ctr[0])
    data = cipher.decrypt(data)
    data = data.split('::::')[1]
    data = eval(data).decode('utf-8')
    data = data.replace('\n', '')
    with open("flag.zip", "wb") as f:
        f.write(base64.b64decode(data))
```

Then we can brute-force the zip file using `john`.

<figure><img src="../../.gitbook/assets/Screenshot 2024-11-10 133747.png" alt=""><figcaption><p>John to brute-force the zip password</p></figcaption></figure>

After opening the zip file, the flag will be stored as a QR code.

<figure><img src="../../.gitbook/assets/Screenshot 2024-11-10 133832.png" alt=""><figcaption><p>Scanning the QR code</p></figcaption></figure>
