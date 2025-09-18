---
icon: fingerprint
---

# doxxed

### Challenge Description

I recently forked a public repository on GitHub. After a few days I deleted my repo. However, my friend informed me that he are still able to access one of my commits from that fork which commit 4bxxxxx. Can you figure out how this happened? See the public repo below.

### Flag

`TCP1P{83fe034b2cfb09deafbb955b03392a083d8f83b2}`

***

### Analysis and Solution

We are given a `.zip` file containing a git repository. From the description, we are supposed to find a commit from a deleted fork. First, we need to find the GitHub URL for this repository. We could find that information from the `.git/config` file.

<figure><img src="../../.gitbook/assets/image (65).png" alt=""><figcaption><p>Contents of .git/config</p></figcaption></figure>

From this file, we can conclude that the `origin` is pointing to `git@github.com:notevilcorp/tools.git`. This is equivalent to the GitHub URL of `https://github.com/notevilcorp/tools`.

Based on this [blog](https://trufflesecurity.com/blog/anyone-can-access-deleted-and-private-repo-data-github), we can conclude that the commit from the deleted fork is still stored by GitHub. By supplying the commit hash, we could access said commit. But, we are only supplied with the first two characters of the commit hash.

Based on this Git documentation, Git could identify a commit with only the first four characters of the commit hash, given that there is only one commit hash that starts with that four characters. This means we could brute-force the hash to get the commit.

```python
# bruteforce.py

from itertools import permutations
import requests

for a in '0123456789abcdef':
    lastsha = permutations('0123456789abcdef', 1)
    for _ in lastsha:
        sha = '4b' + a + _[0]
        res = requests.get('https://github.com/notevilcorp/tools/commit/' + sha)
        if res.status_code != 404:
            print(sha)
            exit()
```

After we use this script, we got a commit hash of `4b15`. Therefore we need to go to `https://github.com/notevilcorp/tools/commit/4b15` to access the commit from the deleted fork.

<figure><img src="../../.gitbook/assets/image (66).png" alt=""><figcaption><p>Diff of the 4b15 commit</p></figcaption></figure>

Looking at the diff of this commit, this commit adds a file called `start.sh` containing a command to run a Docker container from the `53buahapel/sup3rsecretools:dev` image. Let's look at this docker image on the Docker Hub.

<figure><img src="../../.gitbook/assets/image (67).png" alt=""><figcaption><p>Layers of the Docker image</p></figcaption></figure>

Based on the layers in this image, we can see that there is an `exec` file that is replacing the default `exec` executable. Let's extract that file to look into it further. To do that, we could extract the image by using the `docker save` command and saving the result to a `.tar` file.

<figure><img src="../../.gitbook/assets/image (68).png" alt=""><figcaption><p>Running commands to extract the Docker image</p></figcaption></figure>

After looking around, the `exec` executable that we are looking for is on `3ef0ed19552377195b1dddad9b036de38fc2ff4a86ce921016edaae42e00a8d1/layer.tar`.&#x20;

<figure><img src="../../.gitbook/assets/image (69).png" alt=""><figcaption><p>Extracting the layer containing the exec executable</p></figcaption></figure>

Since this is an executable, let's reverse engineer it using Ghidra.

<figure><img src="../../.gitbook/assets/image (60).png" alt=""><figcaption><p>Decompilation result of the main() function of the exec executable</p></figcaption></figure>

From the decompilation, we could see that this executable will do a cURL request to `https://asciified.thelicato.io/api/v2/ascii?text=` and supplying a Base64 string as the `text` query parameter. Decoding the Base64 string will get us the flag.

<figure><img src="../../.gitbook/assets/image (61).png" alt=""><figcaption><p>Decoding result of the Base64 string</p></figcaption></figure>
