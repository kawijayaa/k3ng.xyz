---
icon: fingerprint
---

# Frontier Exposed

### Challenge Description

The chaos within the Frontier Cluster is relentless, with malicious actors exploiting vulnerabilities to establish footholds across the expanse. During routine surveillance, an open directory vulnerability was identified on a web server, suggesting suspicious activities tied to the Frontier Board. Your mission is to thoroughly investigate the server and determine a strategy to dismantle their infrastructure. Any credentials uncovered during the investigation would prove invaluable in achieving this objective. Spawn the docker and start the investigation!

### Flag

`HTB{C2_cr3d3nt14ls_3xp0s3d}`

***

### Analysis

We are given a website that contains a directory listing for presumably a home directory.

<figure><img src="../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

Let's see the `.bash_history`file to see what commands has been executed.

<figure><img src="../../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

### Solution

There is a suspicious Base64 string when running the C2 client. Let's try to decode that.

<figure><img src="../../.gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

And we got the flag!
