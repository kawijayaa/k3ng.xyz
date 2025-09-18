---
icon: server
---

# Apolo

### Challenge Description

In the lawless expanse of the Frontier Cluster, Apolo serves as a beacon of security, working to safeguard the Frontier Cluster's assets from bounty hunters.

### Flags

User flag: `HTB{llm_ex9l01t_4_RC3}`

Root flag: `HTB{cl0n3_rc3_f1l3}`

***

### Enumeration

We are only given an IP address since this is a red-teaming type challenge. The first thing to do is enumeration using `nmap`.

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

After enumeration, we can see that port 22 and 80 is open. That means we have an SSH server and an HTTP server in this challenge. And we also found the hostname for the IP address (`apolo.htb`). We need configure our hosts file to redirect the hostname to our given IP.

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

When accessing the HTTP server, we are greeted with a static website. I got stuck here for a while until I saw a hyperlink to `ai.apolo.htb`.&#x20;

<figure><img src="../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

After setting the new hostname to the same IP and accessing it, we are redirected to a FlowiseAI website, but we are stuck on the login dialog.

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

### Initial Access

After searching for vulnerabilities, I found out about [this authentication bypass exploit](https://www.exploit-db.com/exploits/52001), where we can bypass the authentication by capitalizing the `api/v1` part of the URL. To redirect every request that uses the `api/v1`, I used Burp Suite to replace every `api/v1`to `API/V1`, therefore bypassing the authentication.

<figure><img src="../../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

After adding that rule, we can freely access the website. We can find a MongoDB credential on the credentials page.&#x20;

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

The username and password on the MongoDB URL can be used to login to SSH. Then we can get the user flag inside the `user.txt`file.

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

### Privilege Escalation

To find ways to escalate privileges, I tried to see what sudo access the current user has with `sudo -l`.&#x20;

<figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

And the results are this user can use sudo for the `rclone`command. This command is usually used to transfer data from cloud storage providers. I also got stuck in this for quite a while since I assumed that the data must come from a cloud storage.&#x20;

But after some research, there is a [vulnerability when moving symlinks](https://github.com/rclone/rclone/security/advisories/GHSA-hrxh-9w67-g4cv). The `rclone`command will change the permissions of the target of the link instead of the link itself, making it possible to change permissions of files owned by root. I basically just followed the PoC but instead of targeting the `/etc/shadow/`file, I targeted the entire `/root`directory.&#x20;

<figure><img src="../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

After doing the steps in the PoC, I can access the root flag in `/root/root.txt`and solve the challenge.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>
