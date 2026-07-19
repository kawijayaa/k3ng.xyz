---
title: Project Victoria Incident Report
date: 2026-07-01
thumbnail: /images/project_victoria/project_victoria_2.png
description: An incident report based on the Project Victoria case from the SOCSIM course.
---

# 🕵️ BEC Investigation Report

> **Platform:** SOC Simulation Project — WDLabs  
> **Environment:** Microsoft 365 Unified Audit Logs / Microsoft Sentinel

---

## 📋 Case Details

| Field                   | Value                           |
| ----------------------- | ------------------------------- |
| **WDLabs Case Name**    | Project Victoria                |
| **Case Reference**      | Case 001                        |
| **Affected Account**    | `donald.anderson@wdlabs.com.au` |
| **Incident Date Range** | `2026-03-07` — `2026-03-10`     |
| **Investigation Date**  | 2026-06-10                      |
| **Analyst**             | k3ng                            |

---

## 1. Attack Narrative

Between 7 March 2026 and 10 March 2026, a threat actor compromised WDLabs' corporate Microsoft cloud environment, resulting in the unauthorised exfiltration of multiple internal documents and the launch of an internal phishing campaign. The initial breach occurred via an internal phishing email sent from `dalan.coburn@wdlabs.com.au` to `donald.anderson@wdlabs.com.au`, suggesting that the sender's account was compromised by the threat actor. This led to the unauthorised access of the `donald.anderson@wdlabs.com.au` account from an unusual external IP. The impact of this incident is account compromise and internal data theft. The threat actor managed to exfiltrate multiple internal PDF documents from the company's SharePoint site. They also leveraged the compromised account of Donald Anderson to gather information about the company to launch targeted phishing campaigns to other staff members of WDLabs.

---

## 2. Timeline of Events

| Time (UTC)                                | Activity                | Detail                                                                                                               | Technique                                             |
| ----------------------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| 07/03/2026 02:19:50                       | Suspicious Email        | A suspicious email was sent by `dalan.coburn@wdlabs.com.au` to `donald.anderson@wdlabs.com.au` regarding training.   | T1534 - Internal Spearphishing                        |
| 07/03/2026 02:27:32                       | Initial Access          | First malicious login by `15.135.61.79` to`donald.anderson@wdlabs.com.au`.                                           | T1078.004 - Valid Accounts: Cloud Accounts            |
| 07/03/2026 02:49:55 - 10/03/2026 10:15:51 | Email Access            | Multiple emails were read by the threat actor, likely to gather information about the victim.                        | T1114.002 - Email Collection: Remote Email Collection |
| 09/03/2026 07:10:45                       | Malicious Inbox Rule    | A new inbox rule named `.` was created to redirect incoming emails from `naomi.hunter@wdlabs.com.au` to `RSS Feeds`. | T1564.008 - Hide Artifacts: Email Hiding Rules        |
| 09/03/2026 07:21:05 - 10/03/2026 09:44:34 | SharePoint Exfiltration | Multiple PDF files was exfiltrated from the `WDLabsOperations` SharePoint site.                                      | T1530 - Data from Cloud Storage                       |
| 10/03/2026 09:51:40                       | Suspicious Email        | Email sent from `donald.anderson@wdlabs.com.au` to `naomi.hunter@wdlabs.com.au` with the subject `Report`.           | T1534 - Internal Spearphishing                        |

---

## 3. Findings

### 3.1 Initial Access

On 7 March 2026 02:19:50 UTC, the `dalan.coburn@wdlabs.com.au` account sent malicious emails to the target account `donald.anderson@wdlabs.com.au`. From our analysis, one email  was received by `donald.anderson@wdlabs.com.au`  and was titled `URGENT: Training` . The email contains a message requesting the victim to click on a link that supposedly contains a cyber training. The sender also requested the recipient to complete training by close of business (CoB). At the time of investigation, we could not verify the contents of the URL sent  by `dalan.coburn@wdlabs.com.au`. 

Around 8 minutes after `donald.anderson@wdlabs.com.au` received the suspicious email, we recognised a login with the `donald.anderson@wdlabs.com.au` account from `15.135.61.79`. The geo-location of the IP was identified to be in Sydney, Australia, which did not match the expected baseline of Donald Anderson's usual activities therefore marking it as a malicious activity. We suspect that the URL sent by `dalan.coburn@wdlabs.com.au` was a phishing link to harvest the victim's credentials, allowing the threat actor to log in.

---

### 3.2 Unauthorised Activity

On 9 March 2026 07:10:45 UTC, the threat actor created a new inbox rule on the `donald.anderson@wdlabs.com.au` account named `.` from the IP `91.217.249.193:17130`. The inbox rule was set up to redirect emails from `naomi.hunter@wdlabs.com.au` to the `RSS Feeds` folder.  The rule was also set up to always mark captured emails as read. This technique is commonly used to hide any possible security alerts or responses to phishing emails that may be sent to the `donald.anderson@wdlabs.com.au` account to a less visible folder.

On 10 March 2026 09:51:40 UTC, the threat actor sent an email from the `donald.anderson@wdlabs.com.au` account to `naomi.hunter@wdlabs.com.au` using the subject `Report`. The email contains a URL of a file hosted inside the `WDLabsOperation` SharePoint site. We could not verify the contents of the URL but based on the URL format, it is likely that the URL would return a list of files and folders inside the `Shared Documents` folder. Due to the privilege of the threat actor, it is possible that the threat actor created a malicious file inside of the trusted SharePoint site to be used as a phishing vector specifically targeted to Naomi Hunter.

---

### 3.3 Data Access

On 7 March 2026 02:49:55 UTC, the threat actor accessed multiple emails from the `donald.anderson@wdlabs.com.au` Exchange mailbox. It is likely that the threat actor was gathering information about the victim and selecting their next target. This activity repeats around once per day until 10 March 2026 10:15:51 UTC.

On 9 March 2026 07:21:05 UTC, we discovered that the threat actor managed to download multiple PDF files from the `WDLabsOperations` SharePoint site, specifically inside the `Shared Documents` folder. We could not identify the contents of the files exfiltrated by the threat actor. This activity also repeats until 10 March 2026 09:51:40 UTC.

---

## 4. Lessons Learned

I particularly struggled with organisation of evidences when doing this investigation, where queries, screenshots and other evidence were scattered across different files. For upcoming investigations, I would create a separate Markdown file to dump all evidences that is structured based on timestamps. I would also rename screenshots to attribute it to a certain event and/or timestamp.

One thing I learned from this investigation is to always be suspicious of any activity. I almost disregarded the first suspicious email due to the sender being the lab creator, but based on the timing and contents of the email, that event is the only explanation of the malicious initial access. Another thing is to always have an updated timeline of the events occurring on the incident. This helps me tremendously when trying to make sense of what things the threat actor is doing and figuring out if every event has an explanation of why it happened.

---

## 5. Indicators of Compromise
### 5.1 IP Addresses
- `104[.]234[.]32[.]143`
- `173[.]239[.]229[.]83`
- `52[.]106[.]216[.]166`
- `181[.]215[.]65[.]116`
- `104[.]234[.]32[.]142`
- `181[.]215[.]65[.]117`
- `104[.]234[.]32[.]115`
- `104[.]234[.]32[.]118`
- `45[.]133[.]5[.]165`
- `45[.]133[.]5[.]172`
- `45[.]133[.]5[.]15`
- `45[.]133[.]5[.]24`
- `45[.]133[.]5[.]52`
- `45[.]133[.]5[.]48`
- `91[.]217[.]249[.]193[:]17130`
- `91[.]217[.]249[.]193`
- `91[.]217[.]249[.]214`
- `91[.]217[.]249[.]210`
- `91[.]217[.]249[.]220`
- `54[.]206[.]115[.]107`
- `15[.]135[.]61[.]79`
### 5.2 Email Addresses
- `dalan[.]coburn@wdlabs[.]com[.]au`
### 5.3 URLs
-  `hxxps[://]login[.]superlegitlogin[.]wdlabs[.]com[.]au/McPdBMLl`
- `hxxps[://]wdlabs[.]sharepoint[.]com/sites/WDLabsOperations/Shared%20Documents/Forms/AllItems[.]aspx?viewid=8bd96870-5971-4d24-a1ff-6462316e46f3`
## 5.4 Session IDs
- `002ee01a-a45e-12bb-2b80-7cb66d68f1cd`
- `002ee01a-6208-9739-8a17-a7adc52c9df8`
## 6. Appendix

### 6.1 Suspicious Email Evidence
Using the query below, we detected 4 emails sent in quick succession using similar subjects regarding cyber security training.
```
FROM socsim-bec1*
| WHERE source == "mtl" AND Received < "2026-03-07T02:35:40Z" AND RecipientAddress == "donald.anderson@wdlabs.com.au"
| SORT Received
| KEEP Received, SenderAddress, RecipientAddress, Subject
```
![](/images/project_victoria/project_victoria_1.png)
Upon receiving the evidence of Donald Anderson's mailbox, we are able to locate the contents of the last email in the previous evidence. Based on the contents, we identified a URL that may be used by Dalan Coburn to steal credentials from Donald Anderson.
![](/images/project_victoria/project_victoria_2.png)
### 6.2 Initial Access Evidence
To identify unusual access from the `donald.anderson@wdlabs.com.au` account. We executed a query to consolidate client IP addresses and session IDs from the Microsoft 365 Unified Access Logs and grouped them based on the session ID.
```
FROM socsim-bec1*
| EVAL SourceIp = COALESCE(ClientIP, ClientIPAddress)
| EVAL MasterSessionId = COALESCE(MV_FIRST(DeviceProperties.Value.keyword), AppAccessContext.AADSessionId)
| WHERE source == "ual" AND UserId == "donald.anderson@wdlabs.com.au" AND MasterSessionId IS NOT NULL
| STATS Count = COUNT(*), FirstAccess = MIN(CreationTime), SourceIps = MV_CONCAT(VALUES(SourceIp), "\n") BY MasterSessionId
| SORT Count DESC
| KEEP FirstAccess, MasterSessionId, SourceIps, Count
```
![](/images/project_victoria/project_victoria_3.png)
After identifying all IP addresses and session IDs used, we ran all IPs to an API to geo-locate the IP. Results from the API concludes that there are multiple IP addresses that is located outside of Melbourne, Australia.
```
IP                     Country        City
-------------------------------------------------
52[.]106[.]216[.]166   Australia      Melbourne
103[.]51[.]113[.]25    Australia      Melbourne
52[.]123[.]162[.]160   Australia      Melbourne
20[.]190[.]142[.]172   Australia      Melbourne
45[.]133[.]5[.]165     Australia      Sydney
45[.]133[.]5[.]172     Australia      Sydney
45[.]133[.]5[.]15      Australia      Sydney
45[.]133[.]5[.]24      Australia      Sydney
45[.]133[.]5[.]52      Australia      Sydney
45[.]133[.]5[.]48      Australia      Sydney
54[.]206[.]115[.]107   Australia      Sydney
15[.]135[.]61[.]79     Australia      Sydney
52[.]123[.]161[.]122   Australia      The Rocks
91[.]217[.]249[.]193   Germany        Frankfurt am Main
91[.]217[.]249[.]214   Germany        Frankfurt am Main
91[.]217[.]249[.]210   Germany        Frankfurt am Main
91[.]217[.]249[.]220   Germany        Frankfurt am Main
104[.]234[.]32[.]143   United States  Chicago
181[.]215[.]65[.]116   United States  Chicago
104[.]234[.]32[.]142   United States  Chicago
181[.]215[.]65[.]117   United States  Chicago
104[.]234[.]32[.]115   United States  Chicago
104[.]234[.]32[.]118   United States  Chicago
173[.]239[.]229[.]83   United States  New York
```
We can also conclude that the `002df5ba-4e21-5811-12c2-51c77261399e` session ID is considered the baseline and should be ignored since all IP addresses that uses that session ID are located in Melbourne, Australia. We identified two malicious session ID: `002ee01a-6208-9739-8a17-a7adc52c9df8` and `002ee01a-a45e-12bb-2b80-7cb66d68f1cd`. 

To identify the initial access timestamp, we crafted a query to get all activities coming from the malicious session IDs and returning the timestamp of the first event.
```
FROM socsim-bec1*
| EVAL SourceIp = COALESCE(ClientIP, ClientIPAddress)
| EVAL MasterSessionId = COALESCE(MV_FIRST(DeviceProperties.Value.keyword), AppAccessContext.AADSessionId)
| WHERE source == "ual" AND MasterSessionId IN ("002ee01a-a45e-12bb-2b80-7cb66d68f1cd", "002ee01a-6208-9739-8a17-a7adc52c9df8") AND Operation == "UserLoggedIn"
| SORT CreationTime
| LIMIT 1
| KEEP CreationTime, SourceIp, Workload, Operation
```
![](/images/project_victoria/project_victoria_4.png)
Upon further inspection using the query below, the `002ee01a-6208-9739-8a17-a7adc52c9df8` session ID was only used by the threat actor to log in. Therefore, the investigation will focus on the `002ee01a-a45e-12bb-2b80-7cb66d68f1cd` session ID.
```
FROM socsim-bec1*
| EVAL SourceIp = COALESCE(ClientIP, ClientIPAddress)
| EVAL MasterSessionId = COALESCE(MV_FIRST(DeviceProperties.Value.keyword), AppAccessContext.AADSessionId)
| WHERE source == "ual" AND MasterSessionId == "002ee01a-6208-9739-8a17-a7adc52c9df8"
| KEEP CreationTime, SourceIp, Workload, Operation
| SORT CreationTime
```
![](/images/project_victoria/project_victoria_5.png)
### 6.3 Email Read Access Evidence
Using the query below, we identified multiple email's that has been accessed by the threat actor. We suspect that the threat actor is gathering information about the victim and ultimately find their next target.
```
FROM socsim-bec1*
| WHERE source == "ual"
| EVAL SourceIp = COALESCE(ClientIP, ClientIPAddress)
| EVAL MasterSessionId = COALESCE(MV_FIRST(DeviceProperties.Value.keyword), AppAccessContext.AADSessionId)
| WHERE UserId == "donald.anderson@wdlabs.com.au"
  AND MasterSessionId == "002ee01a-a45e-12bb-2b80-7cb66d68f1cd"
  AND Workload == "Exchange" AND Folders.FolderItems.Subject IS NOT NULL
| MV_EXPAND Folders.FolderItems.Subject
| STATS CreationTime = MAX(CreationTime), 
        Subject = MAX(Folders.FolderItems.Subject),
        Type = MAX(OperationProperties.Value) BY Folders.FolderItems.Subject
| KEEP CreationTime, Subject, Type
| SORT CreationTime
```
![](/images/project_victoria/project_victoria_6.png)
### 6.4 Malicious Inbox Rule Evidence
To identify the maliciously created inbox rule, we used a query to filter the Unified Access Logs to only return the `New-InboxRule` operation that is responsible for inbox rule creations.
```
FROM socsim-bec1*
| EVAL SourceIp = COALESCE(ClientIP, ClientIPAddress)
| EVAL MasterSessionId = COALESCE(MV_FIRST(DeviceProperties.Value.keyword), AppAccessContext.AADSessionId)
| WHERE source == "ual" AND MasterSessionId == "002ee01a-a45e-12bb-2b80-7cb66d68f1cd" AND Operation == "New-InboxRule"
| KEEP CreationTime, UserId, Workload, Operation, Parameters.Name, Parameters.Value
```
![](/images/project_victoria/project_victoria_7.png)
Based on the results, we determined that the threat actor created an inbox rule called `.` to mark all emails sent by `naomi.hunter@wdlabs.com.au` as read and redirects them to `RSS Feeds`. This tactic is used by the threat actor to hide any alerts or concerned responses sent to the victim.
### 6.5 SharePoint Exfiltration Evidence
We ran a query to return any `FileDownloaded` events on SharePoint from the malicious session ID. After execution, we detected multiple exfiltration events of PDF files from the `Shared Documents` folder of the `WDLabsOperation` SharePoint site.
```
FROM socsim-bec1*
| EVAL SourceIp = COALESCE(ClientIP, ClientIPAddress)
| EVAL MasterSessionId = COALESCE(MV_FIRST(DeviceProperties.Value.keyword), AppAccessContext.AADSessionId)
| WHERE source == "ual" AND MasterSessionId == "002ee01a-a45e-12bb-2b80-7cb66d68f1cd" AND Workload == "SharePoint" AND Operation == "FileDownloaded"
| KEEP CreationTime, SourceIp, ObjectId
| SORT CreationTime
```
![](/images/project_victoria/project_victoria_8.png)
### 6.6 Suspicious Email Evidence
We crafted a query to return the email sent by Donald Anderson to Naomi Hunter after the identified initial access event. We can identify the subject used by the threat actor is `Report`.
```
FROM socsim-bec1*
| WHERE source == "mtl" AND SenderAddress == "donald.anderson@wdlabs.com.au" AND RecipientAddress == "naomi.hunter@wdlabs.com.au" AND Received > "2026-03-07T12:35:40Z"
| KEEP Received, Subject
| Sort Received
```
![](/images/project_victoria/project_victoria_9.png)
From the mailbox evidence, we concluded that the previously mentioned email contains a SharePoint URL. Based on the URL format, we can infer that the URL returns a certain view in the `Shared Documents/Forms` directory of the `WDLabsOperations` SharePoint site.
![](/images/project_victoria/project_victoria_10.png)

