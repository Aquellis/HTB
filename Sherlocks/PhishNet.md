# PhishNet 

Find the Sherlock [here.](https://app.hackthebox.com/sherlocks/PhishNet?tab=play_sherlock)

## Description
An accounting team receives an urgent payment request from a known vendor. The email appears legitimate but contains a suspicious link and a .zip attachment hiding malware. Your task is to analyze the email headers, and uncover the attacker's scheme.

| Difficulty  | Category |
| ----------- | -------- |
| Very Easy   | SOC      |

**Skills learned:**
* Email Header Analysis

**File attachment(s):**
```text
PhishNet.zip
├── email.eml
```

## Initial Examination
Open the eml file:
* in a text editor to manually examine the email headers 
* using a local email client to visually see the message sent

![Email](../Images/Sherlock_PhishNet_email)

## Questions
**1. What is the originating IP address of the sender?**

Find the originating IP address after the **X-Originating-IP** header.
```
X-Originating-IP: [45.67.89.10]
```

**Answer: 45.67.89.10**

**2. Which mail server relayed this email before reaching the victim?**

This can be found at the topmost **Received: from** listing in the email headers. This was the last mail server that relayed the message before it reached the victim.
```
Received: from mail.business-finance.com ([203.0.113.25])
```

**Answer: 203.0.113.25**

**3. What is the sender's email address?**

The sender's address can be found after the **From** header.
```
From: "Finance Dept" <finance@business-finance.com>
```

**Answer: finance@business-finance.com**

**4. What is the 'Reply-To' email address specified in the email?**

The reply-to address can be found after the **Reply-To** header.
```
Reply-To: <support@business-finance.com>
```

**Answer: support@business-finance.com**

**5. What is the SPF (Sender Policy Framework) result for this email?**

The SPF result can be found in the **Authentication-Results** header.
```
Authentication-Results: spf=pass (domain business-finance.com designates 45.67.89.10 as permitted sender)
	 smtp.mailfrom=business-finance.com;
	 dkim=pass header.d=business-finance.com;
	 dmarc=pass action=none header.from=business-finance.com;

```

**Answer: pass**

**6. What is the domain used in the phishing URL inside the email?**

Phishing URLs can be discovered in the email body. In this case it's found inside an **\<a href>** tag.
```
  <p><a href="https://secure.business-finance.com/invoice/details/view/INV2025-0987/payment">Download Invoice</a></p>
```

**Answer: secure.business-finance.com**

**7. What is the fake company name used in the email?**

Examining the email using a local email client, the sender ends their message with:
```
Best regards,
Finance Department
Business Finance Ltd.
```

It appears that they are trying to disguise themselves as the fake company **Business Finance Ltd.**.

**Answer: Business Finance Ltd.**

**8. What is the name of the attachment included in the email?**

Examing the email using a local email client, we can see the attachment at the bottom.
It can also be found after the **Content-Disposition** header.
```
Content-Disposition: attachment; filename="Invoice_2025_Payment.zip"
```

**Answer: Invoice_2025_Payment.zip**

**9. What is the SHA-256 hash of the attachment?**

To obtain the SHA-256 hash of the email attachment, we must first download it from the email and use a hashing tool or submit the file for analysis. 
In our case we uploaded the file to [VirusTotal](https://www.virustotal.com/gui/file/8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a/details).

**Answer: 8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a**

**10. What is the filename of the malicious file contained within the ZIP attachment?**

Use a ZIP extraction tool on the Invoice_2025_Payment.zip file to see the malicous file it contains.

**Answer: invoice_document.pdf.bat**

**11. Which MITRE ATT&CK techniques are associated with this attack?**

This attack included the attacker sending a phishing email with a malicious attachment. The cooresponding MITRE ATT&CK technique is [T1566.001 - Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/).

**Answer: T1566.001**
