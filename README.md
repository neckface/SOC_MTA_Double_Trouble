# Double Trouble / Incident Report

This repository contains the final forensic analysis and incident report for the traffic analysis exercise.
https://www.malware-traffic-analysis.net/2017/04/21/index.html



<img width="597" height="550" alt="pic_mta" src="https://github.com/user-attachments/assets/9834da46-1e27-4467-993c-7bfd37603c02" />

## 📞 Contact
If you have any questions or feedback:
* GitHub: [@stani-zholob]
* Email: [zholobstanislav408@gmail.com]


# Double Trouble Analysis

## SCENARIO

Marcus Dunham and Marion Dunham are brothers who work at their 
father's business, Dunham Hills Mortuary.  They've shared everything 
since childhood, and that trend continued as they became adults.  For 
example, at the mortuary, they share a joint email address named ***dunhambrothers@dunhamhillsmortuary[.]com***.

The brothers have gotten into plenty of trouble over the years.  Due 
to their mischievious ways, Marcus and Marion earned the knickname 
"Double Trouble."  Accidents always happen in pairs whenever the 
brothers are around.

</aside>

# Task

Figure out which email was used to infect which computer.  After all, how hard can that be?

First, it was decided to examine all 9 emails; separate files were created to view the internal content. The emails were examined superficially. Most of the emails contain links to other unknown services, while the others contain virtually no useful payload. Every E-Mail looked suspicious. The whole point is to figure out, which E-Mail was opened to get malicious data.

![image.png](Double%20Trouble/image.png)

![image.png](Double%20Trouble/image%201.png)

We are analyzing two pcap files. The situation with both looks suspicious. As for Marion, his computer initiated the infection by clicking on a link, as a suspicious GET request initiated by an iframe was detected.

![image.png](Double%20Trouble/image%202.png)

![image.png](Double%20Trouble/image%203.png)

For this task, a small script was written to search for strings in the email files. ALTERNATIVE→ grep -ri “string”

![image.png](Double%20Trouble/image%204.png)

The links were examined.

Strange files and archives were also found.

.zip

![image.png](Double%20Trouble/image%205.png)

.doc

![image.png](Double%20Trouble/image%206.png)

Trying to extract one file from Email

![image.png](Double%20Trouble/image%207.png)

![image.png](Double%20Trouble/image%208.png)

After examining all the zip files → A connection was found

![image.png](Double%20Trouble/image%209.png)

# **Verdict on Marion**

Phishing email received on April 8, 2017, titled "Package Delivery Notification" from `privileges@ns3.logomotion-serveur.com`
Attached archive `FedEx-Parcel-ID-S0JM7T30.zip` contained a malicious JavaScript downloader disguised with a double extension (`FedEx-Parcel-ID-S0JM7T30.doc.js`)
The user extracted and double-clicked the `.js` file, executing it via Windows WScript
The script downloaded **Cerber** ransomware and **Kovter** trojan via HTTP GET requests to compromised domains (e.g., `dev.alaw.net`, `tdricos.ru`). *Confirmed via static code and PCAP correlation*
Cerber executed and encrypted host files. Network logs show C2 callbacks to `p27dokhpz2n7nvgr.1m3xsy.top` (23.249.163.4) and queries to legitimate Bitcoin APIs (`api.blockcypher.com`, `btc.blockr.io`) for ransom operations
Host fully compromised by ransomware. Immediate isolation and remediation required

# Marcus

A strange GET request was found inside the PCAP file, with a file purportedly named trolls.jpg 

![image.png](Double%20Trouble/image%2010.png)

The file has been exported for analysis

![image.png](Double%20Trouble/image%2011.png)

As it turned out, our .jpg file is actually an executable file

![image.png](Double%20Trouble/image%2012.png)

The file was hashed using sha256sum

![image.png](Double%20Trouble/image%2013.png)

And it was sent to VirusTotal for scanning. 

As we have seen, the file has a terrible reputation and contains malicious content.

![image.png](Double%20Trouble/image%2014.png)

Let's record the time the file was downloaded: April 20, 2017, 11:21:32 PM

Three days earlier, a letter was found containing the following message

```csharp
Content-Transfer-Encoding: base64

PGJvZHkgdGl0bGU9IiI+V2hhdCdzIG5ldz8gPGJyPjxicj4NCkkgdmlzaXRlZCB5b3VyIHdlYnNp
dGUgdG9kYXkuLiA8YnI+DQpJJ20gY3VycmVudGx5IGxvb2tpbmcgZm9yIHdvcmsgZWl0aGVyIGZ1
bGwgdGltZSBvciBhcyBhIGludGVybiB0byBnZXQgZXhwZXJpZW5jZSBpbiB0aGUgam9iIGZpaWVs
ZC4gPGJyPg0KUGxlYXNlIGxvb2sgb3ZlciBteSBDViBhbmQgbGV0IG1lIGtub3cgd2hhdCB5b3Ug
dGhpbmsuPGJyPjxicj4NCg0KDQoNClRoYW5rIHlvdSBmb3IgeW91ciB0aW1lLCA8YnI+DQoNCi0t
IDxicj4NCnNlZSBzaGVuYW5kb2FoIG1lbW9yaWFsIGhvc3BpdGFsDQo8L2JvZHk+DQo=

----InfrawareEmailBoundaryDepth1_8AF3E921----

----InfrawareEmailBoundaryDepth1_70E27267--
Content-Type: application/msword;
        name="see shenandoah memorial hospital.doc"
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
        filename="see shenandoah memorial hospital.doc"
```

If we try to decode our file using the appropriate tool, we will get the following message

![image.png](Double%20Trouble/image%2015.png)

![image.png](Double%20Trouble/image%2016.png)

We extracted the file itself and hashed it 

`997e71a509bba6d363b1e7a7f4f5ba30e83babee12b15269bec40eb110f2a254`

and ran it through Virustotal

![image.png](Double%20Trouble/image%2017.png)

Using the [reverse.it](http://reverse.it/) tool in an isolated environment, we noticed that the file runs macros and triggers a redirect to download trolls.jpg, so EMAIL

```csharp
2017-04-17-2155-UTC.eml 
```

![image.png](Double%20Trouble/image%2018.png)

is the answer for Marcus. Marcus saw a job application letter in which macros were run via a .doc file to infect Marion's computer.

# Marcus's Findings

1. On April 17, 2017, Marcus received a phishing email with the subject line “Hi” from a fake job applicant (`mautzel1982@t-online.de`). An infected Microsoft Word document (`see shenandoah memorial hospital.doc`) was attached to the email.
2. When Marcus opened the document, a hidden malicious macro (VBA script) was triggered.
3. The macro initiated a background PowerShell process (`WindowStyle Hidden`), which downloaded a malicious executable file from the attackers’ IP address (`185.165.29.36`). To bypass basic security measures, the file was disguised as an image (`trolls.jpg`), but was actually a Windows executable (PE32).
4. The script saved the downloaded file with the `.exe` extension to a temporary folder and executed it. Subsequently, the compromised system communicated with `myexternalip.com` to verify its external IP address and generated traffic on the Tor network.

The incident has been successfully investigated. The connection between the initial phishing email and the network artifacts (request to `trolls.jpg`) has been 100% confirmed by dynamic analysis data (Hybrid Analysis).

---

Stanislav Zholob 

24.05.2026
