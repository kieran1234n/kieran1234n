##  Homepage

##  Attack Simulations

**Brute Force Attack**

In this scenario, an attacker conducted a port scan and identified that port 22 was open due to a misconfigured firewall. Using Hydra, they attempted to crack user passwords within the network, but these attempts were unsuccessful. To strengthen defenses, I configured Fail2ban, an Intrusion Prevention System (IPS), to block all unknown IPs making SSH attempts. Additionally, Fail2ban was set up to send email notifications to relevant parties for real-time alerts. By blacklisting IP addresses that made multiple failed SSH login attempts, Fail2ban effectively mitigated further brute-force attacks.

![Brute Force Attack](BruteForceAttack.png)




## Log Analytics and Security Monitotoring

This section highlights projects focused on interpreting log data to strengthen security postures and enhance threat detection. Leveraging SIEM tools I’ve worked on transforming raw log data into actionable insights, enabling proactive security monitoring, incident response and compliance tracking.

**Network Traffic Log**

This log highlights key details from a simulated DDoS attack scenario. The network data in this case would typically be sourced from firewalls, switches, routers, IDS/IPS, and network monitoring tools. The focus here is on identifying network attack patterns as soon as possible, giving the team the best possible chance of dealing with them in the right way.

![DDOS](DDOS1.JPG)

Anomalous traffic targeting server 192.168.1.100 was detected, with IP addresses linked to the attack spread globally—classic signs of a Distributed Denial of Service (DDoS) event. Filters were applied to isolate malicious IPs helping identify IOCs. At this stage actions could be taken such as geo-blocking could be introduced to limit regions showing high volumes of hostile activity,  Firewall rules were tightened, and traffic rerouted using load balancers to reduce strain on the primary target.

![DDOS](DDOS2.JPG)


**Systems log with infected users**

The source of this data often comes from things like EDR logs. In this instance I wanted to mimick a scenario with malware infected systems to put an emphasis on several IOCs that can be found within this log type. The dashboard below gives a general view of system health


Another chart focuses solely on infected users, with the filters and queries tailored to isolate key IOCs along with relevant affected users and their contact details. Crucially there are cve IDs. With these I can quickly search through the cve database to find information and advice on how others have dealt with this particular threat and find details about what to expect.


![Systems Log](SystemsLog.png)




## Malware Analysis


This tool was created through the use of a windows vm in which I disabled windows defender and installed Flare VM. The purpose of it is to create an isolated environment for testing static and dynamic code. It’s not connected to the internet but through tools like inetsim and remnux it is possible to mimic an online network giving the chance for malicious code to run without it impacting systems. 


![Malware Analysis Lab](MalwareAnalysisLab.png)


## Security Reports Examples
![Incident Report example](Incident%20Report.pdf)

## Online Tools and Resources 

### IP, Domain and URL Analysis  
- [AbuseIPDB](https://www.abuseipdb.com/) – Checks if an IP has been reported for malicious activity.  
- [URLScan.io](https://urlscan.io/) – Scans and analyzes websites for threats like phishing and malware.  
- [MXToolbox](https://mxtoolbox.com/) – Looks up DNS records, email security settings, and blacklists.  

### Malware Analysis  
- [VirusTotal](https://www.virustotal.com/) – Scans files and URLs for malware using multiple antivirus engines.  
- [Hybrid Analysis](https://www.hybrid-analysis.com/) – Cloud-based malware analysis and sandboxing.  
- [DocGuard](https://www.docguard.io/) – Analyzes suspicious documents for hidden threats.  

### Threat Intelligence and Research  
- [MITRE ATT&CK](https://attack.mitre.org/) – A framework mapping cyberattack techniques and tactics.  
- [Fortinet Threat Intelligence](https://www.fortiguard.com/) – Real-time threat data and malware reports.  
- [CVE Details](https://www.cvedetails.com/) – Searches for known software vulnerabilities (CVEs).  
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework/) – Security best practices and guidelines.  
- [The Hacker News](https://thehackernews.com/) – Cybersecurity news, threat reports, and trends.


## Contact details

kierannutt@gmail.com 
