##  Homepage
* Log Analytics and Monitoring

**[Azure Sandbox Environment]( https://github.com/kieran1234n/Malware-Analysis-Lab.git)

**[Network Security Log]( https://github.com/kieran1234n/Network-Security-Log)

**[System log analysis with Infected users]( https://github.com/kieran1234n/Malware-Analysis-Lab.git)

* Other

**[Malware Analysis Lab]( https://github.com/kieran1234n/Microsoft-Azure-Sandbox-Environment)

**[Simulated Brute Force Attack]( https://github.com/kieran1234n/Simulated-Brute-Force-Attack-Analysis)

## Log Analytics and Security Monitotoring

This section focuses on projects that leverage SIEM tools to transform raw log data into actionable insights, enhancing threat detection and security posture. By filtering and visualizing key data points, these dashboards enable proactive monitoring, incident response, and compliance tracking. The goal is to highlight indicators of compromise (IOCs), making security threats easier to detect and interpret.

**Microsoft Azure Sandbox**

This project involved deploying a Windows VM honeypot in Microsoft Azure to analyze attacker behavior. The virtual network, and Network Security Group rules were configured to allow all traffic while keeping the network isolated. To make the system more attractive to attackers, the Windows Firewall was disabled.
Initial log analysis in the VM’s Event Viewer revealed numerous failed login attempts. To gain deeper insights, logs were ingested into Microsoft Sentinel. A database containing IP address ranges and their corresponding countries was then uploaded, enabling visualization of the geographic distribution of attacker IPs.


![CloudSandbox](CloudProject.png)

**Network Traffic Log**

This log highlights key details from a simulated DDoS attack scenario. The network data in this case would typically be sourced from firewalls, switches, routers, IDS/IPS, and network monitoring tools. The focus here is on identifying network attack patterns as soon as possible, giving the team the best possible chance of dealing with them in the right way.

![DDOS](DDOS1.JPG)

Anomalous traffic targeting server 192.168.1.100 was detected, with IP addresses linked to the attack spread globally—classic signs of a Distributed Denial of Service (DDoS) event. Filters were applied to isolate malicious IPs helping identify IOCs. At this stage actions could be taken such as geo-blocking could be introduced to limit regions showing high volumes of hostile activity,  Firewall rules were tightened, and traffic rerouted using load balancers to reduce strain on the primary target.

![DDOS](DDOS2.JPG)


**Systems log with infected users**

The source of this data often comes from things like EDR logs. In this instance I wanted to mimick a scenario with malware infected systems to put an emphasis on several IOCs that can be found within this log type. The dashboard below gives a general view of system health


Another chart focuses solely on infected users, with the filters and queries tailored to isolate key IOCs along with relevant affected users and their contact details. Crucially there are cve IDs. With these I can quickly search through the cve database to find information and advice on how others have dealt with this particular threat and find details about what to expect.


![Systems Log](SystemsLog3.png)




## Malware Analysis


This tool was created through the use of a windows vm in which I disabled windows defender and installed Flare VM. The purpose of it is to create an isolated environment for testing static and dynamic code. It’s not connected to the internet but through tools like inetsim and remnux it is possible to mimic an online network giving the chance for malicious code to run without it impacting systems. 


![Malware Analysis Lab](MalwareAnalysisLab2.png)


## Security Reports Examples
![Incident Report example](IncidentReport.pdf)

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
