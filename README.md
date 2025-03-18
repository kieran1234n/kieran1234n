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
