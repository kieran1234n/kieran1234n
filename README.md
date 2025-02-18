## Section 1: Homepage

## Section 2: Tools Used

## Section 2: Projects
Incident Response to a DDoS Attack
1. Initial Analysis and Identification
Upon noticing abnormal network activity, an analysis of traffic was conducted to identify the target servers. Using a SIEM tool, network logs were reviewed, revealing that the targeted server had an IP address of 192.168.1.100. The attack originated from multiple IP addresses distributed across various countries, indicating a Distributed Denial of Service (DDoS) attack.

![DDOS attack](DDOS 1.JPG)
 
3. Containment and Mitigation
To mitigate the attack, the following steps would be considered:
•	Traffic Filtering: Implemented firewall rules to filter out traffic from known malicious IPs.
•	Load Balancing: Configured a load balancer to distribute traffic across multiple servers, reducing strain on the targeted server.
•	Geo-blocking: Considering the attack originated from multiple countries, geo-blocking was enforced on specific regions showing excessive malicious activity.
•	DDoS Protection Services: Engaged third-party cloud-based DDoS protection services to absorb and mitigate malicious traffic.
As a last resort, IP changes were considered to minimize continued targeting.
 
4. Eradication and Recovery
This step aims to eliminate any residual threats and restore normal operations:
•	Network Scanning: Conducted scans to detect open ports, backdoors, or any malicious software left behind.
•	Traffic Monitoring: Continued real-time monitoring to ensure no further anomalies were detected.
•	Patch Management: Ensured that all servers and network appliances were patched and up to date to prevent future exploits.
•	Network Reset: If necessary, reconfigured network settings, including reallocating IP addresses and resetting affected devices.
 
5. Post-Incident Analysis and Documentation
Once the attack was mitigated and normal operations restored, a detailed report was compiled, including:
•	Attack Vectors Identified: Sources, methods, and patterns of attack.
•	Response Actions Taken: Steps implemented to contain and mitigate the attack.
•	Impact Assessment: Evaluation of downtime, data loss, and service disruptions.
•	Recommendations for Improvement from this event might include:
o	Strengthening firewall and intrusion prevention system (IPS) rules.
o	Updating DDoS response playbooks.
o	Conducting employee training on threat identification.
o	Introducing rate limiting
Lessons learned were documented, and security policies were updated accordingly to ensure better preparedness for future attacks. 
 
Conclusion
This DDoS incident response highlights the importance of proactive threat detection, rapid mitigation strategies, and continuous improvement in cybersecurity defenses. By implementing enhanced protective measures and refining response strategies, the organization can better defend against future attacks and minimize disruptions.




## Section 4 Security Reports Examples
![Incident Report example](Incident%20Report.pdf)



## Section 5 Contact details
