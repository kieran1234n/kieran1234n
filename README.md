## Section 1: Homepage

## Section 2: Attack Simulations

Brute Force Attack

In this scenario, an attacker conducted a port scan and identified that port 22 was open due to a misconfigured firewall. Using Hydra, they attempted to crack user passwords within the network, but these attempts were unsuccessful. To strengthen defenses, I configured Fail2ban, an Intrusion Prevention System (IPS), to block all unknown IPs making SSH attempts. Additionally, Fail2ban was set up to send email notifications to relevant parties for real-time alerts. By blacklisting IP addresses that made multiple failed SSH login attempts, Fail2ban effectively mitigated further brute-force attacks.

![Brute Force Attack](Brute-Force-Attack.png)




## Section 3: Log Analytics and Security Monitotoring

This section highlights projects focused on interpreting log data to strengthen security postures and enhance threat detection. Leveraging SIEM tools I’ve worked on transforming raw log data into actionable insights, enabling proactive security monitoring, incident response and compliance tracking.

Network Traffic Log – DDoS Incident Overview
This log highlights key details from a simulated DDoS attack scenario. The network data in this case would typically be sourced from firewalls, switches, routers, IDS/IPS, and network monitoring tools. The focus here is on identifying network attack patterns as soon as possible, giving the team the best possible chance of dealing with them in the right way.
Anomalous traffic targeting server 192.168.1.100 was detected, with IP addresses linked to the attack spread globally—classic signs of a Distributed Denial of Service (DDoS) event. Filters were applied to isolate malicious IPs, and geo-blocking was introduced to limit regions showing high volumes of hostile activity. Firewall rules were tightened, and traffic was rerouted using load balancers to reduce strain on the primary target.


Systems log with infected users

For this I focused on mimicking data from something like a malware attack, in reality the source of this data would likely come from EDR logs. Some users are infected with several IOCs. The log below gives a general view of system health


This chart focuses solely on infected users, with the filters and queries tailored to isolate key IOC along with relevant affected users and their contact details. Crucially there are cve IDs available, with these I can quickly search through the cve database to find. This tells me how others have dealt with this particular threat and gives me details about what to expect. 
![image](https://github.com/user-attachments/assets/2df8290e-0dc3-4ab1-8204-47306fd3c105)


![Systems Log](Systems Log.png)




## Section 4: Malware Analysis


This tool was created through the use of a windows vm in which I disabled windows defender and installed Flare VM. The purpose of it is to create an isolated environment for testing static and dynamic code. It’s not connected to the internet but through tools like inetsim and remnux it is possible to mimic an online network giving the chance for malicious code to run without it impacting systems. 


![Malware Analysis Lab](Malware-Analysis-Labe.png)


## Section 5 Security Reports Examples
![Incident Report example](Incident%20Report.pdf)



## Section 6 Contact details
