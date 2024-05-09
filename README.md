
<img src="https://i.imgur.com/1kthLJ2.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>


# Nmap-Metasploit-Penetration-Testing-Report

<h1>Hector M. Reyes  | SOC Analyst </h1>
</h1> Group 17: Script K™  | Stackfull Software </h1>
<h1> Penetration Test Report: Stackfull Software</h1>

<img src="https://i.imgur.com/EskVhbQ.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

 ### [Alternative Link | Google Docs | BeEF (Browser Exploitation Framework) Runbook](https://docs.google.com/document/d/e/2PACX-1vT6Smn9QrZ8bDorjYMhP_KapwiKIrAxUesHClG_aRJNhhlGVn-JrjxK6a6-ihdWqzgvXVsI8sT3e5M0/pub)


## Description 
Your team has been assigned as the offensive security team for Stackfull Software. The team will validate internal security controls to see whether current protocols will protect the Stackfull Software organization's clients. The team will provide services to external clients to validate their security controls. One of your clients, Fullstack Academy, has assigned your team to complete the penetration test for an isolated network.
<br/><br/>

<h3>Tools Used </h3>

- <b> Kali Linux | VMware | VirtualBox </b> 
- <b> Wireshark | Netcat | Nmap </b>
- <b> Metasploit | Burp Suite </b>
- <b> Md5decrypt.net | crackstation.net </b>
- <b> MITRE ATT&CK Framework |
 
![a7cb85b39fe3ecf46fae8f92846b370b](https://github.com/reyestech/Nmap-Metasploit-Penetration-Testing-Report/assets/153461962/b42c1bda-4ff4-4440-8ef4-339011566bf6)

<h2>Responsibilities of the Offensive Security Team </h2><br /> 

- <b> Support test planning to include the development of test objectives, configurations, and schedules.
- <b> Conduct vulnerability assessments, network penetration tests, and engagements.
- <b> Provide documentation, label vulnerabilities, and actively exploit client-owned networks, hardware, and software.
- <b> Communicate with the technical team and executives regarding the results of analysis tasks in client environments.
- <b> Collaborate with a team to share recommendations and findings and address client questions and concerns.
- <b> Research new threats, vulnerabilities, security technologies, and countermeasures to provide mitigation and remediation recommendations.

<img src="https://i.imgur.com/IF3hfxK.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br/><br/>

Requirements<br/>

- <b> Familiarization with Windows, Linux, and other Unix operating systems.<br/>
- <b> Understanding of network or device penetration testing methodology.<br/>
- <b> Familiarity with standard assessment and penetration testing tools. (e.g., Nmap, Wireshark, Metasploit, Netcat, Burp Suite)<br/>
- <b> Experience with common testing frameworks. (MITRE ATT&CK framework)<br/>
- <b> Experience conducting code maintenance and review. (Python or equivalent)<br/>
- <b> Experience creating guides and reporting findings that support customers and engagement success criteria.<br/>
- <b> Verbal and written communications must be clear and concise.<br/>
- <b> Focused adherence to safety and security requirements.<br/>
- <b> Commitment to contributing to security or privacy communication, such as public research, blogging, presentations, etc.<br/>

Rules of Engagement <br /> 
- <b> You are authorized only to scan and attack systems that reside on the same /20 subnet in which the provided Kali Virtual Machine resides. <br /> 
- <b> No social engineering or client-side exploits are permitted. <br /> 
- <b> You can request information from the employees or your team. <br /> 
- <b> You can use any of the tools you are provided; there should be no need to download outside tools for this penetration test. <br /> 

<img src="https://i.imgur.com/fzs7d56.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br/><br/>

Intro
This penetration test aims to identify and secure any vulnerabilities in the client’s network. You will use the various tools provided to test the systems by attempting to exploit their network by employing different techniques that a malicious actor could utilize to access their network. After the analysis, you will report your findings and recommendations for Fullstack Academy to secure its network for the upcoming year.
 
<h2>Vulnerabilities Assessment </h2> <br /> 
1. Exhibit ethical hacking protocols to evaluate security and identify vulnerabilities in target systems, networks, or system infrastructure.
2. Perform vulnerability scanning and perform offensive security techniques with the provided tools.
3. Use modules within Metasploit and establish Meterpreter sessions.
4. Search for privilege escalation opportunities through lateral movement.
5. Apply the pass-the-hash technique to take advantage of flaws in NTLM authentication.
<br/><br/>
 
Tools of the Trade: <br /> 

- <b> Nmap: a network scanner used to discover hosts and services on our network.
- <b> Wireshark: open-source network packet analyzer.
- <b> Netcat: Networking utility for reading from and writing network connections using TCP or UDP.
- <b> Burp Suite: security application used for penetration testing of web applications
- <b> Metasploit: provides information about security vulnerabilities and aids in penetration testing.
- <b> Passwords: Tools used to find passwords. Md5decrypt.net and crackstation.net
- <b> MITRE ATT&CK Framework: a guideline for classifying and describing cyberattacks and intrusions
 
<img src="https://i.imgur.com/jv2Ichh.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

<img src="https://i.imgur.com/j9Hr9Gh.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br/><br/>

Network Reconnaissance: (Picture 1.1-1.4) <br /> 
First, we verified our network IP address and Subnetmask using “ifconfig.” Then, we started a reconnaissance using Nmap and scanned the /20 subnet. After identifying our targets, we scanned their ports 1-5000. Cmd: “nmap -p 1-5000 -sV (insert IP host).” <br /> 

Findings
- <b> ifconfig: 172.31.11.224/20 | netmask: 255.255.240.0
- <b> Host A: ip-172.31.8.66 is hosting an open web server
- <b> Port 1013/tcp, open http Apache httpd (Ubuntu Server)
- <b> Host B: ip-172.31.9.6 is running an SSH server
- <b> Port 2222/tcp, open ssh OpenSSH 3 (Ubuntu Linux)
- <b> Host C: ip-172.31.9.237 & Host D: ip-72.31.15.123: on a Windows Web Server, Port 3389/tcp, Microsoft Terminal
 
Picture 1.1 <br/>
<img src="https://i.imgur.com/MsWagSo.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Picture 1.2 <br/>
<img src="https://i.imgur.com/FyXDZrm.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Picture 1.3 <br/>
<img src="https://i.imgur.com/mqoKLJT.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Picture 1.4 <br/>
<img src="https://i.imgur.com/Ug6peXD.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br/><br/> 
 
Initial Compromise: (Picture 1.5-1.7) <br /> 
We looked for vulnerable targets, such as HTTP servers, that haven't kept up with current network security standards. Host C is running on an unsecured HTTP web server. We browsed the website using its IP and port number (http://172.31.8.66:1013). Using Network Utility Tools to test its defenses and explore the unsecured server, we found the user's IDs and permissions. We explored the host with the command "whoami" to test the server's vulnerabilities and saw we could inject commands into the server.<br/>

Findings
- <b> Fullstack’s server (Host A) is an unsecured web server using the http: protocol with DevOps privileges.
- <b> Host A: 172.31.8.66, Port:1013
- <b> Picture 1.5
 
Picture 1.5 <br/>
<img src="https://i.imgur.com/hM6GCsm.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Picture 1.6 <br/>
<img src="https://i.imgur.com/tLI86qc.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br/><br/>

Pivoting (Picture 1.7-2.0) <br/>
Now that we see we can run commands on the server, we know it’s vulnerable to our code injections. First, we explored Alice’s machine since she had DevOps privileges by heading to DNS Lookup, Search, then Insert “:ls /home/alice-devops/.ssh.” After we went to the “IP” Finder, we saw “Id_rsa.pem.” We noticed that home/alice-devops/.ssh > id has the SSH key. Now, we can connect this computer to our Kali machine with Alice’s privileges. We pasted the hash into a vim file, then changed the permissions of  “id_rsa.pem” to read and write only using the “chomod” command. To ensure the connection will stay open. SSH clients will refuse to use a key that has file permissions open. <br /> 
- <b> ssh -i ~/.ssh/id_pem -p 1011 alice-devops@172.22.28.155
- <b> chmod command: sudo chmod 600 id_rsa.pem

Findings
- <b> Id_rsa.pem
- <b> Host’s OpenSSH Private Key
- <b> Secure connection from our Kali Server to Alice’s Machine

Picture 1.7<br/>
<img src="https://i.imgur.com/dwZYt6R.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>    	

Picture 1.8 <br/>
<img src="https://i.imgur.com/rMJd6sn.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Picture 1.9 <br/>
<img src="https://i.imgur.com/rMJd6sn.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Picture 2.0 <br/>
<img src="https://i.imgur.com/Q4hDDM2.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br/><br/>

System Reconnaissance: (Picture 2.1-2.4) <br /> 
Now that we have an SSH connection to our target, we can access the other Machines on their Network by examining the system and files. We looked through her directory and found a maintenance folder and “ls” inside, where we can insert the MD5 hash. <br /> 

Picture 2.1<br/>
<img src="https://i.imgur.com/TNOSPMK.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Picture 2.2 <br/>
<img src="https://i.imgur.com/XUBGV0k.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>                  	
  
Picture 2.3 <br/>
<img src="https://i.imgur.com/lJatAqu.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Picture 2.4 <br/>
<img src="https://i.imgur.com/lJatAqu.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br/><br/>
 
Password Cracking (Picture 2.5) <br /> 
With the user's MD5 hash, we cracked the password using third-party MD5 cracking tools.
- <b> https://md5decrypt.net. <br /> 
 
Findings <br/>
- <b> MD5 Hash: 00bfc8c729f5d4d529a412b12c58ddd2
- <b> Password: “pokemon.”
 
Picture 2.5 <br/>
 <img src="https://i.imgur.com/3UtxGgR.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br/> <br/>

Metasploit (Picture 2.6-2.) <br /> 
Now that we have the username and password, we use a Metasploit framework to access other users and a Meteroreter shell to access our targets. Create a Meterpreter shell. Use the command “msfconsole” and load “windows/smb/psexec” with the stolen credentials (user ID and password) and the target IP address. Now, we have a secure connection if needed, and we can also change our privileges for ourselves and other users on the server using our admin status. <br /> 

Findings
- <b> Access to Admin server with DevOps privileges.
- <b> Located file “sevte,txt.”
- <b> Meteroreter shell to extracted the file’s contents.

Picture 2.6 <br/>
<img src="https://i.imgur.com/rne2NQp.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Picture 2.7 <br/>
<img src="https://i.imgur.com/ntcYuPe.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

 
Picture 2.8 <br/>
<img src="https://i.imgur.com/fdeIKqz.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Picture 2.9 <br/>
<img src="https://i.imgur.com/JnRj1p8.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Picture 3.0 <br/>
<img src="https://i.imgur.com/Q9EGKNj.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>


![mdr](https://github.com/reyestech/Nmap-Metasploit-Penetration-Testing-Report/assets/153461962/17b72929-c81a-4be8-aad0-2d18e7746222)


## Conclusion <br /> 
The penetration test revealed several critical security vulnerabilities in the client's servers, with a significant lack of Network security being the most prominent issue. A malicious attacker could easily exploit these weak points to access private information through the servers and potentially gain unauthorized access to even more sensitive data on the Network. We detected unauthorized entries into the Network and used that to gain administrative privileges. As a result, we discovered that sensitive data was stored in unsecured locations, which poses a severe threat to the client's security.
<br/><br/>
Recommendations <br /> 
I. Train employees on the best security practices and raise awareness about potential threats.  <br /> 
II. Set up routine security updates and patches on the network.  <br /> 
III. Educate and enforce rules to secure sensitive data on the network.  <br /> 
IV. Regularly change credentials on all devices and user accounts.  <br /> 
V. Set up systems monitoring and provide instructions for its use.  <br /> 
VI. Implement secure tools that detect suspicious activity and provide early warnings. <br /> 

<img src="https://i.imgur.com/zNReKXu.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br/><br/>




