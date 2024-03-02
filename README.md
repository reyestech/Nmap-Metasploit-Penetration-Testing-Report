# Nmap-Metasploit-Penetration-Testing-Report

<img src="https://i.imgur.com/1kthLJ2.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

<h1>Hector M. Reyes  | SOC Analysts </h1>
</h1> Group 17: Script K™  | Stackfull Software </h1>
<h1> Penetration Test Report: Stackfull Software</h1>

<img src="https://i.imgur.com/EskVhbQ.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

<h2>Description</h2>
Your team has been assigned as the offensive security team for Stackfull Software. The team will validate internal security controls to see whether current protocols will protect the Stackfull Software organization's clients. The team will provide services to external clients to validate their security controls. One of your clients, Fullstack Academy, has assigned your team to complete the penetration test for an isolated network.

<h2>Tools Used</h2> 

- <b> Kali Linux | VMware | VirtualBox </b> 
- <b> Wireshark | Netcat | Nmap </b>
- <b> Metasploit | Burp Suite </b>
- <b> Md5decrypt.net | crackstation.net </b>
- <b> MITRE ATT&CK Framework | 


<h2> Responsibilities of the Offensive Security Team </h2>
- <b> Support test planning to include the development of test objectives, configurations, and schedules.
- <b> Conduct vulnerability assessments, network penetration tests, and engagements.
- <b> Provide documentation, label vulnerabilities, and actively exploit client-owned networks, hardware, and software.
- <b> Communicate with the technical team and executives regarding the results of analysis tasks in client environments.
- <b> Collaborate with a team to share recommendations and findings and address client questions and concerns.
- <b> Research new threats, vulnerabilities, security technologies, and countermeasures to provide mitigation and remediation recommendations.

<h2> Requirements </h2> 
- <b> Familiarization with Windows, Linux, and other Unix operating systems.
- <b> Understanding of network or device penetration testing methodology.
- <b> Familiarity with standard assessment and penetration testing tools. (e.g., Nmap, Wireshark, Metasploit, Netcat, Burp Suite)
- <b> Experience with common testing frameworks. (MITRE ATT&CK framework)
- <b> Experience conducting code maintenance and review. (Python or equivalent)
- <b> Experience creating guides and reporting findings that support customers and engagement success criteria.
- <b> Verbal and written communications must be clear and concise.
- <b> Focused adherence to safety and security requirements.
- <b> Commitment to contributing to security or privacy communication, such as public research, blogging, presentations, etc.

<img src="https://i.imgur.com/ fzs7d56.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

<h2> Rules of Engagement: </h2> 
1. You are authorized only to scan and attack systems that reside on the same /20 subnet in which the provided Kali Virtual Machine resides.
2. No social engineering or client-side exploits are permitted.
3. You can request information from the employees or your team.
4. You can use any of the tools you are provided; there should be no need to download outside tools for this penetration test.

<img src="https://i.imgur.com/lcl7mD5.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

Intro
This penetration test aims to identify and secure any vulnerabilities in the client’s network. You will use the various tools provided to test the systems by attempting to exploit their network by employing different techniques that a malicious actor could utilize to access their network. After the analysis, you will report your findings and recommendations for Fullstack Academy to secure its network for the upcoming year.
 
Vulnerabilities Assessment
1. Exhibit ethical hacking protocols to evaluate security and identify vulnerabilities in target systems, networks, or system infrastructure.
2. Perform vulnerability scanning and perform offensive security techniques with the provided tools.
3. Use modules within Metasploit and establish Meterpreter sessions.
4. Search for privilege escalation opportunities through lateral movement.
5. Apply the pass-the-hash technique to take advantage of flaws in NTLM authentication.
 
Tools of the Trade:
- <b> Nmap: a network scanner used to discover hosts and services on our network.
- <b> Wireshark: open-source network packet analyzer.
- <b> Netcat: Networking utility for reading from and writing network connections using TCP or UDP.
- <b> Burp Suite: security application used for penetration testing of web applications
- <b> Metasploit: provides information about security vulnerabilities and aids in penetration testing.
- <b> Passwords: Tools used to find passwords. Md5decrypt.net and crackstation.net
- <b> MITRE ATT&CK Framework: a guideline for classifying and describing cyberattacks and intrusions
 
<img src="https://i.imgur.com/jv2Ichh.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

<img src="https://i.imgur.com/j9Hr9Gh.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Network Reconnaissance: (Picture 1.1-1.4) <br /> 
First, we verified our network IP address and Subnetmask using “ifconfig.” Then, we started a reconnaissance using Nmap and scanned the /20 subnet. After identifying our targets, we scanned their ports 1-5000. Cmd: “nmap -p 1-5000 -sV (insert IP host).” <br /> 

Findings
- <b> ifconfig: 172.31.11.224/20 | netmask: 255.255.240.0
- <b> Host A: ip-172.31.8.66 is hosting an open web server
- <b> Port 1013/tcp, open http Apache httpd (Ubuntu Server)
- <b> Host B: ip-172.31.9.6 is running an SSH server
- <b> Port 2222/tcp, open ssh OpenSSH 3 (Ubuntu Linux)
- <b> Host C: ip-172.31.9.237 & Host D: ip-72.31.15.123: on a Windows Web Server, Port 3389/tcp, Microsoft Terminal
 
 
Picture 1.1
<img src="https://i.imgur.com/MsWagSo.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Picture 1.2
<img src="https://i.imgur.com/FyXDZrm.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Picture 1.3
<img src="https://i.imgur.com/mqoKLJT.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Picture 1.4
<img src="https://i.imgur.com/Ug6peXD.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Initial Compromise: (Picture 1.5-1.7) <br /> 
We looked for vulnerable targets, such as HTTP servers, that haven't kept up with current network security standards. Host C is running on an unsecured HTTP web server. We browsed the website using its IP and port number (http://172.31.8.66:1013). Using Network Utility Tools to test its defenses and explore the unsecured server, we found the user's IDs and permissions. We explored the host with the command "whoami" to test the server's vulnerabilities and saw we could inject commands into the server. <br /> 

Findings
- <b> Fullstack’s server (Host A) is an unsecured web server using the http: protocol with DevOps privileges.
- <b> Host A: 172.31.8.66, Port:1013
- <b> Picture 1.5
 
Picture 1.5
<img src="https://i.imgur.com/hM6GCsm.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Picture 1.6
<img src="https://i.imgur.com/tLI86qc.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Pivoting (Picture 1.7-2.0) <br /> 
Now that we see we can run commands on the server, we know it’s vulnerable to our code injections. First, we explored Alice’s machine since she had DevOps privileges by heading to DNS Lookup, Search, then Insert “:ls /home/alice-devops/.ssh.” After we went to the “IP” Finder, we saw “Id_rsa.pem.” We noticed that home/alice-devops/.ssh > id has the SSH key. Now, we can connect this computer to our Kali machine with Alice’s privileges. We pasted the hash into a vim file, then changed the permissions of  “id_rsa.pem” to read and write only using the “chomod” command. To ensure the connection will stay open. SSH clients will refuse to use a key that has file permissions open. <br /> 
- <b> ssh -i ~/.ssh/id_pem -p 1011 alice-devops@172.22.28.155
- <b> chmod command: sudo chmod 600 id_rsa.pem <br />

Findings
- <b> Id_rsa.pem
- <b> Host’s OpenSSH Private Key
- <b> Secure connection from our Kali Server to Alice’s Machine

Picture 1.7                                                              
  <img src="https://i.imgur.com/dwZYt6R.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>    	
 
 
Picture 1.8
<img src="https://i.imgur.com/rMJd6sn.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Picture 1.9      
<img src="https://i.imgur.com/rMJd6sn.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Picture 2.0
<img src="https://i.imgur.com/Q4hDDM2.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>


System Reconnaissance: (Picture 2.1-2.4) <br /> 
Now that we have an SSH connection to our target, we can access the other Machines on their Network by examining the system and files. We looked through her directory and found a maintenance folder and “ls” inside, where we can insert the MD5 hash. <br /> 

Picture 2.1                            
<img src="https://i.imgur.com/TNOSPMK.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Picture 2.2  
<img src="https://i.imgur.com/XUBGV0k.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>                  	
 
 
 
 Picture 2.3                                                   	
 <img src="https://i.imgur.com/lJatAqu.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
 Picture 2.4
 <img src="https://i.imgur.com/lJatAqu.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Password Cracking (Picture 2.5) <br /> 
With the user's MD5 hash, we cracked the password using third-party MD5 cracking tools.
- <b> https://md5decrypt.net. <br /> 
 
Findings
- <b> MD5 Hash: 00bfc8c729f5d4d529a412b12c58ddd2
- <b> Password: “pokemon.”
 
Picture 2.5
 <img src="https://i.imgur.com/3UtxGgR.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Metasploit (Picture 2.6-2.) <br /> 
Now that we have the username and password, we use a Metasploit framework to access other users and a Meteroreter shell to access our targets. Create a Meterpreter shell. Use the command “msfconsole” and load “windows/smb/psexec” with the stolen credentials (user ID and password) and the target IP address. Now, we have a secure connection if needed, and we can also change our privileges for ourselves and other users on the server using our admin status. <br /> 

Findings
- <b> Access to Admin server with DevOps privileges.
- <b> Located file “sevte,txt.”
- <b> Meteroreter shell to extracted the file’s contents.

Picture 2.6
<img src="https://i.imgur.com/rne2NQp.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>


Picture 2.7
<img src="https://i.imgur.com/ntcYuPe.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

 
Picture 2.8
<img src="https://i.imgur.com/fdeIKqz.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Picture 2.9
<img src="https://i.imgur.com/JnRj1p8.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Picture 3.0
<img src="https://i.imgur.com/Q9EGKNj.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Conclusion <br /> 
The penetration test revealed several critical security vulnerabilities in the client's servers, with a significant lack of Network security being the most prominent issue. A malicious attacker could easily exploit these weak points to access private information through the servers and potentially gain unauthorized access to even more sensitive data on the Network. We detected unauthorized entries into the Network and used that to gain administrative privileges. As a result, we discovered that sensitive data was stored in unsecured locations, which poses a severe threat to the client's security.

 <img src="https://i.imgur.com/zNReKXu.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
Recommendations <br /> 
I. Train employees on the best security practices and raise awareness about potential threats. 
II. Set up routine security updates and patches on the network. 
III. Educate and enforce rules to secure sensitive data on the network. 
IV. Regularly change credentials on all devices and user accounts. 
V. Set up systems monitoring and provide instructions for its use. 
VI. Implement secure tools that detect suspicious activity and provide early warnings.


