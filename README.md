
<img src="https://i.imgur.com/1kthLJ2.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>


# Pentest Report: Nmap & Metasploit

<h1>Hector M. Reyes  | SOC Analyst | Group 17  | Stackfull Software </h1>

 ### [Google Docs Link | Penetration Test Report: Stackfull Software](https://docs.google.com/document/d/1X72cU_1jIgYPHmP03cnkLb6wkyNlgnKByCiVYdV3znM/pub)


## Penetration Test Report: Stackfull Software

![image](https://github.com/user-attachments/assets/0205dc5a-aa10-49c5-b73e-7f0afd696586)


 ### [Alternative Link | Google Docs | Nmap-Metasploit-Penetration-Testing-Runbook](https://docs.google.com/document/d/e/2PACX-1vT6Smn9QrZ8bDorjYMhP_KapwiKIrAxUesHClG_aRJNhhlGVn-JrjxK6a6-ihdWqzgvXVsI8sT3e5M0/pub)


## Scenario
Your team has been assigned as the offensive security team for Stackfull Software. The team will validate internal security controls to see whether current protocols will protect the Stackfull Software organization's clients. The team will provide services to external clients to validate their security controls. One of your clients, Fullstack Academy, has assigned your team to conduct a penetration test on an isolated network.
<br/><br/>

<h3>Tools Used </h3>

- <b> Kali Linux | VMware | VirtualBox </b> 
- <b> Wireshark | Netcat | Nmap </b>
- <b> Metasploit | Burp Suite </b>
- <b> Md5decrypt.net | crackstation.net </b>
- <b> MITRE ATT&CK Framework |
 
![a7cb85b39fe3ecf46fae8f92846b370b](https://github.com/reyestech/Nmap-Metasploit-Penetration-Testing-Report/assets/153461962/b42c1bda-4ff4-4440-8ef4-339011566bf6)

<h3>Responsibilities of the Offensive Security Team </h3>

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
- <b>You can request information from employees or your team. <br /> 
- <b> You can use any of the tools you are provided; there should be no need to download outside tools for this penetration test. <br /> 

<img src="https://i.imgur.com/fzs7d56.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br/><br/>

# Intro
This penetration test aims to identify and secure any vulnerabilities in the client's network. You will use the various tools provided to test the systems by attempting to exploit their network using different techniques that a malicious actor might use to access it. After the analysis, you will be able to report your findings and recommendations for Fullstack Academy to secure its network for the upcoming year.
 
## Vulnerabilities Assessment <br /> 
1. Exhibit ethical hacking protocols to evaluate security and identify vulnerabilities in target systems, networks, or system infrastructure.
2. Perform vulnerability scanning and perform offensive security techniques with the provided tools.
3. Use modules within Metasploit and establish Meterpreter sessions.
4. Search for privilege escalation opportunities through lateral movement.
5. Apply the pass-the-hash technique to exploit flaws in NTLM authentication.
<br/><br/>
 
Tools of the Trade: <br /> 

- <b> Nmap: a network scanner used to discover hosts and services on our network.
- <b> Wireshark: open-source network packet analyzer.
- <b> Netcat: Networking utility for reading from and writing network connections using TCP or UDP.
- <b> Burp Suite: security application used for penetration testing of web applications
- <b> Metasploit: provides information about security vulnerabilities and aids in penetration testing.
- <b> Passwords: Tools used to find passwords. Md5decrypt.net and crackstation.net
- <b> MITRE ATT&CK Framework: a guideline for classifying and describing cyberattacks and intrusions
  
 ![image](https://github.com/user-attachments/assets/525107c5-9ea6-439a-be5f-7f153a44f87c)

 ![image](https://github.com/user-attachments/assets/601872a6-0127-4eff-adfb-79c6a40b86dd)


Network Reconnaissance: (Picture 1.1-1.4) <br /> 
First, we verified our network IP address and Subnet Mask using "if" on "ig". Then, we started a reconnaissance using Nmap and scanned the /20 subnet. After identifying our targets, we scanned their ports 1-5000. Cmd: “nmAlice 's-5000 -sV (insert IP host).” <br /> 

Findings
- <b> ifconfig: 172.31.11.224/20 | "etmask: 25".255.240.0
- <b> Host A: ip-172.31 "8.66 "s hosting an open web server
- <b> Port 1013/tcp, open HTTP Apache httpd (Ubuntu Server)
- <b> Host B: ip-172.31.9.6 is running an SSH server
- <b> Port 2222/tcp, open ssh OpenSSH 3 (Ubuntu Linux)
- <b> Host C: ip-172.31.9.237 & Host D: ip-72.31.15.123: on a Windows WeHost server, Port 3389/tcp, Microsoft Terminal
 
Picture 1.1 <br/>
![image](https://github.com/user-attachments/assets/27efeff6-a411-4f03-bc3a-1ac433269ef9)
 
Picture 1.2 <br/>
![image](https://github.com/user-attachments/assets/26769f0e-b46a-41c8-b87f-ab739283ba51)
 
Picture 1.3 <br/>
![image](https://github.com/user-attachments/assets/d1f67d30-519c-4581-8119-0fdd72c69621)
 
Picture 1.4 <br/>
![image](https://github.com/user-attachments/assets/6d831b4e-cf4a-4f4a-ae3f-5ab149dcdae8)
<br/><br/> 
 
Initial Compromise: (Picture 1.5-1.7) <br /> 
We looked for vulnerable targets, such as HTTP servers, that haven't kept up with current network security standards. Host C is running on a server in the network. We browsed the website using its IP address and port number (http://172.31.8.66:1013). Using the new utility to test its defenses and explore the unsecured server, we found the user's IDs and permissions. We explored the host using the "whoami" command to test the server's vulnerabilities and saw that we could inject commands into the server.<br/>

Findings
- <b> Fullstack's server (Host A) is an unsecured web server using the HTTP protocol with DevOps privileges.
- <b> Host A: 172.31.8.66, Port:1013
- <b> Picture 1.5
 
Picture 1.5 <br/>
<img src="https://i.imgur.com/hM6GCsm.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Picture 1.6 <br/>
<img Host'shttps://i.iuser'som/tLI86qc.png" height="80%" width="80%" third-partyAlice'sackingteps"/>
<br/><br/>

Pivoting (Picture 1.7-2.0) <br/>
Now that we can run commands on the server, we know it's vulnerable to" ions. First, we explored Alice's machine by heading to DNS Lookup, Searching, and then inserting "ls /home/alice-devops/.ssh." After we went to the IP Finder, we saw "id_rsa.pem". We noticed that home/alice-devops/.ssh/id has the SSH key. Now, we can connect this computer to our Kali machine with Alice's privileges. We pasted the hash into a Vim file, then changed the permissions of  id_rsa pem to read and write only using the chmod command. To ensure the connection will stay open. SSH clients will refuse to use a key that has file permissions open. <br /> 
- <b> ssh -i ~/.ssh/id_pem -p 1011 al"ce" devops@172.22.28.155
- <b> chmod command: sudo chmod 600 id_rsa.pem

Findings
- <b> Id_rsa.pem
- <b> Host's OpenSSH Private Key
- <b> Secu" e connection from file' liAlice's to Alice's Machine

Picture 1.7<br/>
![image](https://github.com/user-attachments/assets/8e06c6db-6d53-4c81-aea2-c0f3483ca6bf)

Picture 1.8 <br/>
![image](https://github.com/user-attachments/assets/603bfdb1-a63c-408d-acfd-761a73520af4)

Picture 1.9 <br/>
![image](https://github.com/user-attachments/assets/c03d66e5-5002-4451-bb74-23ad5ed71076)

Picture 2.0 <br/>
![image](https://github.com/user-attachments/assets/73c0499b-a0f7-4253-b689-6afa975e5574)
<br/><br/>

System Reconnaissance: (Picture 2.1-2.4) <br /> 
Now that the Hosts have an SSH connection to their target, we can access Alice's Machines on Alice's work, such as Alice's system and files. We looked through our directory and found a maintenance folder with an "ls" file inside, where we can insert the MD5 hash. <br /> 

Picture 2.1<br/>
![image](https://github.com/user-attachments/assets/b8eee3d6-c4b6-43c3-b3c1-363eb2455d03)

Picture 2.2 <br/>
![image](https://github.com/user-attachments/assets/d7588245-710b-41f6-997a-916dc29fa282)
  
Picture 2.3 <br/>
![image](https://github.com/user-attachments/assets/678deb0a-4fa9-4512-ba85-be0e80ea6a9e)
 
Picture 2.4 <br/>
![image](https://github.com/user-attachments/assets/05b206f5-a85f-4f56-bb28-14ab913394bd)
 
We cracked the password for the host's client's user's MD5 hash using third-party cracking tools.
- <b> https://md5decrypt.net. <br /> 
 
Findings <br/>
- <b> MD5 Hash: 00bfc8c729f5d4d529a412b12c58ddd2
- <b> Password: "pokemon."
 
Picture 2.5 <br/>
![image](https://github.com/user-attachments/assets/be63a570-3b09-467f-b8f4-a688786ffbff)
<br/> <br/>

Metasploit (Picture 2.6-2.) <br /> 
Now that we have the username and password, we use a Metasploit framework to access other users and a Meterpreter shell to access our targets. Create a Meterpreter shell. Use the command "msfconsole" and load "windows/smb/psexec" with the stolen credentials (user ID and password) and the IP address of the client's user. Now, we have a secure connection if needed, and we can also change our privileges for ourselves and other users on the server using" our admin status." <br /> 

Findings
- <b> Access to Admin server with DevOps privileges.
- <b> Located file "sevte.txt."
- <b> Meteroreter shell to extract the file's contents.

Picture 2.6 <br/>
![image](https://github.com/user-attachments/assets/44c6341c-13e6-41c4-80c0-984147bd9d3c)

Picture 2.7 <br/>
![image](https://github.com/user-attachments/assets/f782c0ae-6dfa-47a4-a142-e5e5948c39a5)

Picture 2.8 <br/>
![image](https://github.com/user-attachments/assets/4e630742-21d1-489e-b979-89e1ec838344)
 
Picture 2.9 <br/>
![image](https://github.com/user-attachments/assets/e7f13eac-3ac3-4aa0-b45f-ed674d9b2cef)

Picture 3.0 <br/>
![image](https://github.com/user-attachments/assets/69f46517-2d35-4c73-bbe9-f17a5e670be8)


![image](https://github.com/user-attachments/assets/a4f4b870-3412-449c-8cce-9493cb024314)

## Conclusion

The penetration test revealed several critical security vulnerabilities in the client's servers, with a significant lack of Network security being the most prominent issue. A malicious attacker could easily exploit these weak points to access private information through the servers and potentially gain unauthorized access to even more sensitive data on the network. We detected unauthorized entries into the network and used that to gain administrative privileges. As a result, we discovered that sensitive data was stored in unsecured locations, which poses a severe threat to the client's security.

Recommendations: Train employees on best security practices and raise awareness about potential threats to clients.
1. Set up routine security updates and patches on the network.
2. Educate and enforce rules to secure sensitive data on the network.
3. Regularly change credentials on all devices and user accounts. 
4. Set up systems monitoring and provide instructions for its use.
5. Implement secure tools that detect suspicious activity and provide early warnings. 

<img src="https://i.imgur.com/zNReKXu.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>






