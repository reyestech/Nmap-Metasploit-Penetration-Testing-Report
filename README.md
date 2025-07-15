<div align="center">
  <img src="https://github.com/user-attachments/assets/1aaeaf5f-b0ce-4417-9873-9fdfcc4f84e2" width="99%" alt="Pentest Report Nmap & Metasploit - Intro"/>
</div>

<h1>  Pentest Report: Nmap & Metasploit </h1>
Hector M. Reyes | SOC Analyst | Stackfull Software

[Google Docs Link | Penetration Test Report: Stackfull Software](https://docs.google.com/document/d/1X72cU_1jIgYPHmP03cnkLb6wkyNlgnKByCiVYdV3znM/pub)

<img src="https://github.com/user-attachments/assets/b5c3df39-168b-4b46-9343-39ed36b0a98c" width="30%" alt="Pentest Report Nmap & Metasploit - Tools"/>

---

<img src="https://github.com/user-attachments/assets/b067990e-977d-462d-bcb2-81f8001a5050" width="60%" alt="Pentest Report Nmap & Metasploit - Stackfull"/>

## **Intro**
**Scenario**
Your team has been assigned as the offensive security team for Stackfull Software. The team will validate internal security controls to determine whether current protocols are sufficient to protect the Stackfull Software organization's clients. The team will provide services to external clients to validate their security controls and ensure compliance with relevant regulations. One of your clients, Fullstack Academy, has assigned your team to conduct a penetration test on an isolated network.

Tools Used 
> - Kali Linux | VMware | VirtualBox 
> - Wireshark | Netcat | Nmap 
> - Metasploit | Burp Suite 
> - Md5decrypt.net | crackstation.net 
> - MITRE ATT&CK Framework 


### Responsibilities of the Offensive Security Team 
1. Support test planning to include the development of test objectives, configurations, and schedules.
2. Conduct vulnerability assessments, network penetration tests, and engagements.
3. Provide documentation, label vulnerabilities, and actively exploit client-owned networks, hardware, and software.
4. Communicate with the technical team and executives regarding the results of analysis tasks in client environments.
5. Collaborate with a team to share recommendations and findings and address client questions and concerns.
6. Research new threats, vulnerabilities, security technologies, and countermeasures to provide mitigation and remediation recommendations.

<img src="https://github.com/user-attachments/assets/fd2254d7-f423-4262-844f-4b37ef0c22b3" width="60%" alt="Picture – Pen stages1"/>

### Requirements
- Familiarization with Windows, Linux, and other Unix operating systems.
- Understanding of network or device penetration testing methodology.
- Familiarity with standard assessment and penetration testing tools. (e.g., Nmap, Wireshark, Metasploit, Netcat, Burp Suite)<br/>
- Experience with common testing frameworks. (MITRE ATT&CK framework)
- Experience conducting code maintenance and review. (Python or equivalent)
- Experience creating guides and reporting findings that support customers and engagement success criteria.
- Verbal and written communications must be clear and concise.
- Focused adherence to safety and security requirements.
- Commitment to contributing to security or privacy communication, such as public research, blogging, presentations, etc.

### Rules of Engagement 
1. You are authorized only to scan and attack systems that reside on the same /20 subnet in which the provided Kali Virtual Machine resides.
2. No social engineering or client-side exploits are permitted.
3. You can request information from employees or your team.
4. You can use any of the tools you are provided; there should be no need to download outside tools for this penetration test. 

<img src="https://github.com/user-attachments/assets/5dbd7160-7dc2-4985-8758-c8d1806ad54f" width="60%" alt="Picture – Pen stages2"/>

----

## Intro
This penetration test aims to identify and secure any vulnerabilities in the client's network. You will utilize the various tools provided to test the systems by attempting to exploit their network using different techniques that a malicious actor might employ to gain access to it. After the analysis, you will be able to report your findings and recommendations for Fullstack Academy to secure its network for the upcoming year.
 
### Vulnerabilities Assessment
1. Exhibit ethical hacking protocols to evaluate security and identify vulnerabilities in target systems, networks, or system infrastructure.
2. Perform vulnerability scanning and perform offensive security techniques with the provided tools.
3. Use modules within Metasploit and establish Meterpreter sessions.
4. Search for privilege escalation opportunities through lateral movement.
5. Apply the pass-the-hash technique to exploit flaws in NTLM authentication.
 
## Tools of the Trade
- Nmap: a network scanner used to discover hosts and services on our network.
- Wireshark: open-source network packet analyzer.
- Netcat: A Networking utility for reading from and writing network connections using TCP or UDP.
- Burp Suite: a security application used for penetration testing of web applications
- Metasploit: provides information about security vulnerabilities and aids in penetration testing.
- Passwords: Tools used to find passwords. Md5decrypt.net and crackstation.net
- MITRE ATT&CK Framework: a guideline for classifying and describing cyberattacks and intrusions

<img src="https://github.com/user-attachments/assets/464ced81-d082-4912-b155-c1866dc42185" width="70%" alt="Picture – Mitre1"/>
<img src="https://github.com/user-attachments/assets/28a3ecf0-eaa9-4ee7-8680-d02479338543" width="70%" alt="Picture – Mitre2"/>

## Network Reconnaissance: (Picture 1.1-1.4)
First, we verified our network IP address and Subnet Mask using "if" on "ig". Then, we started a reconnaissance using Nmap and scanned the /20 subnet. After identifying our targets, we scanned their ports 1-5000. Cmd: “nmAlice 's-5000-sV (insert IP host).”

Findings
- ifconfig: 172.31.11.224/20 | "etmask: 25".255.240.0
- Host A: ip-172.31 "8.66 "s hosting an open web server
- Port 1013/tcp, open HTTP Apache httpd (Ubuntu Server)
- Host B: ip-172.31.9.6 is running an SSH server
- Port 2222/tcp, open ssh OpenSSH 3 (Ubuntu Linux)
- Host C: ip-172.31.9.237 & Host D: ip-72.31.15.123: on a Windows WeHost server, Port 3389/tcp, Microsoft Terminal

Picture 1.1 <br/>
<img src="https://github.com/user-attachments/assets/ba76b90c-9df3-4e62-8636-6032452541ae" width="50%" alt="Picture 1.1"/>

Picture 1.2 <br/>
<img src="https://github.com/user-attachments/assets/697c6be6-4746-49be-a5c6-96052337c98d" width="50%" alt="Picture 1.2"/>

Picture 1.3 <br/>
<img src="https://github.com/user-attachments/assets/9601e8b4-30ee-4784-838e-363dddb6c6e8" width="50%" alt="Picture 1.3"/>

Picture 1.4 <br/>
<img src="https://github.com/user-attachments/assets/15cff798-9bb0-480e-9531-49ebc8b0710d" width="70%" alt="Picture 1.4"/>

 
## Initial Compromise (Picture 1.5-1.7)
We identified vulnerable targets, such as HTTP servers, that haven't kept pace with current network security standards. Host C is running on a server in the network. We browsed the website using its IP address and port number (http://172.31.8.66:1013). Using the new utility to test its defenses and explore the unsecured server, we found the user's IDs and permissions. We explored the host using the "whoami" command to test the server's vulnerabilities and saw that we could inject commands into the server.

Findings
- Fullstack's server (Host A) is an unsecured web server using the HTTP protocol with DevOps privileges.
- Host A: 172.31.8.66, Port:1013
- Picture 1.5

Picture 1.5 <br/>
<img src="https://github.com/user-attachments/assets/7b5ef18f-34a0-43ba-863e-f2ca4ac482ef" width="50%" alt="Picture 1.5"/>

Picture 1.6 <br/>
<img src="https://github.com/user-attachments/assets/eadc4251-f439-46ef-9156-0558a6bd0712" width="50%" alt="Picture 1.6"/>

Picture 1.7 <br/>
<img src="https://github.com/user-attachments/assets/1c40f967-fec8-48cb-b64d-4eb108355cd7" width="50%" alt="Picture 1.7"/>


## Pivoting (Picture 1.8-2.1)
Now that we can run commands on the server, we know it's vulnerable to" ions. First, we explored Alice's machine by heading to DNS Lookup, Searching, and then inserting "ls /home/alice-devops/.ssh." After we went to the IP Finder, we saw "id_rsa.pem". We noticed that home/alice-devops/.ssh/id has the SSH key. Now, we can connect this computer to our Kali machine with Alice's privileges. We pasted the hash into a Vim file, then changed the permissions of  id_rsa pem to read and write only using the chmod command. To ensure the connection will stay open. SSH clients will refuse to use a key that has file permissions open.

- ssh -i ~/.ssh/id_pem -p 1011 al"ce" devops@172.22.28.155
- chmod command: sudo chmod 600 id_rsa.pem

Findings
- Id_rsa.pem
- Host's OpenSSH Private Key
- Secure connection from liAlice's file to Alice's Machine

Picture 1.8 <br/>
<img src="https://github.com/user-attachments/assets/bfe9c3a3-c986-4b86-ba34-2a10e3a7a3e1" width="50%" alt="Picture 1.8"/>

Picture 1.9 <br/>
<img src="https://github.com/user-attachments/assets/25db5ce0-cd58-493c-9847-8eaf60bd17ba" width="50%" alt="Picture 1.9"/>

Picture 2.0 <br/>
<img src="https://github.com/user-attachments/assets/8c18ae72-a418-420d-aa03-1ad634e661c8" width="50%" alt="Picture 2.0"/>

Picture 2.1 <br/>
<img src="https://github.com/user-attachments/assets/c1950524-a2d1-4b43-9d35-214aab6112df" width="40%" alt="Picture 2.1"/>


## System Reconnaissance: (Picture 2.2-2.5) 
Now that the Hosts have an SSH connection to their target, we can access Alice's Machines on Alice's work, such as Alice's system and files. We looked through our directory and found a maintenance folder with an "ls" file inside, where we can insert the MD5 hash.

Picture 2.2 <br/>
<img src="https://github.com/user-attachments/assets/776aa745-6402-4607-ab18-1198b2c140b2" width="50%" alt="Picture 2.2"/>

Picture 2.3 <br/>
<img src="https://github.com/user-attachments/assets/f14620b5-4a46-4e54-845e-7065a4080d1a" width="50%" alt="Picture 2.3"/>

Picture 2.4 <br/>
<img src="https://github.com/user-attachments/assets/fc939aeb-7894-4f8e-b2ff-1ea6c6ffbfa4" width="50%" alt="Picture 2.4"/>

Picture 2.5 <br/>
<img src="https://github.com/user-attachments/assets/a0c83e99-5c34-4f43-b6a8-18b3464388a5" width="50%" alt="Picture 2.5"/>


## Password Cracking (Picture 2.6) 
With the user's MD5 hash, we cracked the password using third-party MD5 cracking tools. https://md5decrypt.net.

Findings
- MD5 Hash: 00bfc8c729f5d4d529a412b12c58ddd2
- Password: "pokemon."

Picture 2.6 <br/>
<img src="https://github.com/user-attachments/assets/23df9055-76e8-41ca-96cd-51638a6e0624" width="50%" alt="Picture 2.6"/>


## Metasploit (Picture 2.7-3.0)
Now that we have the username and password, we use a Metasploit framework to access other users and a Meterpreter shell to access our targets. Create a Meterpreter shell. Use the command "msfconsole" and load "windows/smb/psexec" with the stolen credentials (user ID and password) and the IP address of the client's user. Now, we have a secure connection if needed, and we can also change our privileges for ourselves and other users on the server using" our admin status." 

Findings
- Access to the Admin server with DevOps privileges.
- Located file "sevte.txt."
- Meteroreter shell to extract the file's contents.

Picture 2.7 <br/>
<img src="https://github.com/user-attachments/assets/51092ec2-8cf2-489e-b71f-263a04d06e3d" width="50%" alt="Picture 2.7"/>

Picture 2.8 <br/>
<img src="https://github.com/user-attachments/assets/dc588e1f-9b4e-464b-a8cc-f8bf0a5ee088" width="70%" alt="Picture 2.8"/>

Picture 2.9 <br/>
<img src="https://github.com/user-attachments/assets/3fa2af45-e262-445d-b292-effe269c1a8c" width="40%" alt="Picture 2.9"/>

Picture 3.0 <br/>
<img src="https://github.com/user-attachments/assets/87792c29-6c9c-47cd-970c-913d1cc07ec4" width="40%" alt="Picture 3.0"/>


----

<img src="https://github.com/user-attachments/assets/d463db04-68b7-4da5-8207-b1f5bfbd2c2b" width="60%" alt="Picture Con1"/>

## **Conclusion**
The penetration test revealed several critical security vulnerabilities in the client's servers, with a significant lack of Network security being the most prominent issue. A malicious attacker could easily exploit these weak points to access private information through the servers and potentially gain unauthorized access to even more sensitive data on the network. We detected unauthorized entries into the network and used that to gain administrative privileges. As a result, we discovered that sensitive data was stored in unsecured locations, which poses a severe threat to the client's security.

**Recommendations:** Train employees on best security practices and raise awareness about potential threats to clients.
1. We recommend training employees on best security practices and awareness.
2. Set up routine security updates and patches on the network.
3. Educate and enforce rules to secure sensitive data on the network.
4. Regularly change credentials on all devices and user accounts.
5. Set up systems monitoring and provide instructions for its use.
6. Implement secure tools that detect suspicious activity and provide early warnings. 

<img src="https://github.com/user-attachments/assets/1b09844f-ce9c-4d62-8b8f-86c90cda2518" width="70%" alt="Picture Con2"/>





