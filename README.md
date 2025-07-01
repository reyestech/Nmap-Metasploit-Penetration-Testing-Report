![Pentest Report Nmap   Metasploit - Intro](https://github.com/user-attachments/assets/1aaeaf5f-b0ce-4417-9873-9fdfcc4f84e2)

<h1>  Pentest Report: Nmap & Metasploit </h1>
Hector M. Reyes | SOC Analyst | Stackfull Software

[Google Docs Link | Penetration Test Report: Stackfull Software](https://docs.google.com/document/d/1X72cU_1jIgYPHmP03cnkLb6wkyNlgnKByCiVYdV3znM/pub)

![Pentest Report Nmap   Metasploit - Stackfull](https://github.com/user-attachments/assets/b067990e-977d-462d-bcb2-81f8001a5050)

----

![Pentest Report Nmap   Metasploit - Tools](https://github.com/user-attachments/assets/b5c3df39-168b-4b46-9343-39ed36b0a98c)

## Scenario
Your team has been assigned as the offensive security team for Stackfull Software. The team will validate internal security controls to see whether current protocols will protect the Stackfull Software organization's clients. The team will provide services to external clients to validate their security controls. One of your clients, Fullstack Academy, has assigned your team to conduct a penetration test on an isolated network.

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

![Picture – Pen stages1](https://github.com/user-attachments/assets/fd2254d7-f423-4262-844f-4b37ef0c22b3)

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


![Picture – Pen stages2](https://github.com/user-attachments/assets/5dbd7160-7dc2-4985-8758-c8d1806ad54f)

## Intro
This penetration test aims to identify and secure any vulnerabilities in the client's network. You will use the various tools provided to test the systems by attempting to exploit their network using different techniques that a malicious actor might use to access it. After the analysis, you will be able to report your findings and recommendations for Fullstack Academy to secure its network for the upcoming year.
 
### Vulnerabilities Assessment
1. Exhibit ethical hacking protocols to evaluate security and identify vulnerabilities in target systems, networks, or system infrastructure.
2. Perform vulnerability scanning and perform offensive security techniques with the provided tools.
3. Use modules within Metasploit and establish Meterpreter sessions.
4. Search for privilege escalation opportunities through lateral movement.
5. Apply the pass-the-hash technique to exploit flaws in NTLM authentication.
 
## Tools of the Trade
- Nmap: a network scanner used to discover hosts and services on our network.
- Wireshark: open-source network packet analyzer.
- Netcat: Networking utility for reading from and writing network connections using TCP or UDP.
- Burp Suite: security application used for penetration testing of web applications
- Metasploit: provides information about security vulnerabilities and aids in penetration testing.
- Passwords: Tools used to find passwords. Md5decrypt.net and crackstation.net
- MITRE ATT&CK Framework: a guideline for classifying and describing cyberattacks and intrusions
  

![Picture – Mitre1](https://github.com/user-attachments/assets/464ced81-d082-4912-b155-c1866dc42185)
![Picture – Mitre2](https://github.com/user-attachments/assets/28a3ecf0-eaa9-4ee7-8680-d02479338543)


## Network Reconnaissance: (Picture 1.1-1.4)
First, we verified our network IP address and Subnet Mask using "if" on "ig". Then, we started a reconnaissance using Nmap and scanned the /20 subnet. After identifying our targets, we scanned their ports 1-5000. Cmd: “nmAlice 's-5000 -sV (insert IP host).”

Findings
- ifconfig: 172.31.11.224/20 | "etmask: 25".255.240.0
- Host A: ip-172.31 "8.66 "s hosting an open web server
- Port 1013/tcp, open HTTP Apache httpd (Ubuntu Server)
- Host B: ip-172.31.9.6 is running an SSH server
- Port 2222/tcp, open ssh OpenSSH 3 (Ubuntu Linux)
- Host C: ip-172.31.9.237 & Host D: ip-72.31.15.123: on a Windows WeHost server, Port 3389/tcp, Microsoft Terminal
 
Picture 1.1 <br/>
![image](https://github.com/user-attachments/assets/27efeff6-a411-4f03-bc3a-1ac433269ef9)

![Picture 1 1](https://github.com/user-attachments/assets/ba76b90c-9df3-4e62-8636-6032452541ae)


Picture 1.2 <br/>
![image](https://github.com/user-attachments/assets/26769f0e-b46a-41c8-b87f-ab739283ba51)

![Picture 1 2](https://github.com/user-attachments/assets/697c6be6-4746-49be-a5c6-96052337c98d)

Picture 1.3 <br/>
![image](https://github.com/user-attachments/assets/d1f67d30-519c-4581-8119-0fdd72c69621)

![Picture 1 3](https://github.com/user-attachments/assets/9601e8b4-30ee-4784-838e-363dddb6c6e8)

Picture 1.4 <br/>
![image](https://github.com/user-attachments/assets/6d831b4e-cf4a-4f4a-ae3f-5ab149dcdae8)

![Picture 1 4](https://github.com/user-attachments/assets/15cff798-9bb0-480e-9531-49ebc8b0710d)

 
## Initial Compromise (Picture 1.5-1.7)
We looked for vulnerable targets, such as HTTP servers, that haven't kept up with current network security standards. Host C is running on a server in the network. We browsed the website using its IP address and port number (http://172.31.8.66:1013). Using the new utility to test its defenses and explore the unsecured server, we found the user's IDs and permissions. We explored the host using the "whoami" command to test the server's vulnerabilities and saw that we could inject commands into the server.

Findings
- Fullstack's server (Host A) is an unsecured web server using the HTTP protocol with DevOps privileges.
- Host A: 172.31.8.66, Port:1013
- Picture 1.5
 
Picture 1.5 <br/>
![image](https://github.com/user-attachments/assets/a5175714-2607-43fa-ac41-c8b65f73b2ab)

![Picture 1 5](https://github.com/user-attachments/assets/7b5ef18f-34a0-43ba-863e-f2ca4ac482ef)


Picture 1.6 <br/>
![image](https://github.com/user-attachments/assets/01c9de46-c8df-4308-b550-d930a51e8b96)

![Picture 1 6](https://github.com/user-attachments/assets/eadc4251-f439-46ef-9156-0558a6bd0712)


## Pivoting (Picture 1.7-2.0)
Now that we can run commands on the server, we know it's vulnerable to" ions. First, we explored Alice's machine by heading to DNS Lookup, Searching, and then inserting "ls /home/alice-devops/.ssh." After we went to the IP Finder, we saw "id_rsa.pem". We noticed that home/alice-devops/.ssh/id has the SSH key. Now, we can connect this computer to our Kali machine with Alice's privileges. We pasted the hash into a Vim file, then changed the permissions of  id_rsa pem to read and write only using the chmod command. To ensure the connection will stay open. SSH clients will refuse to use a key that has file permissions open.

- ssh -i ~/.ssh/id_pem -p 1011 al"ce" devops@172.22.28.155
- chmod command: sudo chmod 600 id_rsa.pem

Findings
- Id_rsa.pem
- Host's OpenSSH Private Key
- Secu" e connection from file' liAlice's to Alice's Machine

Picture 1.7 <br/>
![image](https://github.com/user-attachments/assets/8e06c6db-6d53-4c81-aea2-c0f3483ca6bf)

![Picture 1 7](https://github.com/user-attachments/assets/1c40f967-fec8-48cb-b64d-4eb108355cd7)


Picture 1.8 <br/>
![image](https://github.com/user-attachments/assets/603bfdb1-a63c-408d-acfd-761a73520af4)

![Picture 1 8](https://github.com/user-attachments/assets/bfe9c3a3-c986-4b86-ba34-2a10e3a7a3e1)


Picture 1.9 <br/>
![image](https://github.com/user-attachments/assets/c03d66e5-5002-4451-bb74-23ad5ed71076)

![Picture 1 9](https://github.com/user-attachments/assets/25db5ce0-cd58-493c-9847-8eaf60bd17ba)


Picture 2.0 <br/>
![image](https://github.com/user-attachments/assets/73c0499b-a0f7-4253-b689-6afa975e5574)

![Picture 2 0](https://github.com/user-attachments/assets/8c18ae72-a418-420d-aa03-1ad634e661c8)


## System Reconnaissance: (Picture 2.1-2.4) 
Now that the Hosts have an SSH connection to their target, we can access Alice's Machines on Alice's work, such as Alice's system and files. We looked through our directory and found a maintenance folder with an "ls" file inside, where we can insert the MD5 hash.

Picture 2.1<br/>
![image](https://github.com/user-attachments/assets/b8eee3d6-c4b6-43c3-b3c1-363eb2455d03)

![Picture 2 1](https://github.com/user-attachments/assets/c1950524-a2d1-4b43-9d35-214aab6112df)


Picture 2.2 <br/>
![image](https://github.com/user-attachments/assets/d7588245-710b-41f6-997a-916dc29fa282)

![Picture 2 2](https://github.com/user-attachments/assets/776aa745-6402-4607-ab18-1198b2c140b2)

  
Picture 2.3 <br/>
![image](https://github.com/user-attachments/assets/678deb0a-4fa9-4512-ba85-be0e80ea6a9e)

![Picture 2 3](https://github.com/user-attachments/assets/f14620b5-4a46-4e54-845e-7065a4080d1a)

 
Picture 2.4 <br/>
![image](https://github.com/user-attachments/assets/05b206f5-a85f-4f56-bb28-14ab913394bd)

![Picture 2 4](https://github.com/user-attachments/assets/fc939aeb-7894-4f8e-b2ff-1ea6c6ffbfa4)

 
We cracked the password for the host's client's user's MD5 hash using third-party cracking tools.
- https://md5decrypt.net. 
 
Findings
- MD5 Hash: 00bfc8c729f5d4d529a412b12c58ddd2
- Password: "pokemon."
 
Picture 2.5 <br/>
![image](https://github.com/user-attachments/assets/be63a570-3b09-467f-b8f4-a688786ffbff)

![Picture 2 5](https://github.com/user-attachments/assets/a0c83e99-5c34-4f43-b6a8-18b3464388a5)


## Metasploit (Picture 2.6-2.)
Now that we have the username and password, we use a Metasploit framework to access other users and a Meterpreter shell to access our targets. Create a Meterpreter shell. Use the command "msfconsole" and load "windows/smb/psexec" with the stolen credentials (user ID and password) and the IP address of the client's user. Now, we have a secure connection if needed, and we can also change our privileges for ourselves and other users on the server using" our admin status." 

Findings
- Access to Admin server with DevOps privileges.
- Located file "sevte.txt."
- Meteroreter shell to extract the file's contents.

Picture 2.6 <br/>
![image](https://github.com/user-attachments/assets/44c6341c-13e6-41c4-80c0-984147bd9d3c)

![Picture 2 6](https://github.com/user-attachments/assets/23df9055-76e8-41ca-96cd-51638a6e0624)


Picture 2.7 <br/>
![image](https://github.com/user-attachments/assets/f782c0ae-6dfa-47a4-a142-e5e5948c39a5)

![Picture 2 7](https://github.com/user-attachments/assets/51092ec2-8cf2-489e-b71f-263a04d06e3d)


Picture 2.8 <br/>

![image](https://github.com/user-attachments/assets/4e630742-21d1-489e-b979-89e1ec838344)

![Picture 2 8](https://github.com/user-attachments/assets/dc588e1f-9b4e-464b-a8cc-f8bf0a5ee088)



Picture 2.9 <br/>
![image](https://github.com/user-attachments/assets/e7f13eac-3ac3-4aa0-b45f-ed674d9b2cef)

![Picture 2 9](https://github.com/user-attachments/assets/3fa2af45-e262-445d-b292-effe269c1a8c)


Picture 3.0 <br/>
![image](https://github.com/user-attachments/assets/69f46517-2d35-4c73-bbe9-f17a5e670be8)

![Picture 3 0](https://github.com/user-attachments/assets/87792c29-6c9c-47cd-970c-913d1cc07ec4)


----

![Picture Con1](https://github.com/user-attachments/assets/d463db04-68b7-4da5-8207-b1f5bfbd2c2b)

## Conclusion
The penetration test revealed several critical security vulnerabilities in the client's servers, with a significant lack of Network security being the most prominent issue. A malicious attacker could easily exploit these weak points to access private information through the servers and potentially gain unauthorized access to even more sensitive data on the network. We detected unauthorized entries into the network and used that to gain administrative privileges. As a result, we discovered that sensitive data was stored in unsecured locations, which poses a severe threat to the client's security.

Recommendations: Train employees on best security practices and raise awareness about potential threats to clients.
> 1. We recommend training employees on best security practices and awareness.
> 2. Set up routine security updates and patches on the network.
> 3. Educate and enforce rules to secure sensitive data on the network.
> 4. Regularly change credentials on all devices and user accounts. 
> 5. Set up systems monitoring and provide instructions for its use.
> 6. Implement secure tools that detect suspicious activity and provide early warnings. 

![Picture Con2](https://github.com/user-attachments/assets/1b09844f-ce9c-4d62-8b8f-86c90cda2518)





