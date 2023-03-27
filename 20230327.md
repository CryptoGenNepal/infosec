---
title: "Mar 26, 2023"
date: 2023-03-26T00:00:00+05:45
draft: false
logo: "images/infosec/default.png"
---

{{< toc >}}

### Jenkins Security Alert: New Security Flaws Could Allow Code Execution Attacks

##### Description
The U.S. FBI, the CISA, and the MS-ISAC have released a joint cybersecurity advisory detailing the IoCs and TTPs associated with the LockBit 3.0 ransomware. The LockBit 3.0 ransomware functions as a RaaS model and is a continuation of previous versions of the ransomware, LockBit 2.0, and LockBit. LockBit actors invested significant technical efforts to develop and fine-tune its malware, issuing two major updates. LockBit 3.0 accepts additional arguments for specific operations in lateral movement and rebooting into Safe Mode. The ransomware is designed to infect only those machines whose language settings do not overlap with those specified in an exclusion list. Initial access to victim networks is obtained via remote desktop protocol (RDP) exploitation, drive-by compromise, phishing campaigns, abuse of valid accounts, and weaponization of public-facing applications. LockBit affiliates have been observed using various freeware and open-source tools during their intrusions. One defining characteristic of the attacks is the use of a custom exfiltration tool referred to as StealBit, which the LockBit group provides to affiliates for double extortion purposes. The LockBit ransomware strain has been used against at least 1,000 victims worldwide, netting the operation over $100 million in illicit profits. LockBit 3.0 was responsible for 21% of 189 ransomware attacks detected against critical infrastructure in Q4 2022, accounting for 40 incidents. Despite LockBit's prolific attack spree, the ransomware gang suffered a huge blow in late September 2022 when a disgruntled LockBit developer released the builder code for LockBit 3.0, raising concerns that other criminal actors could take advantage of the situation and spawn their own variants. The advisory comes as the BianLian ransomware group has shifted its focus from encrypting its victims' files to pure data-theft extortion attacks.

##### Infected Technology
Software and Applications

##### Source
https://thehackernews.com/2023/03/lockbit-30-ransomware-inside.html

##### Recommendation
•	Keep software and operating systems up to date.
•	Use strong and unique passwords and enable two-factor authentication.
•	Limit access to sensitive data and systems
•	Use reliable antivirus and endpoint protection software.
•	Regularly back up data and store backups offline


----------------

### New ‘HinataBot’ botnet could launch massive 3.3 Tbps DDoS attacks

##### Description
A new malware botnet called HinataBot has been discovered by researchers at Akamai that targets Realtek SDK, Huawei routers, and Hadoop YARN servers to recruit devices into a DDoS swarm. The malware is based on Mirai and is a Go-based variant. It exploits old vulnerabilities such as CVE-2014-8361 and CVE-2017-17215 and is under active development, featuring functional improvements and anti-analysis additions. The malware is distributed by brute forcing SSH endpoints or using infection scripts and RCE payloads. Once infected, the malware waits for commands to be executed from the command-and-control server. HinataBot supports HTTP and UDP floods and can potentially perform powerful distributed denial of service attacks. With 1,000 nodes, the UDP flood could generate roughly 336 Gbps, while at 10,000 nodes, the attack data volume would reach 3.3 Tbps. The researchers warn that HinataBot is still in development, and more potent versions may circulate soon, increasing the likelihood of dealing with their botnet at any real scale.

##### Infected Technology
Realtek SDK
Huawei routers
Hadoop YARN servers

##### Source
https://www.bleepingcomputer.com/news/security/new-hinatabot-botnet-could-launch-massive-33-tbps-ddos-attacks/

##### Recommendation
•	Update software and hardware
•	Use strong passwords and change default credentials.
•	Use network segmentation


----------------

### Unauthenticated deserialization vulnerability in the BuddyForms WordPress plugin.

##### Description
The vulnerability was present in a function called 'buddyforms_upload_image_from_url()', which was used to upload images to a WordPress website. The vulnerability was related to the way the function handled untrusted input provided through the 'url' parameter. Specifically, the function allowed for the deserialization of this input, which could be manipulated by an attacker to execute arbitrary PHP code on the target system. An unauthenticated attacker could take advantage of this vulnerability by leveraging the 'url' parameter to call files using a PHAR wrapper. PHAR is a file format used for packaging and distributing PHP applications. By using a PHAR wrapper, the attacker could trick the function into deserializing the input data and executing arbitrary PHP code contained within the PHAR archive. Once the attacker has executed arbitrary PHP code on the target system, they could potentially perform a variety of malicious actions. For example, they could install a backdoor, steal sensitive data, or modify website content to serve malware to unsuspecting visitors. However, it's important to note that for the attacker to perform these actions, they would also need to have a POP chain present. A POP chain is a sequence of steps that an attacker can use to gain control of a target system. Without a POP chain, the attacker would not be able to fully exploit the vulnerability and carry out malicious actions.


##### Infected Technology
Wordpress plugin

##### Source
https://www.tenable.com/security/research/tra-2023-7

##### Recommendation
•	Update the plugin to latest version

##### CVE ID
CVE-2023-26326

----------------

### Python info-stealing malware uses Unicode to evade detection

##### Description
A recent discovery by cybersecurity experts has highlighted the potential misuse of Unicode for Python obfuscation. A malicious Python package named "onyxproxy" was found on PyPI using this technique to avoid detection while stealing sensitive data and credentials from developers. The package uses a combination of different Unicode fonts in its source code to evade automated scans and defenses that identify potentially malicious functions based on string matching. While the text in the code strings may appear normal to the human eye, the different fonts cause Python interpreters to parse and recognize them as fundamentally different. The discovery of "onyxproxy" underscores the need for more robust cybersecurity measures to prevent and detect malicious packages on PyPI and other platforms. This case also serves as a reminder of the importance of being vigilant and cautious when downloading and using third-party packages in your projects. While Python's Unicode support is an essential feature, it can also be misused to hide malicious behavior, as demonstrated by "onyxproxy." It is crucial to keep abreast of potential threats and regularly review the packages and libraries you use to ensure they are legitimate and secure.

##### Infected Technology
Python

##### Source
https://www.bleepingcomputer.com/news/security/python-info-stealing-malware-uses-unicode-to-evade-detection/

##### Recommendation
•	Keep software up-to-date and apply any security patches promptly to protect against known vulnerabilities that could be exploited by malicious packages.

----------------

### Microsoft Warns of Stealthy Outlook Vulnerability Exploited by Russian Hackers

##### Description
Microsoft has provided guidance to help customers detect indicators of compromise (IoCs) associated with a recently patched Outlook vulnerability. The vulnerability, CVE-2023-23397, which was rated as critical with a CVSS score of 9.8, could be used for privilege escalation and allow threat actors to steal NT Lan Manager (NTLM) hashes to stage a relay attack without any user interaction. Microsoft released a security advisory this month noting that external attackers could send specially crafted emails, which would enable them to leak Net-NTLMv2 hash to an untrusted network. The vulnerability was resolved by Microsoft as part of its March 2023 Patch Tuesday updates. However, Russia-based threat actors had already weaponized the flaw to target the government, transportation, energy, and military sectors in Europe. Microsoft has advised organizations to review network telemetry, such as SMBClient event logging and process creation events, to identify potential exploitation via CVE-2023-23397. Meanwhile, the US Cybersecurity and Infrastructure Security Agency has released a new open-source incident response tool that helps detect malicious activities in Microsoft cloud environments.

##### Infected Technology
Microsoft Outlook

##### Source
https://thehackernews.com/2023/03/microsoft-warns-of-stealthy-outlook.html

##### Recommendation
•	Install the latest security patches released by Microsoft.
•	Use end point protection.
