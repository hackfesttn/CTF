# Memory Forensics Lab

**Introduction**
Memory forensic refers to the process of investigating a memory dump to locate malicious behaviors. The dump is a snapshot capture of RAM memory at a specific point of time; it can be a full physical memory dump, a crash dump or a hibernation file.

**Goal**
As investigator, this lab will guide you to extract useful artifacts from a given memory snapshot, including running processes, URLs, passwords, encryption keys, open sockets and active connections, open registry keys. That information can be accessed by obtaining and analyzing the target computer’s physical memory dump. A general approach of this lab would be acquire physical memory and analyze of collected physical memory. The memory acquisition has been already done for you. You will proceed in analyzing the collected memory dump, for each step you will be asked to answer a specific question. 

**Attachment** 
Memory dump acquisition for this lab has been performed using “DumpIt” program which has been already installed on the system where the memory dump has been acquired. 

**Scenario** 
A machine has been compromised by a malware and important files have been encrypted. Our job as memory forensics expert is determine how the malware went into the machine, understand its internal and attempt to recover the important file.

Q1: What is the Operating System of the machine being investigated?

> Author: maro

**Attachment**: [https://drive.google.com/file/d/1gnvkBteAa4idK12yPV1VE5Z3MZKPKW3u/view?usp=sharing](https://drive.google.com/file/d/1gnvkBteAa4idK12yPV1VE5Z3MZKPKW3u/view?usp=sharing)

## Q1: What is the Operating System of the machine being investigated?

**Solves**: 22

**Flag**:  *Win7SP1x64*

**Write-up**:

## Q2: What is the maro’s system password ?

**Solves**: 13

**Flag**:  *aVVj4jjKmHZYensV*

**Write-up**:


## Q3: What is the computer Name ?

**Solves**: 23

**Flag**:  *LAB-VM-C57C*

**Write-up**:

## Q4: What is the IP address of the machine ?

**Solves**: 23

**Flag**:  *10.0.2.15*

**Write-up**:

## Q5: What is the IRC client Software used by the user ?

**Solves**: 23

**Flag**:  *mIRC*

**Write-up**:


## Q6: What is the user’s IRC account Password ?

**Solves**: 18

**Flag**:  *uFB646Vm9CscCwzR*

**Write-up**:


## Q7: What is the user’s IRC account Password ?

**Solves**: 18

**Flag**:  *freenode_infosec*

**Write-up**:


## Q8: What is the Nickname of the attacker? What is the suspicious URL visited by the victim? 

**Solves**: 12

**Flag**:  *bitsmasher_codewaver_https://file.io/yBBkJc*

**Write-up**:

## Q9: What is the suspucious file that has been downloaded ?

**Solves**: 12

**Flag**:  *CyberSecurity_Books_Courses_Tutorials.exe.torrent*

**Write-up**:


## Q10: What is the torrent site/url ?

**Solves**: 1

**Flag**:  *bit.smasher.io/torrent-infected-k19*

**Write-up**:


## Q11: What is the malware's process name ?

**Solves**: 16

**Flag**:  *crypt0r.exe*

**Write-up**:


## Q12: What is the type of this malware? Is it a known malware ?

**Solves**: 12

**Flag**:  *Ransomware_HiddenTear*

**Write-up**:


## Q13: What is the Bitcoin address of the attacker ?

**Solves**: 9

**Flag**:  *13gwqwqH1h7UYFvyyuD9yjD1vg5yUmS682*

**Write-up**:

## Q14: What is the malware's control server ?

**Solves**: 5

**Flag**:  *http://www.bitsmasher.me/victimes.php?info=LAB-VM-C57C-maro%20WtscbSEbLmfh2AJ*

**Write-up**:


## Q15: What is the Encryption password ?

**Solves**: 4

**Flag**:  *WtscbSEbLmfh2AJ*

**Write-up**:


## Q16: Recover the secret !

**Solves**: 3

**Flag**:  *JcE2gHzp6C9ykkQZ*

**Write-up**: