```
nmap -sV -p 22,80,139,445,110,143 10.129.25.255
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-22 20:33 +0545
Nmap scan report for 10.129.25.255 (10.129.25.255)
Host is up (0.32s latency).

PORT    STATE    SERVICE      VERSION
22/tcp  open     ssh          OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp  open     http         Apache httpd 2.4.29 ((Ubuntu))
110/tcp filtered pop3
139/tcp filtered netbios-ssn
143/tcp filtered imap
445/tcp filtered microsoft-ds
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.46 seconds
```

Our client wants to know if we can identify which operating system their provided machine is running on. Submit the OS name as the answer.
->Ubuntu
