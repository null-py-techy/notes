Nmap Scripting Engine (`NSE`) is another handy feature of `Nmap`. It provides us with the possibility to create scripts in Lua for interaction with certain services. There are a total of 14 categories into which these scripts can be divided:

| **Category** | **Description**                                                                                                                         |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| `auth`       | Determination of authentication credentials.                                                                                            |
| `broadcast`  | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| `brute`      | Executes scripts that try to log in to the respective service by brute-forcing with credentials.                                        |
| `default`    | Default scripts executed by using the `-sC` option.                                                                                     |
| `discovery`  | Evaluation of accessible services.                                                                                                      |
| `dos`        | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services.              |
| `exploit`    | This category of scripts tries to exploit known vulnerabilities for the scanned port.                                                   |
| `external`   | Scripts that use external services for further processing.                                                                              |
| `fuzzer`     | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time.     |
| `intrusive`  | Intrusive scripts that could negatively affect the target system.                                                                       |
| `malware`    | Checks if some malware infects the target system.                                                                                       |
| `safe`       | Defensive scripts that do not perform intrusive and destructive access.                                                                 |
| `version`    | Extension for service detection.                                                                                                        |
| `vuln`       | Identification of specific vulnerabilities.                                                                                             |
 Use NSE and its scripts to find the flag that one of the services contain and submit it as the answer.
 ->HTB{873nniuc71bu6usbs1i96as6dsv26}

```sudo nmap -p 80 --script=http-enum,http-title,http-headers,http-methods 10.129.185.221

Deploying root access for null. Password pls:
Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-22 20:21 +0545
Nmap scan report for 10.129.185.221 (10.129.185.221)
Host is up (0.26s latency).

PORT   STATE SERVICE
80/tcp open  http
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
| http-headers:
|   Date: Mon, 22 Sep 2025 14:36:22 GMT
|   Server: Apache/2.4.29 (Ubuntu)
|   Last-Modified: Thu, 10 Sep 2020 02:14:12 GMT
|   ETag: "2c39-5aeec1fc9d59d"
|   Accept-Ranges: bytes
|   Content-Length: 11321
|   Vary: Accept-Encoding
|   Connection: close
|   Content-Type: text/html
|
|_  (Request type: HEAD)
| http-enum:
|_  /robots.txt: Robots file

Nmap done: 1 IP address (1 host up) scanned in 56.42 seconds
```
it was inside robots.txt
