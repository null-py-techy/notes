#### Helpful TCPDump Filters

| **Filter**           | **Result**                                                                                               |
| -------------------- | -------------------------------------------------------------------------------------------------------- |
| host                 | `host` will filter visible traffic to show anything involving the designated host. Bi-directional        |
| src / dest           | `src` and `dest` are modifiers. We can use them to designate a source or destination host or port.       |
| net                  | `net` will show us any traffic sourcing from or destined to the network designated. It uses / notation.  |
| proto                | will filter for a specific protocol type. (ether, TCP, UDP, and ICMP as examples)                        |
| port                 | `port` is bi-directional. It will show any traffic with the specified port as the source or destination. |
| portrange            | `portrange` allows us to specify a range of ports. (0-1024)                                              |
| less / greater "< >" | `less` and `greater` can be used to look for a packet or protocol option of a specific size.             |
| and / &&             | `and` `&&` can be used to concatenate two different filters together. for example, src host AND port.    |
| or                   | `or` allows for a match on either of two conditions. It does not have to meet both. It can be tricky.    |
| not                  | `not` is a modifier saying anything but x. For example, not UDP.                                         |
#### Host Filter
```shell-session
[!bash!]$ ### Syntax: host [IP]
[!bash!]$ sudo tcpdump -i eth0 host 172.16.146.2

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
14:50:53.072536 IP 172.16.146.2.48738 > ec2-52-31-199-148.eu-west-1.compute.amazonaws.com.https: Flags [P.], seq 3400465007:3400465044, ack 254421756, win 501, options [nop,nop,TS val 220968655 ecr 80852594], length 37
14:50:53.108740 IP 172.16.146.2.55606 > 172.67.1.1.https: Flags [P.], seq 4227143181:4227143273, ack 1980233980, win 21975, length 92
14:50:53.173084 IP 172.67.1.1.https > 172.16.146.2.55606: Flags [.], ack 92, win 69, length 0
14:50:53.175017 IP 172.16.146.2.35744 > 172.16.146.1.domain: 55991+ PTR? 148.199.31.52.in-addr.arpa. (44)
14:50:53.175714 IP 172.16.146.1.domain > 172.16.146.2.35744: 55991 1/0/0 PTR ec2-52-31-199-148.eu-west-1.compute.amazonaws.com. (107) 
```
This filter is often used when we want to examine only a specific host or server.
 

#### Source/Destination Filter
```shell-session
[!bash!]$ ### Syntax: src/dst [host|net|port] [IP|Network Range|Port]
[!bash!]$ sudo tcpdump -i eth0 src host 172.16.146.2
  
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
14:53:36.199628 IP 172.16.146.2.48766 > ec2-52-31-199-148.eu-west-1.compute.amazonaws.com.https: Flags [P.], seq 1428378231:1428378268, ack 3778572066, win 501, options [nop,nop,TS val 221131782 ecr 80889856], length 37
14:53:36.203166 IP 172.16.146.2.55606 > 172.67.1.1.https: Flags [P.], seq 4227144035:4227144103, ack 1980235221, win 21975, length 68
14:53:36.267059 IP 172.16.146.2.36424 > 172.16.146.1.domain: 40873+ PTR? 148.199.31.52.in-addr.arpa. (44)
14:53:36.267880 IP 172.16.146.2.51151 > 172.16.146.1.domain: 10032+ PTR? 2.146.16.172.in-addr.arpa. (43)
14:53:36.276425 IP 172.16.146.2.46588 > 172.16.146.1.domain: 28357+ PTR? 1.1.67.172.in-addr.arpa. (41)
14:53:36.337722 IP 172.16.146.2.48766 > ec2-52-31-199-148.eu-west-1.compute.amazonaws.com.https: Flags [.], ack 34, win 501, options [nop,nop,TS val 221131920 ecr 80899875], length 0
14:53:36.338841 IP 172.16.146.2.48766 > ec2-52-31-199-148.eu-west-1.compute.amazonaws.com.https: Flags [.], ack 65, win 501, options [nop,nop,TS val 221131921 ecr 80899875], length 0
14:53:36.339273 IP 172.16.146.2.48766 > ec2-52-31-199-148.eu-west-1.compute.amazonaws.com.https: Flags [P.], seq 37:68, ack 66, win 501, options [nop,nop,TS val 221131922 ecr 80899875], length 31
14:53:36.339334 IP 172.16.146.2.48766 > ec2-52-31-199-148.eu-west-1.compute.amazonaws.com.https: Flags [F.], seq 68, ack 66, win 501, options [nop,nop,TS val 221131922 ecr 80899875], length 0
14:53:36.370791 IP 172.16.146.2.32972 > 172.16.146.1.domain: 3856+ PTR? 1.146.16.172.in-addr.arpa. (43)
```

#### Utilizing Source With Port as a Filter
```shell-session
[!bash!]$ sudo tcpdump -i eth0 tcp src port 80

06:17:08.222534 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [S.], seq 290218379, ack 951057940, win 5840, options [mss 1380,nop,nop,sackOK], length 0
06:17:08.783340 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [.], ack 480, win 6432, length 0
06:17:08.993643 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [.], seq 1:1381, ack 480, win 6432, length 1380: HTTP: HTTP/1.1 200 OK
06:17:09.123830 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [.], seq 1381:2761, ack 480, win 6432, length 1380: HTTP
06:17:09.754737 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [.], seq 2761:4141, ack 480, win 6432, length 1380: HTTP
06:17:09.864896 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [P.], seq 4141:5521, ack 480, win 6432, length 1380: HTTP
06:17:09.945011 IP 65.208.228.223.http > dialin-145-254-160-237.pools.arcor-ip.net.3372: Flags [.], seq 5521:6901, ack 480, win 6432, length 1380: HTTP
```

#### Using Destination in Combination with the Net Filter

```shell-session
[!bash!]$ sudo tcpdump -i eth0 dest net 172.16.146.0/24

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
16:33:14.376003 IP 64.233.177.103.443 > 172.16.146.2.36050: Flags [.], ack 1486880537, win 316, options [nop,nop,TS val 2311579424 ecr 263866084], length 0
16:33:14.442123 IP 64.233.177.103.443 > 172.16.146.2.36050: Flags [P.], seq 0:385, ack 1, win 316, options [nop,nop,TS val 2311579493 ecr 263866084], length 385
16:33:14.442188 IP 64.233.177.103.443 > 172.16.146.2.36050: Flags [P.], seq 385:1803, ack 1, win 316, options [nop,nop,TS val 2311579493 ecr 263866084], length 1418
16:33:14.442223 IP 64.233.177.103.443 > 172.16.146.2.36050: Flags [.], seq 1803:4639, ack 1, win 316, options [nop,nop,TS val 2311579494 ecr 263866084], length 2836
16:33:14.443161 IP 64.233.177.103.443 > 172.16.146.2.36050: Flags [P.], seq 4639:5817, ack 1, win 316, options [nop,nop,TS val 2311579495 ecr 263866084], length 1178
16:33:14.443199 IP 64.233.177.103.443 > 172.16.146.2.36050: Flags [.], seq 5817:8653, ack 1, win 316, options [nop,nop,TS val 2311579495 ecr 263866084], length 2836
16:33:14.444407 IP 64.233.177.103.443 > 172.16.146.2.36050: Flags [.], seq 8653:10071, ack 1, win 316, options [nop,nop,TS val 2311579497 ecr 263866084], length 1418
16:33:14.445479 IP 64.233.177.103.443 > 172.16.146.2.36050: Flags [.], seq 10071:11489, ack 1, win 316, options [nop,nop,TS val 2311579497 ecr 263866084], length 1418
16:33:14.445531 IP 64.233.177.103.443 > 172.16.146.2.36050: Flags [.], seq 11489:12907, ack 1, win 316, options [nop,nop,TS val 2311579498 ecr 263866084], length 1418
16:33:14.446955 IP 64.233.177.103.443 > 172.16.146.2.36050: Flags [.], seq 12907:14325, ack 1, win 316, options [nop,nop,TS val 2311579498 ecr 263866084], length 1418
```
#### Protocol Filter - Common Name

```shell-session
[!bash!]$ ### Syntax: [tcp/udp/icmp]
[!bash!]$ sudo tcpdump -i eth0 udp

06:17:09.864896 IP dialin-145-254-160-237.pools.arcor-ip.net.3009 > 145.253.2.203.domain: 35+ A? pagead2.googlesyndication.com. (47)
06:17:10.225414 IP 145.253.2.203.domain > dialin-145-254-160-237.pools.arcor-ip.net.3009: 35 4/0/0 CNAME pagead2.google.com., CNAME pagead.google.akadns.net., A 216.239.59.104, A 216.239.59.99 (146)
```
#### Protocol Filter - Number

```shell-session
[!bash!]$ ### Syntax: proto [protocol number]
[!bash!]$ sudo tcpdump -i eth0 proto 17

06:17:09.864896 IP dialin-145-254-160-237.pools.arcor-ip.net.3009 > 145.253.2.203.domain: 35+ A? pagead2.googlesyndication.com. (47)
06:17:10.225414 IP 145.253.2.203.domain > dialin-145-254-160-237.pools.arcor-ip.net.3009: 35 4/0/0 CNAME pagead2.google.com., CNAME pagead.google.akadns.net., A 216.239.59.104, A 216.239.59.99 (146)
```

![](Pasted%20image%2020250918173420.png)

![](Pasted%20image%2020250918175747.png)

Cheat sheet

|**Command**|**Description**|
|---|---|
|`tcpdump --version`|Prints the tcpdump and libpcap version strings then exits.|
|`tcpdump -h`|Prints the help and usage information.|
|`tcpdump -D`|Prints a list of usable network interfaces from which tcpdump can capture.|
|`tcpdump -i (interface name or #)`|Executes tcpdump and utilizes the interface specified to capture on.|
|`tcpdump -i (int) -w file.pcap`|Runs a capture on the specified interface and writes the output to a file.|
|`tcpdump -r file.pcap`|TCPDump will read the output from a specified file.|
|`tcpdump -r/-w file.pcap -l \\| grep 'string'`|TCPDump will utilize the capture traffic from a live capture or a file and set stdout as line-buffered. We can then utilize pipe (\|) to send that output to other tools such as grep to look for strings or specific patterns.|
|`tcpdump -i (int) host (ip)`|TCPDump will start a capture on the interface specified at (int) and will only capture traffic originating from or destined to the IP address or hostname specified after `host`.|
|`tcpdump -i (int) port (#)`|Will filter the capture for anything sourcing from or destined to port (#) and discard the rest.|
|`tcpdump -i (int) proto (#)`|Will filter the capture for any protocol traffic matching the (#). For example, (6) would filter for any TCP traffic and discard the rest.|
|`tcpdump -i (int) (proto name)`|Will utilize a protocols common name to filter the traffic captured. TCP/UDP/ICMP as examples.|

---

## Tcpdump Common Switches and Filters

|**Switch/Filter**|**Description**|
|---|---|
|`D`|Will display any interfaces available to capture from.|
|`i`|Selects an interface to capture from. ex. -i eth0|
|`n`|Do not resolve hostnames.|
|`nn`|Do not resolve hostnames or well-known ports.|
|`e`|Will grab the ethernet header along with upper-layer data.|
|`X`|Show Contents of packets in hex and ASCII.|
|`XX`|Same as X, but will also specify ethernet headers. (like using Xe)|
|`v, vv, vvv`|Increase the verbosity of output shown and saved.|
|`c`|Grab a specific number of packets, then quit the program.|
|`s`|Defines how much of a packet to grab.|
|`S`|change relative sequence numbers in the capture display to absolute sequence numbers. (13248765839 instead of 101)|
|`q`|Print less protocol information.|
|`r file.pcap`|Read from a file.|
|`w file.pcap`|Write into a file|
|`host`|Host will filter visible traffic to show anything involving the designated host. Bi-directional|
|`src / dest`|`src` and `dest` are modifiers. We can use them to designate a source or destination host or port.|
|`net`|`net` will show us any traffic sourcing from or destined to the network designated. It uses / notation.|
|`proto`|will filter for a specific protocol type. (ether, TCP, UDP, and ICMP as examples)|
|`port`|`port` is bi-directional. It will show any traffic with the specified port as the source or destination.|
|`portrange`|`Portrange` allows us to specify a range of ports. (0-1024)|
|`less / greater "< >"`|`less` and `greater` can be used to look for a packet or protocol option of a specific size.|
|`and / &&`|`and` `&&` can be used to concatenate two different filters together. for example, src host AND port.|
|`or`|`or` Or allows for a match on either of two conditions. It does not have to meet both. It can be tricky.|
|`not`|`not` is a modifier saying anything but x. For example, not UDP.|

---

## TShark

|**Command**|**Description**|
|---|---|
|`tshark -h`|Prints the help menu.|
|`tshark -D`|List available interfaces to capture from.|
|`tshark -i (int)`|Capture on a selected interface. Replace (int) with the interface name or number.|
|`tshark -i eth0 -f "host (ip)"`|apply a filter with (-f) looking for a specific host while utilizing tshark|
|`D`|Will display any interfaces available to capture from and then exit out.|
|`L`|Will list the Link-layer mediums you can capture from and then exit out. (ethernet as an example)|
|`i`|choose an interface to capture from. (-i eth0)|
|`f`|packet filter in libpcap syntax. Used during capture.|
|`c`|Grab a specific number of packets, then quit the program. Defines a stop condition.|
|`a`|Defines an autostop condition. It can be after a duration, specific file size, or after a certain number of packets.|
|`r (pcap-file)`|Read from a file.|
|`W (pcap-file)`|Write into a file using the pcapng format.|
|`P`|Will print the packet summary while writing into a file (-W)|
|`x`|will add Hex and ASCII output into the capture.|
|`h`|See the help menu|

---

## WireShark

|**Capture Filter**|**Description**|
|---|---|
|`host x.x.x.x`|Capture only traffic pertaining to a certain host|
|`net x.x.x.x/24`|Capture traffic to or from a specific network (using slash notation to specify the mask)|
|`src/dst net x.x.x.x/24`|Using src or dst net will only capture traffic sourcing from the specified network or destined to the target network|
|`port #`|will filter out all traffic except the port you specify|
|`not`|will capture everything except the variable specified. ex. `not port 80`|
|`and`|AND will concatenate your specified ports. ex. `host 192.168.1.1 and port 80`|
|`portrange x-x`|Portrange will grab traffic from all ports within the range only|
|`ip / ether / tcp`|These filters will only grab traffic from specified protocol headers.|
|`broadcast / multicast / unicast`|Grabs a specific type of traffic. one to one, one to many, or one to all.|

|**Display Filter**|**Description**|
|---|---|
|`ip.addr == x.x.x.x`|Capture only traffic pertaining to a certain host. This is an OR statement.|
|`ip.addr == x.x.x.x/24`|Capture traffic pertaining to a specific network. This is an OR statement.|
|`ip.src/dst == x.x.x.x`|Capture traffic to or from a specific host.|
|`dns / tcp / ftp / arp / ip`|filter traffic by a specific protocol. There are many more options.|
|`tcp.port == x`|filter by a specific tcp port.|
|`src.port / dst.port ==x`|will capture everything except the port specified.|
|`and / or / not`|AND will concatenate, OR will find either of two options, NOT will exclude your input option.|
|`tcp.stream eq #`|Allows us to follow a tcp session in which we captured the entire stream. Replace (#) with the session to reassemble.|
|`http`|Will filter for any traffic matching the http protocol.|
|`http && image-jfif`|This filter will display any packet with a jpeg image file.|
|`ftp`|Filters for the ftp protocol.|
|`ftp.request.command`|Will filter for any control commands sent over ftp control channel.|
|`ftp-data`|Will show any objects transfered over ftp.|

---

## Misc Commands

|**Command**|**Description**|
|---|---|
|`sudo *`|Sudo will run the command that proceeds it with elevated privileges.|
|`which (application)`|Utilizes which to determine if (application) is installed on the host. Replace the application with what you are looking for. ex. `which tcpdump`|
|`sudo apt install (application)`|Uses elevated privileges to install an application package if it does not exist on the host. ex. `sudo apt install wireshark`|
|`man (application)`|Displays the manual pages for an application. ex. `man tcpdump`.|

## Common Ports and Protocols

|**Port Number**|**Protocol**|**Description**|
|---|---|---|
|`20`|FTP-Data|Data channel for passing FTP files.|
|`21`|FTP-Command|Control channel for issuing commands to an FTP server.|
|`22`|SSH|Secure Shell Service port. Provides secure remote communications|
|`23`|Telnet|Telnet service provides cleartext communications between hosts.|
|`25`|SMTP|Simple Mail Transfer protocol. Utilized for email transmissions between servers.|
|`53`|DNS|Domain Name Services. Provides name resolution with multiple protocols|
|`69`|TFTP|Trivial File Transfer Protocol. A lightweight, minimal-function transfer protocol.|
|`80`|HTTP|HyperText Transfer Protocol. Provides dynamic web services|
|`88`|Kerberos|Providing cryptographic network authentication|
|`110`|POP3|Mail service utilized by clients to retrieve email from a server.|
|`111`|RPC|Remote Procedure Call. Remote service for managing network file systems.|
|`115`|SFTP|SSH File Transfer Protocol. An extension of SSH providing secure and reliable FTP services.|
|`123`|NTP|Network Time Protocol. Provides timing and sync services for network devices.|
|`137`|Netbios-NS|Local network name resolution.|
|`139`|Netbios-SSN|Provides session services for data transfer. Services like SMB can utilize it.|
|`179`|BGP|Border Gateway Protocol. BGP is a protocol for exchanging routing info with autonomous systems worldwide.|
|`389`|LDAP|Lightweight Directory Access Protocol. System agnostic authentication and authorization services.|
|`443`|HTTPS|HyperText Transfer Protocol Secure. An extension of HTTP utilizing SSL/TLS for encrypting the communications.|
|`445`|SMB|Server Message Block. SMB allows for the sharing of services, files, networking ports, and printers between hosts.|