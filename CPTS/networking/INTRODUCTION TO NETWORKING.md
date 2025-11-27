#### Common Terminology

|**Network Type**|**Definition**|
|---|---|
|Wide Area Network (WAN)|Internet|
|Local Area Network (LAN)|Internal Networks (Ex: Home or Office)|
|Wireless Local Area Network (WLAN)|Internal Networks accessible over Wi-Fi|
|Virtual Private Network (VPN)|Connects multiple network sites to one `LAN`|
## VPN

There are three main types `Virtual Private Networks` (`VPN`), but all three have the same goal of making the user feel as if they were plugged into a different network.

#### Site-To-Site VPN

Both the client and server are Network Devices, typically either `Routers` or `Firewalls`, and share entire network ranges. This is most commonly used to join company networks together over the Internet, allowing multiple locations to communicate over the Internet as if they were local.

#### Remote Access VPN

This involves the client's computer creating a virtual interface that behaves as if it is on a client's network. Hack The Box utilizes `OpenVPN`, which makes a TUN Adapter letting us access the labs. When analyzing these VPNs, an important piece to consider is the routing table that is created when joining the VPN. If the VPN only creates routes for specific networks (ex: 10.10.10.0/24), this is called a `Split-Tunnel VPN`, meaning the Internet connection is not going out of the VPN. This is great for Hack The Box because it provides access to the Lab without the privacy concern of monitoring your internet connection. However, for a company, `split-tunnel` VPN's are typically not ideal because if the machine is infected with malware, network-based detection methods will most likely not work as that traffic goes out the Internet.

#### SSL VPN

This is essentially a VPN that is done within our web browser and is becoming increasingly common as web browsers are becoming capable of doing anything. Typically these will stream applications or entire desktop sessions to your web browser. A great example of this would be the HackTheBox Pwnbox.

## Star

The star topology is a network component that maintains a connection to all hosts. Each host is connected to the `central network component` via a separate link. This is usually a router, a hub, or a switch. These handle the `forwarding function` for the data packets. To do this, the data packets are received and forwarded to the destination. The data traffic on the central network component can be very high since all data and connections go through it.

#### Star Topology

![Diagram showing connections between Hosts A, B, C, D, E, and F.](https://academy.hackthebox.com/storage/modules/34/redesigned/topo_star.png)

---

![[Pasted image 20250902164820.png## ISO/OSI vs. TCP/IP

`TCP/IP` is a communication protocol that allows hosts to connect to the Internet. It refers to the `Transmission Control Protocol` used in and by applications on the Internet. In contrast to `OSI`, it allows a lightening of the rules that must be followed, provided that general guidelines are followed.

`OSI`, on the other hand, is a communication gateway between the network and end-users. The OSI model is usually referred to as the reference model because it is newer and more widely used. It is also known for its strict protocol and limitations.


| **Layer**        | **Function**                                                                                                                                                                                                                | **Function** |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| `7.Application`  | Among other things, this layer controls the input and output of data and provides the application functions.                                                                                                                |              |
| `6.Presentation` | The presentation layer's task is to transfer the system-dependent presentation of data into a form independent of the application.                                                                                          |              |
| `5.Session`      | The session layer controls the logical connection between two systems and prevents, for example, connection breakdowns or other problems.                                                                                   |              |
| `4.Transport`    | Layer 4 is used for end-to-end control of the transferred data. The Transport Layer can detect and avoid congestion situations and segment data streams.                                                                    |              |
| `3.Network`      | On the networking layer, connections are established in circuit-switched networks, and data packets are forwarded in packet-switched networks. Data is transmitted over the entire network from the sender to the receiver. |              |
| `2.Data Link`    | The central task of layer 2 is to enable reliable and error-free transmissions on the respective medium. For this purpose, the bitstreams from layer 1 are divided into blocks or frames.                                   |              |
| `1.Physical`     | The transmission techniques used are, for example, electrical signals, optical signals, or electromagnetic waves. Through layer 1, the transmission takes place on wired or wireless transmission lines.                    |              |

---

|**Layer**|**Function**|
|---|---|
|`4.Application`|The Application Layer allows applications to access the other layers' services and defines the protocols applications use to exchange data.|
|`3.Transport`|The Transport Layer is responsible for providing (TCP) session and (UDP) datagram services for the Application Layer.|
|`2.Internet`|The Internet Layer is responsible for host addressing, packaging, and routing functions.|
|`1.Link`|The Link layer is responsible for placing the TCP/IP packets on the network medium and receiving corresponding packets from the network medium. TCP/IP is designed to work independently of the network access method, frame format, and medium.|

---

|**Protocol**|**Acronym**|**Description**|
|---|---|---|
|Wired Equivalent Privacy|`WEP`|WEP is a type of security protocol that was commonly used to secure wireless networks.|
|Secure Shell|`SSH`|A secure network protocol used to log into and execute commands on a remote system|
|File Transfer Protocol|`FTP`|A network protocol used to transfer files from one system to another|
|Simple Mail Transfer Protocol|`SMTP`|A protocol used to send and receive emails|
|Hypertext Transfer Protocol|`HTTP`|A client-server protocol used to send and receive data over the internet|
|Server Message Block|`SMB`|A protocol used to share files, printers, and other resources in a network|
|Network File System|`NFS`|A protocol used to access files over a network|
|Simple Network Management Protocol|`SNMP`|A protocol used to manage network devices|
|Wi-Fi Protected Access|`WPA`|WPA is a wireless security protocol that uses a password to protect wireless networks from unauthorized access.|
|Temporal Key Integrity Protocol|`TKIP`|TKIP is also a security protocol used in wireless networks but less secure.|
|Network Time Protocol|`NTP`|It is used to synchronize the timing of computers on a network.|
|Virtual Local Area Network|`VLAN`|It is a way to segment a network into multiple logical networks.|
|VLAN Trunking Protocol|`VTP`|VTP is a Layer 2 protocol that is used to establish and maintain a virtual LAN (VLAN) spanning multiple switches.|
|Routing Information Protocol|`RIP`|RIP is a distance-vector routing protocol used in local area networks (LANs) and wide area networks (WANs).|
|Open Shortest Path First|`OSPF`|It is an interior gateway protocol (IGP) for routing traffic within a single Autonomous System (AS) in an Internet Protocol (IP) network.|
|Interior Gateway Routing Protocol|`IGRP`|IGRP is a Cisco proprietary interior gateway protocol designed for routing within autonomous systems.|
|Enhanced Interior Gateway Routing Protocol|`EIGRP`|It is an advanced distance-vector routing protocol that is used to route IP traffic within a network.|
|Pretty Good Privacy|`PGP`|PGP is an encryption program that is used to secure emails, files, and other types of data.|
|Network News Transfer Protocol|`NNTP`|NNTP is a protocol used for distributing and retrieving messages in newsgroups across the internet.|
|Cisco Discovery Protocol|`CDP`|It is a proprietary protocol developed by Cisco Systems that allows network administrators to discover and manage Cisco devices connected to the network.|
|Hot Standby Router Protocol|`HSRP`|HSRP is a protocol used in Cisco routers to provide redundancy in the event of a router or other network device failure.|
|Virtual Router Redundancy Protocol|`VRRP`|It is a protocol used to provide automatic assignment of available Internet Protocol (IP) routers to participating hosts.|
|Spanning Tree Protocol|`STP`|STP is a network protocol used to ensure a loop-free topology in Layer 2 Ethernet networks.|
|Terminal Access Controller Access-Control System|`TACACS`|TACACS is a protocol that provides centralized authentication, authorization, and accounting for network access.|
|Session Initiation Protocol|`SIP`|It is a signaling protocol used for establishing and terminating real-time voice, video and multimedia sessions over an IP network.|
|Voice Over IP|`VOIP`|VOIP is a technology that allows for telephone calls to be made over the internet.|
|Extensible Authentication Protocol|`EAP`|EAP is a framework for authentication that supports multiple authentication methods, such as passwords, digital certificates, one-time passwords, and public-key authentication.|
|Lightweight Extensible Authentication Protocol|`LEAP`|LEAP is a proprietary wireless authentication protocol developed by Cisco Systems. It is based on the Extensible Authentication Protocol (EAP) used in the Point-to-Point Protocol (PPP).|
|Protected Extensible Authentication Protocol|`PEAP`|PEAP is a security protocol that provides an encrypted tunnel for wireless networks and other types of networks.|
|Systems Management Server|`SMS`|SMS is a systems management solution that helps organizations manage their networks, systems, and mobile devices.|
|Microsoft Baseline Security Analyzer|`MBSA`|It is a free security tool from Microsoft that is used to detect potential security vulnerabilities in Windows computers, networks, and systems.|
|Supervisory Control and Data Acquisition|`SCADA`|It is a type of industrial control system that is used to monitor and control industrial processes, such as those in manufacturing, power generation, and water and waste treatment.|
|Virtual Private Network|`VPN`|VPN is a technology that allows users to create a secure, encrypted connection to another network over the internet.|
|Internet Protocol Security|`IPsec`|IPsec is a protocol used to provide secure, encrypted communication over a network. It is commonly used in VPNs, or Virtual Private Networks, to create a secure tunnel between two devices.|
|Point-to-Point Tunneling Protocol|`PPTP`|It is a protocol used to create a secure, encrypted tunnel for remote access.|
|Network Address Translation|`NAT`|NAT is a technology that allows multiple devices on a private network to connect to the internet using a single public IP address. NAT works by translating the private IP addresses of devices on the network into a single public IP address, which is then used to connect to the internet.|
|Carriage Return Line Feed|`CRLF`|Combines two control characters to indicate the end of a line and a start of a new one for certain text file formats.|
|Asynchronous JavaScript and XML|`AJAX`|Web development technique that allows creating dynamic web pages using JavaScript and XML/JSON.|
|Internet Server Application Programming Interface|`ISAPI`|Allows to create performance-oriented web extensions for web servers using a set of APIs.|
|Uniform Resource Identifier|`URI`|It is a syntax used to identify a resource on the Internet.|
|Uniform Resource Locator|`URL`|Subset of URI that identifies a web page or another resource on the Internet, including the protocol and the domain name.|
|Internet Key Exchange|`IKE`|IKE is a protocol used to set up a secure connection between two computers. It is used in virtual private networks (VPNs) to provide authentication and encryption for data transmission, protecting the data from outside eavesdropping and tampering.|
|Generic Routing Encapsulation|`GRE`|This protocol is used to encapsulate the data being transmitted within the VPN tunnel.|
|Remote Shell|`RSH`|It is a program under Unix that allows executing commands and programs on a remote computer.|

---

| **Protocol**                                              | **Acronym**  | **Port**         | **Description**                                                                                                                                                                    |
| --------------------------------------------------------- | ------------ | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Telnet                                                    | `Telnet`     | `23`             | Remote login service                                                                                                                                                               |
| Secure Shell                                              | `SSH`        | `22`             | Secure remote login service                                                                                                                                                        |
| Simple Network Management Protocol                        | `SNMP`       | `161-162`        | Manage network devices                                                                                                                                                             |
| Hyper Text Transfer Protocol                              | `HTTP`       | `80`             | Used to transfer webpages                                                                                                                                                          |
| Hyper Text Transfer Protocol Secure                       | `HTTPS`      | `443`            | Used to transfer secure webpages                                                                                                                                                   |
| Domain Name System                                        | `DNS`        | `53`             | Lookup domain names                                                                                                                                                                |
| File Transfer Protocol                                    | `FTP`        | `20-21`          | Used to transfer files                                                                                                                                                             |
| Trivial File Transfer Protocol                            | `TFTP`       | `69`             | Used to transfer files                                                                                                                                                             |
| Network Time Protocol                                     | `NTP`        | `123`            | Synchronize computer clocks                                                                                                                                                        |
| Simple Mail Transfer Protocol                             | `SMTP`       | `25`             | Used for email transfer                                                                                                                                                            |
| Post Office Protocol                                      | `POP3`       | `110`            | Used to retrieve emails                                                                                                                                                            |
| Internet Message Access Protocol                          | `IMAP`       | `143`            | Used to access emails                                                                                                                                                              |
| Server Message Block                                      | `SMB`        | `445`            | Used to transfer files                                                                                                                                                             |
| Network File System                                       | `NFS`        | `111`, `2049`    | Used to mount remote systems                                                                                                                                                       |
| Bootstrap Protocol                                        | `BOOTP`      | `67`, `68`       | Used to bootstrap computers                                                                                                                                                        |
| Kerberos                                                  | `Kerberos`   | `88`             | Used for authentication and authorization                                                                                                                                          |
| Lightweight Directory Access Protocol                     | `LDAP`       | `389`            | Used for directory services                                                                                                                                                        |
| Remote Authentication Dial-In User Service                | `RADIUS`     | `1812`, `1813`   | Used for authentication and authorization                                                                                                                                          |
| Dynamic Host Configuration Protocol                       | `DHCP`       | `67`, `68`       | Used to configure IP addresses                                                                                                                                                     |
| Remote Desktop Protocol                                   | `RDP`        | `3389`           | Used for remote desktop access                                                                                                                                                     |
| Network News Transfer Protocol                            | `NNTP`       | `119`            | Used to access newsgroups                                                                                                                                                          |
| Remote Procedure Call                                     | `RPC`        | `135`, `137-139` | Used to call remote procedures                                                                                                                                                     |
| Identification Protocol                                   | `Ident`      | `113`            | Used to identify user processes                                                                                                                                                    |
| Internet Control Message Protocol                         | `ICMP`       | `0-255`          | Used to troubleshoot network issues                                                                                                                                                |
| Internet Group Management Protocol                        | `IGMP`       | `0-255`          | Used for multicasting                                                                                                                                                              |
| Oracle DB (Default/Alternative) Listener                  | `oracle-tns` | `1521`/`1526`    | The Oracle database default/alternative listener is a service that runs on the database host and receives requests from Oracle clients.                                            |
| Ingres Lock                                               | `ingreslock` | `1524`           | Ingres database is commonly used for large commercial applications and as a backdoor that can execute commands remotely via RPC.                                                   |
| Squid Web Proxy                                           | `http-proxy` | `3128`           | Squid web proxy is a caching and forwarding HTTP web proxy used to speed up a web server by caching repeated requests.                                                             |
| Secure Copy Protocol                                      | `SCP`        | `22`             | Securely copy files between systems                                                                                                                                                |
| Session Initiation Protocol                               | `SIP`        | `5060`           | Used for VoIP sessions                                                                                                                                                             |
| Simple Object Access Protocol                             | `SOAP`       | `80`, `443`      | Used for web services                                                                                                                                                              |
| Secure Socket Layer                                       | `SSL`        | `443`            | Securely transfer files                                                                                                                                                            |
| TCP Wrappers                                              | `TCPW`       | `113`            | Used for access control                                                                                                                                                            |
| Internet Security Association and Key Management Protocol | `ISAKMP`     | `500`            | Used for VPN connections                                                                                                                                                           |
| Microsoft SQL Server                                      | `ms-sql-s`   | `1433`           | Used for client connections to the Microsoft SQL Server.                                                                                                                           |
| Kerberized Internet Negotiation of Keys                   | `KINK`       | `892`            | Used for authentication and authorization                                                                                                                                          |
| Open Shortest Path First                                  | `OSPF`       | `89`             | Used for routing                                                                                                                                                                   |
| Point-to-Point Tunneling Protocol                         | `PPTP`       | `1723`           | Is used to create VPNs                                                                                                                                                             |
| Remote Execution                                          | `REXEC`      | `512`            | This protocol is used to execute commands on remote computers and send the output of commands back to the local computer.                                                          |
| Remote Login                                              | `RLOGIN`     | `513`            | This protocol starts an interactive shell session on a remote computer.                                                                                                            |
| X Window System                                           | `X11`        | `6000`           | It is a computer software system and network protocol that provides a graphical user interface (GUI) for networked computers.                                                      |
| Relational Database Management System                     | `DB2`        | `50000`          | RDBMS is designed to store, retrieve and manage data in a structured format for enterprise applications such as financial systems, customer relationship management (CRM) systems. |
