
`Network Traffic Analysis (NTA)` can be described as the act of examining network traffic to characterize common ports and protocols utilized, establish a baseline for our environment, monitor and respond to threats, and ensure the greatest possible insight into our organization's network.

#### Common Traffic Analysis Tools

| **Tool**    | **Description**                                                                                                                                                                                                                                                                                                                        |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tcpdump`   | [tcpdump](https://www.tcpdump.org/) is a command-line utility that, with the aid of LibPcap, captures and interprets network traffic from a network interface or capture file.                                                                                                                                                         |
| `Wireshark` | [Wireshark](https://www.wireshark.org/) is a graphical network traffic analyzer. It captures and decodes frames off the wire and allows for an in-depth look into the environment. It can run many different dissectors against the traffic to characterize the protocols and applications and provide insight into what is happening. |
![[Pasted image 20250903142152.png]]
A PDU is a data packet made up of control information and data encapsulated from each layer of the OSI model.
![[Pasted image 20250903142443.png]]
![[Pasted image 20250903142538.png]]
#### MAC-Addressing

Each logical or physical interface attached to a host has a Media Access Control (`MAC`) address. This address is a 48-bit `six octet` address represented in hexadecimal format. If we look at the image below, we can see an example of one by the `red` arrow.

#### Mac-Address

![Network interface configuration for en0: flags, MAC address, IPv6 and IPv4 addresses, netmask, and status details.](https://academy.hackthebox.com/storage/modules/81/Addressing.png)
## IP Addressing

The Internet Protocol (`IP`) was developed to deliver data from one host to another across network boundaries. IP is responsible for routing packets, the encapsulation of data, and fragmentation and reassembly of datagrams when they reach the destination host. By nature, IP is a connectionless protocol that provides no assurances that data will reach its intended recipient. For the reliability and validation of data delivery, IP relies on upper-layer protocols such as TCP. Currently, there exist two main versions of IP. IPv4, which is the current dominant standard, and IPv6, which is intended to be the successor of IPv4.

#### IPv4
An IPv4 address is made up of a 32-bit `four octet` number represented in decimal format. In our example, we can see the address `192.168.86.243`.Each octet of an IP address can be represented by a number ranging from `0` to `255`. When examining a PDU, we will find IP addresses in layer three (`Network`) of the OSI model and layer two (`internet`) of the TCP-IP model.

#### TCP VS. UDP

| **Characteristic**         | **TCP**                                                                    | **UDP**                                                                 |
| -------------------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `Transmission`             | Connection-oriented                                                        | Connectionless. Fire and forget.                                        |
| `Connection Establishment` | TCP uses a three-way handshake to ensure that a connection is established. | UDP does not ensure the destination is listening.                       |
| `Data Delivery`            | Stream-based conversations                                                 | packet by packet, the source does not care if the destination is active |
| `Receipt of data`          | Sequence and Acknowledgement numbers are utilized to account for data.     | UDP does not care.                                                      |
| `Speed`                    | TCP has more overhead and is slower because of its built-in functions.     | UDP is fast but unreliable.                                             |
## CP Three-way Handshake

One of the ways TCP ensures the delivery of data from server to client is the utilization of sessions. These sessions are established through what is called a three-way handshake. To make this happen, TCP utilizes an option in the TCP header called flags.

#### TCP Three-way Handshake

![Network packet capture showing TCP connections between IPs 192.168.1.140 and 174.143.213.184, with protocols TCP and HTTP, displaying sequence and acknowledgment numbers.](https://academy.hackthebox.com/storage/modules/81/three-way-handshake.png)

When examining this output, we can see the start of our handshake on line one. Looking at the information highlighted in the `red box`, we can see our initial Syn flag is set. If we look at the port numbers underlined in `green`, we can see two numbers, `57678` and `80`. The first number is the random high port number in use by the client, and the second is the well-known port for HTTP used by the server to listen for incoming web request connections. In line 2, we can see the server's response to the client with an `SYN / ACK` packet sent to the same ports. On line 3, we can see the client acknowledge the server's synchronization packet to establish the connection.

## HTTP

Hypertext Transfer Protocol (`HTTP`) is a stateless Application Layer protocol that has been in use since 1990. HTTP enables the transfer of data in clear text between a client and server over TCP. The client would send an HTTP request to the server, asking for a resource. A session is established, and the server responds with the requested media (HTML, images, hyperlinks, video). HTTP utilizes ports 80 or 8000 over TCP during normal operations. In exceptional circumstances, it can be modified to use alternate ports, or even at times, UDP.

#### HTTP Methods

To perform operations such as fetching webpages, requesting items for download, or posting your most recent tweet all require the use of specific methods. These methods define the actions taken when requesting a URI. Methods:

| **Method** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `HEAD`     | `required` is a safe method that requests a response from the server similar to a Get request except that the message body is not included. It is a great way to acquire more information about the server and its operational status.                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `GET`      | `required` Get is the most common method used. It requests information and content from the server. For example, `GET http://10.1.1.1/Webserver/index.html` requests the index.html page from the server based on our supplied URI.                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `POST`     | `optional` Post is a way to submit information to a server based on the fields in the request. For example, submitting a message to a Facebook post or website forum is a POST action. The actual action taken can vary based on the server, and we should pay attention to the response codes sent back to validate the action.                                                                                                                                                                                                                                                                                                                                          |
| `PUT`      | `optional` Put will take the data appended to the message and place it under the requested URI. If an item does not exist there already, it will create one with the supplied data. If an object already exists, the new PUT will be considered the most up-to-date, and the object will be modified to match. The easiest way to visualize the differences between PUT and POST is to think of it like this; PUT will create or update an object at the URI supplied, while POST will create child entities at the provided URI. The action taken can be compared with the difference between creating a new file vs. writing comments about that file on the same page. |
| `DELETE`   | `optional` Delete does as the name implies. It will remove the object at the given URI.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `TRACE`    | `optional` Allows for remote server diagnosis. The remote server will echo the same request that was sent in its response if the TRACE method is enabled.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `OPTIONS`  | `optional` The Options method can gather information on the supported HTTP methods the server recognizes. This way, we can determine the requirements for interacting with a specific resource or server without actually requesting data or objects from it.                                                                                                                                                                                                                                                                                                                                                                                                             |
| `CONNECT`  | `optional` Connect is reserved for use with Proxies or other security devices like firewalls. Connect allows for tunneling over HTTP. (`SSL tunnels`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
![](Pasted%20image%2020250917103200.png)

![](Pasted%20image%2020250917103215.png)

#### FTP Commands

| **Command** | **Description**                                                    |
| ----------- | ------------------------------------------------------------------ |
| `USER`      | specifies the user to log in as.                                   |
| `PASS`      | sends the password for the user attempting to log in.              |
| `PORT`      | when in active mode, this will change the data port used.          |
| `PASV`      | switches the connection to the server from active mode to passive. |
| `LIST`      | displays a list of the files in the current directory.             |
| `CWD`       | will change the current working directory to one specified.        |
| `PWD`       | prints out the directory you are currently working in.             |
| `SIZE`      | will return the size of a file specified.                          |
| `RETR`      | retrieves the file from the FTP server.                            |
| `QUIT`      | ends the session.                                                  |
![](Pasted%20image%2020250917104044.png)
![](Pasted%20image%2020250917104107.png)
