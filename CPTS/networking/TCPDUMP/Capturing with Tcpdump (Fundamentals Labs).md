## Tasks

#### Task #1

`Validate Tcpdump is installed on our machine.`

Before we can get started, ensure we have tcpdump installed. What command do we use to determine if tcpdump is installed on Linux?

**Click to show answer**To determine if we have tcpdump installed, we can utilize the command in Linux or hit the Windows key and start typing tcpdump on Windows.

```shell-session
[!bash!]$ which tcpdump
```

---

#### Task #2

`Start a capture.`

Once we know tcpdump is installed, we are ready to start our first capture. If we are unsure of what interfaces we have to listen from, we can utilize a built-in switch to list them all for us.

Which tcpdump switch is used to show us all possible interfaces we can listen to?

**Click to show answer**

`Step one`: List interfaces to capture from.

```shell-session
[!bash!]$ tcpdump -D 
```

`Step two`: Start our capture.

```shell-session
[!bash!]$ tcpdump -i [interface name or #]
```

---

#### Task #3

`Utilize Basic Capture Filters.`

Now that we can capture traffic, let us modify how that information is presented to us. We will accomplish this by adding verbosity to our output and displaying contents in ASCII and Hex. Once we complete this task, attempt it again using other switches.

Disable name resolution and display relative sequence numbers for another challenge.

**Click to show answer**

```shell-session
[!bash!]$ tcpdump -i [interface name or #] -vX
```

---

#### Task #4

`Save a Capture to a .PCAP file.`

Now it is up to us how we wish to capture and see the output. Remember, when utilizing capture filters, it will modify what we get. Grab our first full capture from the wire, and save it to a PCAP file. This will be a sample to baseline the enterprise network.

**Click to show answer**

```shell-session
[!bash!]$ tcpdump -i [interface name or #] -nvw [/path/of/filename.pcap]
```

---

#### Task #5

`Read the Capture from a .PCAP file.`

Our team members have given us a PCAP they captured while surveying another section of the enterprise, read the PCAP file into tcpdump, and modify our view of the PCAP to help us determine what is happening. We can disable hostname and port resolution for simplicity and ensure we see any TCP sequence and acknowledgment numbers in absolute values. For the sake of the lab, utilize the PCAP file we created in the previous step for this task.

**Click to show answer**

```shell-session
[!bash!]$ tcpdump -nnSXr [file/to/read.pcap]
```



## Questions
1.What TCPDump switch will allow us to pipe the contents of a pcap file out to another function such as 'grep'?
->`-l`

---
2.True or False: The filter "port" looks at source and destination traffic.
->`True`

---
3.If we wished to filter out ICMP traffic from our capture, what filter could we use? ( word only, not symbol please.)
->`not icmp`

---
4.What command will show you where / if TCPDump is installed?
->`which tcpdump`

---
5.How do you start a capture with TCPDump to capture on eth0?
->`tcpdump -i eth0`

---
6.What switch will provide more verbosity in your output?
->`-v`

---
7.What switch will write your capture output to a .pcap file?
->`w`

---
8.What switch will read a capture from a .pcap file?
->`r`

---
9.What switch will show the contents of a capture in Hex and ASCII?
->`X`
