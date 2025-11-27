## Different Formats

While we run various scans, we should always save the results. We can use these later to examine the differences between the different scanning methods we have used. `Nmap` can save the results in 3 different formats.

- Normal output (`-oN`) with the `.nmap` file extension
- Grepable output (`-oG`) with the `.gnmap` file extension
- XML output (`-oX`) with the `.xml` file extension

We can also specify the option (`-oA`) to save the results in all formats. The command could look like this:
```shell-session
ninjathebox98w1@htb[/htb]$ sudo nmap 10.129.2.28 -p- -oA target
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-16 12:14 CEST
Nmap scan report for 10.129.2.28
Host is up (0.0091s latency).
Not shown: 65525 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 10.22 seconds
```

| **Scanning Options** | **Description**                                                                 |
| -------------------- | ------------------------------------------------------------------------------- |
| `10.129.2.28`        | Scans the specified target.                                                     |
| `-p-`                | Scans all ports.                                                                |
| `-oA target`         | Saves the results in all formats, starting the name of each file with 'target'. |
If no full path is given, the results will be stored in the directory we are currently in. Next, we look at the different formats `Nmap` has created for us.

  Saving the Results

```shell-session
ninjathebox98w1@htb[/htb]$ ls

target.gnmap target.xml  target.nmap
```
## Style sheets

With the XML output, we can easily create HTML reports that are easy to read, even for non-technical people. This is later very useful for documentation, as it presents our results in a detailed and clear way. To convert the stored results from XML format to HTML, we can use the tool `xsltproc`.

  Saving the Results

```shell-session
ninjathebox98w1@htb[/htb]$ xsltproc target.xml -o target.html
```

 Perform a full TCP port scan on your target and create an HTML report. Submit the number of the highest port as the answer.
 -> 31337
 Open 10.129.185.221:22
Open 10.129.185.221:80
Open 10.129.185.221:110
Open 10.129.185.221:139
Open 10.129.185.221:143
Open 10.129.185.221:445
Open 10.129.185.221:31337