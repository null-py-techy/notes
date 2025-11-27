 Now our client wants to know if it is possible to find out the version of the running services. Identify the version of service our client was talking about and submit the flag as the answer.
 ->HTB{kjnsdf2n982n1827eh76238s98di1w6}
- `sudo nmap 10.129.2.47 -sS -Pn -n --disable-arp-ping --source-port 53 -p- -vvv`
- Port 5000 is shown.
- `sudo nmap 10.129.2.47 -sS -sV -Pn -n --disable-arp-ping --source-port 53 -p50000 -vvv`
- `ncat -nv --source-port 53 10.129.2.47 50000`

sudo systemctl stop systemd-resolved