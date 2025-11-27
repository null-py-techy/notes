 ```
dig @10.129.2.48 version.bind txt chaos


; <<>> DiG 9.20.13 <<>> @10.129.2.48 version.bind txt chaos
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 37657
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 79032da3c11b957f2863579968d162da77bc7c2c34ac0e8d (good)
;; QUESTION SECTION:
;version.bind.			CH	TXT

;; ANSWER SECTION:
version.bind.		0	CH	TXT	"HTB{GoTtgUnyze9Psw4vGjcuMpHRp}"

;; AUTHORITY SECTION:
version.bind.		0	CH	NS	version.bind.

;; Query time: 245 msec
;; SERVER: 10.129.2.48#53(10.129.2.48) (UDP)
;; WHEN: Mon Sep 22 20:38:15 +0545 2025
;; MSG SIZE  rcvd: 126
```

After the configurations are transferred to the system, our client wants to know if it is possible to find out our target's DNS server version. Submit the DNS server version of the target as the answer.
->HTB{GoTtgUnyze9Psw4vGjcuMpHRp}