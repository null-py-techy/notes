Questions:

1.What version of nginx is running?
-> `1.14.2`
Hint: do nmap scan with -sCV then we get the service running with the version.

2.What is the domain name of the main website?
->`trick.htb`

3.What is the full path of the local file on Linux allows us to resolve domain names without the use of DNS?
->`/etc/hosts`

4.What is the other domain name that we can find?
->->`preprod-payroll.trick.htb`

so in this machine we learn that if we have 53 tcp port running on the machine ,its often configured to allow transfers.
first find the exisiting domain name.
we can `dig @10.129.227.180 axfr trick.htb` and we find it.

5.What is the name of the software running on preprod-payroll.trick.htb?
->`Payroll Management System`

hint:i got inside prepod subdomain and read the source code it was there.

6.What kind of vulnerability can be exploited to bypass the login page and read data?
->`SQL Injection`
hint:Look for public exploits for Payroll Management System in a search engine.

7.What single privilege does the database user have?
->`FILE`

ran sqlmap this command 
```
sqlmap -u http://preprod-payroll.trick.htb/ajax.php?action=login -- data="username=abc&password=abc" -p username --privileges
```

8.What is another virtual host name that NGINX is configured for?@0