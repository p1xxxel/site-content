# Hackthebox Pit

![pit](/pit.png)

**Operating System** : Linux

**Difficulty** : Medium

**Points** : 30

**Creators** : polarbearer and GibParadox

## Nmap Scan
```bash
22/tcp   open  ssh             OpenSSH 8.0 (protocol 2.0)
80/tcp   open  http            nginx 1.14.1
9090/tcp open  ssl/zeus-admin?
```

Nginx at port 80

cockpit at port 9090

dns found dms-pit.htb

Visiting the page initially, it is 403 forbidden and searching directories does not return anything interesting.
![403](/dms-pit_403_forbidden.png.png)

From the udp scan, we can see that there is a snmp port open.
```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-30 18:53 IST
Nmap scan report for dms-pit.htb (10.10.10.241)
Host is up (0.079s latency).
Not shown: 999 filtered ports
PORT    STATE         SERVICE
161/udp open|filtered snmp

Nmap done: 1 IP address (1 host up) scanned in 1085.90 seconds
```

## snmpwalk

```bash
snmpwalk -c public -v1 10.10.10.241
```
Unfortunately snmpwalk does not give us the interesting result that we needed.

## using snmp perl scripts
#### Link : https://github.com/dheiland-r7/snmp

We get 2 important things using 
```bash
./snmpbw.pl 10.10.10.241 public 2 1
```
1. Possible web directory
	![snmp web dir](/snmp_web_directory.png)
2. Usernames
	![snmp usernames](/snmp_usernames.png)
	Possible usernames found : root, michelle
# Login Page
Visiting the directory found through snmp perl scripts, we get a seedDMS sign in page. 
Using sqlmap does not give anything meaningful.

## Bruteforce
We have the usernames : michelle and root

Using xatonet 10 million passwords top 100, we find the credentials of the user michelle.
```bash
michelle:michelle
```

## Upgrade Note
Logging in as michelle, we see there is a upgrade note from administrator.
![upgrade note](./upgrade_note.png)
According to this, seeddms was upgraded from 5.1.10 to 5.1.15.
A changelog is also attached stating the same.

Going to the users list in seedDMS, we get some usernames along with their emails
```bash
Name

Administrator (admin)  
[admin@pit.htb](mailto:admin@pit.htb)  

Jack (jack)  
[jack@dms-pit.htb](mailto:jack@dms-pit.htb)  

Michelle (michelle)  
[michelle@pit.htb](mailto:michelle@pit.htb)
```

## Related CVEs
The version of seedDMS is 5.1.15 but a web shell upload of earlier version works.
![cve used](/cve_used.png)

## Web Shell
I copied the file 1.php to `/var/www/html/seeddms51x` otherwise it keeps on getting deleted. With that I have a persistent web shell.

I am unable to use a full fledged reverse shell probably due to hardening of the web server.

## server users
following non system users are obtained from `cat /etc/passwd`

```bash
root:x:0:0:root:/root:/bin/bash
michelle:x:1000:1000::/home/michelle:/bin/bash
```
## mysql credentials
```bash
dbUser=seeddms
dbPass=ied^ieY6xoquu
dbHostname="localhost"
dbDatabase="seeddms"
```
![mysql creds](/mysql_creds.png)

#### mysqldump
```bash
mysqldump -useeddms -pied^ieY6xoquu seeddms > a.sql
```

Got some hashes from the dump but cracking the only gives the already known credential
```bash
michelle:michelle
```
![mysqldump](/mysqldump.png)
Visiting the port 9090 it gives us a login page.

## cockpit creds
Initially I couldn't login but after finding the mysql creds, it could be used to login as michelle.

```bash
michelle:ied^ieY6xoquu
```

## Accessing the web terminal

### user.txt
Using the web terminal we get the user.txt as michelle
![web terminal user flag](/web_terminal_user_flag.png)

### adding ssh public key
By going to **Accounts**=>**michelle**=>**Authorized Public SSH Keys**=>**+**, we can add ssh public key.

![ssh public key](/added_ssh_public_key.png)

# Linpeas
Running linpeas, I saw one interesting thing about ACLs
![ACL linpeas](/ACL_linpeas.png)

This means that we can write and execute commands at `/usr/local/monitoring` but cannot read.

## SNMP command execution
`/usr/local/monitoring` seemed similar to something that I saw in the SNMP scripts.
![monitor bin](/monitor_bin.png)

When we cat the file at `/usr/bin/monitor`, we can see that it is a shell script to execute `check*sh`
![monitor shell script](/monitor_shell_script.png)

Researching a bit more about why it was in the SNMP results, I find this: 
https://book.hacktricks.xyz/pentesting/pentesting-snmp/snmp-rce

This basically tells how we can execute command using SNMP.

So what we need to do is place our payload at `/usr/local/monitoring` directory(we can do so due to the ACL), make sure that the name is such that it can be called by `check*sh` and lastly call the `snmpwalk` command given in hacktricks.

One thing to keep in mind is that there is a cleanup performed after some interval so the files you place in `/usr/local/monitoring` will automatically be removed.

I placed the following with the name `check123.sh`
![ssh payload](/ssh_payload.png)

After that I used the following command from hacktricks :
```bash
snmpwalk -v1 -c public 10.10.10.241 NET-SNMP-EXTEND-MIB::nsExtendObjects
```

Now if we try to login to `pit.htb` as root, we succeed.

## root.txt
![getting root flag](/getting_root_flag.png)
