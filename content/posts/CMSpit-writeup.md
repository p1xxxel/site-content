# Tryhackme CMSpit

![CMSpit](/CMSpit.png)

**Operating System** : Linux

**Difficulty** : Medium

**Creator** : stuxnet

Doing a nmap scan, we get

```bash
PORT   STATE SERVICE  VERSION
22/tcp open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.10
| ssh-hostkey:
|   2048 7f:25:f9:40:23:25:cd:29:8b:28:a9:d9:82:f5:49:e4 (RSA)
|   256 0a:f4:29:ed:55:43:19:e7:73:a7:09:79:30:a8:49:1b (ECDSA)
|_  256 2f:43:ad:a3:d1:5b:64:86:33:07:5d:94:f9:dc:a4:01 (ED25519)
80/tcp open  ssl/http Apache/2.4.18 (Ubuntu)
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-title: Authenticate Please!
|_Requested resource was /auth/login?to=/
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We see that port 80 and 22 are open.Going to the website at port 80, we see that it is Cockpit CMS and asks us to login. 
Searching for exploit, I came across a recent vulnerability that allows unauthenticated RCE by NoSQL injection.

https://swarm.ptsecurity.com/rce-cockpit-cms/

# Enumerating Users
If we send the following request in burpsuite, we can get a list of all users :
![](/CMSpit_enum_users.png)

So we get the following users :
```bash
admin
darkStar7471
skidy
ekoparty
```

# Compromising Admin account
Now that we have the list of users, we need to get into the admin account in order to get RCE.

In order to get the admin account, first we need to get a reset token and then use that reset token to reset the password of the account.

## Getting password reset token
To get the token, we send the following request in burpsuite
![](/CMSpit_getting_token.png)

To check which user this token belongs to, we can send the following request
![](/CMSpit_checking_user_token.png)

Clearly, this token belongs to the admin user.

## Resetting admin password
Now that we have the admin token, we can use it to reset the password by sending the following request :
![](/CMSpit_pass_reset.png)

Now we can use the credentials admin:Password1 to login to the CMS.
![](/CMSpit_logged_in.png)

# Getting a shell
Now that we have the admin account, we can use it to get a shell.
To do that we need to go to `/finder` and click on the upload button.
![](/CMSpit_finder_upload.png)

Then we can upload any php shell either reverse shell or a web shell.
I will  be using this one 
https://github.com/pentestmonkey/php-reverse-shell

Edit the content of reverse shell to your tun0 ip and preferred port and start a listener.

After uploading the reverse shell, go to `/php-reverse-shell` and your shell should be activated.

![](/CMSpit_getting_shell.png)

Now upgrade your shell to a fully interactive tty using
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
Ctrl+z
stty raw -echo
fg

```

# Getting user
Running linpeas, we see that there is port open that is not available from outside the server.
![](/CMSpit_mongo_port.png)

Searching for this port, we get that this port is for mongodb.

We can connect to it by typing mongo in the terminal.

There are some interesting databases
![](/CMSpit_mongo_dbs.png)

In the `sudouserbak` database,we find a collection named user and dumping it we get the user credentials.

![](/CMSpit_user_creds.png)

Now we can just ssh into the server as `stux` using the creds and get user.txt
```bash
stux:p4ssw0rdhack3d!123
```

![](/CMSpit_getting_user.png)

# Getting root
Doing a `sudo -l`, we see that we can execute `exiftool` as root.

We can use this to read root.txt from the command listed in gtfobins

![](/CMSpit_getting_root.png)
