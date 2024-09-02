


## Web App Exploitation
This probably has a custom developed web application which include some web security flaw which must be identified and exploited. The question is: Which security flaw?

### Directory Enumeration

Mandatory checks for `robots.txt` and `security.txt`.
```
curl http://$TG/robots.txt
curl http://$TG/.well-known/security.txt
```

```
gobuster dir -u $TG -w /usr/share/wordlists/wfuzz/general/common.txt
gobuster dir -u $TG -x html,php,js -w /usr/share/wordlists/wfuzz/general/common.txt
```

#### Fuzzzzzzzz
```
ffuf -w /usr/share/wordlists/wfuzz/general/common.txt -u http://$TG/FUZZ
```

### XSS vulnerabilities
Start with common XSS Payloads

### SQL injection
Start with common SQLi Payloads

### Command injection
Some PHP scripts allow command injection like `index.php?cmd=<COMMAND>`.

### Server Enumeration
Usually, we don't have to do this. But, hey! If everything else fails, why not :smirk:


## Cryptography
This often features ciphertexts, cryptographic algorithms (AES, RSA), or cryptographic systems (Diffie-Hellman) which involve several encryption and decryption protocols used to uncover hidden messages or vulnerabilities.


## Steganography

`zsteg`, `stegcracker`

```
steghide extract -sf <filename>
```

```
binwalk <FILENAME>
binwalk -e <FILENAME>  # to extract
binwalk -dd ".*" <FILENAME>  # to force-extract
```


## Binary exploitation
This category often features compiled programs which have a vulnerability allowing a competitor to gain a command shell on the server running the vulnerable program. This often has the user exercising reverse engineering skills as well.

### Buffer Overflow
Exploiting a buffer overflow (which sometimes has some security mitigations in place) to gain a command shell and read a file.

### Format String
Exploiting a format string vulnerability to gain a command shell and read a file.

## Reverse Engineering
This category often features programs from all operating systems which must be reverse engineered to determine how the program operates. Typically the goal is to get the application to reach a certain point or perform some action in order to achieve a solution.

Ofcouse you can try `IDA Pro` or `Ghidra`. But you can also start with `strings`! :heart_eyes:

### ELF Reversing
### EXE Reversing

### Android APK Reversing
`apktool`

[bytecode-viewer](https://github.com/Konloch/bytecode-viewer) : Android APK Reverse Engineering Suite

## Programming/Coding
Showcase your supreme coding skills to solve challenges. The problem here will be either time-complexity, space-complexity or both. :sob:

## Forensics
This category often features memory dumps, hidden files, or encrypted data which must be analyzed for information about underlying information.

Start with identifying which file it is. [File signature](https://en.wikipedia.org/wiki/List_of_file_signatures) 101!
```
file <FILENAME> 
```

For memory dumps:
Also check [this](https://noob-atbash.github.io/CTF-writeups/fword-20/forensic/memory) out for a refresher.
```
volatility -f <FILE>  --imageinfo
```

Converting ASCII hexdump output into binary files
```
xxd -r <ASCII-HEXDUMP> <OUTPUT-FILE>
```


## Networking
This mostly features packet captures (PCAPs) which must be analyzed for information about an underlying surface.
Wireshark FTW!

## OSINT


## Blockchain


## Miscellaneous
Recursively search the current directory (`.`) and all the files inside for the string "flag".
```
grep -Rnw . -e 'flag'
```

```
find / -name "name_of_file" -type f 2>/dev/null
```

Set Target
```
TG=192.168.XXX.XXX
```

## 1. Information Gathering and Reconnaissance

[DNS lookup](https://dnschecker.org/all-dns-records-of-domain.php) | [Abuse IPDB](https://www.abuseipdb.com/) | [Shodan](https://www.shodan.io/) | 
[WayBackMachine](https://archive.org/web/) | [VirusTotal](https://www.virustotal.com/gui/home/search) | [App.Any.Run](https://app.any.run/)


## 2. Scanning and Enumeration

#### Nmap
```
sudo nmap -sS $TG -vvv -oN Nmap_init.txt
sudo nmap -sS -A $TG -vvv -oN Nmap_init.txt
```


### FTP (Port 20/21)
Check for `anonymous` login.
```
ftp $TG
```
Note: You can use commands like `ls`, `pwd`, `cd` and `get`.

Maybe checkout other variants of FTP like `lftp`.

### SSH (Port 22)
```
ssh <USERNAME>@$TG
```

Got ssh username, but has no password? Try bruteforcing with [Hydra](#bruteforcing-with-hydra)

Got ssh keys (at `~.ssh/id_rsa`)? Try this; 
```
chmod 600 id_rsa
ssh -i id_rsa <USERNAME>@$TG
```

You can also try cracking SSH PRIVATE keys using `john`;
```
ssh2john id_rsa > id_rsa.john
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.john
```

**SCP** <br>
Copy from remote to local;
```
scp -r <USERNAME>@$TG:/remote/path/to/foo /local/bar/
```

Copy from local to remote;
```
scp /local/bar/file USER@REMOTE_IP:/remote/path/to/foo
```

**SSH Tunneling**

Syntax: `ssh -L <LOCAL_PORT>:<TG_IP>:<TG_PORT> <USER>@<SSH_IP>`

```
ssh -L 2222:172.17.0.2:8080 <USERNMAE>@$TG
```

### Telnet (Port 23)

```
telnet $TG
```


### HTTP (Port 80)
Refer Web app exploitation


### Kerberos (Port 88)
Kerberos is a key authentication service within Active Directory. 


**Kerbrute**
```
/opt/kerbrute/kerbrute --dc $TG -d $TG userenum /path/to/wordlist.lst
```


### SMB (Ports 139/445)

Check for **EternalBlue**

`139/tcp open  netbios-ssn` (ms17-010) [CVE-2017-0143]

> A critical remote code execution vulnerability exists in Microsoft SMBv1


```
enum4linux $TG
```


Syntax: `smbclient -L //server/[service] -U <USERNAME>`
Syntax: `smbclient -L -N //server/[service] -U <USERNAME>` for no password.

```
smbclient -L //$TG/ -U '<USERNAME>'

smbclient -L //$TG/<SHARE> -U '<USERNAME>'
```


```
evil-winrm  -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'
```


```
evil-winrm -i 10.10.196.249 -u Administrator -H '0e0363213e37b94221497260b0bcb4fc'
```



### HTTPS (Port 443)

Must check the SSL certificate and look into sections like the `Subject Alt Names`.




#### Bruteforcing with Hydra

**HTTP Forms**
```
hydra -l <USERNAME> -P /usr/share/wordlists/rockyou.txt $TG http-post-form "/path/to/login:ed=^USER^&pw=^PASS^:F=incorrect" -t 10
```

**SSH**
```
hydra -l <USERNAME> -P /usr/share/wordlists/rockyou.txt $TG ssh -t 10
```


#### Password cracking

Step 1: Try [CrackStation](https://crackstation.net/) first! Then we can look into others;


**Hash type identification**: `hashid`, `hash-identifier` or we can use [Hash Analyzer](https://www.tunnelsup.com/hash-analyzer/).

To list the hash formats supported by John
```
john --list:formats 
```

To crack simple hashes;
```
john input_file --wordlist=/usr/share/wordlists/rockyou.txt --format=<HASH-FORMAT>
```


Find the hash [`MODE`](https://hashcat.net/wiki/doku.php?id=example_hashes) here!
```
hashcat -a 0 -m MODE input_file /usr/share/wordlists/rockyou.txt -O
```

For salted hash, `hashcat` expects the input file to be in the format `<hash>:<salt>`.



## 3. Exploitation

[ExploitDB](https://www.exploit-db.com/)

`msfconsole` is your friend here :smile:


Once you got shell using metasploit, try [upgrading the shell](https://infosecwriteups.com/metasploit-upgrade-normal-shell-to-meterpreter-shell-2f09be895646).
Background the current shell by typing **Ctrl + z**. Then;
```
use post/multi/manage/shell_to_meterpreter
```
Set the required variables and hit `run`!

`portfwd` command in meterpreter can be used to forward a local port to a remote service.

Syntax: `portfwd add –l <LOCAL-PORT> –p <REMOTE-PORT> –r <TARGET-HOST>`
```
portfwd add –l 3389 –p 3389 –r 172.16.194.191
portfwd delete –l 3389 –p 3389 –r 172.16.194.191
```


#### Shell Stabilization

`python -c 'import pty; pty.spawn("/bin/bash")'` <br>
`export TERM=xterm` <br>
[Optional] Hit **Ctrl + Z** and run `raw -echo; fg` <br>


#### Got Shell? IG again!
`whoami` && `id` && `sudo -l` && `cat /etc/*release` && `uname -a`


## 4. Privilege Escalation

Find **SUID** files! [GTFOBins](https://gtfobins.github.io/)
```
find / -perm -u=s -type f 2>/dev/null
```
```
sudo -l
```
```
cat /etc/sudoers
```


#### Very Handy Links ;)

- Have a Domain Name? Do a [DNS lookup](https://dnschecker.org/all-dns-records-of-domain.php)!
- [PHP] pentestmonkey/[php-reverse-shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)
- Reverse Shell Generator [here](https://www.revshells.com/) FTW!
- [CyberChef](https://gchq.github.io/CyberChef/)
- Have non-salted hashes? Give [CrackStation](https://crackstation.net/) a try!
- Free [WebHooks](https://webhook.site/ ) for all!



---

[Markdown Cheatsheet](https://www.markdownguide.org/cheat-sheet/) | [Markdown Emojis](https://gist.github.com/rxaviers/7360908)
