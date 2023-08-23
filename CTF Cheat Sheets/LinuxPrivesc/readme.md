---
icon: code-square
---
# Linux Privesc

## OS, Kernel & Hostname

```bash
cat /etc/os-release
cat /etc/issue
cat /proc/version
hostname
uname -a
```

## Users

```bash
cat /etc/passwd
id
sudo -l

# See user special groups and list files
groups
find / -group management -ls 2>/dev/null
```

## Network

```bash
netstat -antup
```

### Try scanning other ports using netcat
```
dave@ubuntu:~/Desktop$ nc -nvz 192.168.122.4 1-10000 2>&1 | grep -v failed
Connection to 192.168.122.4 80 port [tcp/*] succeeded!
```
### SSH tunnel
Example to create a SSH tunnel and access port 80 in 192.168.122.4
```
ssh -L 80:192.168.122.4:80 dave@10.10.10.109
```
Now we can access 127.0.0.1:80.

## Processes Running

```bash
ps aux
ps aux | grep root

```

## Installed Packages

```bash
dpkg -l (Debian)
rpm -qa (Fedora)
```

## Find SUID

```bash
find / -perm -u=s -type f 2>/dev/null
find /* -user root -perm -4000 -print 2>/dev/null
```

## World writable scripts invoked as root

```bash
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null
```

## World executable folder

```bash
find / -perm -o x -type d 2>/dev/null
```

## World writable and executable folders

```bash
find / \\( -perm -o w -perm -o x \\) -type d 2>/dev/null
```

## Find world-writable files in `/etc`

```bash
find /etc -perm -2 -type f 2>/dev/null
find / -perm -2 -type f 2>/dev/null
```

## World-writable directories

```bash
find / -writable -type d 2>/dev/null
```
